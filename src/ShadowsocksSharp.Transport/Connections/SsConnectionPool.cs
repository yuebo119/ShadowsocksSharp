using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Diagnostics;
using ShadowsocksSharp.Outbound;

namespace ShadowsocksSharp.Transport.Connections;

/// <summary>
/// Shadowsocks 连接管理器 - 高性能版本
/// </summary>
/// <remarks>
/// 优化:
/// - Socket 直接操作替代 TcpClient
/// - DNS 缓存避免重复解析
/// - TCP 连接预热减少首次连接延迟
/// - 连接健康检查避免使用已断开的连接
/// - 空闲连接自动清理
/// </remarks>
public sealed class SsConnectionPool : IDisposable
{
    private static readonly ConcurrentDictionary<string, DnsCacheEntry> SharedDnsCache =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly SsServerConfig _config;
    private readonly ForwardProxyConfig _forwardProxy;
    private readonly IOutboundConnector? _connector;
    private readonly SemaphoreSlim _semaphore;
    private readonly int _maxSize;
    private readonly ConcurrentQueue<WarmSocket> _warmPool = new();
    private readonly int _warmPoolSize;
    private readonly Timer? _cleanupTimer;
    private readonly int _recvBufferSize;
    private readonly int _sendBufferSize;
    private readonly int _maxConnectsPerSecond;
    private readonly SemaphoreSlim? _connectLimiter;
    private readonly Timer? _connectLimiterTimer;
    private int _warmRefillInFlight;

    // 空闲连接最大存活时间（秒）
    private const int MaxIdleSeconds = 30;

    private IPAddress[]? _cachedAddresses;
    private DateTime _dnsExpiry;
    private DateTime _dnsBackoffUntil;
    private int _dnsFailCount;
    private readonly Lock _dnsLock = new();

    private int _active;
    private int _failCount;
    private DateTime _lastFailTime;
    private bool _disposed;
    private static long _connectionIdCounter;

    public int ActiveCount => _active;
    public int MaxSize => _maxSize;

    public SsConnectionPool(
        SsServerConfig config,
        int initialCount = 0,
        int maxSize = 100,
        int warmPoolSize = 0,
        int socketReceiveBuffer = 0,
        int socketSendBuffer = 0,
        ForwardProxyConfig? forwardProxy = null,
        IOutboundConnector? connector = null)
    {
        _config = config;
        _forwardProxy = forwardProxy ?? new ForwardProxyConfig();
        _connector = connector;
        _maxSize = maxSize;
        // warmPoolSize=0 表示关闭预热池，避免连接复用导致的 nonce/盐不同步
        _warmPoolSize = Math.Max(0, warmPoolSize);
        _recvBufferSize = socketReceiveBuffer > 0 ? socketReceiveBuffer : 16384;
        _sendBufferSize = socketSendBuffer > 0 ? socketSendBuffer : 16384;
        _semaphore = new SemaphoreSlim(maxSize, maxSize);

        _maxConnectsPerSecond = Math.Max(0, config.MaxConnectionsPerSecond);
        if (_maxConnectsPerSecond > 0)
        {
            _connectLimiter = new SemaphoreSlim(_maxConnectsPerSecond, _maxConnectsPerSecond);
            _connectLimiterTimer = new Timer(RefillConnectLimiter, null,
                TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
            Log.I($"Connect rate limit: {_maxConnectsPerSecond}/s");
        }

        // 定期清理空闲连接
        _cleanupTimer = new Timer(CleanupIdleConnections, null,
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));

        Log.I($"Connection limiter created: max={maxSize}");
    }

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        // 预解析 DNS
        await ResolveDnsAsync(ct).ConfigureAwait(false);

        // 预热连接池
        if (_warmPoolSize > 0)
        {
            _ = WarmUpAsync(ct);
        }

        Log.D("Connection limiter ready");
    }

    /// <summary>
    /// 清理空闲连接
    /// </summary>
    private void CleanupIdleConnections(object? state)
    {
        if (_disposed) return;

        var now = Environment.TickCount64;
        var cleaned = 0;
        var count = _warmPool.Count;

        for (var i = 0; i < count; i++)
        {
            if (!_warmPool.TryDequeue(out var warm)) break;

            // 检查是否过期或已断开
            var idleMs = now - warm.CreatedAt;
            if (idleMs > MaxIdleSeconds * 1000 || !IsSocketAlive(warm.Socket))
            {
                warm.Socket.Dispose();
                cleaned++;
            }
            else
            {
                _warmPool.Enqueue(warm);
            }
        }

        if (cleaned > 0)
        {
            Log.D($"Cleaned {cleaned} idle connections, remaining: {_warmPool.Count}");
        }
    }

    /// <summary>
    /// 检查 Socket 是否仍然存活（无阻塞）
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsSocketAlive(Socket socket)
    {
        try
        {
            // Poll 检查：0 微秒超时，检查是否可读
            // 如果可读但 Available=0，说明对端已关闭
            if (socket.Poll(0, SelectMode.SelectRead))
            {
                return socket.Available > 0;
            }
            return socket.Connected;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 预热连接池（后台执行）
    /// </summary>
    private async Task WarmUpAsync(CancellationToken ct)
    {
        try
        {
            for (var i = 0; i < _warmPoolSize && !ct.IsCancellationRequested; i++)
            {
                var socket = await CreateSocketAsync(ct).ConfigureAwait(false);
                if (socket != null)
                {
                    _warmPool.Enqueue(new WarmSocket(socket, Environment.TickCount64));
                    Log.D($"Warm pool: {_warmPool.Count}/{_warmPoolSize}");
                }
                else
                {
                    break; // 连接失败，停止预热
                }
            }
        }
        catch (Exception ex)
        {
            Log.D($"Warm up stopped: {ex.Message}");
        }
    }

    /// <summary>
    /// DNS 解析并缓存（5分钟有效期）
    /// </summary>
    private async ValueTask ResolveDnsAsync(CancellationToken ct)
    {
        // 如果是 IP 地址，直接解析
        if (IPAddress.TryParse(_config.Host, out var ip))
        {
            _cachedAddresses = [ip];
            _dnsExpiry = DateTime.MaxValue;
            return;
        }

        var now = DateTime.UtcNow;
        if (SharedDnsCache.TryGetValue(_config.Host, out var shared) && shared.Addresses != null && now < shared.Expiry)
        {
            _cachedAddresses = shared.Addresses;
            _dnsExpiry = shared.Expiry;
            return;
        }

        lock (_dnsLock)
        {
            if (_cachedAddresses != null && now < _dnsExpiry)
                return;
            if (_cachedAddresses == null && now < _dnsBackoffUntil)
                throw new InvalidOperationException("DNS backoff in effect");
        }

        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var addresses = await Dns.GetHostAddressesAsync(_config.Host, ct).ConfigureAwait(false);
            sw.Stop();
            PerfMetrics.Record("dns_ms", sw.ElapsedMilliseconds);
            lock (_dnsLock)
            {
                _cachedAddresses = addresses;
                _dnsExpiry = DateTime.UtcNow.AddMinutes(5);
                _dnsFailCount = 0;
                _dnsBackoffUntil = DateTime.MinValue;
            }
            SharedDnsCache[_config.Host] = new DnsCacheEntry(addresses, _dnsExpiry);
            Log.D($"DNS resolved: {_config.Host} -> {addresses[0]}");
        }
        catch (Exception ex)
        {
            var failCount = Interlocked.Increment(ref _dnsFailCount);
            var backoffSeconds = Math.Min(30, 1 << Math.Min(failCount, 5));
            var backoffUntil = DateTime.UtcNow.AddSeconds(backoffSeconds);

            lock (_dnsLock)
            {
                if (_cachedAddresses != null)
                {
                    _dnsExpiry = backoffUntil;
                }
                else
                {
                    _dnsBackoffUntil = backoffUntil;
                }
            }

            if (_cachedAddresses != null)
            {
                Log.W($"DNS refresh failed: {ex.Message}, using cached addresses for {backoffSeconds}s");
                return;
            }

            Log.E($"DNS resolution failed: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// 获取新连接
    /// </summary>
    public async Task<SsConnection?> GetConnectionAsync(string host, int port, CancellationToken ct = default)
    {
        if (_disposed) return null;

        // 熔断机制
        if (_failCount >= 5 && DateTime.UtcNow - _lastFailTime < TimeSpan.FromSeconds(5))
        {
            Log.W("Circuit breaker: too many failures");
            return null;
        }

        // 并发控制
        if (!await _semaphore.WaitAsync(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false))
        {
            Log.W($"Max connections reached: {_active}/{_maxSize}");
            return null;
        }

        try
        {
            Socket? socket = null;

            // 优先从预热池获取健康的连接
            while (_warmPool.TryDequeue(out var warm))
            {
                var idleMs = Environment.TickCount64 - warm.CreatedAt;

                // 检查连接是否健康
                if (idleMs < MaxIdleSeconds * 1000 && IsSocketAlive(warm.Socket))
                {
                    socket = warm.Socket;
                    Log.D($"Using warm socket (idle {idleMs}ms)");

                    // 后台补充预热池
                    TryReplenishWarmPool();
                    break;
                }
                else
                {
                    // 连接已过期或断开，丢弃
                    warm.Socket.Dispose();
                    Log.D($"Discarded stale warm socket (idle {idleMs}ms)");
                }
            }

            // 创建新连接
            socket ??= await CreateSocketAsync(ct).ConfigureAwait(false);

            if (socket != null)
            {
                var conn = new SsConnection(socket, this);
                conn.Bind(host, port);
                Interlocked.Increment(ref _active);
                Interlocked.Exchange(ref _failCount, 0);
                Log.IncrementConnections();
                Log.D(conn.Id, $"New connection -> {host}:{port} ({_active}/{_maxSize})");
                return conn;
            }

            Interlocked.Increment(ref _failCount);
            _lastFailTime = DateTime.UtcNow;

            _semaphore.Release();
            return null;
        }
        catch
        {
            _semaphore.Release();
            throw;
        }
    }

    /// <summary>
    /// 补充预热池
    /// </summary>
    private async Task ReplenishWarmPoolAsync(CancellationToken ct)
    {
        if (_disposed) return;
        if (_warmPool.Count >= _warmPoolSize) return;

        try
        {
            var socket = await CreateSocketAsync(ct).ConfigureAwait(false);
            if (socket != null && _warmPool.Count < _warmPoolSize)
            {
                _warmPool.Enqueue(new WarmSocket(socket, Environment.TickCount64));
            }
            else
            {
                socket?.Dispose();
            }
        }
        catch
        {
            // 忽略补充失败
        }
    }

    /// <summary>
    /// 创建 Socket 连接（使用 Socket 直接操作）
    /// </summary>
    private async Task<Socket?> CreateSocketAsync(CancellationToken ct)
    {
        Socket? socket = null;
        try
        {
            if (_connector != null)
            {
                return await _connector.ConnectAsync(new OutboundConnectRequest(_config, _forwardProxy, ct))
                    .ConfigureAwait(false);
            }

            if (_connectLimiter != null)
                await _connectLimiter.WaitAsync(ct).ConfigureAwait(false);

            // 确保 DNS 已解析
            await ResolveDnsAsync(ct).ConfigureAwait(false);

            var addresses = _cachedAddresses!;
            if (addresses.Length == 1)
            {
                socket = await ConnectToAddressAsync(addresses[0], ct).ConfigureAwait(false);
                return socket;
            }

            socket = await ConnectHappyEyeballsAsync(addresses, ct).ConfigureAwait(false);
            if (socket != null)
                return socket;

            for (var i = 2; i < addresses.Length; i++)
            {
                socket = await ConnectToAddressAsync(addresses[i], ct).ConfigureAwait(false);
                if (socket != null)
                    return socket;
            }

            return null;
        }
        catch (OperationCanceledException)
        {
            Log.E($"Timeout connecting to SS: {_config.Host}:{_config.Port}");
            socket?.Dispose();
            return null;
        }
        catch (Exception ex)
        {
            Log.E($"Failed to connect to SS: {ex.Message}");
            socket?.Dispose();
            return null;
        }
    }

    private async Task<Socket?> ConnectHappyEyeballsAsync(IPAddress[] addresses, CancellationToken ct)
    {
        if (addresses.Length == 0)
            return null;

        var primary = addresses[0];
        var secondary = addresses[1];

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var primaryTask = ConnectToAddressAsync(primary, cts.Token);
        var secondaryTask = StartSecondaryAfterDelayAsync(secondary, TimeSpan.FromMilliseconds(250), cts.Token);

        var completed = await Task.WhenAny(primaryTask, secondaryTask).ConfigureAwait(false);
        var winner = await completed.ConfigureAwait(false);
        if (winner != null)
        {
            cts.Cancel();
            _ = DrainSocketAsync(completed == primaryTask ? secondaryTask : primaryTask);
            return winner;
        }

        var other = completed == primaryTask ? secondaryTask : primaryTask;
        return await other.ConfigureAwait(false);
    }

    private async Task<Socket?> StartSecondaryAfterDelayAsync(IPAddress address, TimeSpan delay, CancellationToken ct)
    {
        try
        {
            await Task.Delay(delay, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null;
        }

        return await ConnectToAddressAsync(address, ct).ConfigureAwait(false);
    }

    private static async Task DrainSocketAsync(Task<Socket?> task)
    {
        try
        {
            var socket = await task.ConfigureAwait(false);
            socket?.Dispose();
        }
        catch { }
    }

    private async Task<Socket?> ConnectToAddressAsync(IPAddress address, CancellationToken ct)
    {
        Socket? socket = null;
        try
        {
            socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            // 优化 Socket 配置
            ConfigureSocket(socket);

            // 连接超时
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(Math.Min(_config.Timeout, 15)));

            Log.D($"Connecting to SS: {_config.Host}:{_config.Port}");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await socket.ConnectAsync(address, _config.Port, cts.Token).ConfigureAwait(false);
            sw.Stop();
            PerfMetrics.Record("connect_ms", sw.ElapsedMilliseconds);

            Log.D("SS connected");
            return socket;
        }
        catch (OperationCanceledException)
        {
            socket?.Dispose();
            return null;
        }
        catch
        {
            socket?.Dispose();
            return null;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ConfigureSocket(Socket socket)
    {
        socket.NoDelay = true;
        socket.ReceiveBufferSize = _recvBufferSize;
        socket.SendBufferSize = _sendBufferSize;

        // TCP KeepAlive - 更积极的检测
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 30);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 5);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);

        // 设置 Linger 选项：关闭时立即释放
        socket.LingerState = new LingerOption(true, 0);
    }

    /// <summary>
    /// 释放连接
    /// </summary>
    public void Release(SsConnection? conn)
    {
        if (conn == null) return;

        var id = conn.Id;

        // SS 一条 TCP 连接对应一条会话，使用后直接关闭避免重用导致加密状态错位
        conn.Dispose();

        Interlocked.Decrement(ref _active);
        Log.DecrementConnections();
        try
        {
            _semaphore.Release();
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        Log.D(id, $"Connection closed ({_active}/{_maxSize})");
    }

    /// <summary>
    /// 生成连接 ID
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static string GenerateId()
    {
        var id = Interlocked.Increment(ref _connectionIdCounter);
        return id.ToString("x8");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cleanupTimer?.Dispose();
        _connectLimiterTimer?.Dispose();
        _connectLimiter?.Dispose();

        // 清理预热池
        while (_warmPool.TryDequeue(out var warm))
        {
            warm.Socket.Dispose();
        }

        _semaphore.Dispose();
        Log.I("Connection limiter disposed");
    }

    private void RefillConnectLimiter(object? state)
    {
        if (_connectLimiter == null) return;
        try
        {
            var deficit = _maxConnectsPerSecond - _connectLimiter.CurrentCount;
            if (deficit > 0)
                _connectLimiter.Release(deficit);
        }
        catch (ObjectDisposedException) { }
    }

    private void TryReplenishWarmPool()
    {
        if (_warmPoolSize <= 0 || _disposed)
            return;

        if (Interlocked.CompareExchange(ref _warmRefillInFlight, 1, 0) != 0)
            return;

        _ = Task.Run(async () =>
        {
            try
            {
                await ReplenishWarmPoolAsync(CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Exchange(ref _warmRefillInFlight, 0);
            }
        });
    }

    /// <summary>
    /// 预热连接包装器
    /// </summary>
    private readonly record struct WarmSocket(Socket Socket, long CreatedAt);

    private sealed class DnsCacheEntry
    {
        public DnsCacheEntry(IPAddress[]? addresses = null, DateTime expiry = default)
        {
            Addresses = addresses;
            Expiry = expiry;
        }

        public IPAddress[]? Addresses { get; set; }
        public DateTime Expiry { get; set; }
    }
}

/// <summary>
/// SS 服务器连接（基于 Socket）
/// </summary>
public sealed class SsConnection : IDisposable
{
    private readonly Socket _socket;
    private readonly SsConnectionPool _pool;
    private NetworkStream? _stream;
    private bool _disposed;

    public string Id { get; } = SsConnectionPool.GenerateId();
    public string TargetHost { get; private set; } = string.Empty;
    public int TargetPort { get; private set; }

    public NetworkStream Stream => _stream ??= new NetworkStream(_socket, ownsSocket: false);
    public bool IsHealthy => !_disposed && _socket.Connected;
    internal Socket Socket => _socket;

    public SsConnection(Socket socket, SsConnectionPool pool)
    {
        _socket = socket;
        _pool = pool;
    }

    public void Bind(string host, int port)
    {
        TargetHost = host;
        TargetPort = port;
    }

    internal void Reset()
    {
        try { _stream?.Dispose(); } catch { }
        _stream = null;
        TargetHost = string.Empty;
        TargetPort = 0;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try { _stream?.Dispose(); } catch { }
        try { _socket.Dispose(); } catch { }
    }
}
