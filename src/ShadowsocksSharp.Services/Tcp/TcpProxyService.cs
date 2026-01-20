using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Core.Model;
using ShadowsocksSharp.Core.Strategy;
using ShadowsocksSharp.Diagnostics;
using ShadowsocksSharp.Inbound;
using ShadowsocksSharp.Outbound;
using ShadowsocksSharp.Shadowsocks;
using ShadowsocksSharp.Shadowsocks.Encryption;
using ShadowsocksSharp.Transport.Connections;
using ShadowsocksSharp.Transport.Relay;
using ShadowsocksSharp.Services.Pac;

namespace ShadowsocksSharp.Services.Tcp;

/// <summary>
/// TCP 代理入口：接收本地连接、协商入站协议并转发到 SS 上游。
/// </summary>
public sealed class TcpProxyService : IHostedService
{
    private readonly Config _config;
    private readonly IServerSelector _selector;
    private readonly AutoDetectInbound _inbound = new();
    private readonly IOutboundConnector _connector;
    private readonly PacService _pac;
    private readonly ConcurrentDictionary<string, ConnectLimiter> _connectLimiters = new();
    private readonly ConcurrentDictionary<string, SsConnectionPool> _connectionPools = new();

    private Socket? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    public TcpProxyService(Config config, IServerSelector selector, IOutboundConnector connector, PacService pac)
    {
        _config = config;
        _selector = selector;
        _connector = connector;
        _pac = pac;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_config.Servers.Count == 0)
        {
            Log.W("No servers configured. TCP proxy not started.");
            return Task.CompletedTask;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var ct = _cts.Token;

        var address = _config.ShareOverLan ? IPAddress.Any : IPAddress.Loopback;
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(address, _config.LocalPort));
        _listener.Listen(_config.TcpListenBacklog);

        _acceptLoop = Task.Run(() => AcceptLoopAsync(ct), ct);
        Log.I($"TCP proxy listening on {address}:{_config.LocalPort}");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel();
        if (_listener != null)
        {
            try { _listener.Close(); } catch { }
            _listener = null;
        }

        if (_acceptLoop != null)
        {
            try { await _acceptLoop.ConfigureAwait(false); } catch { }
        }

        foreach (var limiter in _connectLimiters.Values)
        {
            limiter.Dispose();
        }
        _connectLimiters.Clear();

        foreach (var pool in _connectionPools.Values)
        {
            pool.Dispose();
        }
        _connectionPools.Clear();
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptAsync(ct).ConfigureAwait(false);
                client.NoDelay = true;
                _ = HandleClientAsync(client, ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Log.W($"Accept error: {ex.Message}");
            }
        }
    }

    private async Task HandleClientAsync(Socket client, CancellationToken ct)
    {
        using var stream = new NetworkStream(client, ownsSocket: true);
        InboundResult? inbound = null;
        SsServerConfig? server = null;
        ConnectLimiterLease? lease = null;
        try
        {
            // 自动识别 SOCKS5/HTTP，并解析目标请求。
            inbound = await _inbound.HandleAsync(stream, ct).ConfigureAwait(false);
            if (inbound.IsPacRequest)
            {
                // 以 HTTP 方式返回 PAC 内容。
                var proxyAddress = $"127.0.0.1:{_config.LocalPort}";
                await _pac.HandlePacRequestAsync(stream, inbound.PacRequestPath!, proxyAddress, ct).ConfigureAwait(false);
                return;
            }

            if (inbound.Request == null)
            {
                if (inbound.OnFailed != null)
                    await inbound.OnFailed(stream, ct).ConfigureAwait(false);
                return;
            }

            var request = inbound.Request;
            if (request.Protocol == InboundProtocol.Socks5UdpAssociate)
            {
                // SOCKS5 UDP ASSOCIATE：返回 UDP 绑定端点并保持 TCP 连接。
                await HandleUdpAssociateAsync(client, stream, ct).ConfigureAwait(false);
                return;
            }

            var context = new ServerSelectionContext(request.Protocol, client.RemoteEndPoint, request.Host, request.Port);
            server = _selector.Select(context, _config.Servers, _config.CurrentIndex);

            // 根据配置对新建上游连接进行限速。
            lease = await AcquireConnectPermitAsync(server, ct).ConfigureAwait(false);

            // 连接池获取 + 策略延迟统计。
            var pool = GetConnectionPool(server);
            var connectTimer = Stopwatch.StartNew();
            var connection = await pool.GetConnectionAsync(request.Host, request.Port, ct).ConfigureAwait(false);
            connectTimer.Stop();
            _selector.ReportLatency(server, connectTimer.Elapsed);

            if (connection == null)
                throw new InvalidOperationException("Failed to acquire SS connection.");

            var encryptor = EncryptorFactory.Create(server.Method, server.Password);
            var decryptor = EncryptorFactory.Create(server.Method, server.Password);

            try
            {
                using var ssStream = new ShadowsocksStream(connection.Stream, encryptor, decryptor);
                await ssStream.SendAddressAsync(request.Host, request.Port, ct).ConfigureAwait(false);

                if (inbound.OnConnected != null)
                    await inbound.OnConnected(stream, ct).ConfigureAwait(false);

                // 双向转发，并上报流量用于策略反馈。
                var stats = await DuplexRelay.RelayAsync(stream, ssStream, request.InitialPayload, ct).ConfigureAwait(false);
                _selector.ReportTraffic(server, stats.RemoteToClientBytes, stats.ClientToRemoteBytes);
            }
            finally
            {
                pool.Release(connection);
            }
        }
        catch (Exception ex)
        {
            if (server != null)
                _selector.ReportFailure(server);
            Log.W($"Client session error: {ex.Message}");
            try
            {
                if (stream.CanWrite && inbound?.OnFailed != null)
                    await inbound.OnFailed(stream, ct).ConfigureAwait(false);
            }
            catch { }
        }
        finally
        {
            lease?.Dispose();
        }
    }

    private async ValueTask<ConnectLimiterLease?> AcquireConnectPermitAsync(SsServerConfig server, CancellationToken ct)
    {
        if (server.MaxConnectionsPerSecond <= 0)
            return null;

        if (!UseOutboundConnector(server, _config.ForwardProxy))
            return null;

        // 按服务器限速，避免连接风暴并降低对其他服务器的影响。
        var key = BuildConnectionKey(server, _config.ForwardProxy);
        var limiter = _connectLimiters.GetOrAdd(key, _ => new ConnectLimiter(server.MaxConnectionsPerSecond));
        return await limiter.AcquireAsync(ct).ConfigureAwait(false);
    }

    private async Task HandleUdpAssociateAsync(Socket client, NetworkStream stream, CancellationToken ct)
    {
        var bindAddress = GetUdpBindAddress(client);
        var response = BuildSocks5Success(bindAddress, _config.LocalPort);
        await stream.WriteAsync(response, ct).ConfigureAwait(false);

        // UDP 关联期间保持 TCP 连接不关闭。
        var buffer = new byte[64];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false);
                if (read == 0)
                    break;
            }
        }
        catch (OperationCanceledException) { }
    }

    private IPAddress GetUdpBindAddress(Socket client)
    {
        var ipv6 = client.AddressFamily == AddressFamily.InterNetworkV6;
        if (_config.ShareOverLan)
            return ipv6 ? IPAddress.IPv6Any : IPAddress.Any;
        return ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
    }

    private static byte[] BuildSocks5Success(IPAddress address, int port)
    {
        var addrBytes = address.GetAddressBytes();
        var response = new byte[4 + addrBytes.Length + 2];
        response[0] = 0x05;
        response[1] = 0x00;
        response[2] = 0x00;
        response[3] = addrBytes.Length == 16 ? (byte)0x04 : (byte)0x01;
        Buffer.BlockCopy(addrBytes, 0, response, 4, addrBytes.Length);
        response[4 + addrBytes.Length] = (byte)(port >> 8);
        response[5 + addrBytes.Length] = (byte)(port & 0xFF);
        return response;
    }

    private SsConnectionPool GetConnectionPool(SsServerConfig server)
    {
        var key = BuildConnectionKey(server, _config.ForwardProxy);
        return _connectionPools.GetOrAdd(key, _key =>
        {
            var useConnector = UseOutboundConnector(server, _config.ForwardProxy);
            var pool = new SsConnectionPool(
                server,
                maxSize: server.ConnectionPoolSize,
                warmPoolSize: server.WarmPoolSize,
                socketReceiveBuffer: server.SocketReceiveBuffer,
                socketSendBuffer: server.SocketSendBuffer,
                forwardProxy: _config.ForwardProxy,
                connector: useConnector ? _connector : null);

            _ = pool.InitializeAsync(_cts?.Token ?? CancellationToken.None);
            return pool;
        });
    }

    private static bool UseOutboundConnector(SsServerConfig server, ForwardProxyConfig proxy)
    {
        return !string.IsNullOrWhiteSpace(server.Plugin) || proxy.Enabled;
    }

    private static string BuildConnectionKey(SsServerConfig server, ForwardProxyConfig proxy)
    {
        if (!proxy.Enabled)
            return $"{server.Host}:{server.Port}|{server.Plugin}|{server.PluginOptions}|{server.PluginArgs}";

        return $"{server.Host}:{server.Port}|{server.Plugin}|{server.PluginOptions}|{server.PluginArgs}|" +
               $"{proxy.Type}|{proxy.Host}:{proxy.Port}|{proxy.UseAuth}|{proxy.Username}";
    }

    private sealed class ConnectLimiter : IDisposable
    {
        private readonly SemaphoreSlim _semaphore;
        private readonly int _limit;
        private readonly Timer _refillTimer;
        private bool _disposed;

        public ConnectLimiter(int limit)
        {
            _limit = Math.Max(1, limit);
            _semaphore = new SemaphoreSlim(_limit, _limit);
            _refillTimer = new Timer(Refill, null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        }

        public async ValueTask<ConnectLimiterLease> AcquireAsync(CancellationToken ct)
        {
            var acquired = await _semaphore.WaitAsync(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
            if (!acquired)
                throw new InvalidOperationException("Connect rate limit exceeded.");

            return new ConnectLimiterLease();
        }

        private void Refill(object? state)
        {
            if (_disposed) return;
            try
            {
                var deficit = _limit - _semaphore.CurrentCount;
                if (deficit > 0)
                    _semaphore.Release(deficit);
            }
            catch (ObjectDisposedException) { }
        }

        public void Dispose()
        {
            _disposed = true;
            _refillTimer.Dispose();
            _semaphore.Dispose();
        }
    }

    private readonly struct ConnectLimiterLease : IDisposable
    {
        public void Dispose() { }
    }
}
