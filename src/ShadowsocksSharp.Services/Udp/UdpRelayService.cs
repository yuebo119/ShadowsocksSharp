using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Hosting;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Core.Model;
using ShadowsocksSharp.Core.Strategy;
using ShadowsocksSharp.Diagnostics;
using ShadowsocksSharp.Outbound;
using ShadowsocksSharp.Shadowsocks.Encryption;
using ShadowsocksSharp.Transport.Buffers;

namespace ShadowsocksSharp.Services.Udp;

/// <summary>
/// SOCKS5 UDP 中继：AEAD-UDP 加解密、会话管理，并支持插件/前置代理上游。
/// </summary>
public sealed class UdpRelayService : IHostedService
{
    private readonly Config _config;
    private readonly IServerSelector _selector;
    private readonly Sip003PluginManager _pluginManager;
    private readonly ConcurrentDictionary<IPEndPoint, UdpSession> _sessions = new();
    private readonly UdpFragmentReassembler _fragmentReassembler = new();
    private readonly Lock _sessionLock = new();
    private readonly int _maxSessions;
    private readonly TimeSpan _sessionTimeout;
    private Socket? _localSocket;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private Timer? _cleanupTimer;

    public UdpRelayService(Config config, IServerSelector selector, Sip003PluginManager pluginManager)
    {
        _config = config;
        _selector = selector;
        _pluginManager = pluginManager;
        _maxSessions = Math.Max(0, config.MaxUdpSessions);
        _sessionTimeout = TimeSpan.FromSeconds(Math.Max(30, config.UdpSessionTimeoutSeconds));
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_config.Servers.Count == 0)
            return Task.CompletedTask;

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var ct = _cts.Token;

        var bindAddress = _config.ShareOverLan ? IPAddress.Any : IPAddress.Loopback;
        _localSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _localSocket.Bind(new IPEndPoint(bindAddress, _config.LocalPort));

        _cleanupTimer = new Timer(_ => CleanupSessions(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

        _loop = Task.Run(() => ReceiveLoopAsync(ct), ct);
        Log.I($"UDP relay listening on {bindAddress}:{_config.LocalPort}");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel();
        _cleanupTimer?.Dispose();
        _cleanupTimer = null;

        if (_localSocket != null)
        {
            try { _localSocket.Close(); } catch { }
            _localSocket = null;
        }

        if (_loop != null)
        {
            try { await _loop.ConfigureAwait(false); } catch { }
        }

        foreach (var session in _sessions.Values)
        {
            session.Dispose();
        }
        _sessions.Clear();
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        if (_localSocket == null) return;

        var buffer = new byte[65536];
        EndPoint remote = new IPEndPoint(IPAddress.Any, 0);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _localSocket.ReceiveFromAsync(buffer, SocketFlags.None, remote, ct).ConfigureAwait(false);
                if (result.ReceivedBytes <= 0)
                    continue;

                var client = (IPEndPoint)result.RemoteEndPoint;
                var payload = buffer.AsMemory(0, result.ReceivedBytes);

                await HandleClientPacketAsync(client, payload, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Log.W($"UDP recv error: {ex.Message}");
            }
        }
    }

    private async Task HandleClientPacketAsync(IPEndPoint client, ReadOnlyMemory<byte> packet, CancellationToken ct)
    {
        // 将 SOCKS5 UDP FRAG 分片重组为单个完整报文。
        if (!TryNormalizePacket(client, packet, out var normalized))
            return;

        if (normalized.Length < 4)
            return;

        var selectorContext = new ServerSelectionContext(
            InboundProtocol.Socks5,
            client,
            "udp",
            0);
        var server = _selector.Select(selectorContext, _config.Servers, _config.CurrentIndex);

        var session = await GetOrCreateSessionAsync(client, server, ct).ConfigureAwait(false);
        if (session == null)
            return;

        session.Touch();

        var body = normalized.Slice(3);
        var outBuffer = ArrayPool<byte>.Shared.Rent(body.Length + 64);
        try
        {
            var encryptedLength = AeadUdpCipher.Encrypt(server.Method, server.Password, body.Span, outBuffer);
            await session.SendToServerAsync(outBuffer.AsMemory(0, encryptedLength), ct).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(outBuffer);
        }
    }

    private async Task<UdpSession?> GetOrCreateSessionAsync(IPEndPoint client, SsServerConfig server, CancellationToken ct)
    {
        if (!_sessions.TryGetValue(client, out var session))
        {
            // 根据服务器与前置代理配置选择上游模式（直连/插件/代理）。
            var mode = ResolveUpstreamMode(server, _config.ForwardProxy, out var ignoreProxy);
            if (mode == UdpUpstreamMode.Unsupported)
            {
                Log.W("UDP relay only supports SOCKS5 forward proxy; packet dropped.");
                return null;
            }

            if (ignoreProxy)
                Log.W("Forward proxy is ignored for UDP when SIP003 plugin is enabled.");

            var created = new UdpSession(client, server, _config.ForwardProxy, _localSocket!, _pluginManager, mode);
            if (_sessions.TryAdd(client, created))
            {
                session = created;
                TrimSessionsIfNeeded();
            }
            else
            {
                created.Dispose();
                session = _sessions[client];
            }
        }

        try
        {
            await session.EnsureReadyAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            if (_sessions.TryRemove(client, out var removed))
                removed.Dispose();
            Log.W($"UDP session init failed: {ex.Message}");
            return null;
        }

        return session;
    }

    private bool TryNormalizePacket(IPEndPoint client, ReadOnlyMemory<byte> packet, out ReadOnlyMemory<byte> normalized)
    {
        normalized = default;

        if (packet.Length < 4)
            return false;

        var frag = packet.Span[2];
        if (frag == 0x00)
        {
            normalized = packet;
            return true;
        }

        return _fragmentReassembler.TryReassemble(client, packet, out normalized);
    }

    private void CleanupSessions()
    {
        var now = DateTime.UtcNow;
        foreach (var (key, session) in _sessions)
        {
            if ((now - session.LastActive) > _sessionTimeout)
            {
                if (_sessions.TryRemove(key, out var removed))
                {
                    removed.Dispose();
                }
            }
        }

        _fragmentReassembler.CleanupExpired();
    }

    private void TrimSessionsIfNeeded()
    {
        if (_maxSessions <= 0 || _sessions.Count <= _maxSessions)
            return;

        lock (_sessionLock)
        {
            while (_sessions.Count > _maxSessions)
            {
                IPEndPoint? oldestKey = null;
                var oldest = DateTime.MaxValue;
                foreach (var entry in _sessions)
                {
                    if (entry.Value.LastActive < oldest)
                    {
                        oldest = entry.Value.LastActive;
                        oldestKey = entry.Key;
                    }
                }

                if (oldestKey == null)
                    break;

                // 按 LRU 清理最旧会话，限制 UDP 会话数量。
                if (_sessions.TryRemove(oldestKey, out var removed))
                    removed.Dispose();
                else
                    break;
            }
        }
    }

    private enum UdpUpstreamMode
    {
        Direct,
        Plugin,
        Socks5Proxy,
        Unsupported
    }

    private static UdpUpstreamMode ResolveUpstreamMode(SsServerConfig server, ForwardProxyConfig proxy, out bool ignoreProxy)
    {
        ignoreProxy = false;
        if (!string.IsNullOrWhiteSpace(server.Plugin))
        {
            ignoreProxy = proxy.Enabled;
            return UdpUpstreamMode.Plugin;
        }

        if (proxy.Enabled)
        {
            return proxy.Type == ForwardProxyType.Socks5
                ? UdpUpstreamMode.Socks5Proxy
                : UdpUpstreamMode.Unsupported;
        }

        return UdpUpstreamMode.Direct;
    }

    private static bool TryParseSocks5Address(ReadOnlySpan<byte> buffer, out int headerLength)
    {
        headerLength = 0;
        if (buffer.Length < 1)
            return false;

        var atyp = buffer[0];
        var offset = 1;
        int addressLength;

        switch (atyp)
        {
            case 0x01:
                addressLength = 4;
                break;
            case 0x04:
                addressLength = 16;
                break;
            case 0x03:
                if (buffer.Length < 2)
                    return false;
                addressLength = buffer[1];
                offset = 2;
                break;
            default:
                return false;
        }

        var total = offset + addressLength + 2;
        if (buffer.Length < total)
            return false;

        headerLength = total;
        return true;
    }

    private static bool TryGetSocks5UdpPayload(ReadOnlySpan<byte> packet, out int payloadOffset)
    {
        payloadOffset = 0;
        if (packet.Length < 4)
            return false;
        if (packet[0] != 0x00 || packet[1] != 0x00)
            return false;
        if (packet[2] != 0x00)
            return false;
        if (!TryParseSocks5Address(packet.Slice(3), out var headerLen))
            return false;

        payloadOffset = 3 + headerLen;
        return payloadOffset <= packet.Length;
    }

    private static byte[] BuildSocks5UdpHeader(string host, int port)
    {
        var (type, address) = BuildSocks5Address(host);
        var header = new byte[3 + 1 + address.Length + 2];
        header[0] = 0x00;
        header[1] = 0x00;
        header[2] = 0x00;
        header[3] = type;
        Buffer.BlockCopy(address, 0, header, 4, address.Length);
        header[4 + address.Length] = (byte)(port >> 8);
        header[5 + address.Length] = (byte)(port & 0xFF);
        return header;
    }

    private static (byte type, byte[] address) BuildSocks5Address(string host)
    {
        if (IPAddress.TryParse(host, out var ip))
        {
            var bytes = ip.GetAddressBytes();
            return bytes.Length == 4 ? ((byte)0x01, bytes) : ((byte)0x04, bytes);
        }

        var domain = Encoding.ASCII.GetBytes(host);
        var addr = new byte[1 + domain.Length];
        addr[0] = (byte)domain.Length;
        Buffer.BlockCopy(domain, 0, addr, 1, domain.Length);
        return (0x03, addr);
    }

    /// <summary>
    /// 每个客户端的 UDP 会话：负责上游传输（直连/插件/代理）与回包。
    /// </summary>
    private sealed class UdpSession : IDisposable
    {
        private readonly IPEndPoint _client;
        private readonly SsServerConfig _server;
        private readonly ForwardProxyConfig _proxy;
        private readonly Socket _localSocket;
        private readonly Sip003PluginManager _pluginManager;
        private readonly UdpUpstreamMode _mode;
        private readonly byte[]? _proxyHeader;
        private byte[]? _buffer;
        private readonly SemaphoreSlim _initLock = new(1, 1);
        private Socket? _remoteSocket;
        private Socket? _proxyControlSocket;
        private bool _initialized;
        private bool _disposed;

        public DateTime LastActive { get; private set; } = DateTime.UtcNow;

        public UdpSession(
            IPEndPoint client,
            SsServerConfig server,
            ForwardProxyConfig proxy,
            Socket localSocket,
            Sip003PluginManager pluginManager,
            UdpUpstreamMode mode)
        {
            _client = client;
            _server = server;
            _proxy = proxy;
            _localSocket = localSocket;
            _pluginManager = pluginManager;
            _mode = mode;
            _proxyHeader = mode == UdpUpstreamMode.Socks5Proxy
                ? BuildSocks5UdpHeader(server.Host, server.Port)
                : null;
        }

        public async Task EnsureReadyAsync(CancellationToken ct)
        {
            if (_initialized)
                return;

            // 以单次初始化模式建立上游通道，避免并发重复建链。
            await _initLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_initialized)
                    return;

                if (_mode == UdpUpstreamMode.Direct)
                {
                    var ip = ResolveServer(_server.Host);
                    _remoteSocket = new Socket(ip.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                    _remoteSocket.Connect(new IPEndPoint(ip, _server.Port));
                }
                else if (_mode == UdpUpstreamMode.Plugin)
                {
                    var plugin = _pluginManager.GetOrCreate(_server);
                    plugin.EnsureRunning();
                    var endpoint = plugin.LocalEndPoint;
                    // 等待插件绑定 UDP 端口，避免首包发送过早导致丢失。
                    await WaitForUdpListenerAsync(endpoint, TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
                    _remoteSocket = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                    _remoteSocket.Connect(endpoint);
                }
                else if (_mode == UdpUpstreamMode.Socks5Proxy)
                {
                    await InitializeSocks5ProxyAsync(ct).ConfigureAwait(false);
                }

                _initialized = true;
                // 后台接收上游回包并转发给客户端。
                _ = ReceiveLoopAsync();
            }
            finally
            {
                _initLock.Release();
            }
        }

        public void Touch() => LastActive = DateTime.UtcNow;

        public async Task SendToServerAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
        {
            if (_remoteSocket == null)
                throw new InvalidOperationException("UDP session not initialized.");

            if (_mode == UdpUpstreamMode.Socks5Proxy)
            {
                // SOCKS5 UDP ASSOCIATE 需要附加 UDP 头部信息。
                var header = _proxyHeader ?? [];
                var buffer = ArrayPool<byte>.Shared.Rent(header.Length + data.Length);
                try
                {
                    Buffer.BlockCopy(header, 0, buffer, 0, header.Length);
                    data.CopyTo(buffer.AsMemory(header.Length));
                    await _remoteSocket.SendAsync(
                            buffer.AsMemory(0, header.Length + data.Length),
                            SocketFlags.None,
                            ct)
                        .ConfigureAwait(false);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
            else
            {
                await _remoteSocket.SendAsync(data, SocketFlags.None, ct).ConfigureAwait(false);
            }
        }

        private async Task ReceiveLoopAsync()
        {
            while (!_disposed)
            {
                try
                {
                    if (_remoteSocket == null)
                        return;

                    var buffer = _buffer ??= BufferPool.RentExtraLarge();
                    var n = await _remoteSocket.ReceiveAsync(buffer, SocketFlags.None).ConfigureAwait(false);
                    if (n <= 0) continue;

                    var payload = buffer.AsSpan(0, n);
                    if (_mode == UdpUpstreamMode.Socks5Proxy)
                    {
                        // 代理模式下需剥离 SOCKS5 UDP 头部。
                        if (!TryGetSocks5UdpPayload(payload, out var offset))
                            continue;
                        payload = payload.Slice(offset);
                    }

                    // 还原 AEAD-UDP 明文内容。
                    var plain = ArrayPool<byte>.Shared.Rent(payload.Length);
                    try
                    {
                        var len = AeadUdpCipher.Decrypt(_server.Method, _server.Password, payload, plain);
                        if (len <= 0) continue;

                        // 重建 SOCKS5 UDP 响应（RSV/FRAG/ATYP/ADDR/PORT + DATA）。
                        var sendBuf = ArrayPool<byte>.Shared.Rent(len + 3);
                        try
                        {
                            sendBuf[0] = 0x00;
                            sendBuf[1] = 0x00;
                            sendBuf[2] = 0x00;
                            Buffer.BlockCopy(plain, 0, sendBuf, 3, len);

                            await _localSocket.SendToAsync(sendBuf.AsMemory(0, len + 3), SocketFlags.None, _client)
                                .ConfigureAwait(false);
                            Touch();
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(sendBuf);
                        }
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(plain);
                    }
                }
                catch { }
            }
        }

        private async Task InitializeSocks5ProxyAsync(CancellationToken ct)
        {
            if (_proxy.Type != ForwardProxyType.Socks5)
                throw new InvalidOperationException("UDP relay only supports SOCKS5 forward proxy.");

            var proxyAddress = ResolveServer(_proxy.Host);
            var control = new Socket(proxyAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true
            };

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _proxy.TimeoutSeconds)));

            await control.ConnectAsync(proxyAddress, _proxy.Port, cts.Token).ConfigureAwait(false);
            await Socks5AuthenticateAsync(control, _proxy, cts.Token).ConfigureAwait(false);

            var localIp = ((IPEndPoint)control.LocalEndPoint!).Address;
            var udpSocket = new Socket(proxyAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.Bind(new IPEndPoint(localIp, 0));

            // UDP 关联期间保持 TCP 控制连接不关闭。
            var relayEndpoint = await Socks5UdpAssociateAsync(control, (IPEndPoint)udpSocket.LocalEndPoint!, cts.Token)
                .ConfigureAwait(false);
            udpSocket.Connect(relayEndpoint);

            _proxyControlSocket = control;
            _remoteSocket = udpSocket;
        }

        private static async Task Socks5AuthenticateAsync(Socket socket, ForwardProxyConfig proxy, CancellationToken ct)
        {
            var authMethod = proxy.UseAuth ? (byte)0x02 : (byte)0x00;
            var hello = new byte[] { 0x05, 0x01, authMethod };
            await socket.SendAsync(hello, SocketFlags.None, ct).ConfigureAwait(false);

            var resp = new byte[2];
            await ReceiveExactAsync(socket, resp, ct).ConfigureAwait(false);
            if (resp[0] != 0x05)
                throw new InvalidOperationException("Invalid SOCKS5 proxy response.");

            if (resp[1] == 0x02)
            {
                var user = Encoding.ASCII.GetBytes(proxy.Username ?? string.Empty);
                var pass = Encoding.ASCII.GetBytes(proxy.Password ?? string.Empty);
                var auth = new byte[3 + user.Length + pass.Length];
                auth[0] = 0x01;
                auth[1] = (byte)user.Length;
                Buffer.BlockCopy(user, 0, auth, 2, user.Length);
                auth[2 + user.Length] = (byte)pass.Length;
                Buffer.BlockCopy(pass, 0, auth, 3 + user.Length, pass.Length);
                await socket.SendAsync(auth, SocketFlags.None, ct).ConfigureAwait(false);

                var authResp = new byte[2];
                await ReceiveExactAsync(socket, authResp, ct).ConfigureAwait(false);
                if (authResp[1] != 0x00)
                    throw new InvalidOperationException("SOCKS5 proxy authentication failed.");
            }
            else if (resp[1] != 0x00)
            {
                throw new InvalidOperationException("SOCKS5 proxy does not support required auth.");
            }
        }

        private static async Task<IPEndPoint> Socks5UdpAssociateAsync(Socket socket, IPEndPoint udpClient, CancellationToken ct)
        {
            var addrBytes = udpClient.Address.GetAddressBytes();
            var req = new byte[4 + addrBytes.Length + 2];
            req[0] = 0x05;
            req[1] = 0x03;
            req[2] = 0x00;
            req[3] = addrBytes.Length == 16 ? (byte)0x04 : (byte)0x01;
            Buffer.BlockCopy(addrBytes, 0, req, 4, addrBytes.Length);
            req[4 + addrBytes.Length] = (byte)(udpClient.Port >> 8);
            req[5 + addrBytes.Length] = (byte)(udpClient.Port & 0xFF);

            await socket.SendAsync(req, SocketFlags.None, ct).ConfigureAwait(false);

            var head = new byte[4];
            await ReceiveExactAsync(socket, head, ct).ConfigureAwait(false);
            if (head[1] != 0x00)
                throw new InvalidOperationException("SOCKS5 UDP associate failed.");

            var atyp = head[3];
            IPAddress relayAddress;

            if (atyp == 0x01)
            {
                var addr = new byte[4];
                await ReceiveExactAsync(socket, addr, ct).ConfigureAwait(false);
                relayAddress = new IPAddress(addr);
            }
            else if (atyp == 0x04)
            {
                var addr = new byte[16];
                await ReceiveExactAsync(socket, addr, ct).ConfigureAwait(false);
                relayAddress = new IPAddress(addr);
            }
            else if (atyp == 0x03)
            {
                var lenBuf = new byte[1];
                await ReceiveExactAsync(socket, lenBuf, ct).ConfigureAwait(false);
                var name = new byte[lenBuf[0]];
                await ReceiveExactAsync(socket, name, ct).ConfigureAwait(false);
                var host = Encoding.ASCII.GetString(name);
                relayAddress = ResolveServer(host);
            }
            else
            {
                throw new InvalidOperationException("Invalid SOCKS5 UDP relay address type.");
            }

            var portBuf = new byte[2];
            await ReceiveExactAsync(socket, portBuf, ct).ConfigureAwait(false);
            var port = (portBuf[0] << 8) | portBuf[1];

            return new IPEndPoint(relayAddress, port);
        }

        private static async Task ReceiveExactAsync(Socket socket, byte[] buffer, CancellationToken ct)
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                var n = await socket.ReceiveAsync(buffer.AsMemory(offset, buffer.Length - offset), ct).ConfigureAwait(false);
                if (n <= 0)
                    throw new IOException("Proxy connection closed.");
                offset += n;
            }
        }

        private static IPAddress ResolveServer(string host)
        {
            if (IPAddress.TryParse(host, out var ip))
                return ip;
            return Dns.GetHostAddresses(host)[0];
        }

        private static async Task WaitForUdpListenerAsync(IPEndPoint endpoint, TimeSpan timeout, CancellationToken ct)
        {
            var deadline = DateTime.UtcNow + timeout;
            while (DateTime.UtcNow < deadline)
            {
                if (IsUdpListenerActive(endpoint))
                    return;

                await Task.Delay(20, ct).ConfigureAwait(false);
            }
        }

        private static bool IsUdpListenerActive(IPEndPoint endpoint)
        {
            try
            {
                var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();
                foreach (var listener in listeners)
                {
                    if (listener.Port != endpoint.Port)
                        continue;

                    if (listener.Address.Equals(endpoint.Address) ||
                        listener.Address.Equals(IPAddress.Any) ||
                        listener.Address.Equals(IPAddress.IPv6Any))
                    {
                        return true;
                    }
                }
            }
            catch { }

            return false;
        }

        public void Dispose()
        {
            _disposed = true;
            try { _remoteSocket?.Dispose(); } catch { }
            try { _proxyControlSocket?.Dispose(); } catch { }
            if (_buffer != null)
            {
                BufferPool.Return(_buffer);
                _buffer = null;
            }
            _initLock.Dispose();
        }
    }

    /// <summary>
    /// 按客户端重组 SOCKS5 UDP FRAG 分片。
    /// </summary>
    private sealed class UdpFragmentReassembler
    {
        private static readonly TimeSpan FragmentTimeout = TimeSpan.FromSeconds(10);
        private const int MaxFragments = 16;
        private const int MaxReassemblyBytes = 64 * 1024;
        private readonly ConcurrentDictionary<IPEndPoint, FragmentBuffer> _buffers = new();

        public bool TryReassemble(IPEndPoint client, ReadOnlyMemory<byte> packet, out ReadOnlyMemory<byte> normalized)
        {
            normalized = default;
            var span = packet.Span;
            if (span.Length < 4)
                return false;

            var frag = span[2];
            if (frag == 0x00)
            {
                normalized = packet;
                return true;
            }

            // RFC1928：FRAG 高位表示该分片序列的结束片段。
            var fragIndex = frag & 0x7F;
            var isFinal = (frag & 0x80) != 0;
            if (fragIndex == 0)
                return false;

            if (!TryParseSocks5Address(span.Slice(3), out var headerLen))
                return false;

            // 头部与数据分离存储，便于合并时保持 ATYP/ADDR/PORT 一致。
            if (fragIndex > MaxFragments)
                return false;

            var header = span.Slice(3, headerLen).ToArray();
            var data = span.Slice(3 + headerLen).ToArray();
            if (header.Length + data.Length > MaxReassemblyBytes)
                return false;

            var buffer = _buffers.GetOrAdd(client, _ => new FragmentBuffer());
            if (!buffer.AddFragment(fragIndex, isFinal, header, data, MaxFragments, MaxReassemblyBytes))
            {
                _buffers.TryRemove(client, out _);
                return false;
            }

            if (!buffer.TryAssemble(out var body))
                return false;

            _buffers.TryRemove(client, out _);
            var output = new byte[3 + body.Length];
            output[0] = 0x00;
            output[1] = 0x00;
            output[2] = 0x00;
            body.CopyTo(output.AsSpan(3));
            normalized = output;
            return true;
        }

        public void CleanupExpired()
        {
            var now = DateTime.UtcNow;
            foreach (var (key, buffer) in _buffers)
            {
                if (buffer.IsExpired(now))
                {
                    if (_buffers.TryRemove(key, out _))
                    {
                        buffer.Reset();
                    }
                }
            }
        }

        private sealed class FragmentBuffer
        {
            private readonly Dictionary<int, byte[]> _fragments = new();
            private byte[]? _header;
            private int _highestIndex;
            private int _finalIndex;
            private DateTime _lastUpdated = DateTime.UtcNow;
            private int _totalBytes;

            public bool AddFragment(int index, bool isFinal, byte[] header, byte[] data, int maxFragments, int maxBytes)
            {
                if (index > maxFragments)
                {
                    Reset();
                    return false;
                }

                var now = DateTime.UtcNow;
                if (now - _lastUpdated > FragmentTimeout)
                    // 超时则丢弃已缓存分片。
                    Reset();

                if (_header != null && !_header.AsSpan().SequenceEqual(header))
                    // 目标地址变化视为新序列，清空缓存。
                    Reset();

                if (index < _highestIndex)
                    // 遇到乱序或重复索引时直接重置，避免错误拼接。
                    Reset();

                if (_header == null)
                {
                    _header = header;
                    _totalBytes = header.Length;
                }

                _highestIndex = Math.Max(_highestIndex, index);
                if (_fragments.TryGetValue(index, out var existing))
                    _totalBytes -= existing.Length;
                _fragments[index] = data;
                _totalBytes += data.Length;
                if (isFinal)
                    _finalIndex = index;
                _lastUpdated = now;

                if (_totalBytes > maxBytes)
                {
                    Reset();
                    return false;
                }

                return true;
            }

            public bool TryAssemble(out byte[] body)
            {
                body = [];
                if (_finalIndex <= 0 || _header == null)
                    return false;

                var total = _header.Length;
                for (var i = 1; i <= _finalIndex; i++)
                {
                    if (!_fragments.TryGetValue(i, out var part))
                        return false;
                    total += part.Length;
                }

                // 按顺序拼接：头部 + 分片数据。
                var buffer = new byte[total];
                _header.CopyTo(buffer, 0);
                var offset = _header.Length;
                for (var i = 1; i <= _finalIndex; i++)
                {
                    var part = _fragments[i];
                    Buffer.BlockCopy(part, 0, buffer, offset, part.Length);
                    offset += part.Length;
                }

                body = buffer;
                return true;
            }

            public bool IsExpired(DateTime now) => now - _lastUpdated > FragmentTimeout;

            public void Reset()
            {
                _fragments.Clear();
                _header = null;
                _highestIndex = 0;
                _finalIndex = 0;
                _lastUpdated = DateTime.UtcNow;
                _totalBytes = 0;
            }
        }
    }
}
