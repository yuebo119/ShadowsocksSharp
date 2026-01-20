using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ShadowsocksSharp.Tests.Mocks;

/// <summary>
/// Minimal SOCKS5 proxy server with UDP ASSOCIATE support.
/// </summary>
public sealed class MockSocks5ProxyServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly string? _username;
    private readonly string? _password;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;
    private Socket? _udpSocket;
    private IPEndPoint? _clientUdpEndpoint;

    public int Port { get; }

    public MockSocks5ProxyServer(int port, string? username = null, string? password = null)
    {
        Port = port;
        _username = username;
        _password = password;
        _listener = new TcpListener(IPAddress.Loopback, port);
    }

    public void Start()
    {
        _listener.Start();
        _cts = new CancellationTokenSource();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token), _cts.Token);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
            catch (OperationCanceledException) { }
            catch { }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using var _ = client;
        using var stream = client.GetStream();

        if (!await HandleHandshakeAsync(stream, ct).ConfigureAwait(false))
            return;

        if (!await HandleUdpAssociateAsync(stream, ct).ConfigureAwait(false))
            return;

        await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
    }

    private async Task<bool> HandleHandshakeAsync(NetworkStream stream, CancellationToken ct)
    {
        var header = new byte[2];
        if (!await ReadExactAsync(stream, header, ct).ConfigureAwait(false))
            return false;

        if (header[0] != 0x05)
            return false;

        var methodCount = header[1];
        var methods = new byte[methodCount];
        if (!await ReadExactAsync(stream, methods, ct).ConfigureAwait(false))
            return false;

        var requireAuth = !string.IsNullOrWhiteSpace(_username);
        byte selected = requireAuth ? (byte)0x02 : (byte)0x00;
        if (requireAuth && !methods.Contains((byte)0x02))
            selected = 0xFF;
        if (!requireAuth && !methods.Contains((byte)0x00))
            selected = 0xFF;

        await stream.WriteAsync(new[] { (byte)0x05, selected }, ct).ConfigureAwait(false);
        if (selected == 0xFF)
            return false;

        if (selected == 0x02)
        {
            if (!await HandleUserPassAuthAsync(stream, ct).ConfigureAwait(false))
                return false;
        }

        return true;
    }

    private async Task<bool> HandleUserPassAuthAsync(NetworkStream stream, CancellationToken ct)
    {
        var header = new byte[2];
        if (!await ReadExactAsync(stream, header, ct).ConfigureAwait(false))
            return false;
        if (header[0] != 0x01)
            return false;

        var userLen = header[1];
        var user = new byte[userLen];
        if (!await ReadExactAsync(stream, user, ct).ConfigureAwait(false))
            return false;

        var passLenBuf = new byte[1];
        if (!await ReadExactAsync(stream, passLenBuf, ct).ConfigureAwait(false))
            return false;

        var passLen = passLenBuf[0];
        var pass = new byte[passLen];
        if (!await ReadExactAsync(stream, pass, ct).ConfigureAwait(false))
            return false;

        var username = Encoding.ASCII.GetString(user);
        var password = Encoding.ASCII.GetString(pass);
        var ok = username == _username && password == _password;

        await stream.WriteAsync(new[] { (byte)0x01, ok ? (byte)0x00 : (byte)0x01 }, ct).ConfigureAwait(false);
        return ok;
    }

    private async Task<bool> HandleUdpAssociateAsync(NetworkStream stream, CancellationToken ct)
    {
        var header = new byte[4];
        if (!await ReadExactAsync(stream, header, ct).ConfigureAwait(false))
            return false;

        if (header[0] != 0x05 || header[1] != 0x03)
            return false;

        var addressResult = await ReadAddressAsync(stream, header[3], ct).ConfigureAwait(false);
        if (addressResult == null)
            return false;

        var (clientAddress, clientPort) = addressResult.Value;
        _clientUdpEndpoint = new IPEndPoint(clientAddress, clientPort);

        _udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var relay = (IPEndPoint)_udpSocket.LocalEndPoint!;

        await SendUdpAssociateReplyAsync(stream, relay, ct).ConfigureAwait(false);
        _ = Task.Run(() => UdpRelayLoopAsync(_udpSocket, ct), ct);
        return true;
    }

    private async Task UdpRelayLoopAsync(Socket socket, CancellationToken ct)
    {
        var buffer = new byte[65536];
        EndPoint remote = new IPEndPoint(IPAddress.Any, 0);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, remote, ct).ConfigureAwait(false);
                if (result.ReceivedBytes <= 0)
                    continue;

                var from = (IPEndPoint)result.RemoteEndPoint;
                if (_clientUdpEndpoint == null)
                    continue;

                if (from.Equals(_clientUdpEndpoint))
                {
                    if (!TryParseUdpRequest(buffer.AsSpan(0, result.ReceivedBytes), out var dest, out var payloadOffset))
                        continue;

                    await socket.SendToAsync(buffer.AsMemory(payloadOffset, result.ReceivedBytes - payloadOffset), SocketFlags.None, dest)
                        .ConfigureAwait(false);
                }
                else
                {
                    var header = BuildUdpHeader(from);
                    var outBuffer = new byte[header.Length + result.ReceivedBytes];
                    Buffer.BlockCopy(header, 0, outBuffer, 0, header.Length);
                    Buffer.BlockCopy(buffer, 0, outBuffer, header.Length, result.ReceivedBytes);
                    await socket.SendToAsync(outBuffer, SocketFlags.None, _clientUdpEndpoint).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch { }
        }
    }

    private static bool TryParseUdpRequest(ReadOnlySpan<byte> packet, out IPEndPoint destination, out int payloadOffset)
    {
        destination = new IPEndPoint(IPAddress.Loopback, 0);
        payloadOffset = 0;

        if (packet.Length < 4)
            return false;
        if (packet[0] != 0x00 || packet[1] != 0x00)
            return false;
        if (packet[2] != 0x00)
            return false;

        if (!TryParseAddress(packet.Slice(3), out var address, out var port, out var headerLength))
            return false;

        payloadOffset = 3 + headerLength;
        destination = new IPEndPoint(address, port);
        return payloadOffset <= packet.Length;
    }

    private static byte[] BuildUdpHeader(IPEndPoint source)
    {
        var (type, address) = BuildSocks5Address(source.Address);
        var header = new byte[3 + 1 + address.Length + 2];
        header[0] = 0x00;
        header[1] = 0x00;
        header[2] = 0x00;
        header[3] = type;
        Buffer.BlockCopy(address, 0, header, 4, address.Length);
        header[4 + address.Length] = (byte)(source.Port >> 8);
        header[5 + address.Length] = (byte)(source.Port & 0xFF);
        return header;
    }

    private static (byte type, byte[] address) BuildSocks5Address(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 ? ((byte)0x01, bytes) : ((byte)0x04, bytes);
    }

    private static bool TryParseAddress(ReadOnlySpan<byte> buffer, out IPAddress address, out int port, out int headerLength)
    {
        address = IPAddress.Loopback;
        port = 0;
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

        if (atyp == 0x03)
        {
            var host = Encoding.ASCII.GetString(buffer.Slice(offset, addressLength));
            address = ResolveAddress(host);
        }
        else
        {
            address = new IPAddress(buffer.Slice(offset, addressLength));
        }

        port = (buffer[offset + addressLength] << 8) | buffer[offset + addressLength + 1];
        headerLength = total;
        return true;
    }

    private static async Task<(IPAddress address, int port)?> ReadAddressAsync(NetworkStream stream, byte atyp, CancellationToken ct)
    {
        if (atyp == 0x01)
        {
            var addr = new byte[4];
            if (!await ReadExactAsync(stream, addr, ct).ConfigureAwait(false))
                return null;
            var address = new IPAddress(addr);
            var port = await ReadPortAsync(stream, ct).ConfigureAwait(false);
            return port == null ? null : (address, port.Value);
        }
        else if (atyp == 0x04)
        {
            var addr = new byte[16];
            if (!await ReadExactAsync(stream, addr, ct).ConfigureAwait(false))
                return null;
            var address = new IPAddress(addr);
            var port = await ReadPortAsync(stream, ct).ConfigureAwait(false);
            return port == null ? null : (address, port.Value);
        }
        else if (atyp == 0x03)
        {
            var lenBuf = new byte[1];
            if (!await ReadExactAsync(stream, lenBuf, ct).ConfigureAwait(false))
                return null;
            var name = new byte[lenBuf[0]];
            if (!await ReadExactAsync(stream, name, ct).ConfigureAwait(false))
                return null;
            var host = Encoding.ASCII.GetString(name);
            var address = ResolveAddress(host);
            var port = await ReadPortAsync(stream, ct).ConfigureAwait(false);
            return port == null ? null : (address, port.Value);
        }
        return null;
    }

    private static async Task<int?> ReadPortAsync(NetworkStream stream, CancellationToken ct)
    {
        var portBuf = new byte[2];
        if (!await ReadExactAsync(stream, portBuf, ct).ConfigureAwait(false))
            return null;
        return (portBuf[0] << 8) | portBuf[1];
    }

    private static IPAddress ResolveAddress(string host)
    {
        if (IPAddress.TryParse(host, out var ip))
            return ip;
        return Dns.GetHostAddresses(host)[0];
    }

    private static async Task SendUdpAssociateReplyAsync(NetworkStream stream, IPEndPoint relay, CancellationToken ct)
    {
        var addrBytes = relay.Address.GetAddressBytes();
        var reply = new byte[4 + addrBytes.Length + 2];
        reply[0] = 0x05;
        reply[1] = 0x00;
        reply[2] = 0x00;
        reply[3] = addrBytes.Length == 16 ? (byte)0x04 : (byte)0x01;
        Buffer.BlockCopy(addrBytes, 0, reply, 4, addrBytes.Length);
        reply[4 + addrBytes.Length] = (byte)(relay.Port >> 8);
        reply[5 + addrBytes.Length] = (byte)(relay.Port & 0xFF);
        await stream.WriteAsync(reply, ct).ConfigureAwait(false);
    }

    private static async Task<bool> ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct).ConfigureAwait(false);
            if (n <= 0)
                return false;
            offset += n;
        }
        return true;
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _listener.Stop();

        if (_acceptLoop != null)
        {
            try
            {
                await _acceptLoop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch { }
        }

        try { _udpSocket?.Dispose(); } catch { }
        _cts?.Dispose();
    }
}
