using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ShadowsocksSharp.Tests.Mocks;

/// <summary>
/// Minimal SOCKS5 UDP client for integration tests.
/// </summary>
public sealed class Socks5UdpClient : IAsyncDisposable
{
    private TcpClient? _control;
    private NetworkStream? _stream;
    private Socket? _udp;
    private IPEndPoint? _relayEndpoint;

    public async Task ConnectAsync(string host, int port, string? username = null, string? password = null, CancellationToken ct = default)
    {
        _control = new TcpClient();
        await _control.ConnectAsync(host, port, ct).ConfigureAwait(false);
        _stream = _control.GetStream();

        var methods = string.IsNullOrWhiteSpace(username) ? new byte[] { 0x00 } : new byte[] { 0x02 };
        await _stream.WriteAsync(new byte[] { 0x05, (byte)methods.Length }.Concat(methods).ToArray(), ct).ConfigureAwait(false);

        var response = new byte[2];
        await ReadExactAsync(_stream, response, ct).ConfigureAwait(false);
        if (response[1] == 0xFF)
            throw new InvalidOperationException("SOCKS5 no acceptable auth methods.");

        if (response[1] == 0x02)
        {
            await SendUserPassAuthAsync(username ?? string.Empty, password ?? string.Empty, ct).ConfigureAwait(false);
        }

        var bindAddress = IPAddress.Loopback;
        _udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _udp.Bind(new IPEndPoint(bindAddress, 0));

        var udpEndpoint = (IPEndPoint)_udp.LocalEndPoint!;
        var request = BuildUdpAssociateRequest(udpEndpoint);
        await _stream.WriteAsync(request, ct).ConfigureAwait(false);

        var replyHeader = new byte[4];
        await ReadExactAsync(_stream, replyHeader, ct).ConfigureAwait(false);
        if (replyHeader[1] != 0x00)
            throw new InvalidOperationException("SOCKS5 UDP associate failed.");

        _relayEndpoint = await ReadSocks5AddressAsync(_stream, replyHeader[3], ct).ConfigureAwait(false);
    }

    public async Task<byte[]> SendAndReceiveAsync(string host, int port, byte[] data, bool fragment, int fragmentSize, CancellationToken ct = default)
    {
        if (_udp == null || _relayEndpoint == null)
            throw new InvalidOperationException("UDP client not initialized.");

        if (fragment && fragmentSize > 0)
        {
            await SendFragmentsAsync(host, port, data, fragmentSize, ct).ConfigureAwait(false);
        }
        else
        {
            var packet = BuildUdpPacket(host, port, data, frag: 0x00);
            await _udp.SendToAsync(packet, SocketFlags.None, _relayEndpoint, ct).ConfigureAwait(false);
        }

        return await ReceiveResponseAsync(ct).ConfigureAwait(false);
    }

    public async Task SendAsync(string host, int port, byte[] data, bool fragment, int fragmentSize, CancellationToken ct = default)
    {
        if (_udp == null || _relayEndpoint == null)
            throw new InvalidOperationException("UDP client not initialized.");

        if (fragment && fragmentSize > 0)
        {
            await SendFragmentsAsync(host, port, data, fragmentSize, ct).ConfigureAwait(false);
            return;
        }

        var packet = BuildUdpPacket(host, port, data, frag: 0x00);
        await _udp.SendToAsync(packet, SocketFlags.None, _relayEndpoint, ct).ConfigureAwait(false);
    }

    private async Task SendUserPassAuthAsync(string username, string password, CancellationToken ct)
    {
        var userBytes = Encoding.ASCII.GetBytes(username);
        var passBytes = Encoding.ASCII.GetBytes(password);
        var auth = new byte[3 + userBytes.Length + passBytes.Length];
        auth[0] = 0x01;
        auth[1] = (byte)userBytes.Length;
        Buffer.BlockCopy(userBytes, 0, auth, 2, userBytes.Length);
        auth[2 + userBytes.Length] = (byte)passBytes.Length;
        Buffer.BlockCopy(passBytes, 0, auth, 3 + userBytes.Length, passBytes.Length);
        await _stream!.WriteAsync(auth, ct).ConfigureAwait(false);

        var response = new byte[2];
        await ReadExactAsync(_stream!, response, ct).ConfigureAwait(false);
        if (response[1] != 0x00)
            throw new InvalidOperationException("SOCKS5 auth failed.");
    }

    private async Task SendFragmentsAsync(string host, int port, byte[] data, int fragmentSize, CancellationToken ct)
    {
        var total = data.Length;
        var offset = 0;
        var fragIndex = 1;

        while (offset < total)
        {
            var chunk = Math.Min(fragmentSize, total - offset);
            var frag = offset + chunk >= total ? (byte)(fragIndex | 0x80) : (byte)fragIndex;
            var slice = new byte[chunk];
            Buffer.BlockCopy(data, offset, slice, 0, chunk);
            var packet = BuildUdpPacket(host, port, slice, frag);
            await _udp!.SendToAsync(packet, SocketFlags.None, _relayEndpoint!, ct).ConfigureAwait(false);
            offset += chunk;
            fragIndex++;
        }
    }

    private async Task<byte[]> ReceiveResponseAsync(CancellationToken ct)
    {
        var buffer = new byte[65536];
        EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
        var result = await _udp!.ReceiveFromAsync(buffer, SocketFlags.None, remote, ct).ConfigureAwait(false);
        if (!TryParseUdpResponse(buffer.AsSpan(0, result.ReceivedBytes), out var payload))
            throw new InvalidOperationException("Invalid UDP response.");
        return payload;
    }

    private static bool TryParseUdpResponse(ReadOnlySpan<byte> packet, out byte[] payload)
    {
        payload = [];
        if (packet.Length < 4)
            return false;
        if (packet[0] != 0x00 || packet[1] != 0x00)
            return false;
        if (packet[2] != 0x00)
            return false;

        if (!TryParseAddress(packet.Slice(3), out _, out _, out var headerLength))
            return false;

        var offset = 3 + headerLength;
        if (offset > packet.Length)
            return false;
        payload = packet[offset..].ToArray();
        return true;
    }

    private static byte[] BuildUdpPacket(string host, int port, ReadOnlySpan<byte> data, byte frag)
    {
        var (type, address) = BuildSocks5Address(host);
        var packet = new byte[3 + 1 + address.Length + 2 + data.Length];
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = frag;
        packet[3] = type;
        Buffer.BlockCopy(address, 0, packet, 4, address.Length);
        packet[4 + address.Length] = (byte)(port >> 8);
        packet[5 + address.Length] = (byte)(port & 0xFF);
        data.CopyTo(packet.AsSpan(6 + address.Length));
        return packet;
    }

    private static byte[] BuildUdpAssociateRequest(IPEndPoint endpoint)
    {
        var addrBytes = endpoint.Address.GetAddressBytes();
        var request = new byte[4 + addrBytes.Length + 2];
        request[0] = 0x05;
        request[1] = 0x03;
        request[2] = 0x00;
        request[3] = addrBytes.Length == 16 ? (byte)0x04 : (byte)0x01;
        Buffer.BlockCopy(addrBytes, 0, request, 4, addrBytes.Length);
        request[4 + addrBytes.Length] = (byte)(endpoint.Port >> 8);
        request[5 + addrBytes.Length] = (byte)(endpoint.Port & 0xFF);
        return request;
    }

    private static async Task<IPEndPoint> ReadSocks5AddressAsync(NetworkStream stream, byte atyp, CancellationToken ct)
    {
        if (atyp == 0x01)
        {
            var addr = new byte[4];
            await ReadExactAsync(stream, addr, ct).ConfigureAwait(false);
            var port = await ReadPortAsync(stream, ct).ConfigureAwait(false);
            return new IPEndPoint(new IPAddress(addr), port);
        }

        if (atyp == 0x04)
        {
            var addr = new byte[16];
            await ReadExactAsync(stream, addr, ct).ConfigureAwait(false);
            var port = await ReadPortAsync(stream, ct).ConfigureAwait(false);
            return new IPEndPoint(new IPAddress(addr), port);
        }

        if (atyp == 0x03)
        {
            var lenBuf = new byte[1];
            await ReadExactAsync(stream, lenBuf, ct).ConfigureAwait(false);
            var name = new byte[lenBuf[0]];
            await ReadExactAsync(stream, name, ct).ConfigureAwait(false);
            var host = Encoding.ASCII.GetString(name);
            var port = await ReadPortAsync(stream, ct).ConfigureAwait(false);
            return new IPEndPoint(ResolveAddress(host), port);
        }

        throw new InvalidOperationException("Invalid SOCKS5 address type.");
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

    private static IPAddress ResolveAddress(string host)
    {
        if (IPAddress.TryParse(host, out var ip))
            return ip;
        return Dns.GetHostAddresses(host)[0];
    }

    private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct).ConfigureAwait(false);
            if (n <= 0)
                throw new IOException("SOCKS5 control channel closed.");
            offset += n;
        }
    }

    private static async Task<int> ReadPortAsync(NetworkStream stream, CancellationToken ct)
    {
        var portBuf = new byte[2];
        await ReadExactAsync(stream, portBuf, ct).ConfigureAwait(false);
        return (portBuf[0] << 8) | portBuf[1];
    }

    public async ValueTask DisposeAsync()
    {
        try { _udp?.Dispose(); } catch { }
        try { _stream?.Dispose(); } catch { }
        try { _control?.Close(); } catch { }
        await Task.CompletedTask;
    }
}
