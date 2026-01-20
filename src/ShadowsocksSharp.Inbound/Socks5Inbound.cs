using System.Net;
using System.Net.Sockets;
using ShadowsocksSharp.Core.Model;

namespace ShadowsocksSharp.Inbound;

/// <summary>
/// 最小化 SOCKS5 握手与 CONNECT/UDP ASSOCIATE 解析。
/// </summary>
public sealed class Socks5Inbound
{
    private static readonly ReadOnlyMemory<byte> Socks5NoAuth = new byte[] { 0x05, 0x00 };
    private static readonly ReadOnlyMemory<byte> Socks5Success = new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    private static readonly ReadOnlyMemory<byte> Socks5Failure = new byte[] { 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    private static readonly ReadOnlyMemory<byte> Socks5CommandNotSupported = new byte[] { 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };

    public async Task<InboundResult> HandleAsync(NetworkStream stream, byte firstByte, CancellationToken ct)
    {
        // 客户端握手：VER, NMETHODS。
        var header = new byte[2];
        header[0] = firstByte;
        if (!await ReadExactAsync(stream, header.AsMemory(1, 1), ct).ConfigureAwait(false))
            return new InboundResult(null, null, null, null);

        var nMethods = header[1];
        if (nMethods <= 0)
            return new InboundResult(null, null, null, null);

        var methods = new byte[nMethods];
        if (!await ReadExactAsync(stream, methods, ct).ConfigureAwait(false))
            return new InboundResult(null, null, null, null);

        // 本地代理仅支持「无认证」方式。
        await stream.WriteAsync(Socks5NoAuth, ct).ConfigureAwait(false);

        var requestHeader = new byte[4];
        if (!await ReadExactAsync(stream, requestHeader, ct).ConfigureAwait(false))
            return new InboundResult(null, null, null, null);

        var command = requestHeader[1];
        if (command != 0x01 && command != 0x03)
        {
            // 仅支持 CONNECT(0x01) 与 UDP ASSOCIATE(0x03)。
            return new InboundResult(
                null,
                null,
                (s, token) => s.WriteAsync(Socks5CommandNotSupported, token),
                null);
        }

        var (host, port) = await ReadAddressAsync(stream, requestHeader[3], ct).ConfigureAwait(false);

        if (command == 0x03)
        {
            // UDP ASSOCIATE 由 TCP 服务返回 UDP 绑定端点。
            var request = new ConnectRequest(host, port, InboundProtocol.Socks5UdpAssociate, ReadOnlyMemory<byte>.Empty);
            return new InboundResult(
                request,
                null,
                (s, token) => s.WriteAsync(Socks5Failure, token),
                null);
        }

        var connectRequest = new ConnectRequest(host, port, InboundProtocol.Socks5, ReadOnlyMemory<byte>.Empty);

        return new InboundResult(
            connectRequest,
            (s, token) => s.WriteAsync(Socks5Success, token),
            (s, token) => s.WriteAsync(Socks5Failure, token),
            null);
    }

    private static async Task<(string host, int port)> ReadAddressAsync(NetworkStream stream, byte atyp, CancellationToken ct)
    {
        return atyp switch
        {
            0x01 => await ReadIPv4Async(stream, ct).ConfigureAwait(false),
            0x03 => await ReadDomainAsync(stream, ct).ConfigureAwait(false),
            0x04 => await ReadIPv6Async(stream, ct).ConfigureAwait(false),
            _ => throw new InvalidOperationException($"Unknown ATYP: {atyp}")
        };
    }

    private static async Task<(string host, int port)> ReadIPv4Async(NetworkStream stream, CancellationToken ct)
    {
        var buf = new byte[6];
        if (!await ReadExactAsync(stream, buf, ct).ConfigureAwait(false))
            throw new IOException("SOCKS5 address read failed.");

        var host = new IPAddress(buf.AsSpan(0, 4)).ToString();
        var port = (buf[4] << 8) | buf[5];
        return (host, port);
    }

    private static async Task<(string host, int port)> ReadIPv6Async(NetworkStream stream, CancellationToken ct)
    {
        var buf = new byte[18];
        if (!await ReadExactAsync(stream, buf, ct).ConfigureAwait(false))
            throw new IOException("SOCKS5 address read failed.");

        var host = new IPAddress(buf.AsSpan(0, 16)).ToString();
        var port = (buf[16] << 8) | buf[17];
        return (host, port);
    }

    private static async Task<(string host, int port)> ReadDomainAsync(NetworkStream stream, CancellationToken ct)
    {
        var lenBuf = new byte[1];
        if (!await ReadExactAsync(stream, lenBuf, ct).ConfigureAwait(false))
            throw new IOException("SOCKS5 domain length read failed.");

        var len = lenBuf[0];
        var buf = new byte[len + 2];
        if (!await ReadExactAsync(stream, buf, ct).ConfigureAwait(false))
            throw new IOException("SOCKS5 domain read failed.");

        var host = System.Text.Encoding.ASCII.GetString(buf, 0, len);
        var port = (buf[len] << 8) | buf[len + 1];
        return (host, port);
    }

    private static async Task<bool> ReadExactAsync(NetworkStream stream, Memory<byte> buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.Slice(offset, buffer.Length - offset), ct).ConfigureAwait(false);
            if (n == 0)
                return false;
            offset += n;
        }
        return true;
    }
}
