using System.Net;
using System.Net.Sockets;
using System.Text;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Diagnostics;

namespace ShadowsocksSharp.Outbound;

/// <summary>
/// 通过 SOCKS5 / HTTP 前置代理建立到 SS 服务器的 TCP 隧道。
/// </summary>
public sealed class ForwardProxyConnector : IOutboundConnector
{
    public async ValueTask<Socket> ConnectAsync(OutboundConnectRequest request)
    {
        var proxy = request.ForwardProxy;
        if (!proxy.Enabled)
            throw new InvalidOperationException("Forward proxy is not enabled.");

        var ct = request.CancellationToken;
        // 前置代理仅处理 TCP 链路；UDP 由 UdpRelayService 单独处理。
        var proxySocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, proxy.TimeoutSeconds)));

        await proxySocket.ConnectAsync(proxy.Host, proxy.Port, cts.Token).ConfigureAwait(false);

        if (proxy.Type == ForwardProxyType.Socks5)
        {
            // SOCKS5：方法协商 -> (可选)认证 -> CONNECT 目标。
            await HandshakeSocks5Async(proxySocket, request.Server, proxy, cts.Token).ConfigureAwait(false);
        }
        else
        {
            // HTTP：CONNECT host:port + 可选 Basic 认证。
            await HandshakeHttpAsync(proxySocket, request.Server, proxy, cts.Token).ConfigureAwait(false);
        }

        return proxySocket;
    }

    private static async Task HandshakeSocks5Async(Socket socket, SsServerConfig server, ForwardProxyConfig proxy, CancellationToken ct)
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

        var (addrType, addrBytes) = BuildSocks5Address(server.Host);
        var portBytes = new[] { (byte)(server.Port >> 8), (byte)(server.Port & 0xFF) };
        var req = new byte[4 + addrBytes.Length + 2];
        req[0] = 0x05;
        req[1] = 0x01;
        req[2] = 0x00;
        req[3] = addrType;
        Buffer.BlockCopy(addrBytes, 0, req, 4, addrBytes.Length);
        Buffer.BlockCopy(portBytes, 0, req, 4 + addrBytes.Length, 2);

        await socket.SendAsync(req, SocketFlags.None, ct).ConfigureAwait(false);

        var head = new byte[4];
        await ReceiveExactAsync(socket, head, ct).ConfigureAwait(false);
        if (head[1] != 0x00)
            throw new InvalidOperationException("SOCKS5 proxy connect failed.");

        var atyp = head[3];
        var addrLen = atyp switch
        {
            0x01 => 4,
            0x03 => await ReceiveByteAsync(socket, ct).ConfigureAwait(false),
            0x04 => 16,
            _ => throw new InvalidOperationException("Invalid SOCKS5 address type.")
        };

        // 读取 BND.ADDR 与 BND.PORT，避免后续读取错位。
        var skip = new byte[addrLen + 2];
        await ReceiveExactAsync(socket, skip, ct).ConfigureAwait(false);
    }

    private static async Task HandshakeHttpAsync(Socket socket, SsServerConfig server, ForwardProxyConfig proxy, CancellationToken ct)
    {
        var builder = new StringBuilder();
        builder.Append("CONNECT ").Append(server.Host).Append(':').Append(server.Port).Append(" HTTP/1.1\r\n");
        builder.Append("Host: ").Append(server.Host).Append(':').Append(server.Port).Append("\r\n");
        if (proxy.UseAuth)
        {
            var raw = $"{proxy.Username}:{proxy.Password}";
            var token = Convert.ToBase64String(Encoding.ASCII.GetBytes(raw));
            builder.Append("Proxy-Authorization: Basic ").Append(token).Append("\r\n");
        }
        builder.Append("\r\n");

        var bytes = Encoding.ASCII.GetBytes(builder.ToString());
        await socket.SendAsync(bytes, SocketFlags.None, ct).ConfigureAwait(false);

        var resp = await ReceiveHeaderAsync(socket, ct).ConfigureAwait(false);
        if (!resp.StartsWith("HTTP/1.1 200") && !resp.StartsWith("HTTP/1.0 200"))
            throw new InvalidOperationException($"HTTP proxy connect failed: {resp.Split('\r', '\n')[0]}");
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

    private static async Task<int> ReceiveByteAsync(Socket socket, CancellationToken ct)
    {
        var buf = new byte[1];
        await ReceiveExactAsync(socket, buf, ct).ConfigureAwait(false);
        return buf[0];
    }

    private static async Task<string> ReceiveHeaderAsync(Socket socket, CancellationToken ct)
    {
        var buffer = new byte[4096];
        var total = 0;
        // 读取到 HTTP 头结束或达到缓冲上限。
        while (total < buffer.Length)
        {
            var n = await socket.ReceiveAsync(buffer.AsMemory(total, buffer.Length - total), ct).ConfigureAwait(false);
            if (n <= 0)
                break;
            total += n;
            if (total >= 4 && buffer.AsSpan(0, total).IndexOf("\r\n\r\n"u8) >= 0)
                break;
        }
        return Encoding.ASCII.GetString(buffer, 0, total);
    }
}
