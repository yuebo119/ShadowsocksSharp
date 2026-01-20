using System.Net.Sockets;
using System.Text;
using ShadowsocksSharp.Core.Model;

namespace ShadowsocksSharp.Inbound;

/// <summary>
/// 解析 HTTP 代理请求与 CONNECT 隧道，并处理 PAC 请求。
/// </summary>
public sealed class HttpInbound
{
    private static readonly ReadOnlyMemory<byte> Http200 = "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray();
    private static readonly ReadOnlyMemory<byte> Http502 = "HTTP/1.1 502 Bad Gateway\r\n\r\n"u8.ToArray();
    private static readonly ReadOnlyMemory<byte> Http400 = "HTTP/1.1 400 Bad Request\r\n\r\n"u8.ToArray();

    public async Task<InboundResult> HandleAsync(NetworkStream stream, byte firstByte, CancellationToken ct)
    {
        var (requestText, body) = await ReadHeaderAsync(stream, firstByte, ct).ConfigureAwait(false);
        if (string.IsNullOrEmpty(requestText))
            return new InboundResult(null, null, null, null);

        var lines = requestText.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0)
            return new InboundResult(null, null, null, null);

        var requestLine = lines[0];
        var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            return new InboundResult(null, null, null, null);

        var method = parts[0];
        var url = parts[1];

        // 本地 PAC 请求直接交给 PAC 服务处理。
        if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase) &&
            (url.StartsWith("/pac", StringComparison.OrdinalIgnoreCase) ||
             url.StartsWith("/proxy.pac", StringComparison.OrdinalIgnoreCase)))
        {
            return new InboundResult(null, null, null, url);
        }

        if (string.Equals(method, "CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            // CONNECT 在返回 200 后进入纯 TCP 隧道模式。
            if (!TryParseHostPort(url, out var connectHost, out var connectPort))
            {
                return new InboundResult(
                    null,
                    null,
                    (s, token) => s.WriteAsync(Http400, token),
                    null);
            }

            var request = new ConnectRequest(connectHost, connectPort, InboundProtocol.HttpConnect, ReadOnlyMemory<byte>.Empty);
            return new InboundResult(
                request,
                (s, token) => s.WriteAsync(Http200, token),
                (s, token) => s.WriteAsync(Http502, token),
                null);
        }

        var hostHeader = lines.FirstOrDefault(l => l.StartsWith("Host:", StringComparison.OrdinalIgnoreCase));
        var hostValue = hostHeader?.AsSpan(5).Trim().ToString() ?? string.Empty;

        var uri = url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            ? new Uri(url)
            : new Uri($"http://{hostValue}{url}");

        var targetHost = uri.Host;
        var targetPort = uri.Port;

        // 将绝对路径请求改写为 origin-form，并移除 Proxy-* 头。
        var rewritten = BuildHttpRequest(method, uri, lines);
        var headerBytes = Encoding.ASCII.GetBytes(rewritten);
        byte[] payload;
        if (body.Length == 0)
        {
            payload = headerBytes;
        }
        else
        {
            payload = new byte[headerBytes.Length + body.Length];
            Buffer.BlockCopy(headerBytes, 0, payload, 0, headerBytes.Length);
            body.CopyTo(payload.AsMemory(headerBytes.Length));
        }

        var requestInfo = new ConnectRequest(targetHost, targetPort, InboundProtocol.Http, payload);
        return new InboundResult(
            requestInfo,
            null,
            (s, token) => s.WriteAsync(Http502, token),
            null);
    }

    private static bool TryParseHostPort(string hostPort, out string host, out int port)
    {
        var colon = hostPort.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(hostPort.AsSpan(colon + 1), out port))
        {
            host = string.Empty;
            port = 0;
            return false;
        }

        host = hostPort[..colon];
        return !string.IsNullOrWhiteSpace(host);
    }

    private static string BuildHttpRequest(string method, Uri uri, string[] headers)
    {
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(uri.PathAndQuery).Append(" HTTP/1.1\r\n");
        foreach (var h in headers.AsSpan(1))
        {
            if (!h.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase))
                sb.Append(h).Append("\r\n");
        }
        sb.Append("\r\n");
        return sb.ToString();
    }

    private static async Task<(string headerText, ReadOnlyMemory<byte> body)> ReadHeaderAsync(NetworkStream stream, byte firstByte, CancellationToken ct)
    {
        var buffer = new byte[8192];
        buffer[0] = firstByte;
        var total = 1;

        while (total < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), ct).ConfigureAwait(false);
            if (n == 0) break;
            total += n;
            if (total >= 4 && buffer.AsSpan(0, total).IndexOf("\r\n\r\n"u8) >= 0)
                break;
        }

        if (total == 0)
            return ("", ReadOnlyMemory<byte>.Empty);

        var headerEnd = buffer.AsSpan(0, total).IndexOf("\r\n\r\n"u8);
        if (headerEnd < 0)
            return ("", ReadOnlyMemory<byte>.Empty);

        var headerText = Encoding.ASCII.GetString(buffer, 0, headerEnd);
        var bodyOffset = headerEnd + 4;
        var bodyLen = Math.Max(0, total - bodyOffset);
        var body = bodyLen > 0 ? buffer.AsMemory(bodyOffset, bodyLen) : ReadOnlyMemory<byte>.Empty;
        return (headerText, body);
    }
}
