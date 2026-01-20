using System.Net.Sockets;
using ShadowsocksSharp.Core.Model;

namespace ShadowsocksSharp.Inbound;

/// <summary>
/// 通过首字节判断 SOCKS5 或 HTTP，并分发到对应解析器。
/// </summary>
public sealed class AutoDetectInbound
{
    // 常见 HTTP 方法首字节：GET/POST/DELETE/HEAD/OPTIONS/CONNECT/TRACE。
    private static readonly byte[] HttpMethodFirstBytes = "GPDHOCT"u8.ToArray();

    private readonly Socks5Inbound _socks5 = new();
    private readonly HttpInbound _http = new();

    public async Task<InboundResult> HandleAsync(NetworkStream stream, CancellationToken ct)
    {
        // 只读取 1 字节决定协议类型，减少额外缓冲。
        var first = new byte[1];
        var n = await stream.ReadAsync(first.AsMemory(), ct).ConfigureAwait(false);
        if (n == 0)
            return new InboundResult(null, null, null, null);

        var b = first[0];
        if (b == 0x05)
        {
            return await _socks5.HandleAsync(stream, b, ct).ConfigureAwait(false);
        }

        if (HttpMethodFirstBytes.AsSpan().IndexOf(b) >= 0)
        {
            return await _http.HandleAsync(stream, b, ct).ConfigureAwait(false);
        }

        return new InboundResult(null, null, null, null);
    }
}
