using System.Net;
using System.Net.Sockets;
using ShadowsocksSharp.Diagnostics;

namespace ShadowsocksSharp.Outbound;

/// <summary>
/// 直连到 Shadowsocks 服务器的 TCP 连接器。
/// </summary>
public sealed class DirectConnector : IOutboundConnector
{
    public async ValueTask<Socket> ConnectAsync(OutboundConnectRequest request)
    {
        var server = request.Server;
        var ct = request.CancellationToken;

        // 仅当 Host 不是字面量 IP 时才进行 DNS 解析。
        if (!IPAddress.TryParse(server.Host, out var address))
        {
            var resolved = await Dns.GetHostAddressesAsync(server.Host, ct).ConfigureAwait(false);
            address = resolved[0];
        }

        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        socket.NoDelay = true;
        socket.ReceiveBufferSize = server.SocketReceiveBuffer > 0 ? server.SocketReceiveBuffer : 16384;
        socket.SendBufferSize = server.SocketSendBuffer > 0 ? server.SocketSendBuffer : 16384;

        // 将连接超时与整体操作超时分离，避免长时间阻塞。
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(Math.Min(server.Timeout, 15)));

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await socket.ConnectAsync(address, server.Port, cts.Token).ConfigureAwait(false);
        sw.Stop();
        PerfMetrics.Record("ss_connect_ms", sw.ElapsedMilliseconds);
        Log.D($"Connected to SS {server.Host}:{server.Port} in {sw.ElapsedMilliseconds}ms");

        return socket;
    }
}
