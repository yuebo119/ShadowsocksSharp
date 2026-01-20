using System.Net.Sockets;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Diagnostics;

namespace ShadowsocksSharp.Outbound;

/// <summary>
/// 连接到 SIP003 插件的本地端口，由插件负责转发到 SS 服务器。
/// </summary>
public sealed class Sip003PluginConnector : IOutboundConnector
{
    private readonly Sip003PluginManager _manager;

    public Sip003PluginConnector(Sip003PluginManager manager)
    {
        _manager = manager;
    }

    public async ValueTask<Socket> ConnectAsync(OutboundConnectRequest request)
    {
        var server = request.Server;
        if (string.IsNullOrWhiteSpace(server.Plugin))
            throw new InvalidOperationException("SIP003 plugin not configured.");

        // 确保插件进程已启动，并获取其本地监听端点。
        var instance = _manager.GetOrCreate(server);
        instance.EnsureRunning();

        var endpoint = instance.LocalEndPoint;
        var socket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };

        await socket.ConnectAsync(endpoint, request.CancellationToken).ConfigureAwait(false);
        Log.D($"Connected to plugin endpoint {endpoint}");
        return socket;
    }
}
