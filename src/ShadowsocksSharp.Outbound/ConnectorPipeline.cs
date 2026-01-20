using System.Net.Sockets;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Diagnostics;

namespace ShadowsocksSharp.Outbound;

/// <summary>
/// 按固定顺序选择上游连接路径：SIP003 插件 > 前置代理 > 直连。
/// </summary>
public sealed class ConnectorPipeline : IOutboundConnector
{
    private readonly Sip003PluginConnector _plugin;
    private readonly ForwardProxyConnector _proxy;
    private readonly DirectConnector _direct;

    public ConnectorPipeline(Sip003PluginManager pluginManager)
    {
        _plugin = new Sip003PluginConnector(pluginManager);
        _proxy = new ForwardProxyConnector();
        _direct = new DirectConnector();
    }

    public ValueTask<Socket> ConnectAsync(OutboundConnectRequest request)
    {
        var server = request.Server;
        var proxy = request.ForwardProxy;

        if (!string.IsNullOrWhiteSpace(server.Plugin))
        {
            // 插件接管上游连接，本地仅需连接到插件的本地端口；此时前置代理不生效。
            if (proxy.Enabled)
            {
                Log.W("Forward proxy is ignored when SIP003 plugin is enabled.");
            }
            return _plugin.ConnectAsync(request);
        }

        if (proxy.Enabled)
        {
            // 未配置插件时才允许走前置代理。
            return _proxy.ConnectAsync(request);
        }

        return _direct.ConnectAsync(request);
    }
}
