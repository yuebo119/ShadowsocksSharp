using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Core.Strategy;
using ShadowsocksSharp.Outbound;
using ShadowsocksSharp.Services.Pac;
using ShadowsocksSharp.Services.Tcp;
using ShadowsocksSharp.Services.Udp;

namespace ShadowsocksSharp.Tests;

public sealed class TestUdpProxyHost : IAsyncDisposable
{
    private readonly TcpProxyService _tcp;
    private readonly UdpRelayService _udp;
    private readonly Sip003PluginManager _pluginManager;
    private readonly Config _config;

    public int Port => _config.LocalPort;

    public TestUdpProxyHost(SsServerConfig server, int localPort, ForwardProxyConfig? proxy = null)
    {
        _config = new Config
        {
            Servers = [server],
            CurrentIndex = 0,
            LocalPort = localPort,
            AutoSetSystemProxy = false,
            ForwardProxy = proxy ?? new ForwardProxyConfig()
        };

        var selector = new StaticServerSelector();
        _pluginManager = new Sip003PluginManager();
        var connector = new ConnectorPipeline(_pluginManager);
        var pac = new PacService(_config, Path.Combine(Path.GetTempPath(), "ShadowsocksSharp.Tests"));

        _tcp = new TcpProxyService(_config, selector, connector, pac);
        _udp = new UdpRelayService(_config, selector, _pluginManager);
    }

    public async Task StartAsync()
    {
        await _tcp.StartAsync(CancellationToken.None).ConfigureAwait(false);
        await _udp.StartAsync(CancellationToken.None).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await _udp.StopAsync(CancellationToken.None).ConfigureAwait(false);
        await _tcp.StopAsync(CancellationToken.None).ConfigureAwait(false);
        _pluginManager.Dispose();
    }
}
