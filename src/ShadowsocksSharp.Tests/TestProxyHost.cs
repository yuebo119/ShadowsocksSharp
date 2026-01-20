using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Core.Strategy;
using ShadowsocksSharp.Outbound;
using ShadowsocksSharp.Services.Pac;
using ShadowsocksSharp.Services.Tcp;

namespace ShadowsocksSharp.Tests;

public sealed class TestProxyHost : IAsyncDisposable
{
    private readonly TcpProxyService _tcp;
    private readonly Config _config;

    public int Port => _config.LocalPort;

    public TestProxyHost(SsServerConfig server, int localPort)
    {
        _config = new Config
        {
            Servers = [server],
            CurrentIndex = 0,
            LocalPort = localPort,
            AutoSetSystemProxy = false
        };

        var selector = new StaticServerSelector();
        var pluginManager = new Sip003PluginManager();
        var connector = new ConnectorPipeline(pluginManager);
        var pac = new PacService(_config, Path.Combine(Path.GetTempPath(), "ShadowsocksSharp.Tests"));

        _tcp = new TcpProxyService(_config, selector, connector, pac);
    }

    public Task StartAsync() => _tcp.StartAsync(CancellationToken.None);

    public async ValueTask DisposeAsync()
    {
        await _tcp.StopAsync(CancellationToken.None);
    }
}
