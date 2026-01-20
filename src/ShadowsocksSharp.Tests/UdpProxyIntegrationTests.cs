using System.Net;
using System.Net.Sockets;
using System.Text;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Tests.Mocks;
using Xunit;

namespace ShadowsocksSharp.Tests;

public sealed class UdpProxyIntegrationTests
{
    [Fact]
    public async Task UdpDirect_RoundTrip_ShouldEcho()
    {
        await using var ssServer = new MockShadowsocksUdpServer(0, "test-password");
        ssServer.Start();

        var localPort = GetAvailablePort();
        var serverConfig = new SsServerConfig
        {
            Host = "127.0.0.1",
            Port = ssServer.Port,
            Password = "test-password",
            Method = "aes-256-gcm",
            LocalPort = localPort,
            Timeout = 30
        };

        await using var proxyHost = new TestUdpProxyHost(serverConfig, localPort);
        await proxyHost.StartAsync();
        await Task.Delay(100);

        await using var client = new Socks5UdpClient();
        await client.ConnectAsync("127.0.0.1", localPort);

        var payload = Encoding.ASCII.GetBytes("udp-echo");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var response = await client.SendAndReceiveAsync(
            "8.8.8.8",
            53,
            payload,
            fragment: false,
            fragmentSize: 0,
            ct: cts.Token);

        Assert.Equal(payload, response);
    }

    [Fact]
    public async Task UdpDirect_Fragmented_ShouldReassemble()
    {
        await using var ssServer = new MockShadowsocksUdpServer(0, "test-password");
        ssServer.Start();

        var localPort = GetAvailablePort();
        var serverConfig = new SsServerConfig
        {
            Host = "127.0.0.1",
            Port = ssServer.Port,
            Password = "test-password",
            Method = "aes-256-gcm",
            LocalPort = localPort,
            Timeout = 30
        };

        await using var proxyHost = new TestUdpProxyHost(serverConfig, localPort);
        await proxyHost.StartAsync();
        await Task.Delay(100);

        await using var client = new Socks5UdpClient();
        await client.ConnectAsync("127.0.0.1", localPort);

        var payload = new byte[4096];
        for (var i = 0; i < payload.Length; i++)
            payload[i] = (byte)(i % 251);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var response = await client.SendAndReceiveAsync(
            "1.1.1.1",
            5353,
            payload,
            fragment: true,
            fragmentSize: 512,
            ct: cts.Token);

        Assert.Equal(payload, response);
    }

    [Fact]
    public async Task UdpViaSocks5Proxy_ShouldEcho()
    {
        await using var ssServer = new MockShadowsocksUdpServer(0, "test-password");
        ssServer.Start();

        var proxyPort = GetAvailablePort();
        await using var forwardProxy = new MockSocks5ProxyServer(proxyPort);
        forwardProxy.Start();

        var localPort = GetAvailablePort();
        var serverConfig = new SsServerConfig
        {
            Host = "127.0.0.1",
            Port = ssServer.Port,
            Password = "test-password",
            Method = "aes-256-gcm",
            LocalPort = localPort,
            Timeout = 30
        };

        var forwardProxyConfig = new ForwardProxyConfig
        {
            Enabled = true,
            Type = ForwardProxyType.Socks5,
            Host = "127.0.0.1",
            Port = proxyPort,
            TimeoutSeconds = 5
        };

        await using var proxyHost = new TestUdpProxyHost(serverConfig, localPort, forwardProxyConfig);
        await proxyHost.StartAsync();
        await Task.Delay(100);

        await using var client = new Socks5UdpClient();
        await client.ConnectAsync("127.0.0.1", localPort);

        var payload = Encoding.ASCII.GetBytes("udp-proxy");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var response = await client.SendAndReceiveAsync(
            "9.9.9.9",
            53,
            payload,
            fragment: false,
            fragmentSize: 0,
            ct: cts.Token);

        Assert.Equal(payload, response);
    }

    [Fact]
    public async Task UdpViaPlugin_ShouldEcho()
    {
        await using var ssServer = new MockShadowsocksUdpServer(0, "test-password");
        ssServer.Start();

        var localPort = GetAvailablePort();
        var (pluginPath, pluginArgs) = GetPluginCommand();
        var serverConfig = new SsServerConfig
        {
            Host = "127.0.0.1",
            Port = ssServer.Port,
            Password = "test-password",
            Method = "aes-256-gcm",
            LocalPort = localPort,
            Timeout = 30,
            Plugin = pluginPath,
            PluginArgs = pluginArgs
        };

        await using var proxyHost = new TestUdpProxyHost(serverConfig, localPort);
        await proxyHost.StartAsync();
        await Task.Delay(200);

        await using var client = new Socks5UdpClient();
        await client.ConnectAsync("127.0.0.1", localPort);

        var payload = Encoding.ASCII.GetBytes("udp-plugin");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var response = await client.SendAndReceiveAsync(
            "4.4.4.4",
            123,
            payload,
            fragment: false,
            fragmentSize: 0,
            ct: cts.Token);

        Assert.Equal(payload, response);
    }

    private static int GetAvailablePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static (string pluginPath, string pluginArgs) GetPluginCommand()
    {
        var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        var dllPath = Path.Combine(root, "tools", "Sip003UdpPlugin", "bin", "Debug", "net10.0", "Sip003UdpPlugin.dll");
        if (File.Exists(dllPath))
            return ("dotnet", $"\"{dllPath}\"");

        var exePath = Path.Combine(root, "tools", "Sip003UdpPlugin", "bin", "Debug", "net10.0", "Sip003UdpPlugin.exe");
        if (File.Exists(exePath))
            return (exePath, string.Empty);

        throw new FileNotFoundException("SIP003 test plugin not found.", exePath);
    }
}
