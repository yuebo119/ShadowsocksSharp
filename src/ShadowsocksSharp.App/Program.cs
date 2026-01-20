using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Net;
using System.Net.Sockets;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Core.Strategy;
using ShadowsocksSharp.Core.Utilities;
using ShadowsocksSharp.Diagnostics;
using ShadowsocksSharp.Outbound;
using ShadowsocksSharp.Services.Pac;
using ShadowsocksSharp.Services.Subscription;
using ShadowsocksSharp.Services.SystemProxy;
using ShadowsocksSharp.Services.Tcp;
using ShadowsocksSharp.Services.Udp;
using ShadowsocksSharp.Shadowsocks;
using ShadowsocksSharp.Shadowsocks.Encryption;

namespace ShadowsocksSharp.App;

internal sealed class CommandLineArgs
{
    public bool Help { get; init; }
    public bool TestProxy { get; init; }
    public bool TestSs { get; init; }
    public bool Quiet { get; init; }
    public bool Verbose { get; init; }
    public bool UpdateSubscriptions { get; init; }
    public int ServerIndex { get; init; } = -1;
    public int Port { get; init; } = 1080;
    public string? Url { get; init; }
    public string? ImportUrl { get; init; }

    public static CommandLineArgs Parse(string[] args)
    {
        var help = args.Contains("--help") || args.Contains("-h");
        var test = args.Contains("--test") || args.Contains("-t");
        var testSs = args.Contains("--test-ss");
        var quiet = args.Contains("--quiet") || args.Contains("-q");
        var verbose = args.Contains("--verbose") || args.Contains("-v");
        var updateSubs = args.Contains("--update-subscriptions");

        var serverIndex = -1;
        var port = 1080;
        string? url = null;
        string? importUrl = null;

        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "--server" or "-s" && i + 1 < args.Length)
                int.TryParse(args[i + 1], out serverIndex);
            if (args[i] is "--port" or "-p" && i + 1 < args.Length)
                int.TryParse(args[i + 1], out port);
            if (args[i] is "--url" or "-u" && i + 1 < args.Length)
                url = args[i + 1];
            if (args[i] is "--import" or "--open-url" && i + 1 < args.Length)
                importUrl = args[i + 1];
        }

        return new CommandLineArgs
        {
            Help = help,
            TestProxy = test,
            TestSs = testSs,
            Quiet = quiet,
            Verbose = verbose,
            UpdateSubscriptions = updateSubs,
            ServerIndex = serverIndex,
            Port = port,
            Url = url,
            ImportUrl = importUrl
        };
    }
}

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var cmd = CommandLineArgs.Parse(args);
        Log.Initialize(logDirectory: "logs", consoleEnabled: !cmd.Quiet, fileEnabled: true);
        Log.MinLevel = cmd.Verbose ? LogLevel.Debug : LogLevel.Info;

        try
        {
            if (cmd.Help) return ShowHelp();

            var configManager = new ConfigManager();
            var config = configManager.LoadConfig();

            if (cmd.ServerIndex >= 0)
                config.CurrentIndex = cmd.ServerIndex;

            if (!string.IsNullOrWhiteSpace(cmd.ImportUrl))
            {
                var servers = SsUrlParser.Parse(cmd.ImportUrl);
                if (servers.Count > 0)
                {
                    config.Servers.AddRange(servers);
                    config.CurrentIndex = config.Servers.Count - 1;
                    configManager.SaveConfig(config);
                    Log.I($"Imported {servers.Count} server(s).");
                }
            }

            if (cmd.UpdateSubscriptions)
            {
                await UpdateSubscriptionsAsync(configManager, config).ConfigureAwait(false);
                return 0;
            }

            if (cmd.TestSs) return await TestSsServerAsync(config).ConfigureAwait(false);
            if (cmd.TestProxy) return await TestProxyAsync(cmd.Port, cmd.Url).ConfigureAwait(false);

            if (config.EnablePerformanceMetrics)
                PerfMetrics.Initialize(true, TimeSpan.FromSeconds(config.MetricsIntervalSeconds));

            using var host = BuildHost(configManager, config);
            await host.RunAsync().ConfigureAwait(false);
            return 0;
        }
        finally
        {
            PerfMetrics.Shutdown();
            Log.Flush();
        }
    }

    private static IHost BuildHost(ConfigManager configManager, Config config)
    {
        var selector = ServerSelectorFactory.Create(config);
        var pluginManager = new Sip003PluginManager();
        var connector = new ConnectorPipeline(pluginManager);
        var pac = new PacService(config, Path.GetDirectoryName(configManager.ConfigPath)!);

        GeositeUpdater.Load(Path.Combine(AppContext.BaseDirectory, "Geosite", "dlc.dat"));

        return Host.CreateDefaultBuilder()
            .ConfigureServices(services =>
            {
                services.AddSingleton(config);
                services.AddSingleton(configManager);
                services.AddSingleton(selector);
                services.AddSingleton(pluginManager);
                services.AddSingleton<IOutboundConnector>(connector);
                services.AddSingleton(pac);
                services.AddSingleton<IHostedService>(sp => sp.GetRequiredService<PacService>());
                services.AddHostedService<TcpProxyService>();
                services.AddHostedService<UdpRelayService>();
                if (OperatingSystem.IsWindows())
                    services.AddHostedService<SystemProxyService>();
            })
            .Build();
    }

    private static async Task UpdateSubscriptionsAsync(ConfigManager configManager, Config config)
    {
        if (config.OnlineConfigSource.Count == 0)
        {
            Log.W("No subscription sources configured.");
            return;
        }

        using var httpClient = new HttpClient();
        var subscription = new SubscriptionService(httpClient);

        var merged = new List<SsServerConfig>();
        foreach (var source in config.OnlineConfigSource)
        {
            try
            {
                var servers = await subscription.GetServersAsync(source, CancellationToken.None).ConfigureAwait(false);
                foreach (var server in servers)
                {
                    server.Group = source;
                    merged.Add(server);
                }
            }
            catch (Exception ex)
            {
                Log.W($"Subscription failed: {source} ({ex.Message})");
            }
        }

        if (merged.Count > 0)
        {
            config.Servers.RemoveAll(s => !string.IsNullOrWhiteSpace(s.Group));
            config.Servers.AddRange(merged);
            configManager.SaveConfig(config);
            Log.I($"Updated subscriptions: {merged.Count} server(s).");
        }
    }

    private static int ShowHelp()
    {
        Console.WriteLine("""
            ShadowsocksSharp (Modern)

            Usage: ShadowsocksSharp.exe [options]

            Options:
              -h, --help                 Show help
              -s, --server N             Select server by index
              -t, --test                 Test local proxy
              --test-ss                  Test SS server directly
              -p, --port N               Test port (default: 1080)
              -u, --url URL              Test URL
              --import URL               Import ss:// link
              --update-subscriptions     Update SIP008 sources
              -q, --quiet                Disable console log
              -v, --verbose              Enable debug log

            Config: %APPDATA%\\ShadowsocksSharp\\config.json
            """);
        return 0;
    }

    private static async Task<int> TestProxyAsync(int port, string? url)
    {
        Console.WriteLine("Proxy Test\n");

        url ??= "https://httpbin.org/ip";
        Console.WriteLine($"Proxy: 127.0.0.1:{port}");
        Console.WriteLine($"URL:   {url}\n");

        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy($"http://127.0.0.1:{port}"),
            UseProxy = true
        };

        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

        try
        {
            Console.WriteLine("1. HTTP proxy...");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await http.GetAsync(url);
            Console.WriteLine($"   ✅ {resp.StatusCode} ({sw.ElapsedMilliseconds}ms)");
            Console.WriteLine($"   {await resp.Content.ReadAsStringAsync()}\n");

            Console.WriteLine("2. HTTPS tunnel...");
            sw.Restart();
            resp = await http.GetAsync("https://api.ipify.org?format=json");
            Console.WriteLine($"   ✅ {resp.StatusCode} ({sw.ElapsedMilliseconds}ms)");
            Console.WriteLine($"   {await resp.Content.ReadAsStringAsync()}\n");

            Console.WriteLine("All tests passed! ✅");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> TestSsServerAsync(Config config)
    {
        Console.WriteLine("SS Server Test\n");

        if (config.Servers.Count == 0)
        {
            Console.WriteLine("Error: No server configured.");
            return 1;
        }

        var server = config.Servers[Math.Clamp(config.CurrentIndex, 0, config.Servers.Count - 1)];
        Console.WriteLine($"Server:   {server.Host}:{server.Port}");
        Console.WriteLine($"Cipher:   {server.Method}");
        Console.WriteLine($"Password: {server.Password[..Math.Min(4, server.Password.Length)]}****\n");

        using var tcp = new TcpClient();
        try
        {
            var task = tcp.ConnectAsync(server.Host, server.Port);
            if (await Task.WhenAny(task, Task.Delay(5000)) != task)
            {
                Console.WriteLine("   ❌ Timeout");
                return 1;
            }
            await task;
            Console.WriteLine("   ✅ Connected");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ {ex.Message}");
            return 1;
        }

        var stream = tcp.GetStream();
        var enc = EncryptorFactory.Create(server.Method, server.Password);

        Span<byte> addr = stackalloc byte[260];
        var addrLen = ShadowsocksAddress.WriteAddress("httpbin.org", 80, addr);
        var buf = new byte[2048];
        enc.Encrypt(addr.Slice(0, addrLen), buf, out var len);
        await stream.WriteAsync(buf.AsMemory(0, len));

        var http = "GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"u8.ToArray();
        enc.Encrypt(http, http.Length, buf, out len);
        await stream.WriteAsync(buf.AsMemory(0, len));

        Console.WriteLine("Sent request, waiting response...");
        var respBuf = new byte[8192];
        var decBuf = new byte[8192];
        stream.ReadTimeout = 10000;

        try
        {
            var n = await stream.ReadAsync(respBuf);
            if (n > 0)
            {
                var dec = EncryptorFactory.Create(server.Method, server.Password);
                dec.Decrypt(respBuf, n, decBuf, out var decLen);
                Console.WriteLine($"   ✅ Received {decLen}B");
            }
            else
            {
                Console.WriteLine("   ❌ No response");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ {ex.Message}");
        }

        enc.Dispose();
        Console.WriteLine("Test completed.");
        return 0;
    }
}
