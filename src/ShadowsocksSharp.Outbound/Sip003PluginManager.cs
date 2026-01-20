using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Diagnostics;

namespace ShadowsocksSharp.Outbound;

/// <summary>
/// 管理 SIP003 插件进程（按服务器与插件参数组合缓存实例）。
/// </summary>
public sealed class Sip003PluginManager : IDisposable
{
    private readonly ConcurrentDictionary<string, Sip003PluginInstance> _instances =
        new(StringComparer.OrdinalIgnoreCase);

    public Sip003PluginInstance GetOrCreate(SsServerConfig server)
    {
        var key = $"{server.Plugin}|{server.PluginOptions}|{server.PluginArgs}|{server.Host}:{server.Port}";
        return _instances.GetOrAdd(key, _ => new Sip003PluginInstance(server));
    }

    public void Dispose()
    {
        foreach (var instance in _instances.Values)
        {
            instance.Dispose();
        }
        _instances.Clear();
    }
}

/// <summary>
/// 单个 SIP003 插件进程及其本地监听端点。
/// </summary>
public sealed class Sip003PluginInstance : IDisposable
{
    private readonly SsServerConfig _server;
    private readonly object _lock = new();
    private Process? _process;
    private bool _disposed;

    public IPEndPoint LocalEndPoint { get; private set; } = new(IPAddress.Loopback, 0);

    public Sip003PluginInstance(SsServerConfig server)
    {
        _server = server;
    }

    public void EnsureRunning()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(Sip003PluginInstance));

        lock (_lock)
        {
            if (_process is { HasExited: false })
                return;

            // 为插件绑定一个空闲本地端口，并暴露给上游连接器。
            LocalEndPoint = new IPEndPoint(IPAddress.Loopback, GetFreePort());

            var startInfo = new ProcessStartInfo
            {
                FileName = _server.Plugin,
                Arguments = _server.PluginArgs,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false,
                WorkingDirectory = Environment.CurrentDirectory
            };

            // SIP003 环境变量：描述远端服务器与本地绑定信息。
            startInfo.Environment["SS_REMOTE_HOST"] = _server.Host;
            startInfo.Environment["SS_REMOTE_PORT"] = _server.Port.ToString();
            startInfo.Environment["SS_LOCAL_HOST"] = LocalEndPoint.Address.ToString();
            startInfo.Environment["SS_LOCAL_PORT"] = LocalEndPoint.Port.ToString();
            startInfo.Environment["SS_PLUGIN_OPTIONS"] = _server.PluginOptions ?? string.Empty;

            _process = new Process { StartInfo = startInfo };
            _process.Start();

            Log.I($"SIP003 plugin started: {_server.Plugin} -> {LocalEndPoint}");
        }
    }

    private static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            if (_process is { HasExited: false })
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit();
            }
        }
        catch { }
        finally
        {
            _process?.Dispose();
            _process = null;
        }
    }
}
