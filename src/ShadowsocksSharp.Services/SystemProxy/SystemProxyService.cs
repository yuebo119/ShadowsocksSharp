using Microsoft.Extensions.Hosting;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Diagnostics;
using ShadowsocksSharp.Services.Pac;

namespace ShadowsocksSharp.Services.SystemProxy;

[SupportedOSPlatform("windows")]
public sealed class SystemProxyService : IHostedService
{
    private const string RegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    private const int INTERNET_OPTION_REFRESH = 37;

    private static SystemProxyService? _current;
    private static readonly EventHandler ProcessExitHandler = (_, _) => _current?.HandleExit();
    private static readonly ConsoleCancelEventHandler CancelHandler = (_, _) => _current?.HandleExit();
    private static readonly ConsoleCtrlHandler ConsoleHandler = _ =>
    {
        _current?.HandleExit();
        return false;
    };

    private readonly Config _config;
    private readonly PacService _pac;
    private bool _enabled;
    private bool _exitHooked;

    public SystemProxyService(Config config, PacService pac)
    {
        _config = config;
        _pac = pac;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_config.AutoSetSystemProxy || !_config.Enabled)
            return Task.CompletedTask;

        if (!OperatingSystem.IsWindows())
        {
            Log.W("System proxy is only supported on Windows.");
            return Task.CompletedTask;
        }

        var bypassList = BuildBypassList(_config.BypassList, _config.BypassLocal);

        if (_config.GlobalProxy)
        {
            _enabled = ApplyProxy($"127.0.0.1:{_config.LocalPort}", null, bypassList);
        }
        else
        {
            // PAC 模式：支持本地 PAC 或在线 PAC（UseOnlinePac + PacUrl）。
            var pacUrl = _config.UseOnlinePac && !string.IsNullOrWhiteSpace(_config.PacUrl)
                ? _config.PacUrl
                : _pac.GetPacUrl("127.0.0.1", _config.LocalPort);
            _enabled = ApplyProxy(null, pacUrl, bypassList);
        }

        ToggleExitHandlers(_enabled);
        Log.I($"System proxy set: {_enabled}");
        return Task.CompletedTask;

        static string BuildBypassList(string rawBypass, bool bypassLocal)
        {
            if (string.IsNullOrWhiteSpace(rawBypass))
                return bypassLocal ? "<local>" : string.Empty;

            var tokens = rawBypass
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();

            tokens.RemoveAll(t => t.Equals("<local>", StringComparison.OrdinalIgnoreCase));
            if (bypassLocal)
                tokens.Add("<local>");

            return string.Join(';', tokens);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        HandleExit();
        ToggleExitHandlers(enable: false);
        return Task.CompletedTask;
    }

    private void HandleExit()
    {
        if (!_enabled || !_config.AutoSetSystemProxy || !OperatingSystem.IsWindows())
            return;

        ApplyProxy(null, null, null);
        _enabled = false;
    }

    private void ToggleExitHandlers(bool enable)
    {
        if (enable)
        {
            if (_exitHooked)
                return;
            _current = this;
            AppDomain.CurrentDomain.ProcessExit += ProcessExitHandler;
            Console.CancelKeyPress += CancelHandler;
            if (OperatingSystem.IsWindows())
                SetConsoleCtrlHandler(ConsoleHandler, add: true);
            _exitHooked = true;
            return;
        }

        if (!_exitHooked)
            return;

        AppDomain.CurrentDomain.ProcessExit -= ProcessExitHandler;
        Console.CancelKeyPress -= CancelHandler;
        if (OperatingSystem.IsWindows())
            SetConsoleCtrlHandler(ConsoleHandler, add: false);
        _current = null;
        _exitHooked = false;
    }

    private delegate bool ConsoleCtrlHandler(CtrlType sig);

    private enum CtrlType : uint
    {
        CtrlCEvent = 0,
        CtrlBreakEvent = 1,
        CtrlCloseEvent = 2,
        CtrlLogoffEvent = 5,
        CtrlShutdownEvent = 6
    }

    private bool ApplyProxy(string? proxyServer, string? pacUrl, string? proxyBypass)
    {
        try
        {
            using var registry = Registry.CurrentUser.OpenSubKey(RegistryPath, true);
            if (registry == null)
            {
                Log.E("Failed to open proxy registry key");
                return false;
            }

            if (!string.IsNullOrEmpty(pacUrl))
            {
                registry.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                registry.SetValue("ProxyServer", "", RegistryValueKind.String);
                registry.SetValue("AutoConfigURL", pacUrl, RegistryValueKind.String);
            }
            else if (!string.IsNullOrEmpty(proxyServer))
            {
                registry.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                registry.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
                registry.SetValue("AutoConfigURL", "", RegistryValueKind.String);
            }
            else
            {
                registry.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            }

            if (proxyBypass != null)
                registry.SetValue("ProxyOverride", proxyBypass, RegistryValueKind.String);

            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
            return true;
        }
        catch (Exception ex)
        {
            Log.E($"Failed to set system proxy: {ex.Message}");
            return false;
        }
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    [DllImport("Kernel32")]
    private static extern bool SetConsoleCtrlHandler(ConsoleCtrlHandler handler, bool add);
}
