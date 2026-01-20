using ShadowsocksSharp.Diagnostics;
using ShadowsocksSharp.Shadowsocks.Encryption;
using System.Text.Json;

namespace ShadowsocksSharp.Core.Configuration;

/// <summary>
/// 配置管理器
/// 负责加载、验证和保存应用程序配置
/// </summary>
public sealed class ConfigManager
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        TypeInfoResolver = ConfigJsonContext.Default
    };

    private readonly string _configPath;

    /// <summary>
    /// 配置文件路径
    /// </summary>
    public string ConfigPath => _configPath;

    public ConfigManager()
    {
        // 优先从当前目录加载，否则从 AppData 加载
        var localPath = Path.Combine(Environment.CurrentDirectory, "config.json");
        if (File.Exists(localPath))
        {
            _configPath = localPath;
        }
        else
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "ShadowsocksSharp");
            Directory.CreateDirectory(appDataPath);
            _configPath = Path.Combine(appDataPath, "config.json");
        }
    }

    /// <summary>
    /// 加载配置文件
    /// </summary>
    /// <returns>配置对象，文件不存在或解析失败返回空配置</returns>
    public Config LoadConfig()
    {
        if (!File.Exists(_configPath))
        {
            Log.W($"Config not found: {_configPath}");
            return new Config();
        }

        try
        {
            Log.D($"Loading config: {_configPath}");
            var json = File.ReadAllText(_configPath);
            var config = JsonSerializer.Deserialize(json, ConfigJsonContext.Default.Config) ?? new Config();

            ValidateConfig(config);
            Log.I($"Config loaded: {config.Servers.Count} server(s)");
            return config;
        }
        catch (JsonException ex)
        {
            Log.E($"Config parse error: {ex.Message}");
            return new Config();
        }
        catch (Exception ex)
        {
            Log.E($"Config load failed: {ex.Message}");
            return new Config();
        }
    }

    /// <summary>
    /// 保存配置到文件
    /// </summary>
    public bool SaveConfig(Config config)
    {
        try
        {
            var json = JsonSerializer.Serialize(config, ConfigJsonContext.Default.Config);
            File.WriteAllText(_configPath, json);
            Log.I("Config saved");
            return true;
        }
        catch (Exception ex)
        {
            Log.E($"Config save failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 验证配置有效性
    /// </summary>
    private static void ValidateConfig(Config config)
    {
        // 验证索引范围
        if (config.CurrentIndex < 0 || config.CurrentIndex >= config.Servers.Count)
        {
            config.CurrentIndex = config.Servers.Count > 0 ? 0 : -1;
        }

        // 验证端口范围
        if (config.LocalPort <= 0 || config.LocalPort > 65535)
        {
            config.LocalPort = 1080;
        }

        if (config.TcpListenBacklog <= 0)
        {
            config.TcpListenBacklog = 1024;
        }

        if (config.MetricsIntervalSeconds <= 0)
        {
            config.MetricsIntervalSeconds = 60;
        }

        if (config.UdpSessionTimeoutSeconds <= 0)
        {
            config.UdpSessionTimeoutSeconds = 300;
        }

        if (config.MaxUdpSessions < 0)
        {
            config.MaxUdpSessions = 0;
        }

        if (config.ForwardProxy.TimeoutSeconds <= 0)
            config.ForwardProxy.TimeoutSeconds = 5;

        if (config.UseOnlinePac && string.IsNullOrWhiteSpace(config.PacUrl))
        {
            Log.W("UseOnlinePac is enabled but PacUrl is empty; fallback to local PAC.");
            config.UseOnlinePac = false;
        }

        // 验证服务器配置
        foreach (var server in config.Servers)
        {
            ValidateServer(server);
        }
    }

    /// <summary>
    /// 验证服务器配置
    /// </summary>
    private static void ValidateServer(SsServerConfig server)
    {
        // 验证端口
        if (server.Port <= 0 || server.Port > 65535)
        {
            Log.W($"Invalid port {server.Port}, using 8388");
            server.Port = 8388;
        }

        // 验证超时
        if (server.Timeout <= 0)
        {
            server.Timeout = 300;
        }

        // 验证加密方法
        if (!EncryptorFactory.IsSupported(server.Method))
        {
            Log.W($"Unsupported cipher: {server.Method}");
        }

        if (server.SocketReceiveBuffer < 0) server.SocketReceiveBuffer = 0;
        if (server.SocketSendBuffer < 0) server.SocketSendBuffer = 0;
        if (server.ConnectionPoolSize <= 0) server.ConnectionPoolSize = 200;
        if (server.WarmPoolSize < 0) server.WarmPoolSize = 0;
        if (server.FirstPacketTimeoutSeconds <= 0) server.FirstPacketTimeoutSeconds = 30;
        if (server.RelayMinBufferSize <= 0) server.RelayMinBufferSize = 8192;
        if (server.RelayMaxBufferSize < server.RelayMinBufferSize)
            server.RelayMaxBufferSize = server.RelayMinBufferSize;
        if (server.MaxConnectionsPerSecond < 0) server.MaxConnectionsPerSecond = 0;
    }
}
