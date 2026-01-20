using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShadowsocksSharp.Core.Configuration;

/// <summary>
/// Shadowsocks 服务器配置
/// </summary>
public class SsServerConfig
{
    /// <summary>服务器地址</summary>
    [JsonPropertyName("Server")]
    public string Host { get; set; } = "127.0.0.1";

    /// <summary>服务器端口</summary>
    [JsonPropertyName("ServerPort")]
    public int Port { get; set; } = 8388;

    /// <summary>密码</summary>
    [JsonPropertyName("Password")]
    public string Password { get; set; } = string.Empty;

    /// <summary>加密方法</summary>
    [JsonPropertyName("Method")]
    public string Method { get; set; } = "aes-256-gcm";

    /// <summary>本地代理端口</summary>
    [JsonPropertyName("LocalPort")]
    public int LocalPort { get; set; } = 1080;

    /// <summary>连接超时（秒）</summary>
    [JsonPropertyName("Timeout")]
    public int Timeout { get; set; } = 300;

    /// <summary>是否启用</summary>
    [JsonPropertyName("Enable")]
    public bool Enabled { get; set; } = true;

    /// <summary>备注名称</summary>
    [JsonPropertyName("Remarks")]
    public string Name { get; set; } = string.Empty;

    /// <summary>插件路径 (SIP003)</summary>
    [JsonPropertyName("Plugin")]
    public string Plugin { get; set; } = string.Empty;

    /// <summary>插件参数 (SIP003)</summary>
    [JsonPropertyName("PluginOpts")]
    public string PluginOptions { get; set; } = string.Empty;

    /// <summary>插件额外参数 (SIP003)</summary>
    [JsonPropertyName("PluginArgs")]
    public string PluginArgs { get; set; } = string.Empty;

    /// <summary>订阅分组标识</summary>
    [JsonPropertyName("Group")]
    public string Group { get; set; } = string.Empty;

    /// <summary>TCP 发送缓冲大小（字节，0 表示使用默认）</summary>
    [JsonPropertyName("SocketSendBuffer")]
    public int SocketSendBuffer { get; set; } = 16384;

    /// <summary>TCP 接收缓冲大小（字节，0 表示使用默认）</summary>
    [JsonPropertyName("SocketReceiveBuffer")]
    public int SocketReceiveBuffer { get; set; } = 16384;

    /// <summary>SS 连接池最大连接数（0 表示使用默认）</summary>
    [JsonPropertyName("ConnectionPoolSize")]
    public int ConnectionPoolSize { get; set; } = 200;

    /// <summary>预热连接池大小（0 表示自动计算）</summary>
    [JsonPropertyName("WarmPoolSize")]
    public int WarmPoolSize { get; set; } = 0;

    /// <summary>首包超时（秒）</summary>
    [JsonPropertyName("FirstPacketTimeoutSeconds")]
    public int FirstPacketTimeoutSeconds { get; set; } = 30;

    /// <summary>中继最小缓冲大小（字节）</summary>
    [JsonPropertyName("RelayMinBufferSize")]
    public int RelayMinBufferSize { get; set; } = 8192;

    /// <summary>中继最大缓冲大小（字节）</summary>
    [JsonPropertyName("RelayMaxBufferSize")]
    public int RelayMaxBufferSize { get; set; } = 65536;

    /// <summary>每秒新建连接上限（0 表示无限制）</summary>
    [JsonPropertyName("MaxConnectionsPerSecond")]
    public int MaxConnectionsPerSecond { get; set; } = 0;

    // 代码兼容属性
    [JsonIgnore] public string Server { get => Host; set => Host = value; }
    [JsonIgnore] public int ServerPort { get => Port; set => Port = value; }
    [JsonIgnore] public bool Enable { get => Enabled; set => Enabled = value; }
    [JsonIgnore] public string Remarks { get => Name; set => Name = value; }
}

/// <summary>
/// 应用程序配置
/// </summary>
public class Config
{
    /// <summary>服务器列表</summary>
    [JsonPropertyName("Configs")]
    public List<SsServerConfig> Servers { get; set; } = [];

    /// <summary>当前选中的服务器索引</summary>
    [JsonPropertyName("Index")]
    public int CurrentIndex { get; set; }

    /// <summary>是否启用全局代理</summary>
    [JsonPropertyName("Global")]
    public bool GlobalProxy { get; set; } = true;

    /// <summary>策略选择器 ID</summary>
    [JsonPropertyName("Strategy")]
    public string Strategy { get; set; } = string.Empty;

    /// <summary>是否允许局域网访问</summary>
    [JsonPropertyName("ShareOverLan")]
    public bool ShareOverLan { get; set; }

    /// <summary>是否启用 IPv6 监听</summary>
    [JsonPropertyName("EnableIPv6")]
    public bool EnableIPv6 { get; set; }

    /// <summary>是否启用代理</summary>
    [JsonPropertyName("Enabled")]
    public bool Enabled { get; set; } = true;

    /// <summary>本地代理端口</summary>
    [JsonPropertyName("LocalPort")]
    public int LocalPort { get; set; } = 1080;

    /// <summary>TCP 监听 backlog</summary>
    [JsonPropertyName("TcpListenBacklog")]
    public int TcpListenBacklog { get; set; } = 1024;

    /// <summary>是否自动设置系统代理</summary>
    [JsonPropertyName("AutoSetSystemProxy")]
    public bool AutoSetSystemProxy { get; set; } = true;

    /// <summary>是否使用在线 PAC</summary>
    [JsonPropertyName("UseOnlinePac")]
    public bool UseOnlinePac { get; set; }

    /// <summary>在线 PAC 地址</summary>
    [JsonPropertyName("PacUrl")]
    public string PacUrl { get; set; } = string.Empty;

    /// <summary>是否启用本地 PAC 的 secret 校验</summary>
    [JsonPropertyName("SecureLocalPac")]
    public bool SecureLocalPac { get; set; } = true;

    /// <summary>更新时是否重新生成 PAC</summary>
    [JsonPropertyName("RegeneratePacOnUpdate")]
    public bool RegeneratePacOnUpdate { get; set; } = true;

    /// <summary>代理绕过列表</summary>
    [JsonPropertyName("ProxyBypass")]
    public string BypassList { get; set; } = "localhost;127.*;10.*;192.168.*";

    /// <summary>不对本地地址使用代理</summary>
    [JsonPropertyName("BypassLocal")]
    public bool BypassLocal { get; set; } = true;

    /// <summary>GeoSite 直连分组</summary>
    [JsonPropertyName("GeositeDirectGroups")]
    public List<string> GeositeDirectGroups { get; set; } =
        ["private", "cn", "geolocation-!cn@cn"];

    /// <summary>GeoSite 代理分组</summary>
    [JsonPropertyName("GeositeProxiedGroups")]
    public List<string> GeositeProxiedGroups { get; set; } =
        ["geolocation-!cn"];

    /// <summary>GeoSite 优先直连 (黑名单模式)</summary>
    [JsonPropertyName("GeositePreferDirect")]
    public bool GeositePreferDirect { get; set; }

    /// <summary>自定义 GeoSite 数据源</summary>
    [JsonPropertyName("GeositeUrl")]
    public string GeositeUrl { get; set; } =
        "https://github.com/v2fly/domain-list-community/raw/release/dlc.dat";

    /// <summary>GeoSite 校验地址</summary>
    [JsonPropertyName("GeositeSha256Url")]
    public string GeositeSha256Url { get; set; } =
        "https://github.com/v2fly/domain-list-community/raw/release/dlc.dat.sha256sum";

    /// <summary>订阅源列表 (SIP008)</summary>
    [JsonPropertyName("OnlineConfigSource")]
    public List<string> OnlineConfigSource { get; set; } = [];

    /// <summary>前置代理配置</summary>
    [JsonPropertyName("ForwardProxy")]
    public ForwardProxyConfig ForwardProxy { get; set; } = new();

    /// <summary>是否启用性能指标采样</summary>
    [JsonPropertyName("EnablePerformanceMetrics")]
    public bool EnablePerformanceMetrics { get; set; } = false;

    /// <summary>性能指标输出间隔（秒）</summary>
    [JsonPropertyName("MetricsIntervalSeconds")]
    public int MetricsIntervalSeconds { get; set; } = 60;

    /// <summary>UDP 会话超时（秒）</summary>
    [JsonPropertyName("UdpSessionTimeoutSeconds")]
    public int UdpSessionTimeoutSeconds { get; set; } = 300;

    /// <summary>UDP 会话上限（0 表示不限制）</summary>
    [JsonPropertyName("MaxUdpSessions")]
    public int MaxUdpSessions { get; set; } = 1024;

    /// <summary>
    /// 获取当前选中的服务器配置
    /// </summary>
    [JsonIgnore]
    public SsServerConfig? CurrentServer =>
        CurrentIndex >= 0 && CurrentIndex < Servers.Count ? Servers[CurrentIndex] : null;

    // 代码兼容属性
    [JsonIgnore] public List<SsServerConfig> Configs { get => Servers; set => Servers = value; }
    [JsonIgnore] public int Index { get => CurrentIndex; set => CurrentIndex = value; }
    [JsonIgnore] public bool Global { get => GlobalProxy; set => GlobalProxy = value; }
}
