using System.Text.Json.Serialization;

namespace ShadowsocksSharp.Core.Configuration;

public enum ForwardProxyType
{
    Socks5 = 0,
    Http = 1
}

/// <summary>
/// 前置代理配置
/// </summary>
public sealed class ForwardProxyConfig
{
    [JsonPropertyName("Enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("Type")]
    public ForwardProxyType Type { get; set; } = ForwardProxyType.Socks5;

    [JsonPropertyName("Host")]
    public string Host { get; set; } = string.Empty;

    [JsonPropertyName("Port")]
    public int Port { get; set; }

    [JsonPropertyName("TimeoutSeconds")]
    public int TimeoutSeconds { get; set; } = 5;

    [JsonPropertyName("UseAuth")]
    public bool UseAuth { get; set; }

    [JsonPropertyName("Username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("Password")]
    public string Password { get; set; } = string.Empty;
}
