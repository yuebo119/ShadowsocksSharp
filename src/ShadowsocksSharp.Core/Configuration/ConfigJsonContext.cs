using System.Text.Json.Serialization;

namespace ShadowsocksSharp.Core.Configuration;

/// <summary>
/// System.Text.Json 源生成上下文（用于避免 AOT/Trim 场景下反射序列化不可用）
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNameCaseInsensitive = true,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(Config))]
[JsonSerializable(typeof(SsServerConfig))]
[JsonSerializable(typeof(ForwardProxyConfig))]
internal partial class ConfigJsonContext : JsonSerializerContext
{
}
