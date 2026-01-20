using System.Text.Json;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Core.Utilities;
using ShadowsocksSharp.Diagnostics;

namespace ShadowsocksSharp.Services.Subscription;

public sealed class SubscriptionService
{
    private readonly HttpClient _httpClient;

    public SubscriptionService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<List<SsServerConfig>> GetServersAsync(string url, CancellationToken ct)
    {
        var content = await _httpClient.GetStringAsync(url, ct).ConfigureAwait(false);
        if (content.Contains("ss://", StringComparison.OrdinalIgnoreCase))
        {
            return SsUrlParser.Parse(content);
        }

        try
        {
            using var doc = JsonDocument.Parse(content);
            return ExtractServers(doc.RootElement).ToList();
        }
        catch (JsonException ex)
        {
            Log.W($"Subscription JSON parse failed: {ex.Message}");
            return [];
        }
    }

    private static IEnumerable<SsServerConfig> ExtractServers(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            if (element.TryGetProperty("server", out _)
                && element.TryGetProperty("server_port", out _)
                && element.TryGetProperty("password", out _)
                && element.TryGetProperty("method", out _))
            {
                yield return new SsServerConfig
                {
                    Host = element.GetProperty("server").GetString() ?? string.Empty,
                    Port = element.GetProperty("server_port").GetInt32(),
                    Password = element.GetProperty("password").GetString() ?? string.Empty,
                    Method = element.GetProperty("method").GetString() ?? string.Empty,
                    Name = element.TryGetProperty("remarks", out var remarks) ? remarks.GetString() ?? string.Empty : string.Empty,
                    Group = element.TryGetProperty("group", out var group) ? group.GetString() ?? string.Empty : string.Empty,
                    Plugin = element.TryGetProperty("plugin", out var plugin) ? plugin.GetString() ?? string.Empty : string.Empty,
                    PluginOptions = element.TryGetProperty("plugin_opts", out var opts) ? opts.GetString() ?? string.Empty : string.Empty
                };
                yield break;
            }

            foreach (var prop in element.EnumerateObject())
            {
                foreach (var server in ExtractServers(prop.Value))
                    yield return server;
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                foreach (var server in ExtractServers(item))
                    yield return server;
            }
        }
    }
}
