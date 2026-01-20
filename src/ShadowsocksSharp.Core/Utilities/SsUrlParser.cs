using System.Text;
using System.Text.RegularExpressions;
using ShadowsocksSharp.Core.Configuration;

namespace ShadowsocksSharp.Core.Utilities;

public static class SsUrlParser
{
    private static readonly Regex LegacyPattern =
        new(@"ss://(?<base64>[A-Za-z0-9+\-/_=]+)(?:#(?<tag>\S+))?", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex LegacyDetails =
        new(@"^(?<method>.+?):(?<password>.*)@(?<host>.+?):(?<port>\d+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static List<SsServerConfig> Parse(string input)
    {
        var servers = new List<SsServerConfig>();
        foreach (var line in input.Split(new[] { '\r', '\n', ' ' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var server = ParseSingle(line);
            if (server != null)
                servers.Add(server);
        }
        return servers;
    }

    public static SsServerConfig? ParseSingle(string ssUrl)
    {
        if (!ssUrl.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
            return null;

        var legacy = ParseLegacy(ssUrl);
        if (legacy != null)
            return legacy;

        if (!Uri.TryCreate(ssUrl, UriKind.Absolute, out var uri))
            return null;

        var userInfo = uri.UserInfo;
        var base64 = userInfo.Replace('-', '+').Replace('_', '/');
        var padded = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
        var parts = decoded.Split(new[] { ':' }, 2);
        if (parts.Length != 2)
            return null;

        var server = new SsServerConfig
        {
            Method = parts[0],
            Password = parts[1],
            Host = uri.IdnHost,
            Port = uri.Port
        };

        var remark = UrlDecode(uri.GetComponents(UriComponents.Fragment, UriFormat.Unescaped));
        if (!string.IsNullOrWhiteSpace(remark))
            server.Name = remark;

        var query = ParseQuery(uri.Query);
        query.TryGetValue("plugin", out var plugin);
        if (!string.IsNullOrWhiteSpace(plugin))
        {
            var pluginParts = plugin.Split(';', 2);
            server.Plugin = pluginParts[0];
            if (pluginParts.Length > 1)
                server.PluginOptions = pluginParts[1];
        }

        return server;
    }

    private static SsServerConfig? ParseLegacy(string ssUrl)
    {
        var match = LegacyPattern.Match(ssUrl);
        if (!match.Success)
            return null;

        var base64 = match.Groups["base64"].Value.TrimEnd('/');
        var padded = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
        string decoded;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
        }
        catch
        {
            return null;
        }

        var detail = LegacyDetails.Match(decoded);
        if (!detail.Success)
            return null;

        var server = new SsServerConfig
        {
            Method = detail.Groups["method"].Value,
            Password = detail.Groups["password"].Value,
            Host = detail.Groups["host"].Value,
            Port = int.Parse(detail.Groups["port"].Value)
        };

        var tag = match.Groups["tag"].Value;
        if (!string.IsNullOrEmpty(tag))
            server.Name = UrlDecode(tag);

        return server;
    }

    public static string ToSsUrl(SsServerConfig server)
    {
        var tag = string.IsNullOrWhiteSpace(server.Name) ? string.Empty : $"#{UrlEncode(server.Name)}";
        var userInfo = $"{server.Method}:{server.Password}";
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(userInfo))
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        var url = $"ss://{base64}@{server.Host}:{server.Port}/";
        if (!string.IsNullOrWhiteSpace(server.Plugin))
        {
            var plugin = server.Plugin;
            if (!string.IsNullOrWhiteSpace(server.PluginOptions))
                plugin += ";" + server.PluginOptions;
            url += "?plugin=" + UrlEncode(plugin);
        }
        return url + tag;
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query))
            return result;

        var trimmed = query.StartsWith("?") ? query[1..] : query;
        foreach (var part in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = part.Split('=', 2);
            if (kv.Length == 0) continue;
            var key = UrlDecode(kv[0]);
            var value = kv.Length > 1 ? UrlDecode(kv[1]) : string.Empty;
            if (!string.IsNullOrEmpty(key))
                result[key] = value;
        }
        return result;
    }

    private static string UrlDecode(string value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        return Uri.UnescapeDataString(value.Replace("+", " "));
    }

    private static string UrlEncode(string value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        return Uri.EscapeDataString(value);
    }
}
