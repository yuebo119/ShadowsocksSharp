using System.Security.Cryptography;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Diagnostics;
using ShadowsocksSharp.Services.Geosite;

namespace ShadowsocksSharp.Services.Pac;

public static class GeositeUpdater
{
    private static readonly Dictionary<string, IList<DomainObject>> Geosites =
        new(StringComparer.OrdinalIgnoreCase);

    private static byte[] _database = Array.Empty<byte>();

    public static IReadOnlyDictionary<string, IList<DomainObject>> GeoSiteMap => Geosites;

    public static void Load(string databasePath)
    {
        if (!File.Exists(databasePath))
        {
            Log.W($"Geosite database not found: {databasePath}");
            return;
        }

        _database = File.ReadAllBytes(databasePath);
        LoadGeositeList();
    }

    public static async Task<bool> UpdateAsync(Config config, HttpClient httpClient)
    {
        if (string.IsNullOrWhiteSpace(config.GeositeUrl))
            return false;

        var url = config.GeositeUrl;
        var shaUrl = config.GeositeSha256Url;
        var verifySha = !string.IsNullOrWhiteSpace(shaUrl);

        var sha256 = SHA256.Create();
        string? shaRemote = null;

        if (verifySha)
        {
            shaRemote = await httpClient.GetStringAsync(shaUrl).ConfigureAwait(false);
            shaRemote = shaRemote.Substring(0, 64).ToUpperInvariant();
            var localHash = Convert.ToHexString(sha256.ComputeHash(_database));
            if (localHash == shaRemote)
            {
                Log.I("Geosite database up-to-date.");
                return false;
            }
        }

        var data = await httpClient.GetByteArrayAsync(url).ConfigureAwait(false);
        if (verifySha && shaRemote != null)
        {
            var actual = Convert.ToHexString(sha256.ComputeHash(data));
            if (!string.Equals(actual, shaRemote, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Geosite SHA256 verification failed.");
        }

        _database = data;
        LoadGeositeList();
        return true;
    }

    public static bool CheckGroup(string group)
        => SeparateAttribute(group, out var name, out _) && Geosites.ContainsKey(name);

    public static List<string> GenerateRules(
        List<string> directGroups,
        List<string> proxiedGroups,
        bool preferDirect)
    {
        return preferDirect
            ? GenerateBlockingRules(proxiedGroups).Concat(GenerateExceptionRules(directGroups)).ToList()
            : new List<string> { "/.*/" }.Concat(GenerateExceptionRules(directGroups)).ToList();
    }

    public static List<string> GenerateExceptionRules(List<string> groups)
        => GenerateBlockingRules(groups).Select(r => $"@@{r}").ToList();

    private static List<string> GenerateBlockingRules(List<string> groups)
    {
        var lines = new List<string>();
        foreach (var group in groups)
        {
            if (!SeparateAttribute(group, out var groupName, out var attribute))
                continue;

            if (!Geosites.TryGetValue(groupName, out var domains))
                continue;

            foreach (var domain in domains)
            {
                if (!string.IsNullOrEmpty(attribute))
                {
                    var attr = new DomainObject.Types.Attribute { Key = attribute, BoolValue = true };
                    if (!domain.Attribute.Contains(attr))
                        continue;
                }

                switch (domain.Type)
                {
                    case DomainObject.Types.Type.Plain:
                        lines.Add(domain.Value);
                        break;
                    case DomainObject.Types.Type.Regex:
                        lines.Add($"/{domain.Value}/");
                        break;
                    case DomainObject.Types.Type.Domain:
                        lines.Add($"||{domain.Value}");
                        break;
                    case DomainObject.Types.Type.Full:
                        lines.Add($"|http://{domain.Value}");
                        lines.Add($"|https://{domain.Value}");
                        break;
                }
            }
        }
        return lines;
    }

    private static bool SeparateAttribute(string group, out string name, out string attribute)
    {
        var parts = group.Split('@');
        if (parts.Length == 1)
        {
            name = parts[0];
            attribute = string.Empty;
            return true;
        }

        if (parts.Length == 2)
        {
            name = parts[0];
            attribute = parts[1];
            return true;
        }

        name = string.Empty;
        attribute = string.Empty;
        return false;
    }

    private static void LoadGeositeList()
    {
        Geosites.Clear();
        if (_database.Length == 0)
            return;

        var list = GeositeList.Parser.ParseFrom(_database);
        foreach (var entry in list.Entries)
        {
            Geosites[entry.GroupName.ToLowerInvariant()] = entry.Domains;
        }
    }
}
