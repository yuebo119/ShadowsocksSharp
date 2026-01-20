using Microsoft.Extensions.Hosting;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Diagnostics;

namespace ShadowsocksSharp.Services.Pac;

public sealed class PacService : IHostedService
{
    private readonly Config _config;
    private readonly string _baseDir;
    private readonly HttpClient _httpClient = new();
    private string _pacSecret = string.Empty;

    public string PacFilePath => Path.Combine(_baseDir, "pac.txt");
    public string UserRulePath => Path.Combine(_baseDir, "user-rule.txt");

    public PacService(Config config, string baseDirectory)
    {
        _config = config;
        _baseDir = baseDirectory;
        Directory.CreateDirectory(_baseDir);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                var updated = await GeositeUpdater.UpdateAsync(_config, _httpClient).ConfigureAwait(false);
                if (updated || _config.RegeneratePacOnUpdate)
                {
                    GeneratePacFile();
                    Log.I("PAC regenerated after Geosite update.");
                }
            }
            catch (Exception ex)
            {
                Log.W($"Geosite update failed: {ex.Message}");
            }
        }, cancellationToken);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _httpClient.Dispose();
        return Task.CompletedTask;
    }

    public string GetPacUrl(string host, int port)
    {
        var secret = _config.SecureLocalPac ? $"&secret={GetPacSecret()}" : string.Empty;
        var contentHash = ComputeHash(GetPacContent());
        return $"http://{host}:{port}/pac?hash={contentHash}{secret}";
    }

    public async Task HandlePacRequestAsync(NetworkStream stream, string pathAndQuery, string proxyAddress, CancellationToken ct)
    {
        if (_config.SecureLocalPac && !pathAndQuery.Contains(GetPacSecret(), StringComparison.Ordinal))
        {
            return;
        }

        var pacContent = $"var __PROXY__ = 'PROXY {proxyAddress};';\n" + GetPacContent();
        var payload = Encoding.UTF8.GetBytes(pacContent);
        var response =
$@"HTTP/1.1 200 OK
Content-Type: application/x-ns-proxy-autoconfig
Content-Length: {payload.Length}
Connection: Close

";
        var header = Encoding.UTF8.GetBytes(response);
        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        await stream.WriteAsync(payload, ct).ConfigureAwait(false);
    }

    public string GetPacContent()
    {
        EnsureUserRuleFile();
        if (!File.Exists(PacFilePath))
        {
            GeneratePacFile();
        }
        return File.ReadAllText(PacFilePath, Encoding.UTF8);
    }

    public void GeneratePacFile()
    {
        var template = LoadTemplate();
        var userRules = LoadUserRules();
        var rules = GeositeUpdater.GenerateRules(
            _config.GeositeDirectGroups,
            _config.GeositeProxiedGroups,
            _config.GeositePreferDirect);

        var content =
$@"var __USERRULES__ = {System.Text.Json.JsonSerializer.Serialize(userRules)};
var __RULES__ = {System.Text.Json.JsonSerializer.Serialize(rules)};
{template}";
        File.WriteAllText(PacFilePath, content, Encoding.UTF8);
    }

    private string LoadTemplate()
    {
        var templatePath = Path.Combine(AppContext.BaseDirectory, "Pac", "abp.js");
        if (!File.Exists(templatePath))
        {
            Log.W($"PAC template not found: {templatePath}");
            return string.Empty;
        }
        return File.ReadAllText(templatePath, Encoding.UTF8);
    }

    private List<string> LoadUserRules()
    {
        var lines = new List<string>();
        if (!File.Exists(UserRulePath))
            return lines;

        foreach (var line in File.ReadAllLines(UserRulePath, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            if (line.StartsWith("!") || line.StartsWith("["))
                continue;
            lines.Add(line.Trim());
        }

        return lines;
    }

    private void EnsureUserRuleFile()
    {
        if (File.Exists(UserRulePath))
            return;

        var templatePath = Path.Combine(AppContext.BaseDirectory, "Pac", "user-rule.txt");
        if (File.Exists(templatePath))
        {
            File.Copy(templatePath, UserRulePath, overwrite: true);
        }
        else
        {
            File.WriteAllText(UserRulePath, string.Empty, Encoding.UTF8);
        }
    }

    private string GetPacSecret()
    {
        if (!string.IsNullOrEmpty(_pacSecret))
            return _pacSecret;

        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        _pacSecret = Convert.ToHexString(bytes);
        return _pacSecret;
    }

    private static string ComputeHash(string content)
    {
        var hash = MD5.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexString(hash);
    }
}
