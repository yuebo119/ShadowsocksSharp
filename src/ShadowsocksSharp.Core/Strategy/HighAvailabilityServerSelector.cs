using System.Collections.Concurrent;
using ShadowsocksSharp.Core.Configuration;

namespace ShadowsocksSharp.Core.Strategy;

public sealed class HighAvailabilityServerSelector : IServerSelector
{
    private sealed class ServerStatus
    {
        public TimeSpan Latency = TimeSpan.FromMilliseconds(50);
        public DateTime LastLatencyUpdate = DateTime.MinValue;
        public DateTime LastRead = DateTime.MinValue;
        public DateTime LastWrite = DateTime.MinValue;
        public DateTime LastFailure = DateTime.MinValue;
        public double Score;
    }

    private readonly ConcurrentDictionary<string, ServerStatus> _status = new(StringComparer.OrdinalIgnoreCase);

    public SsServerConfig Select(ServerSelectionContext context, IReadOnlyList<SsServerConfig> servers, int currentIndex)
    {
        if (servers.Count == 0)
            throw new InvalidOperationException("No servers configured.");

        var now = DateTime.UtcNow;
        SsServerConfig? best = null;
        double bestScore = double.MinValue;

        foreach (var server in servers)
        {
            if (!server.Enabled) continue;
            var status = _status.GetOrAdd(server.Host + ":" + server.Port, _ => new ServerStatus());

            var failurePenalty = Math.Min(300, (now - status.LastFailure).TotalSeconds);
            var latencyMs = Math.Min(2000, status.Latency.TotalMilliseconds);
            var readWriteGap = Math.Min(5, Math.Max(0, (status.LastRead - status.LastWrite).TotalSeconds));

            status.Score = (100 * failurePenalty) - (2 * latencyMs) - (0.5 * 200 * readWriteGap);

            if (status.Score > bestScore)
            {
                bestScore = status.Score;
                best = server;
            }
        }

        return best ?? servers[Math.Clamp(currentIndex, 0, servers.Count - 1)];
    }

    public void ReportLatency(SsServerConfig server, TimeSpan latency)
    {
        var status = _status.GetOrAdd(server.Host + ":" + server.Port, _ => new ServerStatus());
        status.Latency = latency;
        status.LastLatencyUpdate = DateTime.UtcNow;
    }

    public void ReportFailure(SsServerConfig server)
    {
        var status = _status.GetOrAdd(server.Host + ":" + server.Port, _ => new ServerStatus());
        status.LastFailure = DateTime.UtcNow;
    }

    public void ReportTraffic(SsServerConfig server, long inboundBytes, long outboundBytes)
    {
        var status = _status.GetOrAdd(server.Host + ":" + server.Port, _ => new ServerStatus());
        if (inboundBytes > 0) status.LastRead = DateTime.UtcNow;
        if (outboundBytes > 0) status.LastWrite = DateTime.UtcNow;
    }
}
