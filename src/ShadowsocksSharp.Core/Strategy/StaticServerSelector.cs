using ShadowsocksSharp.Core.Configuration;

namespace ShadowsocksSharp.Core.Strategy;

public sealed class StaticServerSelector : IServerSelector
{
    public SsServerConfig Select(ServerSelectionContext context, IReadOnlyList<SsServerConfig> servers, int currentIndex)
    {
        if (servers.Count == 0)
            throw new InvalidOperationException("No servers configured.");

        if (currentIndex >= 0 && currentIndex < servers.Count && servers[currentIndex].Enabled)
            return servers[currentIndex];

        foreach (var server in servers)
        {
            if (server.Enabled)
                return server;
        }

        return servers[0];
    }

    public void ReportLatency(SsServerConfig server, TimeSpan latency) { }
    public void ReportFailure(SsServerConfig server) { }
    public void ReportTraffic(SsServerConfig server, long inboundBytes, long outboundBytes) { }
}
