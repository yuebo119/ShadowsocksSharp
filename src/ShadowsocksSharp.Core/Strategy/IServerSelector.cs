using ShadowsocksSharp.Core.Configuration;

namespace ShadowsocksSharp.Core.Strategy;

public interface IServerSelector
{
    SsServerConfig Select(ServerSelectionContext context, IReadOnlyList<SsServerConfig> servers, int currentIndex);
    void ReportLatency(SsServerConfig server, TimeSpan latency);
    void ReportFailure(SsServerConfig server);
    void ReportTraffic(SsServerConfig server, long inboundBytes, long outboundBytes);
}
