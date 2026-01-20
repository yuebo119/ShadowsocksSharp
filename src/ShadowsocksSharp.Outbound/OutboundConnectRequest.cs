using ShadowsocksSharp.Core.Configuration;

namespace ShadowsocksSharp.Outbound;

public sealed record OutboundConnectRequest(
    SsServerConfig Server,
    ForwardProxyConfig ForwardProxy,
    CancellationToken CancellationToken);
