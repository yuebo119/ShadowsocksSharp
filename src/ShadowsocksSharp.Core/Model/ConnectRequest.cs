namespace ShadowsocksSharp.Core.Model;

public sealed record ConnectRequest(
    string Host,
    int Port,
    InboundProtocol Protocol,
    ReadOnlyMemory<byte> InitialPayload);
