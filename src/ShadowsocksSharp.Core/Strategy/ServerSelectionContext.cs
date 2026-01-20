using System.Net;
using ShadowsocksSharp.Core.Model;

namespace ShadowsocksSharp.Core.Strategy;

public sealed record ServerSelectionContext(
    InboundProtocol Protocol,
    EndPoint? ClientEndPoint,
    string DestinationHost,
    int DestinationPort);
