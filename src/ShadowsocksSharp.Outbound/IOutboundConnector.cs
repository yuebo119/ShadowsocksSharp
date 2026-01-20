using System.Net.Sockets;

namespace ShadowsocksSharp.Outbound;

public interface IOutboundConnector
{
    ValueTask<Socket> ConnectAsync(OutboundConnectRequest request);
}
