using System.Net.Sockets;
using ShadowsocksSharp.Core.Model;

namespace ShadowsocksSharp.Inbound;

public sealed record InboundResult(
    ConnectRequest? Request,
    Func<NetworkStream, CancellationToken, ValueTask>? OnConnected,
    Func<NetworkStream, CancellationToken, ValueTask>? OnFailed,
    string? PacRequestPath)
{
    public bool IsPacRequest => !string.IsNullOrEmpty(PacRequestPath);
}
