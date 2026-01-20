using System.Net;
using System.Net.Sockets;

namespace Sip003UdpPlugin;

internal static class Program
{
    private static async Task Main()
    {
        var localHost = GetRequiredEnv("SS_LOCAL_HOST");
        var localPort = int.Parse(GetRequiredEnv("SS_LOCAL_PORT"));
        var remoteHost = GetRequiredEnv("SS_REMOTE_HOST");
        var remotePort = int.Parse(GetRequiredEnv("SS_REMOTE_PORT"));

        var localAddress = ResolveAddress(localHost);
        var remoteAddress = ResolveAddress(remoteHost);

        using var localSocket = new Socket(localAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        localSocket.Bind(new IPEndPoint(localAddress, localPort));

        using var remoteSocket = new Socket(remoteAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        remoteSocket.Connect(new IPEndPoint(remoteAddress, remotePort));

        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        IPEndPoint? lastClient = null;
        var clientLoop = RelayFromClientAsync(localSocket, remoteSocket, cts.Token, endpoint => lastClient = endpoint);
        var serverLoop = RelayFromServerAsync(localSocket, remoteSocket, cts.Token, () => lastClient);

        await Task.WhenAny(clientLoop, serverLoop).ConfigureAwait(false);
    }

    private static async Task RelayFromClientAsync(
        Socket localSocket,
        Socket remoteSocket,
        CancellationToken ct,
        Action<IPEndPoint> updateClient)
    {
        var buffer = new byte[65536];
        EndPoint remote = new IPEndPoint(IPAddress.Any, 0);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await localSocket.ReceiveFromAsync(buffer, SocketFlags.None, remote, ct).ConfigureAwait(false);
                if (result.ReceivedBytes <= 0)
                    continue;

                var client = (IPEndPoint)result.RemoteEndPoint;
                updateClient(client);
                await remoteSocket.SendAsync(buffer.AsMemory(0, result.ReceivedBytes), SocketFlags.None, ct)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch { }
        }
    }

    private static async Task RelayFromServerAsync(
        Socket localSocket,
        Socket remoteSocket,
        CancellationToken ct,
        Func<IPEndPoint?> getClient)
    {
        var buffer = new byte[65536];
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var n = await remoteSocket.ReceiveAsync(buffer, SocketFlags.None, ct).ConfigureAwait(false);
                if (n <= 0)
                    continue;

                var client = getClient();
                if (client == null)
                    continue;

                await localSocket.SendToAsync(buffer.AsMemory(0, n), SocketFlags.None, client, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch { }
        }
    }

    private static string GetRequiredEnv(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException($"Missing env var: {name}");
        return value;
    }

    private static IPAddress ResolveAddress(string host)
    {
        if (IPAddress.TryParse(host, out var ip))
            return ip;
        return Dns.GetHostAddresses(host)[0];
    }
}
