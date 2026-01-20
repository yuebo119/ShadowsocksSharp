using System.Net;
using System.Net.Sockets;
using ShadowsocksSharp.Shadowsocks.Encryption;

namespace ShadowsocksSharp.Tests.Mocks;

/// <summary>
/// Mock Shadowsocks UDP server that echoes decrypted payloads.
/// </summary>
public sealed class MockShadowsocksUdpServer : IAsyncDisposable
{
    private readonly Socket _socket;
    private readonly string _password;
    private readonly string _method;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public int Port { get; }

    public MockShadowsocksUdpServer(int port, string password, string method = "aes-256-gcm")
    {
        _password = password;
        _method = method;
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Loopback, port));
        Port = ((IPEndPoint)_socket.LocalEndPoint!).Port;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => ReceiveLoopAsync(_cts.Token), _cts.Token);
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[65536];
        EndPoint remote = new IPEndPoint(IPAddress.Any, 0);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, remote, ct).ConfigureAwait(false);
                if (result.ReceivedBytes <= 0)
                    continue;

                var client = (IPEndPoint)result.RemoteEndPoint;
                var plain = new byte[result.ReceivedBytes];
                var len = AeadUdpCipher.Decrypt(_method, _password, buffer.AsSpan(0, result.ReceivedBytes), plain);
                if (len <= 0)
                    continue;

                var encrypted = new byte[len + 64];
                var outLen = AeadUdpCipher.Encrypt(_method, _password, plain.AsSpan(0, len), encrypted);
                await _socket.SendToAsync(encrypted.AsMemory(0, outLen), SocketFlags.None, client).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch { }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        try { _socket.Close(); } catch { }

        if (_loop != null)
        {
            try
            {
                await _loop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch { }
        }

        _cts?.Dispose();
        _socket.Dispose();
    }
}
