using System.Net;
using System.Net.Sockets;

namespace ShadowsocksSharp.Tests.Mocks;

/// <summary>
/// 模拟 Echo 服务器 - 简单返回接收到的数据
/// </summary>
public class MockEchoServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptTask;

    public int Port { get; }
    public long TotalBytesReceived { get; private set; }
    public long TotalBytesSent { get; private set; }

    public MockEchoServer(int port)
    {
        Port = port;
        _listener = new TcpListener(IPAddress.Loopback, port);
    }

    public void Start()
    {
        _listener.Start();
        _cts = new CancellationTokenSource();
        _acceptTask = AcceptConnectionsAsync(_cts.Token);
    }

    private async Task AcceptConnectionsAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(ct);
                _ = HandleClientAsync(client, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch { }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using var _ = client;
        using var stream = client.GetStream();
        var buffer = new byte[8192];

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var bytesRead = await stream.ReadAsync(buffer, ct);
                if (bytesRead == 0) break;

                TotalBytesReceived += bytesRead;
                
                await stream.WriteAsync(buffer.AsMemory(0, bytesRead), ct);
                TotalBytesSent += bytesRead;
            }
        }
        catch (OperationCanceledException) { }
        catch { }
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _listener.Stop();

        if (_acceptTask != null)
        {
            try
            {
                await _acceptTask.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch { }
        }

        _cts?.Dispose();
    }
}
