using System.Net;
using System.Net.Sockets;

namespace ShadowsocksSharp.Tests.Mocks;

/// <summary>
/// 模拟目标服务器 - Echo 服务器，用于测试端到端数据流转
/// </summary>
public class MockTargetServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptTask;
    private readonly Func<byte[], byte[]> _responseGenerator;

    public int Port { get; }
    public List<byte[]> ReceivedData { get; } = [];

    public MockTargetServer(int port, Func<byte[], byte[]>? responseGenerator = null)
    {
        Port = port;
        _listener = new TcpListener(IPAddress.Loopback, port);
        _responseGenerator = responseGenerator ?? (data => data); // 默认 echo
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

                var received = buffer[..bytesRead];
                ReceivedData.Add(received);

                var response = _responseGenerator(received);
                await stream.WriteAsync(response, ct);
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
