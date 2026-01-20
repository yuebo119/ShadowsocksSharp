using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ShadowsocksSharp.Tests.Mocks;

/// <summary>
/// 模拟 HTTP 服务器 - 用于测试 HTTP 代理功能
/// </summary>
public class MockHttpServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptTask;

    public int Port { get; }
    public List<string> ReceivedRequests { get; } = [];
    public string ResponseBody { get; set; } = "Hello from mock server!";

    public MockHttpServer(int port)
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
            var bytesRead = await stream.ReadAsync(buffer, ct);
            if (bytesRead == 0) return;

            var request = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            ReceivedRequests.Add(request);

            // 构建 HTTP 响应
            var responseBody = ResponseBody;
            var response = $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {responseBody.Length}\r\nConnection: close\r\n\r\n{responseBody}";
            var responseBytes = Encoding.ASCII.GetBytes(response);
            
            await stream.WriteAsync(responseBytes, ct);
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
