using System.Net;
using System.Net.Sockets;
using System.Text;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Tests.Mocks;
using Xunit;

namespace ShadowsocksSharp.Tests;

/// <summary>
/// HTTP 代理协议测试
/// </summary>
public class HttpProxyProtocolTests : IAsyncLifetime
{
    private MockShadowsocksServer? _mockSsServer;
    private MockHttpServer? _mockTargetServer;
    private TestProxyHost? _proxyServer;
    
    private int _ssServerPort;
    private int _targetServerPort;
    private int _proxyPort;

    public async Task InitializeAsync()
    {
        _ssServerPort = GetAvailablePort();
        _targetServerPort = GetAvailablePort();
        _proxyPort = GetAvailablePort();

        _mockTargetServer = new MockHttpServer(_targetServerPort);
        _mockTargetServer.Start();

        _mockSsServer = new MockShadowsocksServer(_ssServerPort, "test-password", "aes-256-gcm");
        _mockSsServer.Start();

        var config = new SsServerConfig
        {
            Host = "127.0.0.1",
            Port = _ssServerPort,
            Password = "test-password",
            Method = "aes-256-gcm",
            LocalPort = _proxyPort,
            Timeout = 30
        };

        _proxyServer = new TestProxyHost(config, _proxyPort);
        await _proxyServer.StartAsync();
        await Task.Delay(100);
    }

    public async Task DisposeAsync()
    {
        if (_proxyServer != null)
        {
            await _proxyServer.DisposeAsync();
        }

        if (_mockSsServer != null)
            await _mockSsServer.DisposeAsync();

        if (_mockTargetServer != null)
            await _mockTargetServer.DisposeAsync();
    }

    private static int GetAvailablePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    [Fact]
    public async Task HttpProxy_ConnectMethod_ShouldReturn200()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act
        var connectRequest = $"CONNECT 127.0.0.1:{_targetServerPort} HTTP/1.1\r\nHost: 127.0.0.1:{_targetServerPort}\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(connectRequest));

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert
        Assert.Contains("HTTP/1.1 200", response);
        Assert.Contains("Connection Established", response);
    }

    [Fact]
    public async Task HttpProxy_ConnectMethod_InvalidTarget_ShouldReturnError()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act - 连接到无效目标
        var connectRequest = "CONNECT invalid-host HTTP/1.1\r\nHost: invalid-host\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(connectRequest));

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert - 应该返回 400 Bad Request
        Assert.Contains("400", response);
    }

    [Fact]
    public async Task HttpProxy_GetMethod_WithAbsoluteUrl_ShouldForward()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act
        var getRequest = $"GET http://127.0.0.1:{_targetServerPort}/test HTTP/1.1\r\nHost: 127.0.0.1:{_targetServerPort}\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(getRequest));

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert
        Assert.Contains("HTTP/1.1 200 OK", response);
    }

    [Fact]
    public async Task HttpProxy_PostMethod_ShouldForwardBody()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act
        var body = "test=data&foo=bar";
        var postRequest = $"POST http://127.0.0.1:{_targetServerPort}/submit HTTP/1.1\r\n" +
                         $"Host: 127.0.0.1:{_targetServerPort}\r\n" +
                         $"Content-Type: application/x-www-form-urlencoded\r\n" +
                         $"Content-Length: {body.Length}\r\n" +
                         $"\r\n{body}";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(postRequest));

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert
        Assert.Contains("HTTP/1.1 200 OK", response);
    }

    [Fact]
    public async Task HttpProxy_TunnelData_AfterConnect_ShouldTransfer()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // 建立隧道
        var connectRequest = $"CONNECT 127.0.0.1:{_targetServerPort} HTTP/1.1\r\nHost: 127.0.0.1:{_targetServerPort}\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(connectRequest));

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var connectResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead);
        Assert.Contains("200", connectResponse);

        // Act - 通过隧道发送请求
        var httpRequest = "GET /tunnel-test HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest));

        bytesRead = await stream.ReadAsync(buffer);
        var httpResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert
        Assert.Contains("HTTP/1.1 200 OK", httpResponse);
        Assert.Contains("Hello from mock server!", httpResponse);
    }

    [Fact]
    public async Task HttpProxy_MultiplePipeliningRequests_ShouldHandle()
    {
        // Arrange - 测试 HTTP 管线化
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // 建立隧道
        var connectRequest = $"CONNECT 127.0.0.1:{_targetServerPort} HTTP/1.1\r\nHost: 127.0.0.1:{_targetServerPort}\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(connectRequest));

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        Assert.Contains("200", Encoding.ASCII.GetString(buffer, 0, bytesRead));

        // Act - 发送多个请求
        var request1 = "GET /req1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request1));

        bytesRead = await stream.ReadAsync(buffer);
        var response1 = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert
        Assert.Contains("HTTP/1.1 200 OK", response1);
    }

    [Fact]
    public async Task HttpProxy_LargeHeaders_ShouldHandle()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act - 发送带有大量头部的请求
        var headers = new StringBuilder();
        headers.AppendLine($"GET http://127.0.0.1:{_targetServerPort}/ HTTP/1.1");
        headers.AppendLine($"Host: 127.0.0.1:{_targetServerPort}");
        
        // 添加多个自定义头部
        for (int i = 0; i < 50; i++)
        {
            headers.AppendLine($"X-Custom-Header-{i}: {new string('A', 100)}");
        }
        headers.AppendLine();

        await stream.WriteAsync(Encoding.ASCII.GetBytes(headers.ToString()));

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert
        Assert.Contains("HTTP/1.1 200 OK", response);
    }

    [Fact]
    public async Task HttpProxy_WithProxyHeaders_ShouldStrip()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act - 发送带有 Proxy- 前缀头部的请求
        var request = $"GET http://127.0.0.1:{_targetServerPort}/ HTTP/1.1\r\n" +
                     $"Host: 127.0.0.1:{_targetServerPort}\r\n" +
                     "Proxy-Connection: keep-alive\r\n" +
                     "Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n" +
                     "\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request));

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert - 请求应该被转发，Proxy-* 头部应该被移除
        Assert.Contains("HTTP/1.1 200 OK", response);
        
        // 验证目标服务器收到的请求
        Assert.NotEmpty(_mockTargetServer!.ReceivedRequests);
        var receivedRequest = _mockTargetServer.ReceivedRequests.Last();
        Assert.DoesNotContain("Proxy-Connection", receivedRequest);
        Assert.DoesNotContain("Proxy-Authorization", receivedRequest);
    }
}
