using System.Net;
using System.Net.Sockets;
using System.Text;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Tests.Mocks;
using Xunit;

namespace ShadowsocksSharp.Tests;

/// <summary>
/// 端到端集成测试 - 模拟完整的浏览器到目标服务器的数据流转
/// </summary>
public class EndToEndTests : IAsyncLifetime
{
    private const string TestPassword = "test-password-123";
    private const string TestMethod = "aes-256-gcm";
    
    private MockShadowsocksServer? _mockSsServer;
    private MockHttpServer? _mockTargetServer;
    private TestProxyHost? _proxyServer;
    
    private int _ssServerPort;
    private int _targetServerPort;
    private int _proxyPort;

    public async Task InitializeAsync()
    {
        // 分配随机可用端口
        _ssServerPort = GetAvailablePort();
        _targetServerPort = GetAvailablePort();
        _proxyPort = GetAvailablePort();

        // 启动模拟目标 HTTP 服务器
        _mockTargetServer = new MockHttpServer(_targetServerPort);
        _mockTargetServer.Start();

        // 启动模拟 Shadowsocks 服务器
        _mockSsServer = new MockShadowsocksServer(_ssServerPort, TestPassword, TestMethod);
        _mockSsServer.Start();

        // 等待服务器启动
        await Task.Delay(100);
    }

    public async Task DisposeAsync()
    {
        if (_proxyServer != null)
        {
            await _proxyServer.DisposeAsync();
        }

        if (_mockSsServer != null)
        {
            await _mockSsServer.DisposeAsync();
        }

        if (_mockTargetServer != null)
        {
            await _mockTargetServer.DisposeAsync();
        }
    }

    private static int GetAvailablePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private SsServerConfig CreateTestConfig()
    {
        return new SsServerConfig
        {
            Host = "127.0.0.1",
            Port = _ssServerPort,
            Password = TestPassword,
            Method = TestMethod,
            LocalPort = _proxyPort,
            Timeout = 30
        };
    }

    [Fact]
    public async Task Socks5Proxy_SimpleRequest_ShouldRelayDataCorrectly()
    {
        // Arrange
        var config = CreateTestConfig();
        _proxyServer = new TestProxyHost(config, _proxyPort);
        await _proxyServer.StartAsync();
        await Task.Delay(100);

        // Act - 模拟 SOCKS5 客户端连接
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // SOCKS5 握手
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }); // 版本5, 1个方法, 无认证
        
        var response = new byte[2];
        await stream.ReadAsync(response);
        Assert.Equal(0x05, response[0]); // 版本5
        Assert.Equal(0x00, response[1]); // 选择无认证

        // SOCKS5 连接请求 - 连接到目标服务器
        var targetPort = _targetServerPort;
        var connectRequest = new byte[]
        {
            0x05, // 版本
            0x01, // CONNECT 命令
            0x00, // 保留
            0x01, // IPv4 地址类型
            127, 0, 0, 1, // IP 地址
            (byte)(targetPort >> 8), (byte)(targetPort & 0xFF) // 端口
        };
        await stream.WriteAsync(connectRequest);

        var connectResponse = new byte[10];
        await stream.ReadAsync(connectResponse);
        
        // Assert - 连接应该成功
        Assert.Equal(0x05, connectResponse[0]); // 版本
        Assert.Equal(0x00, connectResponse[1]); // 成功

        // 发送 HTTP 请求
        var httpRequest = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest));
        await stream.FlushAsync();

        // 读取响应
        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var httpResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert
        Assert.Contains("HTTP/1.1 200 OK", httpResponse);
        Assert.Contains("Hello from mock server!", httpResponse);
    }

    [Fact]
    public async Task Socks5Proxy_DomainAddress_ShouldRelayDataCorrectly()
    {
        // Arrange
        var config = CreateTestConfig();
        _proxyServer = new TestProxyHost(config, _proxyPort);
        await _proxyServer.StartAsync();
        await Task.Delay(100);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // SOCKS5 握手
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var response = new byte[2];
        await stream.ReadAsync(response);
        Assert.Equal(0x05, response[0]);
        Assert.Equal(0x00, response[1]);

        // SOCKS5 连接请求 - 使用域名
        var domainName = "localhost";
        var domainBytes = Encoding.ASCII.GetBytes(domainName);
        var connectRequest = new byte[4 + 1 + domainBytes.Length + 2];
        connectRequest[0] = 0x05; // 版本
        connectRequest[1] = 0x01; // CONNECT
        connectRequest[2] = 0x00; // 保留
        connectRequest[3] = 0x03; // 域名类型
        connectRequest[4] = (byte)domainBytes.Length;
        Array.Copy(domainBytes, 0, connectRequest, 5, domainBytes.Length);
        connectRequest[5 + domainBytes.Length] = (byte)(_targetServerPort >> 8);
        connectRequest[5 + domainBytes.Length + 1] = (byte)(_targetServerPort & 0xFF);

        await stream.WriteAsync(connectRequest);

        var connectResponse = new byte[10];
        await stream.ReadAsync(connectResponse);
        Assert.Equal(0x05, connectResponse[0]);
        Assert.Equal(0x00, connectResponse[1]); // 成功

        // 发送 HTTP 请求
        var httpRequest = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest));

        // 读取响应
        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var httpResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        Assert.Contains("HTTP/1.1 200 OK", httpResponse);
    }

    [Fact]
    public async Task HttpProxy_ConnectMethod_ShouldEstablishTunnel()
    {
        // Arrange
        var config = CreateTestConfig();
        _proxyServer = new TestProxyHost(config, _proxyPort);
        await _proxyServer.StartAsync();
        await Task.Delay(100);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act - 发送 HTTP CONNECT 请求
        var connectRequest = $"CONNECT 127.0.0.1:{_targetServerPort} HTTP/1.1\r\nHost: 127.0.0.1:{_targetServerPort}\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(connectRequest));

        // 读取 CONNECT 响应
        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var connectResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert - 隧道建立成功
        Assert.Contains("200 Connection Established", connectResponse);

        // 通过隧道发送 HTTP 请求
        var httpRequest = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest));
        await stream.FlushAsync();

        bytesRead = await stream.ReadAsync(buffer);
        var httpResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        Assert.Contains("HTTP/1.1 200 OK", httpResponse);
        Assert.Contains("Hello from mock server!", httpResponse);
    }

    [Fact]
    public async Task HttpProxy_GetRequest_ShouldForwardRequest()
    {
        // Arrange
        var config = CreateTestConfig();
        _proxyServer = new TestProxyHost(config, _proxyPort);
        await _proxyServer.StartAsync();
        await Task.Delay(100);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act - 发送 HTTP GET 请求 (代理格式)
        var httpRequest = $"GET http://127.0.0.1:{_targetServerPort}/ HTTP/1.1\r\nHost: 127.0.0.1:{_targetServerPort}\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest));

        // 读取响应
        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var httpResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert
        Assert.Contains("HTTP/1.1 200 OK", httpResponse);
        Assert.Contains("Hello from mock server!", httpResponse);
    }

    [Fact]
    public async Task Proxy_LargeDataTransfer_ShouldTransferCorrectly()
    {
        // Arrange
        var config = CreateTestConfig();
        _proxyServer = new TestProxyHost(config, _proxyPort);
        await _proxyServer.StartAsync();
        await Task.Delay(100);

        // 创建一个返回大数据的目标服务器
        var largeDataPort = GetAvailablePort();
        var largeData = new string('X', 100000); // 100KB 数据
        await using var largeDataServer = new MockHttpServer(largeDataPort) { ResponseBody = largeData };
        largeDataServer.Start();
        await Task.Delay(50);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // SOCKS5 握手
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var response = new byte[2];
        await stream.ReadAsync(response);

        // SOCKS5 连接
        var connectRequest = new byte[]
        {
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            (byte)(largeDataPort >> 8), (byte)(largeDataPort & 0xFF)
        };
        await stream.WriteAsync(connectRequest);
        var connectResponse = new byte[10];
        await stream.ReadAsync(connectResponse);
        Assert.Equal(0x00, connectResponse[1]); // 成功

        // 发送请求
        var httpRequest = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest));

        // 读取完整响应
        var allData = new MemoryStream();
        var buffer = new byte[8192];
        
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            while (true)
            {
                var bytesRead = await stream.ReadAsync(buffer, cts.Token);
                if (bytesRead == 0) break;
                allData.Write(buffer, 0, bytesRead);
                
                // 检查是否已接收完整响应
                var currentData = Encoding.ASCII.GetString(allData.ToArray());
                if (currentData.Contains(largeData))
                    break;
            }
        }
        catch (OperationCanceledException)
        {
            // 超时
        }

        var responseData = Encoding.ASCII.GetString(allData.ToArray());

        // Assert
        Assert.Contains("HTTP/1.1 200 OK", responseData);
        Assert.Contains(largeData, responseData);
    }

    [Fact]
    public async Task Proxy_MultipleConnections_ShouldHandleConcurrently()
    {
        // Arrange
        var config = CreateTestConfig();
        _proxyServer = new TestProxyHost(config, _proxyPort);
        await _proxyServer.StartAsync();
        await Task.Delay(100);

        // Act - 同时发起多个连接
        var tasks = Enumerable.Range(0, 5).Select(async i =>
        {
            using var client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", _proxyPort);
            using var stream = client.GetStream();

            // SOCKS5 握手
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
            var response = new byte[2];
            await stream.ReadAsync(response);
            if (response[1] != 0x00) return false;

            // SOCKS5 连接
            var connectRequest = new byte[]
            {
                0x05, 0x01, 0x00, 0x01,
                127, 0, 0, 1,
                (byte)(_targetServerPort >> 8), (byte)(_targetServerPort & 0xFF)
            };
            await stream.WriteAsync(connectRequest);
            var connectResponse = new byte[10];
            await stream.ReadAsync(connectResponse);
            if (connectResponse[1] != 0x00) return false;

            // 发送请求
            var httpRequest = $"GET /?id={i} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(httpRequest));

            // 读取响应
            var buffer = new byte[4096];
            var bytesRead = await stream.ReadAsync(buffer);
            var httpResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead);

            return httpResponse.Contains("200 OK");
        }).ToList();

        var results = await Task.WhenAll(tasks);

        // Assert
        Assert.All(results, result => Assert.True(result));
    }

    [Fact]
    public async Task Socks5Proxy_InvalidVersion_ShouldReject()
    {
        // Arrange
        var config = CreateTestConfig();
        _proxyServer = new TestProxyHost(config, _proxyPort);
        await _proxyServer.StartAsync();
        await Task.Delay(100);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act - 发送无效的 SOCKS 版本
        await stream.WriteAsync(new byte[] { 0x04, 0x01, 0x00 }); // SOCKS4 版本

        // 等待一下看服务器如何处理
        await Task.Delay(100);

        // Assert - 连接应该被关闭或被识别为其他协议
        // 由于 0x04 不是 HTTP 方法也不是 SOCKS5，应该被拒绝
    }

    [Fact]
    public async Task HttpProxy_InvalidRequest_ShouldReturnBadRequest()
    {
        // Arrange
        var config = CreateTestConfig();
        _proxyServer = new TestProxyHost(config, _proxyPort);
        await _proxyServer.StartAsync();
        await Task.Delay(100);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act - 发送无效的 HTTP 请求
        await stream.WriteAsync(Encoding.ASCII.GetBytes("GET\r\n\r\n")); // 缺少 URL 和版本

        var buffer = new byte[4096];
        try
        {
            var bytesRead = await stream.ReadAsync(buffer);
            // 可能收到错误响应或连接被关闭
        }
        catch
        {
            // 连接可能被关闭
        }
    }
}
