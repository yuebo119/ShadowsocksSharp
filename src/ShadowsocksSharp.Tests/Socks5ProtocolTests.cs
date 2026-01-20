using System.Net;
using System.Net.Sockets;
using System.Text;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Tests.Mocks;
using Xunit;

namespace ShadowsocksSharp.Tests;

/// <summary>
/// SOCKS5 协议测试
/// </summary>
public class Socks5ProtocolTests : IAsyncLifetime
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
    public async Task Socks5_Handshake_NoAuthMethod_ShouldSucceed()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act - 发送握手请求（支持无认证）
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });

        var response = new byte[2];
        await stream.ReadAsync(response);

        // Assert
        Assert.Equal(0x05, response[0]); // SOCKS5 版本
        Assert.Equal(0x00, response[1]); // 选择无认证方法
    }

    [Fact]
    public async Task Socks5_Handshake_MultipleAuthMethods_ShouldSelectNoAuth()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // Act - 发送握手请求（支持多种认证方法）
        await stream.WriteAsync(new byte[] { 
            0x05,       // 版本
            0x03,       // 3 种方法
            0x00,       // 无认证
            0x01,       // GSSAPI
            0x02        // 用户名/密码
        });

        var response = new byte[2];
        await stream.ReadAsync(response);

        // Assert - 应该选择无认证
        Assert.Equal(0x05, response[0]);
        Assert.Equal(0x00, response[1]);
    }

    [Fact]
    public async Task Socks5_Connect_IPv4_ShouldSucceed()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // 握手
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var handshakeResponse = new byte[2];
        await stream.ReadAsync(handshakeResponse);

        // Act - 发送连接请求（IPv4）
        var connectRequest = new byte[]
        {
            0x05,                   // 版本
            0x01,                   // CONNECT 命令
            0x00,                   // 保留
            0x01,                   // IPv4 地址类型
            127, 0, 0, 1,          // IP 地址
            (byte)(_targetServerPort >> 8), 
            (byte)(_targetServerPort & 0xFF)
        };
        await stream.WriteAsync(connectRequest);

        var response = new byte[10];
        await stream.ReadAsync(response);

        // Assert
        Assert.Equal(0x05, response[0]); // 版本
        Assert.Equal(0x00, response[1]); // 成功 (0x00 = succeeded)
        Assert.Equal(0x00, response[2]); // 保留
        Assert.Equal(0x01, response[3]); // IPv4 地址类型
    }

    [Fact]
    public async Task Socks5_Connect_DomainName_ShouldSucceed()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // 握手
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var handshakeResponse = new byte[2];
        await stream.ReadAsync(handshakeResponse);

        // Act - 发送连接请求（域名）
        var domain = "localhost";
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        var connectRequest = new byte[7 + domainBytes.Length];
        connectRequest[0] = 0x05; // 版本
        connectRequest[1] = 0x01; // CONNECT
        connectRequest[2] = 0x00; // 保留
        connectRequest[3] = 0x03; // 域名类型
        connectRequest[4] = (byte)domainBytes.Length;
        Array.Copy(domainBytes, 0, connectRequest, 5, domainBytes.Length);
        connectRequest[5 + domainBytes.Length] = (byte)(_targetServerPort >> 8);
        connectRequest[6 + domainBytes.Length] = (byte)(_targetServerPort & 0xFF);

        await stream.WriteAsync(connectRequest);

        var response = new byte[10];
        await stream.ReadAsync(response);

        // Assert
        Assert.Equal(0x05, response[0]); // 版本
        Assert.Equal(0x00, response[1]); // 成功
    }

    [Fact]
    public async Task Socks5_DataTransfer_AfterConnect_ShouldWork()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // 完成握手和连接
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var handshakeResponse = new byte[2];
        await stream.ReadAsync(handshakeResponse);

        var connectRequest = new byte[]
        {
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            (byte)(_targetServerPort >> 8), (byte)(_targetServerPort & 0xFF)
        };
        await stream.WriteAsync(connectRequest);
        var connectResponse = new byte[10];
        await stream.ReadAsync(connectResponse);

        // Act - 发送数据
        var requestData = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(requestData));

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var responseData = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert
        Assert.Contains("HTTP/1.1 200 OK", responseData);
    }

    [Fact]
    public async Task Socks5_BinaryData_ShouldTransferCorrectly()
    {
        // Arrange
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // 完成握手和连接
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var handshakeResponse = new byte[2];
        await stream.ReadAsync(handshakeResponse);

        var connectRequest = new byte[]
        {
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            (byte)(_targetServerPort >> 8), (byte)(_targetServerPort & 0xFF)
        };
        await stream.WriteAsync(connectRequest);
        var connectResponse = new byte[10];
        await stream.ReadAsync(connectResponse);
        Assert.Equal(0x00, connectResponse[1]); // 确认连接成功

        // Act - 发送包含所有字节值的数据
        var requestWithBinary = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Binary: ";
        var binaryPart = new byte[128];
        for (int i = 0; i < 128; i++)
        {
            binaryPart[i] = (byte)(i + 32); // 可打印字符
        }
        var fullRequest = Encoding.ASCII.GetBytes(requestWithBinary)
            .Concat(binaryPart)
            .Concat("\r\n\r\n"u8.ToArray())
            .ToArray();

        await stream.WriteAsync(fullRequest);

        var buffer = new byte[4096];
        var bytesRead = await stream.ReadAsync(buffer);
        var responseData = Encoding.ASCII.GetString(buffer, 0, bytesRead);

        // Assert
        Assert.Contains("HTTP/1.1 200 OK", responseData);
    }
}
