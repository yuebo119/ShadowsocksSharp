using System.Net;
using System.Net.Sockets;
using System.Text;
using ShadowsocksSharp.Shadowsocks.Encryption;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Tests.Mocks;
using Xunit;

namespace ShadowsocksSharp.Tests;

/// <summary>
/// 数据完整性测试 - 验证数据在整个代理链路中的正确性
/// </summary>
public class DataIntegrityTests : IAsyncLifetime
{
    private MockShadowsocksServer? _mockSsServer;
    private TestProxyHost? _proxyServer;
    
    private int _ssServerPort;
    private int _proxyPort;

    public async Task InitializeAsync()
    {
        _ssServerPort = GetAvailablePort();
        _proxyPort = GetAvailablePort();

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
    public async Task DataIntegrity_AllByteValues_ShouldPreserve()
    {
        // Arrange - 创建一个 echo 服务器
        var echoPort = GetAvailablePort();
        await using var echoServer = new MockEchoServer(echoPort);
        echoServer.Start();
        await Task.Delay(50);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // SOCKS5 握手和连接
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var handshake = new byte[2];
        await stream.ReadAsync(handshake);

        var connect = new byte[]
        {
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            (byte)(echoPort >> 8), (byte)(echoPort & 0xFF)
        };
        await stream.WriteAsync(connect);
        var connectResponse = new byte[10];
        await stream.ReadAsync(connectResponse);
        Assert.Equal(0x00, connectResponse[1]);

        // Act - 发送包含所有字节值的数据
        var testData = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            testData[i] = (byte)i;
        }
        await stream.WriteAsync(testData);
        await stream.FlushAsync();

        // 读取回显数据
        var receivedData = new byte[256];
        var totalRead = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        
        while (totalRead < 256 && !cts.Token.IsCancellationRequested)
        {
            var bytesRead = await stream.ReadAsync(receivedData.AsMemory(totalRead, 256 - totalRead), cts.Token);
            if (bytesRead == 0) break;
            totalRead += bytesRead;
        }

        // Assert
        Assert.Equal(256, totalRead);
        Assert.Equal(testData, receivedData);
    }

    [Fact]
    public async Task DataIntegrity_LargeData_ShouldPreserve()
    {
        // Arrange
        var echoPort = GetAvailablePort();
        await using var echoServer = new MockEchoServer(echoPort);
        echoServer.Start();
        await Task.Delay(50);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // SOCKS5 握手和连接
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var handshake = new byte[2];
        await stream.ReadAsync(handshake);

        var connect = new byte[]
        {
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            (byte)(echoPort >> 8), (byte)(echoPort & 0xFF)
        };
        await stream.WriteAsync(connect);
        var connectResponse = new byte[10];
        await stream.ReadAsync(connectResponse);
        Assert.Equal(0x00, connectResponse[1]);

        // Act - 发送大数据
        var dataSize = 1024 * 100; // 100KB
        var testData = new byte[dataSize];
        Random.Shared.NextBytes(testData);
        
        await stream.WriteAsync(testData);
        await stream.FlushAsync();

        // 读取回显数据
        var receivedData = new byte[dataSize];
        var totalRead = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        
        while (totalRead < dataSize && !cts.Token.IsCancellationRequested)
        {
            var bytesRead = await stream.ReadAsync(receivedData.AsMemory(totalRead, dataSize - totalRead), cts.Token);
            if (bytesRead == 0) break;
            totalRead += bytesRead;
        }

        // Assert
        Assert.Equal(dataSize, totalRead);
        Assert.Equal(testData, receivedData);
    }

    [Fact]
    public async Task DataIntegrity_RandomData_MultipleChunks_ShouldPreserve()
    {
        // Arrange
        var echoPort = GetAvailablePort();
        await using var echoServer = new MockEchoServer(echoPort);
        echoServer.Start();
        await Task.Delay(50);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _proxyPort);
        using var stream = client.GetStream();

        // SOCKS5 握手和连接
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var handshake = new byte[2];
        await stream.ReadAsync(handshake);

        var connect = new byte[]
        {
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            (byte)(echoPort >> 8), (byte)(echoPort & 0xFF)
        };
        await stream.WriteAsync(connect);
        var connectResponse = new byte[10];
        await stream.ReadAsync(connectResponse);
        Assert.Equal(0x00, connectResponse[1]);

        // Act - 发送多个随机大小的数据块
        var allSentData = new List<byte>();
        var random = new Random(42); // 固定种子以便复现

        for (int i = 0; i < 10; i++)
        {
            var chunkSize = random.Next(100, 5000);
            var chunk = new byte[chunkSize];
            Random.Shared.NextBytes(chunk);
            
            await stream.WriteAsync(chunk);
            allSentData.AddRange(chunk);
            
            // 随机延迟
            await Task.Delay(random.Next(10, 50));
        }
        
        await stream.FlushAsync();

        // 读取所有回显数据
        var totalExpected = allSentData.Count;
        var receivedData = new byte[totalExpected];
        var totalRead = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        
        while (totalRead < totalExpected && !cts.Token.IsCancellationRequested)
        {
            var bytesRead = await stream.ReadAsync(receivedData.AsMemory(totalRead, totalExpected - totalRead), cts.Token);
            if (bytesRead == 0) break;
            totalRead += bytesRead;
        }

        // Assert
        Assert.Equal(totalExpected, totalRead);
        Assert.Equal(allSentData.ToArray(), receivedData);
    }

    [Theory]
    [InlineData("aes-128-gcm")]
    [InlineData("aes-192-gcm")]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    public async Task DataIntegrity_DifferentEncryptionMethods_ShouldWork(string method)
    {
        // Arrange - 使用指定加密方法创建新的服务器
        var ssPort = GetAvailablePort();
        var proxyPort = GetAvailablePort();
        var echoPort = GetAvailablePort();

        await using var ssServer = new MockShadowsocksServer(ssPort, "test-password", method);
        ssServer.Start();

        await using var echoServer = new MockEchoServer(echoPort);
        echoServer.Start();

        var config = new SsServerConfig
        {
            Host = "127.0.0.1",
            Port = ssPort,
            Password = "test-password",
            Method = method,
            LocalPort = proxyPort,
            Timeout = 30
        };

        await using var proxyServer = new TestProxyHost(config, proxyPort);
        await proxyServer.StartAsync();
        await Task.Delay(100);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", proxyPort);
        using var stream = client.GetStream();

        // SOCKS5 握手和连接
        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var handshake = new byte[2];
        await stream.ReadAsync(handshake);

        var connect = new byte[]
        {
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            (byte)(echoPort >> 8), (byte)(echoPort & 0xFF)
        };
        await stream.WriteAsync(connect);
        var connectResponse = new byte[10];
        await stream.ReadAsync(connectResponse);
        Assert.Equal(0x00, connectResponse[1]);

        // Act - 发送测试数据
        var testData = Encoding.UTF8.GetBytes($"Test data for {method}");
        await stream.WriteAsync(testData);
        await stream.FlushAsync();

        // 读取回显
        var receivedData = new byte[testData.Length];
        var totalRead = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        
        while (totalRead < testData.Length && !cts.Token.IsCancellationRequested)
        {
            var bytesRead = await stream.ReadAsync(receivedData.AsMemory(totalRead), cts.Token);
            if (bytesRead == 0) break;
            totalRead += bytesRead;
        }

        // Assert
        Assert.Equal(testData.Length, totalRead);
        Assert.Equal(testData, receivedData);
    }
}

/// <summary>
/// Echo 服务器 - 原样返回收到的数据
/// </summary>
public class MockEchoServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptTask;

    public int Port { get; }

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

                // Echo back
                await stream.WriteAsync(buffer.AsMemory(0, bytesRead), ct);
                await stream.FlushAsync(ct);
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
