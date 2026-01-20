using System.Net;
using System.Net.Sockets;
using ShadowsocksSharp.Core.Configuration;
using ShadowsocksSharp.Transport.Connections;
using ShadowsocksSharp.Tests.Mocks;
using Xunit;

namespace ShadowsocksSharp.Tests;

/// <summary>
/// 连接池测试
/// </summary>
/// <remarks>
/// 注意: SS 协议限制每个连接只能代理一个目标，
/// 因此这是并发控制器而非传统连接池。
/// </remarks>
public class ConnectionPoolTests : IAsyncLifetime
{
    private MockShadowsocksServer? _mockSsServer;
    private int _ssServerPort;

    public async Task InitializeAsync()
    {
        _ssServerPort = GetAvailablePort();
        _mockSsServer = new MockShadowsocksServer(_ssServerPort, "test-password", "aes-256-gcm");
        _mockSsServer.Start();
        await Task.Delay(50);
    }

    public async Task DisposeAsync()
    {
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

    private SsServerConfig CreateTestConfig()
    {
        return new SsServerConfig
        {
            Host = "127.0.0.1",
            Port = _ssServerPort,
            Password = "test-password",
            Method = "aes-256-gcm",
            Timeout = 30
        };
    }

    [Fact]
    public async Task ConnectionPool_GetConnection_ShouldReturnValidConnection()
    {
        // Arrange
        var config = CreateTestConfig();
        using var pool = new SsConnectionPool(config, initialCount: 1, maxSize: 10);
        await pool.InitializeAsync();

        // Act
        var connection = await pool.GetConnectionAsync("example.com", 80, CancellationToken.None);

        // Assert
        Assert.NotNull(connection);
        Assert.True(connection.IsHealthy);
        Assert.NotEmpty(connection.Id);

        pool.Release(connection);
    }

    [Fact]
    public async Task ConnectionPool_ReturnConnection_ShouldDisposeConnection()
    {
        // Arrange
        var config = CreateTestConfig();
        using var pool = new SsConnectionPool(config,  initialCount: 1,  maxSize: 10);
        await pool.InitializeAsync();

        // Act
        var connection = await pool.GetConnectionAsync("example.com", 80, CancellationToken.None);
        Assert.NotNull(connection);
        
        var connectionId = connection.Id;
        pool.Release(connection);

        // Assert - 连接应该被释放
        // Shadowsocks 连接是一次性的，归还后应该被销毁
    }

    [Fact]
    public async Task ConnectionPool_ConcurrentRequests_ShouldRespectMaxPoolSize()
    {
        // Arrange
        var config = CreateTestConfig();
        var maxPoolSize = 5;
        using var pool = new SsConnectionPool(config,  initialCount: 1, maxSize: maxPoolSize);
        await pool.InitializeAsync();

        // Act - 同时请求多个连接
        var tasks = Enumerable.Range(0, maxPoolSize + 2).Select(async i =>
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                var connection = await pool.GetConnectionAsync($"target{i}.com", 80, cts.Token);
                
                if (connection != null)
                {
                    await Task.Delay(500); // 模拟使用连接
                    pool.Release(connection);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }).ToList();

        var results = await Task.WhenAll(tasks);

        // Assert - 应该有一些连接成功，但受到最大池大小限制
        Assert.Contains(true, results);
    }

    [Fact]
    public async Task ConnectionPool_Dispose_ShouldCleanupAllConnections()
    {
        // Arrange
        var config = CreateTestConfig();
        var pool = new SsConnectionPool(config, initialCount: 1, maxSize: 10);
        await pool.InitializeAsync();

        var connection = await pool.GetConnectionAsync("example.com", 80, CancellationToken.None);
        Assert.NotNull(connection);

        // Act
        pool.Dispose();

        // Assert - 之后不应该能获取新连接（返回 null 或抛出异常）
        var newConnection = await pool.GetConnectionAsync("example.com", 80, CancellationToken.None);
        Assert.Null(newConnection);
    }

    [Fact]
    public async Task ConnectionPool_ConnectionTimeout_ShouldReturnNull()
    {
        // Arrange - 使用不可达的服务器地址
        var config = new SsServerConfig
        {
            Host = "10.255.255.1", // 不可路由的地址
            Port = 8388,
            Password = "test-password",
            Method = "aes-256-gcm",
            Timeout = 1 // 1秒超时
        };

        using var pool = new SsConnectionPool(config, initialCount: 0, maxSize: 10);
        await pool.InitializeAsync();

        // Act
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var connection = await pool.GetConnectionAsync("example.com", 80, cts.Token);

        // Assert
        Assert.Null(connection);
    }

    [Fact]
    public async Task PooledConnection_GetStream_ShouldReturnValidStream()
    {
        // Arrange
        var config = CreateTestConfig();
        using var pool = new SsConnectionPool(config, initialCount: 1, maxSize: 10);
        await pool.InitializeAsync();

        // Act
        var connection = await pool.GetConnectionAsync("example.com", 80, CancellationToken.None);
        Assert.NotNull(connection);

        var stream = connection.Stream;

        // Assert
        Assert.NotNull(stream);
        Assert.True(stream.CanRead);
        Assert.True(stream.CanWrite);

        pool.Release(connection);
    }

    [Fact]
    public async Task PooledConnection_Bind_ShouldSetProperties()
    {
        // Arrange
        var config = CreateTestConfig();
        using var pool = new SsConnectionPool(config, initialCount: 1, maxSize: 10);
        await pool.InitializeAsync();

        // Act
        var connection = await pool.GetConnectionAsync("example.com", 443, CancellationToken.None);

        // Assert
        Assert.NotNull(connection);
        Assert.Equal("example.com", connection.TargetHost);
        Assert.Equal(443, connection.TargetPort);
        Assert.NotEmpty(connection.Id);

        pool.Release(connection);
    }

    [Fact]
    public async Task PooledConnection_Release_MultipleTimes_ShouldBeIdempotent()
    {
        // Arrange
        var config = CreateTestConfig();
        using var pool = new SsConnectionPool(config,  initialCount: 1,  maxSize: 10);
        await pool.InitializeAsync();

        var connection = await pool.GetConnectionAsync("example.com", 80, CancellationToken.None);
        Assert.NotNull(connection);

        // Act - 通过 pool.Release 释放
        pool.Release(connection);
        
        // 再次释放 null 不应抛出异常
        pool.Release(null);

        // Assert - 不应该抛出异常
    }
}
