using System.Net;
using System.Net.Sockets;
using System.Text;
using ShadowsocksSharp.Shadowsocks.Encryption;

namespace ShadowsocksSharp.Tests.Mocks;

/// <summary>
/// 模拟 Shadowsocks 服务器 - 用于端到端测试
/// </summary>
public class MockShadowsocksServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly string _password;
    private readonly string _method;
    private CancellationTokenSource? _cts;
    private Task? _acceptTask;
    private readonly List<MockTargetServer> _targetServers = [];

    public int Port { get; }
    public List<string> ReceivedRequests { get; } = [];

    public MockShadowsocksServer(int port, string password, string method = "aes-256-gcm")
    {
        Port = port;
        _password = password;
        _method = method;
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
            catch
            {
                // 忽略其他异常
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using var _ = client;
        using var stream = client.GetStream();
        var decryptor = EncryptorFactory.Create(_method, _password);
        var encryptor = EncryptorFactory.Create(_method, _password);

        try
        {
            var buffer = new byte[65536];
            var decryptBuffer = new byte[131072];

            // 读取并解密第一个数据包（包含目标地址）
            var bytesRead = await stream.ReadAsync(buffer, ct);
            if (bytesRead == 0) return;

            decryptor.Decrypt(buffer, bytesRead, decryptBuffer, out var decryptedLength);
            if (decryptedLength == 0) return;

            // 解析目标地址
            var (targetAddress, targetPort, headerLength) = ParseTargetAddress(decryptBuffer, decryptedLength);
            ReceivedRequests.Add($"{targetAddress}:{targetPort}");

            // 连接到目标服务器
            var targetClient = new TcpClient();
            await targetClient.ConnectAsync(targetAddress, targetPort, ct);
            using var targetStream = targetClient.GetStream();

            // 转发初始请求数据（去掉地址头）
            if (decryptedLength > headerLength)
            {
                await targetStream.WriteAsync(decryptBuffer.AsMemory(headerLength, decryptedLength - headerLength), ct);
            }

            // 双向转发
            var clientToTarget = ForwardAsync(stream, targetStream, decryptor, true, ct);
            var targetToClient = ForwardAsync(targetStream, stream, encryptor, false, ct);

            await Task.WhenAny(clientToTarget, targetToClient);
        }
        catch
        {
            // 连接处理中的异常
        }
        finally
        {
            decryptor.Dispose();
            encryptor.Dispose();
        }
    }

    private static async Task ForwardAsync(NetworkStream source, NetworkStream dest, IEncryptor crypto, bool decrypt, CancellationToken ct)
    {
        var buffer = new byte[65536];
        var processBuffer = new byte[131072];

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var bytesRead = await source.ReadAsync(buffer, ct);
                if (bytesRead == 0) break;

                if (decrypt)
                {
                    crypto.Decrypt(buffer, bytesRead, processBuffer, out var len);
                    if (len > 0)
                        await dest.WriteAsync(processBuffer.AsMemory(0, len), ct);
                }
                else
                {
                    crypto.Encrypt(buffer, bytesRead, processBuffer, out var len);
                    await dest.WriteAsync(processBuffer.AsMemory(0, len), ct);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch { }
    }

    private static (string address, int port, int headerLength) ParseTargetAddress(byte[] buffer, int length)
    {
        var offset = 0;
        var addressType = buffer[offset++];
        string address;

        switch (addressType)
        {
            case 0x01: // IPv4
                address = $"{buffer[offset]}.{buffer[offset + 1]}.{buffer[offset + 2]}.{buffer[offset + 3]}";
                offset += 4;
                break;
            case 0x03: // Domain
                var domainLen = buffer[offset++];
                address = Encoding.ASCII.GetString(buffer, offset, domainLen);
                offset += domainLen;
                break;
            case 0x04: // IPv6
                var ipv6Bytes = new byte[16];
                Array.Copy(buffer, offset, ipv6Bytes, 0, 16);
                address = new IPAddress(ipv6Bytes).ToString();
                offset += 16;
                break;
            default:
                throw new InvalidOperationException($"Unknown address type: {addressType}");
        }

        var port = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        return (address, port, offset);
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
        
        foreach (var server in _targetServers)
        {
            await server.DisposeAsync();
        }
    }
}
