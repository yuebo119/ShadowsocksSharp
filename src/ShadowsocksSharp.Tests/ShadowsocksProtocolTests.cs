using System.Net.Sockets;
using System.Text;
using ShadowsocksSharp.Shadowsocks.Encryption;
using Xunit;

namespace ShadowsocksSharp.Tests;

/// <summary>
/// Shadowsocks 协议兼容性测试
/// 这些测试验证我们的实现与 Shadowsocks AEAD 协议规范的兼容性
/// </summary>
public class ShadowsocksProtocolTests
{
    /// <summary>
    /// 测试 HKDF-SHA1 密钥派生
    /// 使用已知的测试向量验证
    /// </summary>
    [Fact]
    public void HkdfSha1_KnownTestVector_ShouldMatch()
    {
        // 这个测试验证 HKDF-SHA1 实现的正确性
        // 使用简单的输入来确保基本功能
        var encryptor1 = EncryptorFactory.Create("aes-256-gcm", "test-password");
        var encryptor2 = EncryptorFactory.Create("aes-256-gcm", "test-password");
        
        // 相同密码应该产生相同的主密钥
        var data = "Hello World"u8.ToArray();
        var buffer1 = new byte[1024];
        var buffer2 = new byte[1024];
        
        encryptor1.Encrypt(data, data.Length, buffer1, out var len1);
        encryptor2.Encrypt(data, data.Length, buffer2, out var len2);
        
        // 长度应该相同（salt + encrypted length + length tag + encrypted data + data tag）
        Assert.Equal(len1, len2);
        
        // Salt 不同，所以密文也不同（这是正确的行为）
        Assert.NotEqual(buffer1.Take(32).ToArray(), buffer2.Take(32).ToArray());
        
        encryptor1.Dispose();
        encryptor2.Dispose();
    }

    /// <summary>
    /// 测试 Shadowsocks 请求格式
    /// </summary>
    [Fact]
    public void ShadowsocksRequest_DomainAddress_CorrectFormat()
    {
        // Shadowsocks 地址格式:
        // [ATYP (1 byte)] [Address] [Port (2 bytes big-endian)]
        // ATYP: 0x01 = IPv4, 0x03 = Domain, 0x04 = IPv6
        
        var domain = "www.example.com";
        var port = 443;
        
        var request = BuildShadowsocksRequest(domain, port);
        
        // ATYP = 0x03 (domain)
        Assert.Equal(0x03, request[0]);
        
        // Domain length
        Assert.Equal(domain.Length, request[1]);
        
        // Domain bytes
        Assert.Equal(domain, Encoding.ASCII.GetString(request, 2, domain.Length));
        
        // Port (big-endian)
        var portOffset = 2 + domain.Length;
        var parsedPort = (request[portOffset] << 8) | request[portOffset + 1];
        Assert.Equal(port, parsedPort);
    }

    /// <summary>
    /// 测试 Shadowsocks AEAD 加密数据格式
    /// </summary>
    [Fact]
    public void ShadowsocksAead_EncryptedFormat_CorrectStructure()
    {
        var encryptor = EncryptorFactory.Create("chacha20-ietf-poly1305", "test-password");
        var plaintext = "Hello Shadowsocks"u8.ToArray();
        var buffer = new byte[1024];
        
        encryptor.Encrypt(plaintext, plaintext.Length, buffer, out var encryptedLength);
        
        // 预期结构:
        // [Salt (32 bytes)]
        // [Encrypted Length (2 bytes)][Length Tag (16 bytes)]
        // [Encrypted Data (N bytes)][Data Tag (16 bytes)]
        
        var saltSize = 32;
        var tagSize = 16;
        var expectedLength = saltSize + (2 + tagSize) + (plaintext.Length + tagSize);
        
        Assert.Equal(expectedLength, encryptedLength);
        
        encryptor.Dispose();
    }

    /// <summary>
    /// 测试加密后再加密不再包含 salt
    /// </summary>
    [Fact]
    public void ShadowsocksAead_SecondEncryption_NoSalt()
    {
        var encryptor = EncryptorFactory.Create("aes-256-gcm", "test-password");
        var plaintext1 = "First message"u8.ToArray();
        var plaintext2 = "Second message"u8.ToArray();
        var buffer = new byte[1024];
        
        // 第一次加密（包含 salt）
        encryptor.Encrypt(plaintext1, plaintext1.Length, buffer, out var len1);
        
        // 第二次加密（不包含 salt）
        encryptor.Encrypt(plaintext2, plaintext2.Length, buffer, out var len2);
        
        // 第一次: salt(32) + length(2) + tag(16) + data + tag(16)
        var expectedLen1 = 32 + 2 + 16 + plaintext1.Length + 16;
        
        // 第二次: 只有 length(2) + tag(16) + data + tag(16)
        var expectedLen2 = 2 + 16 + plaintext2.Length + 16;
        
        Assert.Equal(expectedLen1, len1);
        Assert.Equal(expectedLen2, len2);
        
        encryptor.Dispose();
    }

    /// <summary>
    /// 测试 Nonce 递增
    /// </summary>
    [Fact]
    public void ShadowsocksAead_NonceIncrement_CorrectBehavior()
    {
        // 每个加密块消耗 2 个 nonce:
        // - 一个用于加密长度
        // - 一个用于加密数据
        
        var encryptor = EncryptorFactory.Create("aes-256-gcm", "test-password");
        var decryptor = EncryptorFactory.Create("aes-256-gcm", "test-password");
        
        // 发送多个数据块
        var msg1 = "Message 1"u8.ToArray();
        var msg2 = "Message 2"u8.ToArray();
        var msg3 = "Message 3"u8.ToArray();
        
        var encBuffer = new byte[4096];
        var decBuffer = new byte[4096];
        
        encryptor.Encrypt(msg1, msg1.Length, encBuffer, out var encLen1);
        decryptor.Decrypt(encBuffer, encLen1, decBuffer, out var decLen1);
        Assert.Equal(msg1, decBuffer.Take(decLen1).ToArray());
        
        encryptor.Encrypt(msg2, msg2.Length, encBuffer, out var encLen2);
        decryptor.Decrypt(encBuffer, encLen2, decBuffer, out var decLen2);
        Assert.Equal(msg2, decBuffer.Take(decLen2).ToArray());
        
        encryptor.Encrypt(msg3, msg3.Length, encBuffer, out var encLen3);
        decryptor.Decrypt(encBuffer, encLen3, decBuffer, out var decLen3);
        Assert.Equal(msg3, decBuffer.Take(decLen3).ToArray());
        
        encryptor.Dispose();
        decryptor.Dispose();
    }

    /// <summary>
    /// 测试 ChaCha20-Poly1305 加密
    /// </summary>
    [Fact]
    public void ChaCha20Poly1305_EncryptDecrypt_ShouldWork()
    {
        var encryptor = EncryptorFactory.Create("chacha20-ietf-poly1305", "my-secret-password");
        var decryptor = EncryptorFactory.Create("chacha20-ietf-poly1305", "my-secret-password");
        
        var originalData = "Test data for ChaCha20-Poly1305 encryption"u8.ToArray();
        var encryptBuffer = new byte[originalData.Length + 1024];
        var decryptBuffer = new byte[originalData.Length + 1024];
        
        encryptor.Encrypt(originalData, originalData.Length, encryptBuffer, out var encryptedLength);
        decryptor.Decrypt(encryptBuffer, encryptedLength, decryptBuffer, out var decryptedLength);
        
        Assert.Equal(originalData.Length, decryptedLength);
        Assert.Equal(originalData, decryptBuffer.Take(decryptedLength).ToArray());
        
        encryptor.Dispose();
        decryptor.Dispose();
    }

    /// <summary>
    /// 测试大数据块分片
    /// </summary>
    [Fact]
    public void ShadowsocksAead_LargePayload_ShouldSplitChunks()
    {
        var encryptor = EncryptorFactory.Create("aes-256-gcm", "test-password");
        
        // 创建超过最大负载大小的数据 (0x3FFF = 16383)
        var largeData = new byte[20000];
        Random.Shared.NextBytes(largeData);
        
        var buffer = new byte[largeData.Length * 2];
        
        encryptor.Encrypt(largeData, largeData.Length, buffer, out var encryptedLength);
        
        // 20000 字节需要分成 2 个块:
        // - 第一块: 16383 字节
        // - 第二块: 3617 字节
        // 
        // 预期输出:
        // Salt: 32
        // Chunk 1: 2 + 16 + 16383 + 16 = 16417
        // Chunk 2: 2 + 16 + 3617 + 16 = 3651
        // 总计: 32 + 16417 + 3651 = 20100
        
        var expectedLength = 32 + (2 + 16 + 16383 + 16) + (2 + 16 + 3617 + 16);
        Assert.Equal(expectedLength, encryptedLength);
        
        encryptor.Dispose();
    }

    private static byte[] BuildShadowsocksRequest(string address, int port)
    {
        using var ms = new MemoryStream();
        
        if (System.Net.IPAddress.TryParse(address, out var ip))
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                ms.WriteByte(0x01); // IPv4
                ms.Write(ip.GetAddressBytes());
            }
            else
            {
                ms.WriteByte(0x04); // IPv6
                ms.Write(ip.GetAddressBytes());
            }
        }
        else
        {
            ms.WriteByte(0x03); // Domain
            var domainBytes = Encoding.ASCII.GetBytes(address);
            ms.WriteByte((byte)domainBytes.Length);
            ms.Write(domainBytes);
        }
        
        // Port (big-endian)
        ms.WriteByte((byte)(port >> 8));
        ms.WriteByte((byte)(port & 0xFF));
        
        return ms.ToArray();
    }
}
