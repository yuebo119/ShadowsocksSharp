using System.Text;
using ShadowsocksSharp.Shadowsocks.Encryption;
using Xunit;

namespace ShadowsocksSharp.Tests;

/// <summary>
/// 加密器单元测试 - 测试 AEAD 加密/解密的正确性
/// </summary>
public class EncryptorTests
{
    private const string TestPassword = "test-password-123";

    [Theory]
    [InlineData("aes-128-gcm")]
    [InlineData("aes-192-gcm")]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    [InlineData("xchacha20-ietf-poly1305")]
    public void Create_WithSupportedMethod_ShouldSucceed(string method)
    {
        // Act
        var encryptor = EncryptorFactory.Create(method, TestPassword);

        // Assert
        Assert.NotNull(encryptor);
        encryptor.Dispose();
    }

    [Fact]
    public void Create_WithUnsupportedMethod_ShouldThrowNotSupportedException()
    {
        // Arrange
        var unsupportedMethod = "unsupported-method";

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => 
            EncryptorFactory.Create(unsupportedMethod, TestPassword));
    }

    [Fact]
    public void IsMethodSupported_WithSupportedMethod_ShouldReturnTrue()
    {
        // Assert
        Assert.True(EncryptorFactory.IsSupported("aes-256-gcm"));
        Assert.True(EncryptorFactory.IsSupported("AES-256-GCM")); // 大小写不敏感
        Assert.True(EncryptorFactory.IsSupported("chacha20-ietf-poly1305"));
        Assert.True(EncryptorFactory.IsSupported("xchacha20-ietf-poly1305"));
    }

    [Fact]
    public void IsMethodSupported_WithUnsupportedMethod_ShouldReturnFalse()
    {
        Assert.False(EncryptorFactory.IsSupported("unsupported"));
    }

    [Theory]
    [InlineData("aes-128-gcm")]
    [InlineData("aes-192-gcm")]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    [InlineData("xchacha20-ietf-poly1305")]
    public void EncryptDecrypt_SmallData_ShouldReturnOriginalData(string method)
    {
        // Arrange
        var encryptor = EncryptorFactory.Create(method, TestPassword);
        var decryptor = EncryptorFactory.Create(method, TestPassword);
        
        var originalData = "Hello, Shadowsocks!"u8.ToArray();
        var encryptBuffer = new byte[originalData.Length + 1024];
        var decryptBuffer = new byte[originalData.Length + 1024];

        // Act
        encryptor.Encrypt(originalData, originalData.Length, encryptBuffer, out var encryptedLength);
        decryptor.Decrypt(encryptBuffer, encryptedLength, decryptBuffer, out var decryptedLength);

        // Assert
        Assert.Equal(originalData.Length, decryptedLength);
        Assert.Equal(originalData, decryptBuffer[..decryptedLength]);

        encryptor.Dispose();
        decryptor.Dispose();
    }

    [Theory]
    [InlineData("aes-128-gcm")]
    [InlineData("aes-192-gcm")]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    [InlineData("xchacha20-ietf-poly1305")]
    public void EncryptDecrypt_LargeData_ShouldReturnOriginalData(string method)
    {
        // Arrange
        var encryptor = EncryptorFactory.Create(method, TestPassword);
        var decryptor = EncryptorFactory.Create(method, TestPassword);
        
        // 生成 64KB 随机数据 - 大于单个 AEAD 包的最大大小 (16383)
        var originalData = new byte[65536];
        Random.Shared.NextBytes(originalData);
        
        // 需要更大的缓冲区来容纳分块加密的开销
        var encryptBuffer = new byte[originalData.Length + 1024 * 10];
        var decryptBuffer = new byte[originalData.Length + 1024 * 10];

        // Act
        encryptor.Encrypt(originalData, originalData.Length, encryptBuffer, out var encryptedLength);
        decryptor.Decrypt(encryptBuffer, encryptedLength, decryptBuffer, out var decryptedLength);

        // Assert
        Assert.Equal(originalData.Length, decryptedLength);
        Assert.Equal(originalData, decryptBuffer[..decryptedLength]);

        encryptor.Dispose();
        decryptor.Dispose();
    }

    [Theory]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    [InlineData("xchacha20-ietf-poly1305")]
    public void EncryptDecrypt_MultipleChunks_ShouldReturnOriginalData(string method)
    {
        // Arrange
        var encryptor = EncryptorFactory.Create(method, TestPassword);
        var decryptor = EncryptorFactory.Create(method, TestPassword);

        var chunk1 = "First chunk of data"u8.ToArray();
        var chunk2 = "Second chunk of data"u8.ToArray();
        var chunk3 = "Third chunk of data"u8.ToArray();

        var encryptBuffer = new byte[2048];
        var decryptBuffer = new byte[2048];
        var allDecrypted = new List<byte>();

        // Act - 加密多个数据块
        encryptor.Encrypt(chunk1, chunk1.Length, encryptBuffer, out var enc1Len);
        decryptor.Decrypt(encryptBuffer, enc1Len, decryptBuffer, out var dec1Len);
        allDecrypted.AddRange(decryptBuffer[..dec1Len]);

        encryptor.Encrypt(chunk2, chunk2.Length, encryptBuffer, out var enc2Len);
        decryptor.Decrypt(encryptBuffer, enc2Len, decryptBuffer, out var dec2Len);
        allDecrypted.AddRange(decryptBuffer[..dec2Len]);

        encryptor.Encrypt(chunk3, chunk3.Length, encryptBuffer, out var enc3Len);
        decryptor.Decrypt(encryptBuffer, enc3Len, decryptBuffer, out var dec3Len);
        allDecrypted.AddRange(decryptBuffer[..dec3Len]);

        // Assert
        var expectedData = chunk1.Concat(chunk2).Concat(chunk3).ToArray();
        Assert.Equal(expectedData, allDecrypted.ToArray());

        encryptor.Dispose();
        decryptor.Dispose();
    }

    [Theory]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    [InlineData("xchacha20-ietf-poly1305")]
    public void Decrypt_SplitPackets_ShouldHandleCorrectly(string method)
    {
        // Arrange - 测试 TCP 流分片场景
        var encryptor = EncryptorFactory.Create(method, TestPassword);
        var decryptor = EncryptorFactory.Create(method, TestPassword);

        var originalData = "This is a test message for split packet scenario"u8.ToArray();
        var encryptBuffer = new byte[originalData.Length + 1024];
        var decryptBuffer = new byte[originalData.Length + 1024];

        // Act - 加密
        encryptor.Encrypt(originalData, originalData.Length, encryptBuffer, out var encryptedLength);

        // 模拟 TCP 分片：将加密数据分成多个小块发送
        var allDecrypted = new List<byte>();
        var offset = 0;
        var chunkSize = 10; // 每次只发送 10 字节

        while (offset < encryptedLength)
        {
            var remaining = encryptedLength - offset;
            var currentChunkSize = Math.Min(chunkSize, remaining);
            var chunk = encryptBuffer[offset..(offset + currentChunkSize)];

            decryptor.Decrypt(chunk, currentChunkSize, decryptBuffer, out var decLen);
            if (decLen > 0)
            {
                allDecrypted.AddRange(decryptBuffer[..decLen]);
            }

            offset += currentChunkSize;
        }

        // Assert
        Assert.Equal(originalData, allDecrypted.ToArray());

        encryptor.Dispose();
        decryptor.Dispose();
    }

    [Theory]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    [InlineData("xchacha20-ietf-poly1305")]
    public void Encrypt_ShouldIncludeSaltOnFirstCall(string method)
    {
        // Arrange
        var encryptor = EncryptorFactory.Create(method, TestPassword);
        var data = "test"u8.ToArray();
        var buffer1 = new byte[1024];
        var buffer2 = new byte[1024];

        // Act
        encryptor.Encrypt(data, data.Length, buffer1, out var len1);
        encryptor.Encrypt(data, data.Length, buffer2, out var len2);

        // Assert - 第一次加密应该包含 salt (32 字节)
        // 后续加密不包含 salt，所以长度应该更短
        Assert.True(len1 > len2);

        encryptor.Dispose();
    }

    [Theory]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    [InlineData("xchacha20-ietf-poly1305")]
    public void EncryptDecrypt_EmptyData_ShouldHandleGracefully(string method)
    {
        // Arrange
        var encryptor = EncryptorFactory.Create(method, TestPassword);
        var decryptor = EncryptorFactory.Create(method, TestPassword);
        
        var emptyData = Array.Empty<byte>();
        var encryptBuffer = new byte[1024];
        var decryptBuffer = new byte[1024];

        // Act
        encryptor.Encrypt(emptyData, 0, encryptBuffer, out var encryptedLength);
        decryptor.Decrypt(encryptBuffer, encryptedLength, decryptBuffer, out var decryptedLength);

        // Assert
        Assert.Equal(0, decryptedLength);

        encryptor.Dispose();
        decryptor.Dispose();
    }

    [Theory]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    [InlineData("xchacha20-ietf-poly1305")]
    public void EncryptDecrypt_BinaryData_ShouldPreserveAllBytes(string method)
    {
        // Arrange - 测试所有可能的字节值
        var encryptor = EncryptorFactory.Create(method, TestPassword);
        var decryptor = EncryptorFactory.Create(method, TestPassword);

        var originalData = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            originalData[i] = (byte)i;
        }

        var encryptBuffer = new byte[originalData.Length + 1024];
        var decryptBuffer = new byte[originalData.Length + 1024];

        // Act
        encryptor.Encrypt(originalData, originalData.Length, encryptBuffer, out var encryptedLength);
        decryptor.Decrypt(encryptBuffer, encryptedLength, decryptBuffer, out var decryptedLength);

        // Assert
        Assert.Equal(originalData.Length, decryptedLength);
        Assert.Equal(originalData, decryptBuffer[..decryptedLength]);

        encryptor.Dispose();
        decryptor.Dispose();
    }

    [Theory]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    [InlineData("xchacha20-ietf-poly1305")]
    public void EncryptDecrypt_ExactMaxPayloadSize_ShouldWork(string method)
    {
        // Arrange - 测试恰好等于最大负载大小的数据
        var encryptor = EncryptorFactory.Create(method, TestPassword);
        var decryptor = EncryptorFactory.Create(method, TestPassword);

        var originalData = new byte[0x3FFF]; // 16383 - 最大负载大小
        Random.Shared.NextBytes(originalData);

        var encryptBuffer = new byte[originalData.Length + 1024];
        var decryptBuffer = new byte[originalData.Length + 1024];

        // Act
        encryptor.Encrypt(originalData, originalData.Length, encryptBuffer, out var encryptedLength);
        decryptor.Decrypt(encryptBuffer, encryptedLength, decryptBuffer, out var decryptedLength);

        // Assert
        Assert.Equal(originalData.Length, decryptedLength);
        Assert.Equal(originalData, decryptBuffer[..decryptedLength]);

        encryptor.Dispose();
        decryptor.Dispose();
    }

    [Theory]
    [InlineData("aes-256-gcm")]
    [InlineData("chacha20-ietf-poly1305")]
    [InlineData("xchacha20-ietf-poly1305")]
    public void EncryptDecrypt_JustOverMaxPayloadSize_ShouldSplitIntoTwoChunks(string method)
    {
        // Arrange - 测试刚好超过最大负载大小的数据
        var encryptor = EncryptorFactory.Create(method, TestPassword);
        var decryptor = EncryptorFactory.Create(method, TestPassword);

        var originalData = new byte[0x3FFF + 1]; // 16384 - 需要分成两块
        Random.Shared.NextBytes(originalData);

        var encryptBuffer = new byte[originalData.Length + 2048];
        var decryptBuffer = new byte[originalData.Length + 2048];

        // Act
        encryptor.Encrypt(originalData, originalData.Length, encryptBuffer, out var encryptedLength);
        decryptor.Decrypt(encryptBuffer, encryptedLength, decryptBuffer, out var decryptedLength);

        // Assert
        Assert.Equal(originalData.Length, decryptedLength);
        Assert.Equal(originalData, decryptBuffer[..decryptedLength]);

        encryptor.Dispose();
        decryptor.Dispose();
    }

    /// <summary>
    /// 测试 XChaCha20 特有的 24 字节 nonce
    /// </summary>
    [Fact]
    public void XChaCha20_ShouldUse24ByteNonce()
    {
        // Arrange
        var encryptor = EncryptorFactory.Create("xchacha20-ietf-poly1305", TestPassword);
        var decryptor = EncryptorFactory.Create("xchacha20-ietf-poly1305", TestPassword);
        
        // 测试多次加密以确保 nonce 递增正常工作
        var testData = "XChaCha20 test with 24-byte nonce"u8.ToArray();
        var encryptBuffer = new byte[1024];
        var decryptBuffer = new byte[1024];

        // Act - 多次加密/解密
        for (int i = 0; i < 10; i++)
        {
            encryptor.Encrypt(testData, testData.Length, encryptBuffer, out var encLen);
            decryptor.Decrypt(encryptBuffer, encLen, decryptBuffer, out var decLen);

            // Assert
            Assert.Equal(testData.Length, decLen);
            Assert.Equal(testData, decryptBuffer[..decLen]);
        }

        encryptor.Dispose();
        decryptor.Dispose();
    }

    /// <summary>
    /// 测试不同加密方法产生不同的密文
    /// </summary>
    [Fact]
    public void DifferentMethods_ShouldProduceDifferentCiphertext()
    {
        // Arrange
        var testData = "Test data"u8.ToArray();
        var methods = new[] { "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305" };
        var ciphertexts = new List<byte[]>();

        // Act
        foreach (var method in methods)
        {
            var encryptor = EncryptorFactory.Create(method, TestPassword);
            var buffer = new byte[1024];
            encryptor.Encrypt(testData, testData.Length, buffer, out var len);
            ciphertexts.Add(buffer[..len]);
            encryptor.Dispose();
        }

        // Assert - 所有密文应该不同
        for (int i = 0; i < ciphertexts.Count; i++)
        {
            for (int j = i + 1; j < ciphertexts.Count; j++)
            {
                Assert.NotEqual(ciphertexts[i], ciphertexts[j]);
            }
        }
    }
}
