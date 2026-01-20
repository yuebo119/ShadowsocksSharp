namespace ShadowsocksSharp.Shadowsocks.Encryption;

/// <summary>
/// AEAD 加密器接口
/// 用于 Shadowsocks 协议的数据加密和解密
/// </summary>
/// <remarks>
/// 实现要求:
/// - 线程不安全，每个连接使用独立实例
/// - Encrypt 首次调用会输出 Salt
/// - Decrypt 支持流式解密，自动缓冲不完整数据
/// </remarks>
public interface IEncryptor : IDisposable
{
    /// <summary>
    /// 加密数据（高性能版本，避免分配）
    /// </summary>
    void Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> output, out int bytesWritten);

    /// <summary>
    /// 解密数据（高性能版本）
    /// </summary>
    void Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> output, out int bytesWritten);

    /// <summary>
    /// 加密数据（兼容版本）
    /// </summary>
    void Encrypt(byte[] buffer, int length, byte[] outBuffer, out int outLength);

    /// <summary>
    /// 解密数据（兼容版本）
    /// </summary>
    void Decrypt(byte[] buffer, int length, byte[] outBuffer, out int outLength);

    /// <summary>
    /// 计算加密后的最大输出大小
    /// </summary>
    int GetEncryptedSize(int plaintextLength);
}
