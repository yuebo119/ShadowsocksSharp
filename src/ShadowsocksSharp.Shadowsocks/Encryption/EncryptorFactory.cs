using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using NaClChaCha = NaCl.Core.ChaCha20Poly1305;
using NaClXChaCha = NaCl.Core.XChaCha20Poly1305;

namespace ShadowsocksSharp.Shadowsocks.Encryption;

/// <summary>
/// 加密算法类型
/// </summary>
public enum CipherType
{
    AesGcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305
}

/// <summary>
/// 加密算法参数
/// </summary>
public readonly record struct CipherInfo(int KeySize, int SaltSize, int NonceSize, int TagSize, CipherType Type);

/// <summary>
/// 加密器工厂 - 带 MasterKey 缓存
/// </summary>
public static class EncryptorFactory
{
    private static readonly FrozenDictionary<string, CipherInfo> Methods = new Dictionary<string, CipherInfo>
    {
        ["aes-128-gcm"] = new(16, 16, 12, 16, CipherType.AesGcm),
        ["aes-192-gcm"] = new(24, 24, 12, 16, CipherType.AesGcm),
        ["aes-256-gcm"] = new(32, 32, 12, 16, CipherType.AesGcm),
        ["chacha20-ietf-poly1305"] = new(32, 32, 12, 16, CipherType.ChaCha20Poly1305),
        ["xchacha20-ietf-poly1305"] = new(32, 32, 24, 16, CipherType.XChaCha20Poly1305)
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    private static readonly bool NativeChaChaSupported = ChaCha20Poly1305.IsSupported;

    // MasterKey 缓存：避免每次创建加密器都派生密钥
    private static readonly ConcurrentDictionary<(string password, int keySize), byte[]> MasterKeyCache = new();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IEncryptor Create(string method, string password)
    {
        if (!Methods.TryGetValue(method, out var info))
            throw new NotSupportedException($"Unsupported cipher: {method}");

        // 从缓存获取或派生 MasterKey
        var masterKey = MasterKeyCache.GetOrAdd(
            (password, info.KeySize),
            static key => DeriveKey(key.password, key.keySize));

        return new AeadCipher(masterKey, info, NativeChaChaSupported);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsSupported(string method) => Methods.ContainsKey(method);

    public static IEnumerable<string> GetSupportedMethods() => Methods.Keys;

    internal static CipherInfo GetCipherInfo(string method)
    {
        if (!Methods.TryGetValue(method, out var info))
            throw new NotSupportedException($"Unsupported cipher: {method}");
        return info;
    }

    internal static byte[] GetMasterKey(string method, string password)
    {
        var info = GetCipherInfo(method);
        return MasterKeyCache.GetOrAdd((password, info.KeySize),
            static key => DeriveKey(key.password, key.keySize));
    }

    /// <summary>
    /// 派生 MasterKey（EVP_BytesToKey 兼容）
    /// </summary>
    private static byte[] DeriveKey(string password, int keySize)
    {
        var pwdLen = System.Text.Encoding.UTF8.GetByteCount(password);
        Span<byte> pwdBytes = pwdLen <= 256 ? stackalloc byte[pwdLen] : new byte[pwdLen];
        System.Text.Encoding.UTF8.GetBytes(password, pwdBytes);

        Span<byte> hash = stackalloc byte[16];
        var result = new byte[keySize];
        var offset = 0;

        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);

        while (offset < keySize)
        {
            if (offset == 0)
            {
                md5.AppendData(pwdBytes);
            }
            else
            {
                md5.AppendData(hash);
                md5.AppendData(pwdBytes);
            }

            md5.GetHashAndReset(hash);

            var len = Math.Min(16, keySize - offset);
            hash[..len].CopyTo(result.AsSpan(offset));
            offset += len;
        }

        return result;
    }
}

/// <summary>
/// AEAD 加密器实现 - 专家级优化版本
/// </summary>
/// <remarks>
/// 优化:
/// - MasterKey 缓存：工厂级别缓存，避免每个加密器重复派生
/// - Span 接口：避免 ToArray() 堆分配
/// - ArrayPool：解密缓冲区池化
/// - Unsafe.WriteUnaligned：高效 Nonce 写入
/// - 预计算常量：减少运行时计算
/// </remarks>
public sealed class AeadCipher : IEncryptor
{
    private const int MaxPayload = 0x3FFF;
    private const int ChunkOverhead = 2 + 16 + 16; // len(2) + len_tag(16) + data_tag(16)
    private const int InitialBufferSize = 65536;

    private static readonly ArrayPool<byte> Pool = ArrayPool<byte>.Shared;

    private readonly byte[] _masterKey;
    private readonly CipherInfo _info;
    private readonly bool _useNativeChacha;
    private readonly int _tagSize;
    private readonly int _saltSize;

    // 加密状态
    private byte[]? _encSubkey;
    private ulong _encNonce;
    private bool _saltSent;
    private readonly byte[] _encNonceBuffer;
    private ChaCha20Poly1305? _encChacha;
    private NaClChaCha? _encNaClChacha;
    private NaClXChaCha? _encNaClXChacha;
    private AesGcm? _encAesGcm;

    // 解密状态
    private byte[]? _decSubkey;
    private ulong _decNonce;
    private byte[]? _decBuffer;
    private int _decBufferLen;
    private bool _saltReceived;
    private readonly byte[] _decNonceBuffer;
    private ChaCha20Poly1305? _decChacha;
    private NaClChaCha? _decNaClChacha;
    private NaClXChaCha? _decNaClXChacha;
    private AesGcm? _decAesGcm;

    public AeadCipher(byte[] masterKey, CipherInfo info, bool useNativeChacha = true)
    {
        _masterKey = masterKey;
        _info = info;
        _tagSize = info.TagSize;
        _saltSize = info.SaltSize;
        _useNativeChacha = useNativeChacha && info.Type == CipherType.ChaCha20Poly1305;
        _encNonceBuffer = new byte[info.NonceSize];
        _decNonceBuffer = new byte[info.NonceSize];
    }

    /// <summary>
    /// 计算加密后的最大输出大小
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int GetEncryptedSize(int plaintextLength)
    {
        var chunks = (plaintextLength + MaxPayload - 1) / MaxPayload;
        var overhead = _saltSent ? 0 : _saltSize;
        return overhead + plaintextLength + chunks * ChunkOverhead;
    }

    /// <summary>
    /// 高性能加密（Span 接口）
    /// </summary>
    public void Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> output, out int bytesWritten)
    {
        bytesWritten = 0;

        if (!_saltSent)
        {
            var salt = output[.._saltSize];
            RandomNumberGenerator.Fill(salt);
            _encSubkey = DeriveSubkey(_masterKey, salt, _info.KeySize);
            bytesWritten = _saltSize;
            _saltSent = true;
            InitializeEncryptor(_encSubkey);
        }

        var offset = 0;
        while (offset < plaintext.Length)
        {
            var chunk = Math.Min(MaxPayload, plaintext.Length - offset);
            EncryptChunk(plaintext.Slice(offset, chunk), output[bytesWritten..], out var chunkLen);
            bytesWritten += chunkLen;
            offset += chunk;
        }
    }

    /// <summary>
    /// 高性能解密（Span 接口）
    /// </summary>
    public void Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> output, out int bytesWritten)
    {
        bytesWritten = 0;

        EnsureDecryptBuffer(ciphertext.Length);
        ciphertext.CopyTo(_decBuffer.AsSpan(_decBufferLen));
        _decBufferLen += ciphertext.Length;

        var pos = 0;

        if (!_saltReceived)
        {
            if (_decBufferLen < _saltSize) return;

            _decSubkey = DeriveSubkey(_masterKey, _decBuffer.AsSpan(0, _saltSize), _info.KeySize);
            pos = _saltSize;
            _saltReceived = true;
            InitializeDecryptor(_decSubkey);
        }

        var headerLen = 2 + _tagSize;
        Span<byte> decLen = stackalloc byte[2]; // reuse small buffer to avoid stackalloc in the loop

        while (true)
        {
            var remaining = _decBufferLen - pos;
            if (remaining < headerLen) break;

            WriteNonce(_decNonceBuffer, _decNonce);

            try
            {
                DecryptBlock(_decBuffer.AsSpan(pos, 2), _decBuffer.AsSpan(pos + 2, _tagSize), decLen);
            }
            catch
            {
                throw new InvalidOperationException("Decrypt failed: length tag mismatch");
            }

            var dataLen = (decLen[0] << 8) | decLen[1];
            if (dataLen > MaxPayload)
                throw new InvalidOperationException($"Invalid payload size: {dataLen}");

            var packetLen = headerLen + dataLen + _tagSize;
            if (remaining < packetLen) break;

            _decNonce++;

            var dataPos = pos + headerLen;
            WriteNonce(_decNonceBuffer, _decNonce++);

            try
            {
                DecryptBlock(
                    _decBuffer.AsSpan(dataPos, dataLen),
                    _decBuffer.AsSpan(dataPos + dataLen, _tagSize),
                    output.Slice(bytesWritten, dataLen));
            }
            catch
            {
                throw new InvalidOperationException("Decrypt failed: data tag mismatch");
            }

            bytesWritten += dataLen;
            pos += packetLen;
        }

        CompactDecryptBuffer(pos);
    }

    // 兼容旧接口
    public void Encrypt(byte[] buffer, int length, byte[] outBuffer, out int outLength)
        => Encrypt(buffer.AsSpan(0, length), outBuffer.AsSpan(), out outLength);

    public void Decrypt(byte[] buffer, int length, byte[] outBuffer, out int outLength)
        => Decrypt(buffer.AsSpan(0, length), outBuffer.AsSpan(), out outLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] DeriveSubkey(byte[] key, ReadOnlySpan<byte> salt, int keySize)
    {
        Span<byte> prk = stackalloc byte[20];
        HMACSHA1.HashData(salt, key, prk);

        var info = "ss-subkey"u8;
        var n = (keySize + 19) / 20;
        var okm = new byte[n * 20];

        Span<byte> t = stackalloc byte[20];
        var tLen = 0;
        Span<byte> input = stackalloc byte[20 + info.Length + 1];

        for (var i = 1; i <= n; i++)
        {
            var inputLen = tLen + info.Length + 1;
            var inputSpan = input[..inputLen];

            if (tLen > 0)
                t[..tLen].CopyTo(inputSpan);
            info.CopyTo(inputSpan.Slice(tLen, info.Length));
            inputSpan[^1] = (byte)i;

            HMACSHA1.HashData(prk, inputSpan, okm.AsSpan((i - 1) * 20, 20));
            okm.AsSpan((i - 1) * 20, 20).CopyTo(t);
            tLen = 20;
        }

        return okm[..keySize];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void InitializeEncryptor(byte[] key)
    {
        if (_info.Type == CipherType.AesGcm)
        {
            _encAesGcm = new AesGcm(key, _tagSize);
            return;
        }

        if (_info.Type == CipherType.ChaCha20Poly1305)
        {
            if (_useNativeChacha && ChaCha20Poly1305.IsSupported)
                _encChacha = new ChaCha20Poly1305(key);
            else
                _encNaClChacha = new NaClChaCha(key);
            return;
        }

        if (_info.Type == CipherType.XChaCha20Poly1305)
        {
            _encNaClXChacha = new NaClXChaCha(key);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void InitializeDecryptor(byte[] key)
    {
        if (_info.Type == CipherType.AesGcm)
        {
            _decAesGcm = new AesGcm(key, _tagSize);
            return;
        }

        if (_info.Type == CipherType.ChaCha20Poly1305)
        {
            if (_useNativeChacha && ChaCha20Poly1305.IsSupported)
                _decChacha = new ChaCha20Poly1305(key);
            else
                _decNaClChacha = new NaClChaCha(key);
            return;
        }

        if (_info.Type == CipherType.XChaCha20Poly1305)
        {
            _decNaClXChacha = new NaClXChaCha(key);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void EncryptChunk(ReadOnlySpan<byte> plain, Span<byte> output, out int outLen)
    {
        outLen = 0;

        Span<byte> lenBytes = stackalloc byte[2];
        lenBytes[0] = (byte)(plain.Length >> 8);
        lenBytes[1] = (byte)(plain.Length & 0xFF);

        WriteNonce(_encNonceBuffer, _encNonce++);
        EncryptBlock(lenBytes, output[..2], output.Slice(2, _tagSize));
        outLen += 2 + _tagSize;

        WriteNonce(_encNonceBuffer, _encNonce++);
        EncryptBlock(plain, output.Slice(outLen, plain.Length), output.Slice(outLen + plain.Length, _tagSize));
        outLen += plain.Length + _tagSize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void EncryptBlock(ReadOnlySpan<byte> plain, Span<byte> cipher, Span<byte> tag)
    {
        if (_encAesGcm != null)
        {
            _encAesGcm.Encrypt(_encNonceBuffer, plain, cipher, tag);
        }
        else if (_encChacha != null)
        {
            _encChacha.Encrypt(_encNonceBuffer, plain, cipher, tag);
        }
        else if (_encNaClChacha != null)
        {
            _encNaClChacha.Encrypt(_encNonceBuffer.AsSpan(0, _info.NonceSize), plain, cipher, tag, ReadOnlySpan<byte>.Empty);
        }
        else if (_encNaClXChacha != null)
        {
            _encNaClXChacha.Encrypt(_encNonceBuffer.AsSpan(0, _info.NonceSize), plain, cipher, tag, ReadOnlySpan<byte>.Empty);
        }
        else
        {
            throw new NotSupportedException("No encryptor available");
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void DecryptBlock(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> tag, Span<byte> plain)
    {
        if (_decAesGcm != null)
        {
            _decAesGcm.Decrypt(_decNonceBuffer, cipher, tag, plain);
        }
        else if (_decChacha != null)
        {
            _decChacha.Decrypt(_decNonceBuffer, cipher, tag, plain);
        }
        else if (_decNaClChacha != null)
        {
            _decNaClChacha.Decrypt(_decNonceBuffer.AsSpan(0, _info.NonceSize), cipher, tag, plain, ReadOnlySpan<byte>.Empty);
        }
        else if (_decNaClXChacha != null)
        {
            _decNaClXChacha.Decrypt(_decNonceBuffer.AsSpan(0, _info.NonceSize), cipher, tag, plain, ReadOnlySpan<byte>.Empty);
        }
        else
        {
            throw new NotSupportedException("No decryptor available");
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void EnsureDecryptBuffer(int additionalLength)
    {
        var required = _decBufferLen + additionalLength;

        if (_decBuffer == null)
        {
            _decBuffer = Pool.Rent(Math.Max(required, InitialBufferSize));
            return;
        }

        if (required > _decBuffer.Length)
        {
            var newSize = Math.Max(required, _decBuffer.Length * 2);
            var newBuf = Pool.Rent(newSize);
            _decBuffer.AsSpan(0, _decBufferLen).CopyTo(newBuf);
            Pool.Return(_decBuffer);
            _decBuffer = newBuf;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void CompactDecryptBuffer(int pos)
    {
        if (pos > 0 && pos < _decBufferLen)
        {
            _decBuffer.AsSpan(pos, _decBufferLen - pos).CopyTo(_decBuffer);
            _decBufferLen -= pos;
        }
        else if (pos >= _decBufferLen)
        {
            _decBufferLen = 0;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteNonce(byte[] buffer, ulong counter)
    {
        Unsafe.WriteUnaligned(ref buffer[0], counter);
        if (buffer.Length > 8)
            buffer.AsSpan(8).Clear();
    }

    public void Dispose()
    {
        _encChacha?.Dispose();
        _encAesGcm?.Dispose();
        _decChacha?.Dispose();
        _decAesGcm?.Dispose();

        if (_decBuffer != null)
        {
            Pool.Return(_decBuffer);
            _decBuffer = null;
        }
    }
}
