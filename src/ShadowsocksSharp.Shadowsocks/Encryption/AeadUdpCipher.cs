using System.Security.Cryptography;
using NaClChaCha = NaCl.Core.ChaCha20Poly1305;
using NaClXChaCha = NaCl.Core.XChaCha20Poly1305;

namespace ShadowsocksSharp.Shadowsocks.Encryption;

public static class AeadUdpCipher
{
    public static int Encrypt(string method, string password, ReadOnlySpan<byte> plaintext, Span<byte> output)
    {
        var info = EncryptorFactory.GetCipherInfo(method);
        var masterKey = EncryptorFactory.GetMasterKey(method, password);

        var salt = output.Slice(0, info.SaltSize);
        RandomNumberGenerator.Fill(salt);
        var subkey = DeriveSubkey(masterKey, salt, info.KeySize);

        var nonce = new byte[info.NonceSize];
        var tag = output.Slice(info.SaltSize + plaintext.Length, info.TagSize);
        var cipher = output.Slice(info.SaltSize, plaintext.Length);

        EncryptBlock(info, subkey, nonce, plaintext, cipher, tag);
        return info.SaltSize + plaintext.Length + info.TagSize;
    }

    public static int Decrypt(string method, string password, ReadOnlySpan<byte> ciphertext, Span<byte> output)
    {
        var info = EncryptorFactory.GetCipherInfo(method);
        if (ciphertext.Length < info.SaltSize + info.TagSize)
            return 0;

        var masterKey = EncryptorFactory.GetMasterKey(method, password);
        var salt = ciphertext.Slice(0, info.SaltSize);
        var subkey = DeriveSubkey(masterKey, salt, info.KeySize);

        var nonce = new byte[info.NonceSize];
        var dataLen = ciphertext.Length - info.SaltSize - info.TagSize;
        var cipher = ciphertext.Slice(info.SaltSize, dataLen);
        var tag = ciphertext.Slice(info.SaltSize + dataLen, info.TagSize);

        DecryptBlock(info, subkey, nonce, cipher, tag, output.Slice(0, dataLen));
        return dataLen;
    }

    private static void EncryptBlock(CipherInfo info, byte[] key, byte[] nonce, ReadOnlySpan<byte> plain, Span<byte> cipher, Span<byte> tag)
    {
        if (info.Type == CipherType.AesGcm)
        {
            using var aes = new AesGcm(key, info.TagSize);
            aes.Encrypt(nonce, plain, cipher, tag);
            return;
        }

        if (info.Type == CipherType.ChaCha20Poly1305)
        {
            if (ChaCha20Poly1305.IsSupported)
            {
                using var chacha = new ChaCha20Poly1305(key);
                chacha.Encrypt(nonce, plain, cipher, tag);
            }
            else
            {
                using var nacl = new NaClChaCha(key);
                nacl.Encrypt(nonce, plain, cipher, tag, ReadOnlySpan<byte>.Empty);
            }
            return;
        }

        if (info.Type == CipherType.XChaCha20Poly1305)
        {
            using var nacl = new NaClXChaCha(key);
            nacl.Encrypt(nonce, plain, cipher, tag, ReadOnlySpan<byte>.Empty);
        }
    }

    private static void DecryptBlock(CipherInfo info, byte[] key, byte[] nonce, ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> tag, Span<byte> plain)
    {
        if (info.Type == CipherType.AesGcm)
        {
            using var aes = new AesGcm(key, info.TagSize);
            aes.Decrypt(nonce, cipher, tag, plain);
            return;
        }

        if (info.Type == CipherType.ChaCha20Poly1305)
        {
            if (ChaCha20Poly1305.IsSupported)
            {
                using var chacha = new ChaCha20Poly1305(key);
                chacha.Decrypt(nonce, cipher, tag, plain);
            }
            else
            {
                using var nacl = new NaClChaCha(key);
                nacl.Decrypt(nonce, cipher, tag, plain, ReadOnlySpan<byte>.Empty);
            }
            return;
        }

        if (info.Type == CipherType.XChaCha20Poly1305)
        {
            using var nacl = new NaClXChaCha(key);
            nacl.Decrypt(nonce, cipher, tag, plain, ReadOnlySpan<byte>.Empty);
        }
    }

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
}
