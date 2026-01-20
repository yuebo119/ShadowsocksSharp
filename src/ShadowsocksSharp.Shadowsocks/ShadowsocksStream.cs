using System.Buffers;
using System.Net.Sockets;
using ShadowsocksSharp.Shadowsocks.Encryption;

namespace ShadowsocksSharp.Shadowsocks;

public sealed class ShadowsocksStream : IDisposable
{
    private readonly NetworkStream _stream;
    private readonly IEncryptor _encryptor;
    private readonly IEncryptor _decryptor;
    private byte[]? _encryptBuffer;
    private byte[]? _cipherBuffer;
    private byte[]? _decryptBuffer;
    private byte[]? _plainBuffer;
    private int _plainOffset;
    private int _plainCount;
    private bool _disposed;

    public ShadowsocksStream(NetworkStream stream, IEncryptor encryptor, IEncryptor decryptor)
    {
        _stream = stream;
        _encryptor = encryptor;
        _decryptor = decryptor;
    }

    public async Task SendAddressAsync(string host, int port, CancellationToken ct)
    {
        Span<byte> addr = stackalloc byte[260];
        var addrLen = ShadowsocksAddress.WriteAddress(host, port, addr);

        var maxSize = _encryptor.GetEncryptedSize(addrLen);
        var buffer = EnsureBuffer(ref _encryptBuffer, maxSize);
        _encryptor.Encrypt(addr.Slice(0, addrLen), buffer, out var outLen);
        await _stream.WriteAsync(buffer.AsMemory(0, outLen), ct).ConfigureAwait(false);
    }

    public async Task WritePlainAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        var maxSize = _encryptor.GetEncryptedSize(data.Length);
        var buffer = EnsureBuffer(ref _encryptBuffer, maxSize);
        _encryptor.Encrypt(data.Span, buffer, out var outLen);
        if (outLen > 0)
            await _stream.WriteAsync(buffer.AsMemory(0, outLen), ct).ConfigureAwait(false);
    }

    public async Task<int> ReadPlainAsync(Memory<byte> output, CancellationToken ct)
    {
        if (_plainCount > 0)
        {
            var toCopy = Math.Min(output.Length, _plainCount);
            _plainBuffer!.AsSpan(_plainOffset, toCopy).CopyTo(output.Span);
            _plainOffset += toCopy;
            _plainCount -= toCopy;
            if (_plainCount == 0)
            {
                if (_plainBuffer != null && !ReferenceEquals(_plainBuffer, _decryptBuffer))
                    ArrayPool<byte>.Shared.Return(_plainBuffer);
                _plainBuffer = null;
                _plainOffset = 0;
            }
            return toCopy;
        }

        var buffer = EnsureBuffer(ref _cipherBuffer, output.Length + 2048);
        var plainBuffer = EnsureBuffer(ref _decryptBuffer, buffer.Length);
        try
        {
            while (true)
            {
                var n = await _stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                if (n == 0)
                    return 0;

                _decryptor.Decrypt(buffer.AsSpan(0, n), plainBuffer.AsSpan(0, plainBuffer.Length), out var outLen);
                if (outLen <= 0)
                    continue;

                if (outLen <= output.Length)
                {
                    plainBuffer.AsSpan(0, outLen).CopyTo(output.Span);
                    return outLen;
                }

                plainBuffer.AsSpan(0, output.Length).CopyTo(output.Span);
                _plainBuffer = plainBuffer;
                _plainOffset = output.Length;
                _plainCount = outLen - output.Length;
                return output.Length;
            }
        }
        finally { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_plainBuffer != null)
        {
            // _plainBuffer may alias _decryptBuffer; avoid double return.
            if (!ReferenceEquals(_plainBuffer, _decryptBuffer))
                ArrayPool<byte>.Shared.Return(_plainBuffer);
            _plainBuffer = null;
        }
        ReturnBuffer(ref _encryptBuffer);
        ReturnBuffer(ref _cipherBuffer);
        ReturnBuffer(ref _decryptBuffer);
        _encryptor.Dispose();
        _decryptor.Dispose();
        _stream.Dispose();
    }

    private static byte[] EnsureBuffer(ref byte[]? buffer, int size)
    {
        if (buffer == null || buffer.Length < size)
        {
            if (buffer != null)
                ArrayPool<byte>.Shared.Return(buffer);
            buffer = ArrayPool<byte>.Shared.Rent(size);
        }
        return buffer;
    }

    private static void ReturnBuffer(ref byte[]? buffer)
    {
        if (buffer == null)
            return;
        ArrayPool<byte>.Shared.Return(buffer);
        buffer = null;
    }
}
