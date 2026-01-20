using System.Buffers;

namespace ShadowsocksSharp.Transport.Buffers;

/// <summary>
/// 缓冲区池 - 顶级专家优化版本
/// </summary>
/// <remarks>
/// 优化:
/// - 使用 ArrayPool.Shared 全局共享池
/// - 提供固定大小桶避免碎片化
/// - ref struct 避免堆分配
/// - 支持 Span/Memory API
/// </remarks>
public static class BufferPool
{
    public const int SmallBufferSize = 4096;
    public const int MediumBufferSize = 16384;
    public const int LargeBufferSize = 32768;
    public const int ExtraLargeBufferSize = 65536;

    // 使用共享池，性能最佳
    private static readonly ArrayPool<byte> Pool = ArrayPool<byte>.Shared;

    /// <summary>
    /// 租用缓冲区
    /// </summary>
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    public static byte[] Rent(int minimumLength) => Pool.Rent(minimumLength);

    /// <summary>
    /// 归还缓冲区
    /// </summary>
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    public static void Return(byte[]? buffer, bool clearArray = false)
    {
        if (buffer != null)
            Pool.Return(buffer, clearArray);
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    public static byte[] RentSmall() => Pool.Rent(SmallBufferSize);

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    public static byte[] RentMedium() => Pool.Rent(MediumBufferSize);

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    public static byte[] RentLarge() => Pool.Rent(LargeBufferSize);

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    public static byte[] RentExtraLarge() => Pool.Rent(ExtraLargeBufferSize);

    /// <summary>
    /// 租用并返回自动归还的 lease
    /// </summary>
    public static BufferLease RentLease(int minimumLength, bool clearOnReturn = false)
        => new(minimumLength, clearOnReturn);
}

/// <summary>
/// 自动归还的缓冲区租约 - 使用 ref struct 避免堆分配
/// </summary>
public ref struct BufferLease
{
    private byte[]? _buffer;
    private readonly bool _clearOnReturn;

    public readonly byte[] Buffer => _buffer!;
    public readonly int Length { get; }

    public BufferLease(int minimumLength, bool clearOnReturn = false)
    {
        _buffer = BufferPool.Rent(minimumLength);
        _clearOnReturn = clearOnReturn;
        Length = minimumLength;
    }

    public readonly Memory<byte> AsMemory() => _buffer.AsMemory(0, Length);
    public readonly Memory<byte> AsMemory(int start, int length) => _buffer.AsMemory(start, length);
    public readonly Span<byte> AsSpan() => _buffer.AsSpan(0, Length);
    public readonly Span<byte> AsSpan(int start, int length) => _buffer.AsSpan(start, length);

    public void Dispose()
    {
        if (_buffer != null)
        {
            BufferPool.Return(_buffer, _clearOnReturn);
            _buffer = null;
        }
    }

    public static implicit operator byte[](BufferLease lease) => lease._buffer!;
    public static implicit operator Span<byte>(BufferLease lease) => lease._buffer.AsSpan(0, lease.Length);
    public static implicit operator Memory<byte>(BufferLease lease) => lease._buffer.AsMemory(0, lease.Length);
}

/// <summary>
/// 可等待的缓冲区租约 (用于 async 方法)
/// </summary>
public sealed class AsyncBufferLease : IDisposable
{
    private byte[]? _buffer;
    private readonly bool _clearOnReturn;

    public byte[] Buffer => _buffer!;
    public int Length { get; }

    public AsyncBufferLease(int minimumLength, bool clearOnReturn = false)
    {
        _buffer = BufferPool.Rent(minimumLength);
        _clearOnReturn = clearOnReturn;
        Length = minimumLength;
    }

    public Memory<byte> AsMemory() => _buffer.AsMemory(0, Length);
    public Memory<byte> AsMemory(int start, int length) => _buffer.AsMemory(start, length);

    public void Dispose()
    {
        if (_buffer != null)
        {
            BufferPool.Return(_buffer, _clearOnReturn);
            _buffer = null;
        }
    }

    public static implicit operator byte[](AsyncBufferLease lease) => lease._buffer!;
}
