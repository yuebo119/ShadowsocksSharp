using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
using ShadowsocksSharp.Diagnostics;
using ShadowsocksSharp.Shadowsocks;

namespace ShadowsocksSharp.Transport.Relay;

public readonly record struct RelayStats(long ClientToRemoteBytes, long RemoteToClientBytes);

public static class DuplexRelay
{
    public static async Task<RelayStats> RelayAsync(
        NetworkStream clientStream,
        ShadowsocksStream remoteStream,
        ReadOnlyMemory<byte> initialPayload,
        CancellationToken ct)
    {
        // 某些入站协议已读入首包，需要先转发给远端。
        if (!initialPayload.IsEmpty)
            await remoteStream.WritePlainAsync(initialPayload, ct).ConfigureAwait(false);

        var readerOptions = new StreamPipeReaderOptions(
            pool: MemoryPool<byte>.Shared,
            bufferSize: 16 * 1024,
            minimumReadSize: 4 * 1024,
            leaveOpen: true);
        var writerOptions = new StreamPipeWriterOptions(
            pool: MemoryPool<byte>.Shared,
            minimumBufferSize: 4 * 1024,
            leaveOpen: true);

        // 使用 PipeReader 控制读取背压；写入直接流向对端流。
        var clientReader = PipeReader.Create(clientStream, readerOptions);
        var clientWriter = PipeWriter.Create(clientStream, writerOptions);
        var clientToRemote = CopyClientToRemoteAsync(clientReader, remoteStream, ct);
        var remoteToClient = PumpRemoteToClientAsync(clientWriter, remoteStream, ct);

        var clientBytes = await Suppress(clientToRemote).ConfigureAwait(false);
        var remoteBytes = await Suppress(remoteToClient).ConfigureAwait(false);

        return new RelayStats(clientBytes, remoteBytes);
    }

    private static async Task<long> CopyClientToRemoteAsync(PipeReader reader, ShadowsocksStream remote, CancellationToken ct)
    {
        long total = 0;
        try
        {
            while (true)
            {
                var result = await reader.ReadAsync(ct).ConfigureAwait(false);
                var buffer = result.Buffer;

                if (!buffer.IsEmpty)
                {
                    // 逐段转发，避免额外拷贝。
                    foreach (var segment in buffer)
                    {
                        total += segment.Length;
                        await remote.WritePlainAsync(segment, ct).ConfigureAwait(false);
                    }
                }

                reader.AdvanceTo(buffer.End);

                if (result.IsCompleted)
                    break;
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Log.D($"Relay copy error: {ex.Message}");
        }
        finally
        {
            await reader.CompleteAsync().ConfigureAwait(false);
        }

        return total;
    }

    private static async Task<long> PumpRemoteToClientAsync(PipeWriter writer, ShadowsocksStream remote, CancellationToken ct)
    {
        long total = 0;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var memory = writer.GetMemory(16 * 1024);
                var n = await remote.ReadPlainAsync(memory, ct).ConfigureAwait(false);
                if (n <= 0) break;
                total += n;
                writer.Advance(n);
                var result = await writer.FlushAsync(ct).ConfigureAwait(false);
                if (result.IsCompleted)
                    break;
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Log.D($"Relay remote->client error: {ex.Message}");
        }
        finally
        {
            await writer.CompleteAsync().ConfigureAwait(false);
        }

        return total;
    }

    private static async Task<long> Suppress(Task<long> task)
    {
        try { return await task.ConfigureAwait(false); } catch { return 0; }
    }

}
