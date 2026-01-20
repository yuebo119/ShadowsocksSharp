using System.Collections.Concurrent;

namespace ShadowsocksSharp.Diagnostics;

/// <summary>
/// 轻量性能指标采样器（P50/P95）
/// </summary>
public static class PerfMetrics
{
    private const int MaxSamples = 512;
    private static readonly ConcurrentDictionary<string, Metric> Metrics =
        new(StringComparer.OrdinalIgnoreCase);

    private static Timer? _timer;
    private static bool _enabled;

    public static void Initialize(bool enabled, TimeSpan? interval = null)
    {
        _enabled = enabled;
        if (!enabled)
            return;

        var period = interval ?? TimeSpan.FromSeconds(60);
        _timer = new Timer(_ => LogSnapshot(), null, period, period);
    }

    public static void Shutdown()
    {
        _timer?.Dispose();
        _timer = null;
    }

    public static void Record(string name, long valueMs)
    {
        if (!_enabled)
            return;

        var metric = Metrics.GetOrAdd(name, _ => new Metric());
        metric.Add(valueMs);
    }

    private static void LogSnapshot()
    {
        foreach (var (name, metric) in Metrics)
        {
            var snapshot = metric.Snapshot();
            if (snapshot.Count == 0)
                continue;

            Log.I($"Perf {name}: count={snapshot.Count} p50={snapshot.P50}ms p95={snapshot.P95}ms max={snapshot.Max}ms");
        }
    }

    private sealed class Metric
    {
        private readonly long[] _buffer = new long[MaxSamples];
        private int _index;
        private int _count;
        private readonly object _lock = new();

        public void Add(long value)
        {
            lock (_lock)
            {
                _buffer[_index] = value;
                _index = (_index + 1) % _buffer.Length;
                if (_count < _buffer.Length)
                    _count++;
            }
        }

        public Snapshot Snapshot()
        {
            lock (_lock)
            {
                if (_count == 0)
                    return default;

                var values = new long[_count];
                for (var i = 0; i < _count; i++)
                {
                    values[i] = _buffer[i];
                }

                Array.Sort(values);
                var p50 = Percentile(values, 0.50);
                var p95 = Percentile(values, 0.95);
                var max = values[^1];
                return new Snapshot(_count, p50, p95, max);
            }
        }

        private static long Percentile(long[] sorted, double percentile)
        {
            if (sorted.Length == 0)
                return 0;

            var index = (int)Math.Ceiling(percentile * sorted.Length) - 1;
            if (index < 0)
                index = 0;
            if (index >= sorted.Length)
                index = sorted.Length - 1;

            return sorted[index];
        }
    }

    private readonly record struct Snapshot(int Count, long P50, long P95, long Max);
}
