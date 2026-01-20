using System.Threading.Channels;
using System.Text;

namespace ShadowsocksSharp.Diagnostics;

/// <summary>
/// 日志级别
/// </summary>
public enum LogLevel
{
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3
}

/// <summary>
/// 日志管理器 - 高性能版本
/// </summary>
/// <remarks>
/// 优化:
/// - 使用 Channel 替代 ConcurrentQueue（更高效的生产者-消费者模式）
/// - 使用 Lock 替代 object（.NET 10 新特性）
/// - 字符串插值优化
/// </remarks>
public static class Log
{
    private static readonly Lock ConsoleLock = new();
    private static readonly Channel<string> LogChannel = Channel.CreateBounded<string>(
        new BoundedChannelOptions(10000)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropOldest
        });
    private static readonly CancellationTokenSource Cts = new();

    private static StreamWriter? _writer;
    private static string _logDir = "logs";
    private static string _currentFile = string.Empty;
    private static DateTime _nextFileRetryUtc;
    private static int _fileErrorCount;

    private static long _totalRequests;
    private static long _activeConnections;

    /// <summary>是否输出到控制台</summary>
    public static bool ConsoleEnabled { get; set; } = true;

    /// <summary>是否输出到文件</summary>
    public static bool FileEnabled { get; set; } = true;

    /// <summary>最小日志级别</summary>
    public static LogLevel MinLevel { get; set; } = LogLevel.Debug;

    /// <summary>总请求数</summary>
    public static long TotalRequests => Volatile.Read(ref _totalRequests);

    /// <summary>当前活动连接数</summary>
    public static long ActiveConnections => Volatile.Read(ref _activeConnections);

    /// <summary>日志事件</summary>
    public static event Action<LogLevel, string>? OnLog;

    // 向后兼容
    public enum Level { Debug = 0, Info = 1, Warn = 2, Error = 3 }

    static Log()
    {
        _ = WriteLogsAsync();
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Flush();
    }

    /// <summary>
    /// 初始化日志系统
    /// </summary>
    public static void Initialize(string? logDirectory = null, bool consoleEnabled = true, bool fileEnabled = true)
    {
        ConsoleEnabled = consoleEnabled;
        FileEnabled = fileEnabled;

        if (logDirectory != null)
            _logDir = logDirectory;

        if (FileEnabled)
            EnsureLogFile();
    }

    private static void EnsureLogFile()
    {
        var logFile = Path.Combine(_logDir, $"ss-{DateTime.Now:yyyy-MM-dd}.log");
        if (logFile == _currentFile && _writer != null) return;

        try
        {
            Directory.CreateDirectory(_logDir);
            _writer?.Dispose();
            _writer = new StreamWriter(logFile, true, Encoding.UTF8)
            {
                AutoFlush = false
            };
            _currentFile = logFile;
            _fileErrorCount = 0;
            _nextFileRetryUtc = DateTime.MinValue;
        }
        catch
        {
            HandleFileError();
        }
    }

    private static async Task WriteLogsAsync()
    {
        var reader = LogChannel.Reader;
        var buffer = new List<string>(50);
        const int BatchSize = 50;

        try
        {
            while (await reader.WaitToReadAsync(Cts.Token).ConfigureAwait(false))
            {
                // 批量读取
                while (reader.TryRead(out var entry))
                {
                    buffer.Add(entry);
                    if (buffer.Count >= BatchSize) break;
                }

                if (buffer.Count > 0 && FileEnabled && DateTime.UtcNow >= _nextFileRetryUtc)
                {
                    try
                    {
                        EnsureLogFile();
                        if (_writer != null)
                        {
                            foreach (var entry in buffer)
                            {
                                await _writer.WriteLineAsync(entry).ConfigureAwait(false);
                            }
                            await _writer.FlushAsync().ConfigureAwait(false);
                        }
                    }
                    catch
                    {
                        HandleFileError();
                    }
                }

                buffer.Clear();
            }
        }
        catch (OperationCanceledException) { }
        catch { /* ignore */ }
    }

    private static void HandleFileError()
    {
        _fileErrorCount = Math.Min(_fileErrorCount + 1, 6);
        var backoffSeconds = Math.Min(60, 1 << _fileErrorCount);
        _nextFileRetryUtc = DateTime.UtcNow.AddSeconds(backoffSeconds);

        try { _writer?.Dispose(); } catch { }
        _writer = null;
    }

    /// <summary>
    /// 刷新并关闭日志
    /// </summary>
    public static void Flush()
    {
        Cts.Cancel();
        LogChannel.Writer.TryComplete();

        // 清空剩余日志
        while (LogChannel.Reader.TryRead(out var entry))
            _writer?.WriteLine(entry);

        _writer?.Flush();
        _writer?.Dispose();
        _writer = null;
    }

    private static void Write(LogLevel level, string message, string? id = null)
    {
        if (level < MinLevel) return;

        var tag = level switch
        {
            LogLevel.Debug => "DBG",
            LogLevel.Info => "INF",
            LogLevel.Warn => "WRN",
            LogLevel.Error => "ERR",
            _ => "LOG"
        };

        // 使用字符串插值优化
        var line = id != null
            ? $"{DateTime.Now:HH:mm:ss.fff} [{tag}] [{id}] {message}"
            : $"{DateTime.Now:HH:mm:ss.fff} [{tag}] {message}";

        if (ConsoleEnabled)
        {
            lock (ConsoleLock)
            {
                var color = Console.ForegroundColor;
                Console.ForegroundColor = level switch
                {
                    LogLevel.Debug => ConsoleColor.DarkGray,
                    LogLevel.Warn => ConsoleColor.Yellow,
                    LogLevel.Error => ConsoleColor.Red,
                    _ => ConsoleColor.White
                };
                Console.WriteLine(line);
                Console.ForegroundColor = color;
            }
        }

        if (FileEnabled)
            LogChannel.Writer.TryWrite(line);

        OnLog?.Invoke(level, message);
    }

    // 基本日志
    public static void D(string msg) => Write(LogLevel.Debug, msg);
    public static void I(string msg) => Write(LogLevel.Info, msg);
    public static void W(string msg) => Write(LogLevel.Warn, msg);
    public static void E(string msg) => Write(LogLevel.Error, msg);
    public static void E(Exception ex) => Write(LogLevel.Error, $"{ex.GetType().Name}: {ex.Message}");

    // 带请求 ID 的日志
    public static void D(string id, string msg) => Write(LogLevel.Debug, msg, id);
    public static void I(string id, string msg) => Write(LogLevel.Info, msg, id);
    public static void W(string id, string msg) => Write(LogLevel.Warn, msg, id);
    public static void E(string id, string msg) => Write(LogLevel.Error, msg, id);

    // 统计
    public static void IncrementRequests() => Interlocked.Increment(ref _totalRequests);
    public static void IncrementConnections() => Interlocked.Increment(ref _activeConnections);
    public static void DecrementConnections() => Interlocked.Decrement(ref _activeConnections);

    // 兼容旧 API
    public static void Info(string msg) => I(msg);
    public static void Warning(string msg) => W(msg);
    public static void Error(string msg) => E(msg);
    public static void Error(Exception ex) => E(ex);
    public static void Debug(string msg) => D(msg);
}

/// <summary>
/// 向后兼容别名
/// </summary>
public static class Logger
{
    public static void Info(string msg) => Log.I(msg);
    public static void Warning(string msg) => Log.W(msg);
    public static void Error(string msg) => Log.E(msg);
    public static void Error(Exception ex) => Log.E(ex);
    public static void Debug(string msg) => Log.D(msg);
}
