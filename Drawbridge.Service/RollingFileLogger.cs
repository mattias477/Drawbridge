using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Drawbridge.Service;

internal sealed record OperationalLogEntry(
    DateTimeOffset Timestamp,
    string Level,
    string Category,
    string Message);

internal sealed class RecentLogBuffer
{
    private const int Capacity = 1_000;
    private readonly ConcurrentQueue<OperationalLogEntry> _entries = new();

    public RecentLogBuffer(string logDirectory)
    {
        try
        {
            string today = Path.Combine(logDirectory, $"service-{DateTime.Today:yyyy-MM-dd}.log");
            if (!File.Exists(today))
            {
                return;
            }

            foreach (string line in File.ReadLines(today).TakeLast(Capacity))
            {
                string[] fields = line.Split('\t', 4);
                if (fields.Length == 4 && DateTimeOffset.TryParse(fields[0], out DateTimeOffset timestamp))
                {
                    Add(new OperationalLogEntry(timestamp, fields[1], fields[2], fields[3]));
                }
                else
                {
                    Add(new OperationalLogEntry(
                        File.GetLastWriteTimeUtc(today),
                        "Information",
                        "Drawbridge.Service",
                        line));
                }
            }
        }
        catch
        {
            // Recent in-memory display is optional; file logging still proceeds.
        }
    }

    public void Add(OperationalLogEntry entry)
    {
        _entries.Enqueue(entry);
        while (_entries.Count > Capacity)
        {
            _entries.TryDequeue(out _);
        }
    }

    public IReadOnlyList<OperationalLogEntry> Recent(int count) =>
        _entries.Reverse().Take(Math.Clamp(count, 1, Capacity)).ToArray();
}

internal sealed class RollingFileLoggerProvider : ILoggerProvider
{
    private readonly string _directory;
    private readonly RecentLogBuffer _recent;
    private readonly object _writeGate = new();
    private DateTime _lastPrunedDay = DateTime.Today;

    public RollingFileLoggerProvider(string directory, RecentLogBuffer recent)
    {
        _directory = directory;
        _recent = recent;
        Directory.CreateDirectory(_directory);
        PruneOldFiles();
    }

    public ILogger CreateLogger(string categoryName) =>
        new RollingFileLogger(categoryName, Write);

    public void Dispose()
    {
    }

    private void Write(string category, LogLevel level, string message, Exception? exception)
    {
        DateTimeOffset now = DateTimeOffset.Now;
        string rendered = exception is null ? message : $"{message} | {exception}";
        var entry = new OperationalLogEntry(now, level.ToString(), category, rendered);
        _recent.Add(entry);

        string line = $"{now:O}\t{level}\t{category}\t{rendered.ReplaceLineEndings(" ")}{Environment.NewLine}";
        lock (_writeGate)
        {
            try
            {
                if (now.Date != _lastPrunedDay)
                {
                    PruneOldFiles();
                    _lastPrunedDay = now.Date;
                }

                string path = Path.Combine(_directory, $"service-{now:yyyy-MM-dd}.log");
                File.AppendAllText(path, line);
            }
            catch
            {
                // Logging is never allowed to stop DNS filtering.
            }
        }
    }

    private void PruneOldFiles()
    {
        try
        {
            foreach (string file in Directory.EnumerateFiles(_directory, "service-*.log"))
            {
                if (File.GetLastWriteTimeUtc(file) < DateTime.UtcNow.AddDays(-30))
                {
                    File.Delete(file);
                }
            }
        }
        catch
        {
            // Best effort only.
        }
    }

    private sealed class RollingFileLogger : ILogger
    {
        private readonly string _category;
        private readonly Action<string, LogLevel, string, Exception?> _write;

        public RollingFileLogger(
            string category,
            Action<string, LogLevel, string, Exception?> write)
        {
            _category = category;
            _write = write;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                _write(_category, logLevel, formatter(state, exception), exception);
            }
        }
    }
}
