using System.Globalization;
using System.Text.Json;

namespace Drawbridge.Core;

/// <summary>Represents one recorded blocked DNS lookup.</summary>
/// <param name="Timestamp">The local time at which the lookup was blocked.</param>
/// <param name="Domain">The blocked DNS hostname.</param>
public sealed record BlockLogEntry(DateTime Timestamp, string Domain);

/// <summary>Represents the number of blocks recorded on one local calendar day.</summary>
/// <param name="Day">The local calendar day.</param>
/// <param name="Count">The number of recorded blocks.</param>
public sealed record DailyBlockCount(DateTime Day, int Count);

/// <summary>
/// Persists blocked lookups in daily logs, retains 90 days of detail, and maintains a separate
/// all-time counter so pruning does not reset the lifetime statistic.
/// </summary>
public sealed class BlockLogService
{
    private const int RetentionDays = 90;
    private const int RecentCapacity = 500;
    private const string FilePrefix = "blocks-";
    private const string FileSuffix = ".log";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    private readonly object _sync = new();
    private readonly DrawbridgePaths _paths;
    private readonly TimeProvider _timeProvider;
    private readonly List<BlockLogEntry> _recent = new();
    private readonly Dictionary<DateTime, int> _dailyCounts = new();
    private long _totalRecorded;
    private DateTime _lastPrunedDay = DateTime.MinValue;

    /// <summary>Creates a block-history service using machine-wide storage.</summary>
    /// <param name="paths">Optional storage paths.</param>
    /// <param name="timeProvider">Optional clock used by deterministic tests.</param>
    public BlockLogService(DrawbridgePaths? paths = null, TimeProvider? timeProvider = null)
    {
        _paths = paths ?? new DrawbridgePaths();
        _timeProvider = timeProvider ?? TimeProvider.System;
        _paths.EnsureCreated(message => Log?.Invoke(message));
    }

    /// <summary>Raised when history files cannot be read, written, or pruned.</summary>
    public event Action<string>? Log;

    /// <summary>Gets the number of blocks recorded today.</summary>
    public int Today
    {
        get
        {
            lock (_sync)
            {
                return _dailyCounts.GetValueOrDefault(LocalNow().Date);
            }
        }
    }

    /// <summary>Gets the number of blocks recorded today.</summary>
    public int TodayBlocked => Today;

    /// <summary>Gets the lifetime count, including days whose detailed logs were pruned.</summary>
    public long TotalRecorded
    {
        get { lock (_sync) return _totalRecorded; }
    }

    /// <summary>Gets the lifetime count, including days whose detailed logs were pruned.</summary>
    public long AllTimeBlocked => TotalRecorded;

    /// <summary>Reloads retained daily logs and the lifetime count from disk.</summary>
    public void Load()
    {
        _paths.EnsureCreated(message => Log?.Invoke(message));
        lock (_sync)
        {
            _recent.Clear();
            _dailyCounts.Clear();
            DateTime today = LocalNow().Date;
            PruneOldFilesLocked(today);

            long retainedCount = 0;
            try
            {
                foreach (string file in Directory.EnumerateFiles(
                    _paths.LogsDirectory, $"{FilePrefix}*{FileSuffix}"))
                {
                    if (!TryGetDayFromFile(file, out DateTime day) ||
                        day < today.AddDays(-(RetentionDays - 1)) || day > today)
                    {
                        continue;
                    }

                    int count = 0;
                    foreach (string line in File.ReadLines(file))
                    {
                        if (!TryParseLine(day, line, out BlockLogEntry entry))
                        {
                            continue;
                        }

                        count++;
                        AddRecentLocked(entry);
                    }

                    _dailyCounts[day] = count;
                    retainedCount += count;
                }

                _recent.Sort((left, right) => left.Timestamp.CompareTo(right.Timestamp));
                TrimRecentLocked();
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Could not fully load block history: {ex.Message}");
            }

            _totalRecorded = Math.Max(LoadLifetimeCountLocked(), retainedCount);
            SaveLifetimeCountLocked();
        }
    }

    /// <summary>Records one blocked lookup in memory and on disk.</summary>
    /// <param name="domain">The blocked DNS hostname.</param>
    public void Record(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        string safeDomain = domain.Trim().Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
        if (safeDomain.Length > 253)
        {
            safeDomain = safeDomain[..253];
        }

        DateTime now = LocalNow();

        lock (_sync)
        {
            if (_lastPrunedDay != now.Date)
            {
                PruneOldFilesLocked(now.Date);
            }

            try
            {
                _paths.EnsureCreated(message => Log?.Invoke(message));
                File.AppendAllText(
                    LogFileFor(now.Date),
                    $"{now:HH:mm:ss.fff}\t{safeDomain}{Environment.NewLine}");
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Could not append block history: {ex.Message}");
            }

            _dailyCounts[now.Date] = _dailyCounts.GetValueOrDefault(now.Date) + 1;
            _totalRecorded++;
            AddRecentLocked(new BlockLogEntry(now, safeDomain));
            TrimRecentLocked();
            SaveLifetimeCountLocked();
        }
    }

    /// <summary>Gets the newest retained block entries first.</summary>
    /// <param name="count">The maximum number of entries, capped at 500.</param>
    public IReadOnlyList<BlockLogEntry> Recent(int count)
    {
        count = Math.Clamp(count, 0, RecentCapacity);
        lock (_sync)
        {
            return _recent
                .OrderByDescending(entry => entry.Timestamp)
                .Take(count)
                .ToArray();
        }
    }

    /// <summary>Gets a zero-filled daily series, oldest day first.</summary>
    /// <param name="days">The number of calendar days to include.</param>
    public IReadOnlyList<DailyBlockCount> LastDays(int days)
    {
        if (days is < 0 or > 3660)
        {
            throw new ArgumentOutOfRangeException(nameof(days));
        }

        lock (_sync)
        {
            DateTime today = LocalNow().Date;
            var result = new List<DailyBlockCount>(days);
            for (int offset = days - 1; offset >= 0; offset--)
            {
                DateTime day = today.AddDays(-offset);
                result.Add(new DailyBlockCount(day, _dailyCounts.GetValueOrDefault(day)));
            }

            return result;
        }
    }

    /// <summary>Gets a zero-filled daily series, oldest day first.</summary>
    /// <param name="days">The number of calendar days to include.</param>
    public IReadOnlyList<DailyBlockCount> Daily(int days) => LastDays(days);

    private DateTime LocalNow() => _timeProvider.GetLocalNow().LocalDateTime;

    private string LogFileFor(DateTime day) =>
        Path.Combine(_paths.LogsDirectory, $"{FilePrefix}{day:yyyy-MM-dd}{FileSuffix}");

    private string LifetimeCountFile => Path.Combine(_paths.LogsDirectory, "block-stats.json");

    private void AddRecentLocked(BlockLogEntry entry) => _recent.Add(entry);

    private void TrimRecentLocked()
    {
        if (_recent.Count <= RecentCapacity)
        {
            return;
        }

        _recent.Sort((left, right) => left.Timestamp.CompareTo(right.Timestamp));
        _recent.RemoveRange(0, _recent.Count - RecentCapacity);
    }

    private void PruneOldFilesLocked(DateTime today)
    {
        _lastPrunedDay = today;
        DateTime cutoff = today.AddDays(-(RetentionDays - 1));
        try
        {
            foreach (string file in Directory.EnumerateFiles(
                _paths.LogsDirectory, $"{FilePrefix}*{FileSuffix}"))
            {
                if (TryGetDayFromFile(file, out DateTime day) && day < cutoff)
                {
                    try
                    {
                        File.Delete(file);
                    }
                    catch (Exception ex)
                    {
                        Log?.Invoke($"Could not prune {Path.GetFileName(file)}: {ex.Message}");
                    }
                }
            }

            foreach (DateTime oldDay in _dailyCounts.Keys.Where(day => day < cutoff).ToArray())
            {
                _dailyCounts.Remove(oldDay);
            }
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Could not prune block history: {ex.Message}");
        }
    }

    private long LoadLifetimeCountLocked()
    {
        try
        {
            if (!File.Exists(LifetimeCountFile))
            {
                return 0;
            }

            LifetimeStats? stats = JsonSerializer.Deserialize<LifetimeStats>(
                File.ReadAllText(LifetimeCountFile), JsonOptions);
            return Math.Max(0, stats?.TotalRecorded ?? 0);
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Could not read lifetime block count: {ex.Message}");
            return 0;
        }
    }

    private void SaveLifetimeCountLocked()
    {
        try
        {
            AtomicFile.WriteAllText(
                LifetimeCountFile,
                JsonSerializer.Serialize(new LifetimeStats { TotalRecorded = _totalRecorded }, JsonOptions));
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Could not save lifetime block count: {ex.Message}");
        }
    }

    private static bool TryGetDayFromFile(string file, out DateTime day)
    {
        string name = Path.GetFileName(file);
        if (!name.StartsWith(FilePrefix, StringComparison.Ordinal) ||
            !name.EndsWith(FileSuffix, StringComparison.Ordinal))
        {
            day = default;
            return false;
        }

        string value = name[FilePrefix.Length..^FileSuffix.Length];
        return DateTime.TryParseExact(
            value,
            "yyyy-MM-dd",
            CultureInfo.InvariantCulture,
            DateTimeStyles.None,
            out day);
    }

    private static bool TryParseLine(DateTime day, string line, out BlockLogEntry entry)
    {
        entry = null!;
        int tab = line.IndexOf('\t');
        if (tab <= 0 || tab == line.Length - 1)
        {
            return false;
        }

        string timeText = line[..tab];
        string domain = line[(tab + 1)..].Trim();
        if (domain.Length == 0)
        {
            return false;
        }

        string[] formats = ["HH:mm:ss.fff", "HH:mm:ss"];
        if (!DateTime.TryParseExact(
                timeText,
                formats,
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out DateTime time))
        {
            return false;
        }

        entry = new BlockLogEntry(day.Add(time.TimeOfDay), domain);
        return true;
    }

    private sealed class LifetimeStats
    {
        public long TotalRecorded { get; set; }
    }
}
