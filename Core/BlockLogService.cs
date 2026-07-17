using System.IO;

namespace Drawbridge.Core;

/// <summary>
/// Persistent record of every blocked lookup. Events append to daily files
/// in %AppData%\Drawbridge\logs (kept 90 days), so history, counters, and
/// the dashboard chart survive restarts. Also feeds the web monitor.
/// </summary>
public class BlockLogService
{
    private static readonly string LogDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Drawbridge", "logs");

    private const int RecentCap = 500;
    private const int KeepDays = 90;

    private readonly object _lock = new();
    private readonly List<(DateTime Time, string Domain)> _recent = new();
    private readonly Dictionary<string, int> _dailyCounts = new(); // "2026-07-14" -> n

    public int Today
    {
        get { lock (_lock) return _dailyCounts.GetValueOrDefault(Key(DateTime.Today)); }
    }

    public int TotalRecorded
    {
        get { lock (_lock) return _dailyCounts.Values.Sum(); }
    }

    /// <summary>Reads existing log files: per-day counts for all retained
    /// days, and the most recent entries for display.</summary>
    public void Load()
    {
        lock (_lock)
        {
            _dailyCounts.Clear();
            _recent.Clear();

            try
            {
                if (!Directory.Exists(LogDir)) return;

                foreach (string file in Directory.GetFiles(LogDir, "blocks-*.log"))
                {
                    string day = Path.GetFileNameWithoutExtension(file)["blocks-".Length..];

                    // Prune files older than the retention window
                    if (DateTime.TryParse(day, out DateTime date) &&
                        date < DateTime.Today.AddDays(-KeepDays))
                    {
                        try { File.Delete(file); } catch { }
                        continue;
                    }

                    string[] lines = File.ReadAllLines(file);
                    _dailyCounts[day] = lines.Length;

                    // Keep recent entries from the last two days for display
                    if (DateTime.TryParse(day, out DateTime d) &&
                        d >= DateTime.Today.AddDays(-1))
                    {
                        foreach (string line in lines)
                        {
                            string[] parts = line.Split('\t');
                            if (parts.Length == 2 &&
                                DateTime.TryParse($"{day} {parts[0]}", out DateTime when))
                            {
                                _recent.Add((when, parts[1]));
                            }
                        }
                    }
                }

                _recent.Sort((a, b) => a.Time.CompareTo(b.Time));
                if (_recent.Count > RecentCap)
                    _recent.RemoveRange(0, _recent.Count - RecentCap);
            }
            catch
            {
                // History is nice-to-have; never let it break filtering
            }
        }
    }

    /// <summary>Records one blocked lookup: to disk and to memory.</summary>
    public void Record(string domain)
    {
        DateTime now = DateTime.Now;
        lock (_lock)
        {
            try
            {
                Directory.CreateDirectory(LogDir);
                File.AppendAllText(
                    Path.Combine(LogDir, $"blocks-{now:yyyy-MM-dd}.log"),
                    $"{now:HH:mm:ss}\t{domain}{Environment.NewLine}");
            }
            catch
            {
                // Disk hiccup: keep counting in memory anyway
            }

            string key = Key(now.Date);
            _dailyCounts[key] = _dailyCounts.GetValueOrDefault(key) + 1;

            _recent.Add((now, domain));
            if (_recent.Count > RecentCap)
                _recent.RemoveAt(0);
        }
    }

    /// <summary>Most recent blocked lookups, newest first.</summary>
    public IReadOnlyList<(DateTime Time, string Domain)> Recent(int count)
    {
        lock (_lock)
        {
            return _recent.AsEnumerable().Reverse().Take(count).ToList();
        }
    }

    /// <summary>The last N days (oldest first), zero-filled — chart food.</summary>
    public IReadOnlyList<(DateTime Day, int Count)> LastDays(int n)
    {
        lock (_lock)
        {
            var result = new List<(DateTime, int)>(n);
            for (int i = n - 1; i >= 0; i--)
            {
                DateTime day = DateTime.Today.AddDays(-i);
                result.Add((day, _dailyCounts.GetValueOrDefault(Key(day))));
            }
            return result;
        }
    }

    private static string Key(DateTime day) => day.ToString("yyyy-MM-dd");
}