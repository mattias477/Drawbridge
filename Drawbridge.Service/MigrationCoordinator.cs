using Drawbridge.Core;
using Microsoft.Win32;
using System.Text.Json;

namespace Drawbridge.Service;

internal sealed record MigrationStatus(bool Eligible, bool SourceExists);

internal sealed class MigrationCoordinator
{
    private const long MaximumMigratedFileBytes = 100L * 1024 * 1024;
    private const long MaximumAggregateBytes = 500L * 1024 * 1024;
    private const int MaximumFileCount = 300;

    private readonly DrawbridgePaths _paths;
    private readonly ServiceConfigurationStore _configuration;
    private readonly BlocklistService _blocklists;
    private readonly BlockLogService _blockLog;
    private readonly PinService _pin;
    private readonly WebMonitorService _webMonitor;
    private readonly ILogger<MigrationCoordinator> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly HashSet<string> _eligibleSources;

    public MigrationCoordinator(
        DrawbridgePaths paths,
        ServiceConfigurationStore configuration,
        BlocklistService blocklists,
        BlockLogService blockLog,
        PinService pin,
        WebMonitorService webMonitor,
        ILogger<MigrationCoordinator> logger)
    {
        _paths = paths;
        _configuration = configuration;
        _blocklists = blocklists;
        _blockLog = blockLog;
        _pin = pin;
        _webMonitor = webMonitor;
        _logger = logger;
        _eligibleSources = DiscoverLegacySources();
    }

    public MigrationStatus GetStatus(string? sourcePath)
    {
        bool valid = TryValidateSource(sourcePath, out string? source);
        return new MigrationStatus(
            _configuration.MigrationEligible,
            valid && Directory.Exists(source));
    }

    public async Task<int> ImportAsync(string? sourcePath, CancellationToken cancellationToken)
    {
        if (!_configuration.MigrationEligible)
        {
            throw new InvalidOperationException("This installation is no longer eligible for first-run migration.");
        }

        if (!TryValidateSource(sourcePath, out string? source) || !Directory.Exists(source))
        {
            throw new ArgumentException("The legacy Drawbridge folder is not valid.", nameof(sourcePath));
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            ValidateImportSet(source);
            int copied = 0;
            string? legacySettings = FirstExisting(
                Path.Combine(source, "settings.json"),
                Path.Combine(source, "blocklists.json"));
            if (legacySettings is not null)
            {
                CopyBounded(legacySettings, _paths.SettingsFile);
                copied++;
            }

            string legacyPin = Path.Combine(source, "pin.json");
            if (File.Exists(legacyPin))
            {
                if (new FileInfo(legacyPin).Length > MaximumMigratedFileBytes)
                {
                    throw new InvalidDataException("Legacy PIN data is unexpectedly large.");
                }

                _pin.ImportLegacyRecord(File.ReadAllText(legacyPin));
                copied++;
            }

            string legacyCache = Path.Combine(source, "cache");
            if (Directory.Exists(legacyCache))
            {
                Directory.CreateDirectory(_paths.CacheDirectory);
                foreach (string file in Directory.EnumerateFiles(legacyCache))
                {
                    string name = Path.GetFileName(file);
                    bool recognized = string.Equals(name, "meta.json", StringComparison.OrdinalIgnoreCase) ||
                                      (name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) &&
                                       name[..^4].All(Uri.IsHexDigit));
                    if (!recognized)
                    {
                        continue;
                    }

                    CopyBounded(file, Path.Combine(_paths.CacheDirectory, name));
                    copied++;
                }
            }

            string legacyLogs = Path.Combine(source, "logs");
            if (Directory.Exists(legacyLogs))
            {
                Directory.CreateDirectory(_paths.LogsDirectory);
                foreach (string file in Directory.EnumerateFiles(legacyLogs, "blocks-????-??-??.log"))
                {
                    MergeBlockLog(file, Path.Combine(_paths.LogsDirectory, Path.GetFileName(file)));
                    copied++;
                }
            }

            bool legacyMonitorEnabled = File.Exists(Path.Combine(source, "webmonitor.enabled"));

            _paths.EnsureCreated();
            _blocklists.LoadSettings();
            _blocklists.RebuildFromCache();
            _blockLog.Load();
            if (legacyMonitorEnabled && _pin.HasPin)
            {
                _webMonitor.PersistEnabled(true);
                _configuration.SetWebMonitor(true);
                _webMonitor.Start();
            }

            _configuration.CompleteMigration();
            _logger.LogInformation("Imported {Count} legacy Drawbridge file(s) from {Source}.", copied, source);
            return copied;
        }
        finally
        {
            _gate.Release();
        }
    }

    private bool TryValidateSource(string? sourcePath, out string? fullPath)
    {
        fullPath = null;
        if (string.IsNullOrWhiteSpace(sourcePath) || !Path.IsPathFullyQualified(sourcePath))
        {
            return false;
        }

        try
        {
            fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(sourcePath));
            var directory = new DirectoryInfo(fullPath);
            return string.Equals(directory.Name, "Drawbridge", StringComparison.OrdinalIgnoreCase) &&
                   _eligibleSources.Contains(fullPath) &&
                   !HasReparsePoint(directory);
        }
        catch
        {
            return false;
        }
    }

    private static string? FirstExisting(params string[] candidates) =>
        candidates.FirstOrDefault(File.Exists);

    private static HashSet<string> DiscoverLegacySources()
    {
        var sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows())
        {
            return sources;
        }

        try
        {
            using RegistryKey? profiles = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            foreach (string sid in profiles?.GetSubKeyNames() ?? [])
            {
                if (sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20")
                {
                    continue;
                }

                using RegistryKey? profile = profiles?.OpenSubKey(sid);
                string? rawPath = profile?.GetValue("ProfileImagePath") as string;
                if (string.IsNullOrWhiteSpace(rawPath))
                {
                    continue;
                }

                string candidate = Path.GetFullPath(Path.Combine(
                    Environment.ExpandEnvironmentVariables(rawPath),
                    "AppData",
                    "Roaming",
                    "Drawbridge"));
                if (Directory.Exists(candidate) && !HasReparsePoint(new DirectoryInfo(candidate)))
                {
                    sources.Add(Path.TrimEndingDirectorySeparator(candidate));
                }
            }
        }
        catch
        {
            // If profile discovery cannot be trusted, migration stays unavailable.
        }

        return sources;
    }

    private static void ValidateImportSet(string source)
    {
        var files = new List<FileInfo>();
        AddIfPresent(files, Path.Combine(source, "settings.json"));
        AddIfPresent(files, Path.Combine(source, "blocklists.json"));
        AddIfPresent(files, Path.Combine(source, "pin.json"));
        AddIfPresent(files, Path.Combine(source, "webmonitor.enabled"));

        AddFilesFromDirectory(files, Path.Combine(source, "cache"));
        AddFilesFromDirectory(files, Path.Combine(source, "logs"));

        if (files.Count > MaximumFileCount || files.Sum(file => file.Length) > MaximumAggregateBytes)
        {
            throw new InvalidDataException("The legacy Drawbridge folder exceeds migration safety limits.");
        }

        if (files.Any(file => file.Length > MaximumMigratedFileBytes || HasReparsePoint(file)))
        {
            throw new InvalidDataException("The legacy Drawbridge folder contains an unsafe file.");
        }

        string? settings = FirstExisting(
            Path.Combine(source, "settings.json"),
            Path.Combine(source, "blocklists.json"));
        if (settings is not null)
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(settings));
            if (document.RootElement.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array))
            {
                throw new InvalidDataException("Legacy filtering settings are not valid JSON.");
            }
        }

        string pin = Path.Combine(source, "pin.json");
        if (File.Exists(pin))
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(pin));
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("Legacy PIN data is not valid JSON.");
            }
        }
    }

    private static void AddIfPresent(List<FileInfo> files, string path)
    {
        if (File.Exists(path))
        {
            files.Add(new FileInfo(path));
        }
    }

    private static void AddFilesFromDirectory(List<FileInfo> files, string directory)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        var info = new DirectoryInfo(directory);
        if (HasReparsePoint(info))
        {
            throw new InvalidDataException("Legacy migration does not follow directory links.");
        }

        files.AddRange(info.EnumerateFiles("*", SearchOption.TopDirectoryOnly));
    }

    private static bool HasReparsePoint(FileSystemInfo info) =>
        (info.Attributes & FileAttributes.ReparsePoint) != 0;

    private static void CopyBounded(string source, string destination)
    {
        if (new FileInfo(source).Length > MaximumMigratedFileBytes)
        {
            throw new InvalidDataException($"Legacy file is unexpectedly large: {Path.GetFileName(source)}");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(source, destination, true);
    }

    private static void MergeBlockLog(string source, string destination)
    {
        if (new FileInfo(source).Length > MaximumMigratedFileBytes)
        {
            throw new InvalidDataException($"Legacy file is unexpectedly large: {Path.GetFileName(source)}");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        if (!File.Exists(destination))
        {
            File.Copy(source, destination);
            return;
        }

        string[] merged = File.ReadLines(destination)
            .Concat(File.ReadLines(source))
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        string temporary = destination + ".migration.tmp";
        File.WriteAllLines(temporary, merged);
        File.Move(temporary, destination, true);
    }
}
