using System.Diagnostics;

namespace Drawbridge.Core;

/// <summary>
/// Resolves and protects Drawbridge's machine-wide persistent storage.
/// </summary>
public sealed class DrawbridgePaths
{
    private const string ProductDirectoryName = "Drawbridge";
    private readonly bool _secureAcl;
    private readonly object _aclLock = new();
    private bool _aclApplied;

    /// <summary>
    /// Creates paths rooted in <see cref="Environment.SpecialFolder.CommonApplicationData"/>.
    /// </summary>
    public DrawbridgePaths()
        : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            ProductDirectoryName), secureAcl: true)
    {
    }

    /// <summary>
    /// Creates paths rooted at an explicit directory. Explicit roots do not have their ACL
    /// changed unless <paramref name="secureAcl"/> is true, which keeps test directories safe.
    /// </summary>
    /// <param name="rootDirectory">The directory in which all Drawbridge state is stored.</param>
    /// <param name="secureAcl">Whether to apply the production machine-wide ACL.</param>
    public DrawbridgePaths(string rootDirectory, bool secureAcl = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        RootDirectory = Path.GetFullPath(rootDirectory);
        _secureAcl = secureAcl;
    }

    /// <summary>Gets the root machine-wide data directory.</summary>
    public string RootDirectory { get; }

    /// <summary>Gets the persisted filtering settings file.</summary>
    public string SettingsFile => Path.Combine(RootDirectory, "settings.json");

    /// <summary>Gets the per-source blocklist cache directory.</summary>
    public string CacheDirectory => Path.Combine(RootDirectory, "cache");

    /// <summary>Gets the conditional-request cache metadata file.</summary>
    public string CacheMetadataFile => Path.Combine(CacheDirectory, "metadata.json");

    /// <summary>Gets the parent PIN hash file.</summary>
    public string PinFile => Path.Combine(RootDirectory, "pin.json");

    /// <summary>Gets the rolling log and block-history directory.</summary>
    public string LogsDirectory => Path.Combine(RootDirectory, "logs");

    /// <summary>Gets the service-owned configuration file.</summary>
    public string ServiceConfigFile => Path.Combine(RootDirectory, "service-config.json");

    /// <summary>Gets the persisted web-monitor enabled marker.</summary>
    public string WebMonitorEnabledFile => Path.Combine(RootDirectory, "webmonitor.enabled");

    /// <summary>
    /// Creates all persistent directories and, for the default production root, restricts
    /// writes to SYSTEM and Administrators while granting Users read and execute access.
    /// </summary>
    /// <param name="log">Optional diagnostic sink.</param>
    public void EnsureCreated(Action<string>? log = null)
    {
        Directory.CreateDirectory(RootDirectory);
        Directory.CreateDirectory(CacheDirectory);
        Directory.CreateDirectory(LogsDirectory);

        if (!_secureAcl || !OperatingSystem.IsWindows())
        {
            return;
        }

        lock (_aclLock)
        {
            if (_aclApplied)
            {
                return;
            }

            ApplyRestrictedAcl(log);
            _aclApplied = true;
        }
    }

    internal void ProtectSensitiveFile(string path)
    {
        if (!_secureAcl || !OperatingSystem.IsWindows())
        {
            return;
        }

        string fullPath = Path.GetFullPath(path);
        string rootPrefix = Path.TrimEndingDirectorySeparator(RootDirectory) + Path.DirectorySeparatorChar;
        if (!fullPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Sensitive files must remain inside the Drawbridge data directory.");
        }

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "icacls.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            },
        };
        process.StartInfo.ArgumentList.Add(fullPath);
        process.StartInfo.ArgumentList.Add("/inheritance:r");
        process.StartInfo.ArgumentList.Add("/grant:r");
        process.StartInfo.ArgumentList.Add("*S-1-5-18:F");
        process.StartInfo.ArgumentList.Add("/grant:r");
        process.StartInfo.ArgumentList.Add("*S-1-5-32-544:F");
        process.StartInfo.ArgumentList.Add("/Q");

        if (!process.Start())
        {
            throw new InvalidOperationException("Could not start icacls to protect the PIN hash.");
        }

        Task<string> output = process.StandardOutput.ReadToEndAsync();
        Task<string> error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15_000))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("Timed out while protecting the PIN hash ACL.");
        }

        Task.WaitAll([output, error], TimeSpan.FromSeconds(2));
        if (process.ExitCode != 0)
        {
            string detail = error.IsCompletedSuccessfully ? error.Result.Trim() : string.Empty;
            throw new InvalidOperationException(
                $"Could not protect the PIN hash ACL (exit {process.ExitCode}): {detail}");
        }
    }

    private void ApplyRestrictedAcl(Action<string>? log)
    {
        try
        {
            // Well-known SIDs make this work on non-English Windows installations.
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "icacls.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                },
            };

            process.StartInfo.ArgumentList.Add(RootDirectory);
            process.StartInfo.ArgumentList.Add("/inheritance:r");
            process.StartInfo.ArgumentList.Add("/grant:r");
            process.StartInfo.ArgumentList.Add("*S-1-5-18:(OI)(CI)F");
            process.StartInfo.ArgumentList.Add("/grant:r");
            process.StartInfo.ArgumentList.Add("*S-1-5-32-544:(OI)(CI)F");
            process.StartInfo.ArgumentList.Add("/grant:r");
            process.StartInfo.ArgumentList.Add("*S-1-5-32-545:(OI)(CI)RX");
            process.StartInfo.ArgumentList.Add("/T");
            process.StartInfo.ArgumentList.Add("/C");
            process.StartInfo.ArgumentList.Add("/Q");

            if (!process.Start())
            {
                throw new InvalidOperationException("Could not start icacls to protect the data directory.");
            }

            if (!process.WaitForExit(15_000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                throw new TimeoutException("Timed out while protecting the data directory ACL.");
            }

            if (process.ExitCode != 0)
            {
                string error = process.StandardError.ReadToEnd().Trim();
                throw new InvalidOperationException(
                    $"Could not fully protect the data directory ACL (exit {process.ExitCode}): {error}");
            }
        }
        catch (Exception ex)
        {
            log?.Invoke($"Could not protect the data directory ACL: {ex.Message}");
            throw;
        }
    }
}
