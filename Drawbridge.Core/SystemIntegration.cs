using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace Drawbridge.Core;

/// <summary>Applies and reverses Drawbridge's privileged Windows networking changes.</summary>
public static class SystemIntegration
{
    private const int HResultFileNotFound = unchecked((int)0x80070002);
    private const int HResultTaskNotFound = unchecked((int)0x8004130F);

    /// <summary>The inbound firewall rule owned by the LAN monitor.</summary>
    public const string WebMonitorFirewallRuleName = "Drawbridge Monitor";

    /// <summary>The legacy scheduled task removed during full cleanup.</summary>
    public const string LegacyScheduledTaskName = "Drawbridge";

    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);

    /// <summary>Points DNS on every active physical Ethernet or Wi-Fi adapter at both loopbacks.</summary>
    /// <param name="log">Optional diagnostic sink.</param>
    /// <returns><see langword="true"/> when every command succeeded.</returns>
    public static bool PointDnsAtDrawbridge(Action<string>? log = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            log?.Invoke("System DNS routing is available only on Windows.");
            return false;
        }

        NetworkInterface[] adapters = ActiveRealAdapters().ToArray();
        if (adapters.Length == 0)
        {
            log?.Invoke("No active physical Ethernet or Wi-Fi adapter was found; DNS routing was not changed.");
            return false;
        }

        bool succeeded = true;
        foreach (NetworkInterface adapter in adapters)
        {
            log?.Invoke($"Routing DNS through Drawbridge on adapter \"{adapter.Name}\".");
            succeeded &= Run(
                "netsh.exe",
                ["interface", "ipv4", "set", "dnsservers", $"name={adapter.Name}",
                 "source=static", "address=127.0.0.1", "register=primary", "validate=no"],
                log);
            succeeded &= Run(
                "netsh.exe",
                ["interface", "ipv6", "set", "dnsservers", $"name={adapter.Name}",
                 "source=static", "address=::1", "register=primary", "validate=no"],
                log);
        }

        succeeded &= FlushDns(log);
        log?.Invoke(succeeded
            ? "System DNS now flows through Drawbridge."
            : "One or more system DNS commands failed; see the preceding diagnostics.");
        return succeeded;
    }

    /// <summary>Restores automatic DNS on every active physical Ethernet or Wi-Fi adapter.</summary>
    /// <param name="log">Optional diagnostic sink.</param>
    /// <returns><see langword="true"/> when every command succeeded.</returns>
    public static bool RestoreAutomaticDns(Action<string>? log = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            log?.Invoke("System DNS restoration is available only on Windows.");
            return false;
        }

        NetworkInterface[] adapters = ActiveRealAdapters().ToArray();
        if (adapters.Length == 0)
        {
            log?.Invoke("No active physical Ethernet or Wi-Fi adapter was found; automatic DNS was not changed.");
            FlushDns(log);
            return false;
        }

        bool succeeded = true;
        foreach (NetworkInterface adapter in adapters)
        {
            log?.Invoke($"Restoring automatic DNS on adapter \"{adapter.Name}\".");
            succeeded &= Run(
                "netsh.exe",
                ["interface", "ipv4", "set", "dnsservers", $"name={adapter.Name}", "source=dhcp"],
                log);
            succeeded &= Run(
                "netsh.exe",
                ["interface", "ipv6", "set", "dnsservers", $"name={adapter.Name}", "source=dhcp"],
                log);
        }

        succeeded &= FlushDns(log);
        log?.Invoke(succeeded
            ? "System DNS restored to automatic."
            : "One or more automatic-DNS restore commands failed; see the preceding diagnostics.");
        return succeeded;
    }

    /// <summary>Checks whether every active real adapter lists both Drawbridge loopback resolvers.</summary>
    public static bool IsDnsPointedAtDrawbridge()
    {
        try
        {
            NetworkInterface[] adapters = ActiveRealAdapters().ToArray();
            return adapters.Length > 0 && adapters.All(adapter =>
            {
                IPAddress[] addresses = adapter.GetIPProperties().DnsAddresses.ToArray();
                return addresses.Contains(IPAddress.Loopback) && addresses.Contains(IPAddress.IPv6Loopback);
            });
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Adds the inbound TCP firewall rule for the LAN web monitor.</summary>
    /// <param name="port">The monitor TCP port.</param>
    /// <param name="log">Optional diagnostic sink.</param>
    /// <returns><see langword="true"/> when the rule was added.</returns>
    public static bool AddWebMonitorFirewallRule(int port = WebMonitorService.Port, Action<string>? log = null)
    {
        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        if (!RemoveWebMonitorFirewallRule(log))
        {
            log?.Invoke("The existing Drawbridge Monitor firewall rule could not be removed; the replacement was not added.");
            return false;
        }

        bool succeeded = Run(
            "netsh.exe",
            ["advfirewall", "firewall", "add", "rule",
             $"name={WebMonitorFirewallRuleName}", "dir=in", "action=allow",
             "protocol=TCP", $"localport={port}", "profile=private"],
            log);
        if (succeeded)
        {
            log?.Invoke("Drawbridge Monitor firewall rule enabled for private networks.");
        }

        return succeeded;
    }

    /// <summary>Deletes the inbound firewall rule owned by the LAN web monitor.</summary>
    /// <param name="log">Optional diagnostic sink.</param>
    /// <returns><see langword="true"/> when the rule is verified absent, including when it never existed.</returns>
    public static bool RemoveWebMonitorFirewallRule(Action<string>? log = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            log?.Invoke("Firewall-rule removal is available only on Windows.");
            return false;
        }

        return RemoveOwnedArtifact(
            "Drawbridge Monitor firewall rule",
            ProbeWebMonitorFirewallRule,
            DeleteWebMonitorFirewallRule,
            log);
    }

    /// <summary>
    /// Uninstaller cleanup: restores DHCP DNS, removes the owned firewall rule, flushes DNS,
    /// and deletes the legacy login scheduled task.
    /// </summary>
    /// <param name="log">Optional diagnostic sink.</param>
    /// <returns><see langword="true"/> only when DNS restoration and both verified removals succeeded.</returns>
    public static bool FullCleanup(Action<string>? log = null)
    {
        bool dnsRestored = RestoreAutomaticDns(log);
        bool firewallRemoved = RemoveWebMonitorFirewallRule(log);
        bool scheduledTaskRemoved = RemoveLegacyScheduledTask(log);
        bool succeeded = CleanupSucceeded(dnsRestored, firewallRemoved, scheduledTaskRemoved);

        log?.Invoke(succeeded
            ? "Full system cleanup finished."
            : $"System cleanup incomplete (DNS: {ResultWord(dnsRestored)}, " +
              $"firewall: {ResultWord(firewallRemoved)}, legacy task: {ResultWord(scheduledTaskRemoved)}).");
        return succeeded;
    }

    internal static bool CleanupSucceeded(
        bool dnsRestored,
        bool firewallRemoved,
        bool scheduledTaskRemoved) =>
        dnsRestored && firewallRemoved && scheduledTaskRemoved;

    internal static bool RemoveOwnedArtifact(
        string description,
        Func<OwnedArtifactProbe> probe,
        Func<OwnedArtifactRemoval> remove,
        Action<string>? log)
    {
        OwnedArtifactProbe before = probe();
        if (before.State == OwnedArtifactState.Absent)
        {
            log?.Invoke($"{description} is already absent.");
            return true;
        }

        if (before.State == OwnedArtifactState.Failed)
        {
            log?.Invoke($"Could not inspect {description}: {before.Error ?? "unknown error"}");
            return false;
        }

        OwnedArtifactRemoval removal = remove();
        if (!removal.Succeeded)
        {
            log?.Invoke($"Could not remove {description}: {removal.Error ?? "unknown error"}");
            return false;
        }

        OwnedArtifactProbe after = probe();
        if (after.State == OwnedArtifactState.Absent)
        {
            log?.Invoke($"{description} removed.");
            return true;
        }

        log?.Invoke(after.State == OwnedArtifactState.Present
            ? $"Could not verify removal of {description}: it is still present."
            : $"Could not verify removal of {description}: {after.Error ?? "unknown error"}");
        return false;
    }

    private static bool RemoveLegacyScheduledTask(Action<string>? log)
    {
        if (!OperatingSystem.IsWindows())
        {
            log?.Invoke("Legacy scheduled-task removal is available only on Windows.");
            return false;
        }

        return RemoveOwnedArtifact(
            "legacy Drawbridge scheduled task",
            ProbeLegacyScheduledTask,
            DeleteLegacyScheduledTask,
            log);
    }

    private static OwnedArtifactProbe ProbeWebMonitorFirewallRule() =>
        WithFirewallRules(rules =>
        {
            object? rule = null;
            try
            {
                rule = ((dynamic)rules).Item(WebMonitorFirewallRuleName);
                return rule is null
                    ? OwnedArtifactProbe.Absent()
                    : OwnedArtifactProbe.Present();
            }
            catch (Exception ex) when (IsArtifactNotFound(ex))
            {
                return OwnedArtifactProbe.Absent();
            }
            finally
            {
                ReleaseComObject(rule);
            }
        }, OwnedArtifactProbe.Failure);

    private static OwnedArtifactRemoval DeleteWebMonitorFirewallRule() =>
        WithFirewallRules(rules =>
        {
            try
            {
                ((dynamic)rules).Remove(WebMonitorFirewallRuleName);
                return OwnedArtifactRemoval.Success();
            }
            catch (Exception ex) when (IsArtifactNotFound(ex))
            {
                return OwnedArtifactRemoval.Success();
            }
            catch (Exception ex)
            {
                return OwnedArtifactRemoval.Failure(Unwrap(ex).Message);
            }
        }, OwnedArtifactRemoval.Failure);

    private static OwnedArtifactProbe ProbeLegacyScheduledTask()
    {
        object? service = null;
        object? folder = null;
        object? task = null;
        try
        {
            service = CreateComObject("Schedule.Service");
            ((dynamic)service).Connect();
            folder = ((dynamic)service).GetFolder("\\");
            task = ((dynamic)folder).GetTask(LegacyScheduledTaskName);
            return task is null
                ? OwnedArtifactProbe.Absent()
                : OwnedArtifactProbe.Present();
        }
        catch (Exception ex) when (IsArtifactNotFound(ex))
        {
            return OwnedArtifactProbe.Absent();
        }
        catch (Exception ex)
        {
            return OwnedArtifactProbe.Failure(Unwrap(ex).Message);
        }
        finally
        {
            ReleaseComObject(task);
            ReleaseComObject(folder);
            ReleaseComObject(service);
        }
    }

    private static OwnedArtifactRemoval DeleteLegacyScheduledTask()
    {
        object? service = null;
        object? folder = null;
        try
        {
            service = CreateComObject("Schedule.Service");
            ((dynamic)service).Connect();
            folder = ((dynamic)service).GetFolder("\\");
            ((dynamic)folder).DeleteTask(LegacyScheduledTaskName, 0);
            return OwnedArtifactRemoval.Success();
        }
        catch (Exception ex) when (IsArtifactNotFound(ex))
        {
            return OwnedArtifactRemoval.Success();
        }
        catch (Exception ex)
        {
            return OwnedArtifactRemoval.Failure(Unwrap(ex).Message);
        }
        finally
        {
            ReleaseComObject(folder);
            ReleaseComObject(service);
        }
    }

    private static T WithFirewallRules<T>(
        Func<object, T> operation,
        Func<string, T> failure)
    {
        object? policy = null;
        object? rules = null;
        try
        {
            policy = CreateComObject("HNetCfg.FwPolicy2");
            rules = ((dynamic)policy).Rules;
            return operation(rules);
        }
        catch (Exception ex)
        {
            return failure(Unwrap(ex).Message);
        }
        finally
        {
            ReleaseComObject(rules);
            ReleaseComObject(policy);
        }
    }

    private static object CreateComObject(string programmaticIdentifier)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows COM is unavailable on this platform.");
        }

        Type type = Type.GetTypeFromProgID(programmaticIdentifier, throwOnError: false)
                    ?? throw new InvalidOperationException(
                        $"Windows COM component {programmaticIdentifier} is unavailable.");
        return Activator.CreateInstance(type)
               ?? throw new InvalidOperationException(
                   $"Windows COM component {programmaticIdentifier} could not be created.");
    }

    private static bool IsArtifactNotFound(Exception exception)
    {
        Exception unwrapped = Unwrap(exception);
        return unwrapped.HResult is HResultFileNotFound or HResultTaskNotFound;
    }

    private static Exception Unwrap(Exception exception)
    {
        while (exception.InnerException is not null &&
               exception is System.Reflection.TargetInvocationException or AggregateException)
        {
            exception = exception.InnerException;
        }

        return exception;
    }

    private static void ReleaseComObject(object? value)
    {
        if (!OperatingSystem.IsWindows() || value is null || !Marshal.IsComObject(value))
        {
            return;
        }

        try { Marshal.FinalReleaseComObject(value); } catch { }
    }

    private static string ResultWord(bool succeeded) => succeeded ? "ok" : "failed";

    private static IEnumerable<NetworkInterface> ActiveRealAdapters()
    {
        NetworkInterface[] interfaces;
        try
        {
            interfaces = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch
        {
            return [];
        }

        return interfaces.Where(adapter =>
            adapter.OperationalStatus == OperationalStatus.Up &&
            adapter.NetworkInterfaceType is
                NetworkInterfaceType.Ethernet or
                NetworkInterfaceType.GigabitEthernet or
                NetworkInterfaceType.Wireless80211 &&
            !adapter.Name.Contains('*') &&
            !adapter.Name.Contains("Filter", StringComparison.OrdinalIgnoreCase) &&
            !adapter.Name.EndsWith("-0000", StringComparison.OrdinalIgnoreCase) &&
            !adapter.Description.Contains("Wi-Fi Direct", StringComparison.OrdinalIgnoreCase));
    }

    private static bool FlushDns(Action<string>? log) =>
        Run("ipconfig.exe", ["/flushdns"], log);

    private static bool Run(
        string fileName,
        IReadOnlyList<string> arguments,
        Action<string>? log,
        bool logNonZeroExit = true)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                },
            };

            foreach (string argument in arguments)
            {
                process.StartInfo.ArgumentList.Add(argument);
            }

            if (!process.Start())
            {
                log?.Invoke($"Could not start {fileName}.");
                return false;
            }

            Task<string> standardOutput = process.StandardOutput.ReadToEndAsync();
            Task<string> standardError = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit((int)CommandTimeout.TotalMilliseconds))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                log?.Invoke($"{fileName} timed out after {CommandTimeout.TotalSeconds:N0} seconds.");
                return false;
            }

            Task.WaitAll([standardOutput, standardError], TimeSpan.FromSeconds(2));
            if (process.ExitCode == 0)
            {
                return true;
            }

            if (logNonZeroExit)
            {
                string detail = standardError.IsCompletedSuccessfully
                    ? standardError.Result.Trim()
                    : string.Empty;
                if (string.IsNullOrEmpty(detail) && standardOutput.IsCompletedSuccessfully)
                {
                    detail = standardOutput.Result.Trim();
                }

                log?.Invoke($"{fileName} exited with code {process.ExitCode}: {detail}");
            }

            return false;
        }
        catch (Exception ex)
        {
            log?.Invoke($"Could not run {fileName}: {ex.Message}");
            return false;
        }
    }
}

internal enum OwnedArtifactState
{
    Present,
    Absent,
    Failed,
}

internal readonly record struct OwnedArtifactProbe(OwnedArtifactState State, string? Error)
{
    internal static OwnedArtifactProbe Present() => new(OwnedArtifactState.Present, null);

    internal static OwnedArtifactProbe Absent() => new(OwnedArtifactState.Absent, null);

    internal static OwnedArtifactProbe Failure(string error) => new(OwnedArtifactState.Failed, error);
}

internal readonly record struct OwnedArtifactRemoval(bool Succeeded, string? Error)
{
    internal static OwnedArtifactRemoval Success() => new(true, null);

    internal static OwnedArtifactRemoval Failure(string error) => new(false, error);
}
