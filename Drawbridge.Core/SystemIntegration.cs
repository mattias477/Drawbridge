using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;

namespace Drawbridge.Core;

/// <summary>Applies and reverses Drawbridge's privileged Windows networking changes.</summary>
public static class SystemIntegration
{
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

        RemoveWebMonitorFirewallRule(log);
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
    /// <returns><see langword="true"/> when netsh accepted the delete command.</returns>
    public static bool RemoveWebMonitorFirewallRule(Action<string>? log = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        return Run(
            "netsh.exe",
            ["advfirewall", "firewall", "delete", "rule", $"name={WebMonitorFirewallRuleName}"],
            log,
            logNonZeroExit: false);
    }

    /// <summary>
    /// Best-effort uninstaller cleanup: restores DHCP DNS, removes owned firewall rules, flushes
    /// DNS, and deletes the legacy login scheduled task.
    /// </summary>
    /// <param name="log">Optional diagnostic sink.</param>
    /// <returns><see langword="true"/> when automatic DNS restoration and flushing succeeded.</returns>
    public static bool FullCleanup(Action<string>? log = null)
    {
        bool dnsRestored = RestoreAutomaticDns(log);
        RemoveWebMonitorFirewallRule(log);
        if (OperatingSystem.IsWindows())
        {
            Run(
                "schtasks.exe",
                ["/Delete", "/F", "/TN", LegacyScheduledTaskName],
                log,
                logNonZeroExit: false);
        }

        log?.Invoke(dnsRestored
            ? "Full system cleanup finished."
            : "System cleanup finished, but automatic DNS restoration was incomplete.");
        return dnsRestored;
    }

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
