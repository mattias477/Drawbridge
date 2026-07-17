using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Drawbridge.Core;

/// <summary>
/// Talks to Windows: points the system's DNS at Drawbridge (and back),
/// registers/unregisters launch-at-login, and provides the full cleanup
/// used by the uninstaller. Requires elevation (see app.manifest).
/// </summary>
public static class SystemIntegration
{
    private const string TaskName = "Drawbridge";
    private const string FirewallRuleName = "Drawbridge Monitor";

    // ---------- full cleanup (uninstaller / --cleanup) ----------

    /// <summary>Undoes every system change Drawbridge can make: DNS back
    /// to automatic, login task removed, web monitor firewall rule removed.
    /// Safe to call even if some of them were never set.</summary>
    public static void FullCleanup(Action<string>? log = null)
    {
        RestoreAutomaticDns(log);
        DisableRunAtLogin(log);
        Run("netsh", $"advfirewall firewall delete rule name=\"{FirewallRuleName}\"");
        log?.Invoke("Full cleanup finished.");
    }

    // ---------- system DNS ----------

    /// <summary>Sets every real, active network adapter to 127.0.0.1 / ::1.</summary>
    public static void PointDnsAtDrawbridge(Action<string>? log = null)
    {
        foreach (NetworkInterface nic in ActiveAdapters())
        {
            log?.Invoke($"Locking DNS on adapter \"{nic.Name}\"");
            Run("netsh", $"interface ipv4 set dnsservers name=\"{nic.Name}\" static 127.0.0.1 primary validate=no");
            Run("netsh", $"interface ipv6 set dnsservers name=\"{nic.Name}\" static ::1 primary validate=no");
        }
        Run("ipconfig", "/flushdns");
        log?.Invoke("System DNS now flows through Drawbridge.");
    }

    /// <summary>The undo: every adapter goes back to automatic (DHCP) DNS.</summary>
    public static void RestoreAutomaticDns(Action<string>? log = null)
    {
        foreach (NetworkInterface nic in ActiveAdapters())
        {
            log?.Invoke($"Restoring DNS on adapter \"{nic.Name}\"");
            Run("netsh", $"interface ipv4 set dnsservers name=\"{nic.Name}\" dhcp");
            Run("netsh", $"interface ipv6 set dnsservers name=\"{nic.Name}\" dhcp");
        }
        Run("ipconfig", "/flushdns");
        log?.Invoke("System DNS restored to automatic.");
    }

    /// <summary>Best-effort check: is any active adapter already pointed at us?</summary>
    public static bool IsDnsPointedAtDrawbridge()
    {
        foreach (NetworkInterface nic in ActiveAdapters())
        {
            foreach (var dns in nic.GetIPProperties().DnsAddresses)
            {
                if (dns.AddressFamily == AddressFamily.InterNetwork &&
                    dns.ToString() == "127.0.0.1")
                    return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Only real, active Ethernet / Wi-Fi adapters. Filters out loopback,
    /// tunnels, Wi-Fi Direct virtual adapters ("Local Area Connection* N"),
    /// and WFP filter-driver bindings ("...-WFP ... Filter-0000").
    /// </summary>
    private static IEnumerable<NetworkInterface> ActiveAdapters() =>
        NetworkInterface.GetAllNetworkInterfaces().Where(n =>
            n.OperationalStatus == OperationalStatus.Up &&
            (n.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
             n.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet ||
             n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) &&
            !n.Name.Contains('*') &&
            !n.Name.Contains("Filter", StringComparison.OrdinalIgnoreCase) &&
            !n.Name.EndsWith("-0000", StringComparison.Ordinal) &&
            !n.Description.Contains("Wi-Fi Direct", StringComparison.OrdinalIgnoreCase));

    // ---------- run at login ----------

    /// <summary>
    /// Registers a scheduled task that starts Drawbridge minimized to the
    /// tray (elevated, no UAC prompt) 30 seconds after login. The delay
    /// lets the network stack settle so we don't race anyone for port 53.
    /// </summary>
    public static void EnableRunAtLogin(Action<string>? log = null)
    {
        string exe = Environment.ProcessPath
                     ?? throw new InvalidOperationException("Can't find my own exe path");

        Run("schtasks",
            $"/Create /F /TN \"{TaskName}\" /TR \"\\\"{exe}\\\" --minimized\" " +
            "/SC ONLOGON /DELAY 0000:30 /RL HIGHEST");
        log?.Invoke($"Drawbridge will start automatically ~30s after login " +
                    $"(running: {exe}).");
    }

    public static void DisableRunAtLogin(Action<string>? log = null)
    {
        Run("schtasks", $"/Delete /F /TN \"{TaskName}\"");
        log?.Invoke("Automatic start at login removed.");
    }

    public static bool IsRunAtLoginEnabled() =>
        Run("schtasks", $"/Query /TN \"{TaskName}\"") == 0;

    // ---------- plumbing ----------

    private static int Run(string file, string args)
    {
        using var p = Process.Start(new ProcessStartInfo
        {
            FileName = file,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        p!.WaitForExit(10_000);
        return p.ExitCode;
    }
}