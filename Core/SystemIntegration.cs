using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Drawbridge.Core;

/// <summary>
/// Talks to Windows: points the system's DNS at Drawbridge (and back),
/// and registers/unregisters launch-at-login via a scheduled task.
/// Everything here requires the app to run elevated (see app.manifest).
/// </summary>
public static class SystemIntegration
{
    private const string TaskName = "Drawbridge";

    // ---------- system DNS ----------

    /// <summary>Sets every active network adapter to use 127.0.0.1 / ::1.</summary>
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

    private static IEnumerable<NetworkInterface> ActiveAdapters() =>
        NetworkInterface.GetAllNetworkInterfaces().Where(n =>
            n.OperationalStatus == OperationalStatus.Up &&
            n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
            n.NetworkInterfaceType != NetworkInterfaceType.Tunnel);

    // ---------- run at login ----------

    /// <summary>
    /// Registers a scheduled task that starts Drawbridge (elevated, no UAC
    /// prompt) 30 seconds after a user logs in. The delay lets the network
    /// stack and other services settle first, so Drawbridge doesn't race
    /// them for port 53 at boot.
    /// </summary>
    public static void EnableRunAtLogin(Action<string>? log = null)
    {
        string exe = Environment.ProcessPath
                     ?? throw new InvalidOperationException("Can't find my own exe path");

        Run("schtasks",
            $"/Create /F /TN \"{TaskName}\" /TR \"\\\"{exe}\\\"\" " +
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