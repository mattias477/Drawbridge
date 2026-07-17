using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Drawbridge.Core;

/// <summary>
/// A small PIN-protected web dashboard served on the LAN, so the parent
/// can check from another computer whether Drawbridge is up, on which
/// machine, and what it has blocked. Plain HTTP intended for the home
/// network only — do not expose this port to the internet.
/// </summary>
public class WebMonitorService
{
    public const int Port = 8053;
    private const string FirewallRuleName = "Drawbridge Monitor";
    private const string CookieName = "dbsession";

    private static readonly string EnabledFlagPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Drawbridge", "webmonitor.enabled");

    private readonly PinService _pin;
    private readonly BlockLogService _blockLog;
    private readonly Func<bool> _bridgeIsUp;
    private readonly Func<int> _domainCount;
    private readonly DateTime _appStartedUtc = DateTime.UtcNow;
    private readonly HashSet<string> _sessions = new();
    private readonly object _sessionLock = new();

    private HttpListener? _listener;

    public event Action<string>? Log;

    public bool IsRunning => _listener?.IsListening == true;

    public WebMonitorService(PinService pin, BlockLogService blockLog,
                             Func<bool> bridgeIsUp, Func<int> domainCount)
    {
        _pin = pin;
        _blockLog = blockLog;
        _bridgeIsUp = bridgeIsUp;
        _domainCount = domainCount;
    }

    // ---------- persisted on/off preference ----------

    public bool WasEnabled => File.Exists(EnabledFlagPath);

    public void PersistEnabled(bool enabled)
    {
        try
        {
            if (enabled)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(EnabledFlagPath)!);
                File.WriteAllText(EnabledFlagPath, "1");
            }
            else if (File.Exists(EnabledFlagPath))
            {
                File.Delete(EnabledFlagPath);
            }
        }
        catch { /* preference only */ }
    }

    // ---------- lifecycle ----------

    public void Start()
    {
        if (IsRunning) return;

        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://+:{Port}/");
        _listener.Start();
        _ = ListenLoopAsync();

        AddFirewallRule();
        Log?.Invoke($"Web monitor running — open {string.Join(" or ", Urls())} " +
                    "from another computer");
    }

    public void Stop()
    {
        if (!IsRunning) return;

        try { _listener?.Stop(); } catch { }
        _listener = null;
        lock (_sessionLock) _sessions.Clear();

        RemoveFirewallRule();
        Log?.Invoke("Web monitor stopped.");
    }

    /// <summary>Addresses another computer can use to reach this monitor.</summary>
    public IReadOnlyList<string> Urls()
    {
        var urls = new List<string> { $"http://{Environment.MachineName.ToLowerInvariant()}:{Port}" };

        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up ||
                nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                continue;

            foreach (var addr in nic.GetIPProperties().UnicastAddresses)
            {
                if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                    urls.Add($"http://{addr.Address}:{Port}");
            }
        }
        return urls;
    }

    // ---------- request handling ----------

    private async Task ListenLoopAsync()
    {
        while (IsRunning)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener!.GetContextAsync();
            }
            catch
            {
                return; // listener stopped
            }

            _ = Task.Run(() => HandleRequestAsync(context));
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext context)
    {
        try
        {
            string path = context.Request.Url?.AbsolutePath ?? "/";

            if (context.Request.HttpMethod == "POST" && path == "/login")
            {
                await HandleLoginAsync(context);
                return;
            }

            if (path == "/logout")
            {
                string? old = GetSessionToken(context.Request);
                if (old is not null)
                    lock (_sessionLock) _sessions.Remove(old);
                Redirect(context.Response, "/");
                return;
            }

            if (!IsAuthenticated(context.Request))
            {
                await WriteHtmlAsync(context.Response, LoginPage());
                return;
            }

            await WriteHtmlAsync(context.Response, DashboardPage());
        }
        catch
        {
            try { context.Response.Abort(); } catch { }
        }
    }

    private async Task HandleLoginAsync(HttpListenerContext context)
    {
        using var reader = new StreamReader(context.Request.InputStream,
                                            context.Request.ContentEncoding);
        string body = await reader.ReadToEndAsync();
        string pin = HttpUtility.ParseQueryString(body)["pin"] ?? "";

        if (_pin.HasPin && _pin.Verify(pin))
        {
            string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            lock (_sessionLock) _sessions.Add(token);

            context.Response.Headers.Add("Set-Cookie",
                $"{CookieName}={token}; Path=/; HttpOnly; SameSite=Strict");
            Redirect(context.Response, "/");
        }
        else
        {
            await Task.Delay(1500); // slow down PIN guessing
            await WriteHtmlAsync(context.Response, LoginPage(error: true));
        }
    }

    private bool IsAuthenticated(HttpListenerRequest request)
    {
        string? token = GetSessionToken(request);
        if (token is null) return false;
        lock (_sessionLock) return _sessions.Contains(token);
    }

    private static string? GetSessionToken(HttpListenerRequest request)
        => request.Cookies[CookieName]?.Value;

    // ---------- pages ----------

    private const string Css = """
        <style>
        body{font-family:Segoe UI,Arial,sans-serif;background:#1E2430;color:#D5DCE8;
             margin:0;padding:24px;max-width:760px;margin:auto}
        h1{color:#fff;font-size:24px}
        .card{background:#252C3B;border-radius:8px;padding:16px;margin:0 0 14px}
        .up{color:#34D399;font-weight:bold}.down{color:#F87171;font-weight:bold}
        .stat{font-size:26px;font-weight:bold;color:#3B82F6}
        .muted{color:#8A93A6;font-size:12px}
        table{width:100%;border-collapse:collapse;font-size:13px}
        td{padding:4px 8px;border-bottom:1px solid #333B4D}
        input{padding:8px;border-radius:6px;border:1px solid #3B4252;
              background:#141922;color:#fff;font-size:16px}
        button{padding:8px 16px;border-radius:6px;border:0;background:#3B82F6;
               color:#fff;font-size:15px;cursor:pointer}
        a{color:#8A93A6}
        </style>
        """;

    private string LoginPage(bool error = false) => $"""
        <!doctype html><html><head><meta charset="utf-8">
        <title>Drawbridge Monitor</title>{Css}</head><body>
        <h1>🏰 Drawbridge Monitor</h1>
        <div class="card">
          <p>Enter the Drawbridge PIN to view this computer's status.</p>
          {(error ? "<p class='down'>Wrong PIN.</p>" : "")}
          {(!_pin.HasPin ? "<p class='down'>No PIN is set in the Drawbridge app — set one on the Security tab first.</p>" : "")}
          <form method="post" action="/login">
            <input type="password" name="pin" autofocus>
            <button type="submit">Unlock</button>
          </form>
        </div></body></html>
        """;

    private string DashboardPage()
    {
        bool up = _bridgeIsUp();
        TimeSpan uptime = DateTime.UtcNow - _appStartedUtc;

        var rows = new StringBuilder();
        foreach ((DateTime time, string domain) in _blockLog.Recent(50))
        {
            rows.Append("<tr><td>").Append(time.ToString("MMM d HH:mm:ss"))
                .Append("</td><td>").Append(WebUtility.HtmlEncode(domain))
                .Append("</td></tr>");
        }
        if (rows.Length == 0)
            rows.Append("<tr><td colspan=2 class='muted'>Nothing blocked yet.</td></tr>");

        return $"""
        <!doctype html><html><head><meta charset="utf-8">
        <meta http-equiv="refresh" content="10">
        <title>Drawbridge — {WebUtility.HtmlEncode(Environment.MachineName)}</title>
        {Css}</head><body>
        <h1>🏰 Drawbridge on {WebUtility.HtmlEncode(Environment.MachineName)}</h1>

        <div class="card">
          Bridge is <span class="{(up ? "up" : "down")}">{(up ? "UP — filtering" : "DOWN — not filtering")}</span>
          <div class="muted">App uptime {uptime.Days}d {uptime.Hours}h {uptime.Minutes}m
          · {_domainCount():N0} domains on the blocklist
          · page auto-refreshes every 10s · <a href="/logout">log out</a></div>
        </div>

        <div class="card">
          <span class="stat">{_blockLog.Today:N0}</span> blocked today
          &nbsp;&nbsp;<span class="stat">{_blockLog.TotalRecorded:N0}</span> total recorded
        </div>

        <div class="card">
          <b>Latest blocked lookups</b>
          <table>{rows}</table>
        </div>
        </body></html>
        """;
    }

    // ---------- plumbing ----------

    private static void Redirect(HttpListenerResponse response, string location)
    {
        response.StatusCode = 302;
        response.RedirectLocation = location;
        response.Close();
    }

    private static async Task WriteHtmlAsync(HttpListenerResponse response, string html)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(html);
        response.ContentType = "text/html; charset=utf-8";
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }

    private void AddFirewallRule()
    {
        RunNetsh($"advfirewall firewall delete rule name=\"{FirewallRuleName}\"");
        RunNetsh($"advfirewall firewall add rule name=\"{FirewallRuleName}\" " +
                 $"dir=in action=allow protocol=TCP localport={Port}");
    }

    public void RemoveFirewallRule()
        => RunNetsh($"advfirewall firewall delete rule name=\"{FirewallRuleName}\"");

    private static void RunNetsh(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            p?.WaitForExit(10_000);
        }
        catch { /* firewall rule is a convenience, not a dependency */ }
    }
}