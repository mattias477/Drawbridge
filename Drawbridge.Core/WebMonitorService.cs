using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;

namespace Drawbridge.Core;

/// <summary>Hosts the optional PIN-protected read-only dashboard for a private LAN.</summary>
public sealed class WebMonitorService : IDisposable, IAsyncDisposable
{
    /// <summary>The TCP port used by the LAN dashboard.</summary>
    public const int Port = 8053;

    private const string SessionCookieName = "dbsession";
    private const int MaximumRequestBodyBytes = 4096;
    private const int MaximumSessions = 256;
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(8);

    private readonly object _lifecycleLock = new();
    private readonly object _sessionLock = new();
    private readonly PinService _pinService;
    private readonly BlockLogService _blockLog;
    private readonly Func<bool> _bridgeIsUp;
    private readonly Func<int> _domainCount;
    private readonly Func<FilterMode> _mode;
    private readonly DrawbridgePaths _paths;
    private readonly DateTimeOffset _startedUtc = DateTimeOffset.UtcNow;
    private readonly Dictionary<string, DateTimeOffset> _sessions = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _requestSlots = new(32, 32);
    private readonly ConcurrentDictionary<long, Task> _activeRequests = new();
    private HttpListener? _listener;
    private CancellationTokenSource? _cancellation;
    private Task? _listenTask;
    private long _requestSequence;
    private bool _disposed;

    /// <summary>Creates the LAN dashboard host.</summary>
    /// <param name="pinService">The parent PIN verifier.</param>
    /// <param name="blockLog">The block history source.</param>
    /// <param name="bridgeIsUp">Returns the current filtering state.</param>
    /// <param name="domainCount">Returns the current active block-rule count.</param>
    /// <param name="mode">Optionally returns the current filtering mode.</param>
    /// <param name="paths">Optional storage paths for the enabled preference.</param>
    public WebMonitorService(
        PinService pinService,
        BlockLogService blockLog,
        Func<bool> bridgeIsUp,
        Func<int> domainCount,
        Func<FilterMode>? mode = null,
        DrawbridgePaths? paths = null)
    {
        _pinService = pinService ?? throw new ArgumentNullException(nameof(pinService));
        _blockLog = blockLog ?? throw new ArgumentNullException(nameof(blockLog));
        _bridgeIsUp = bridgeIsUp ?? throw new ArgumentNullException(nameof(bridgeIsUp));
        _domainCount = domainCount ?? throw new ArgumentNullException(nameof(domainCount));
        _mode = mode ?? (() => FilterMode.Blocklist);
        _paths = paths ?? new DrawbridgePaths();
        _paths.EnsureCreated(message => Log?.Invoke(message));
    }

    /// <summary>Raised for monitor lifecycle and recovered listener errors.</summary>
    public event Action<string>? Log;

    /// <summary>Gets whether the HTTP listener is active.</summary>
    public bool IsRunning
    {
        get
        {
            lock (_lifecycleLock)
            {
                return _listener?.IsListening == true &&
                       _cancellation is { IsCancellationRequested: false };
            }
        }
    }

    /// <summary>Gets whether the persisted monitor-enabled marker exists.</summary>
    public bool WasEnabled => File.Exists(_paths.WebMonitorEnabledFile);

    /// <summary>Persists the desired monitor state for the next service start.</summary>
    /// <param name="enabled">Whether the monitor should start.</param>
    public void PersistEnabled(bool enabled)
    {
        try
        {
            if (enabled)
            {
                _paths.EnsureCreated(message => Log?.Invoke(message));
                AtomicFile.WriteAllText(_paths.WebMonitorEnabledFile, "enabled\n");
            }
            else
            {
                File.Delete(_paths.WebMonitorEnabledFile);
            }
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Could not persist web-monitor preference: {ex.Message}");
        }
    }

    /// <summary>Starts <c>http://+:8053/</c> and manages its private-network firewall rule.</summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_lifecycleLock)
        {
            if (_listener?.IsListening == true)
            {
                return;
            }

            var cancellation = new CancellationTokenSource();
            var listener = new HttpListener
            {
                IgnoreWriteExceptions = true,
            };
            listener.Prefixes.Add($"http://+:{Port}/");
            try
            {
                listener.Start();
                _listener = listener;
                _cancellation = cancellation;
                _listenTask = ListenLoopAsync(listener, cancellation.Token);
            }
            catch
            {
                cancellation.Cancel();
                cancellation.Dispose();
                listener.Close();
                throw;
            }
        }

        SystemIntegration.AddWebMonitorFirewallRule(Port, message => Log?.Invoke(message));
        Log?.Invoke($"Web monitor listening at {string.Join(" or ", Urls())}.");
    }

    /// <summary>Stops the HTTP listener, expires all sessions, and removes its firewall rule.</summary>
    public void Stop() => StopAsync().AsTask().GetAwaiter().GetResult();

    /// <summary>Asynchronously stops the monitor and removes its firewall rule.</summary>
    public async ValueTask StopAsync()
    {
        CancellationTokenSource? cancellation;
        HttpListener? listener;
        Task? listenTask;
        lock (_lifecycleLock)
        {
            cancellation = _cancellation;
            listener = _listener;
            listenTask = _listenTask;
            _cancellation = null;
            _listener = null;
            _listenTask = null;

            cancellation?.Cancel();
            try { listener?.Stop(); } catch { }
            try { listener?.Close(); } catch { }
        }

        if (listenTask is not null)
        {
            try { await listenTask.ConfigureAwait(false); } catch { }
        }

        try
        {
            await Task.WhenAll(_activeRequests.Values.ToArray()).ConfigureAwait(false);
        }
        catch
        {
        }

        cancellation?.Dispose();
        lock (_sessionLock)
        {
            _sessions.Clear();
        }

        SystemIntegration.RemoveWebMonitorFirewallRule(message => Log?.Invoke(message));
        if (listener is not null)
        {
            Log?.Invoke("Web monitor stopped.");
        }
    }

    /// <summary>Gets LAN URLs likely to work from another device.</summary>
    public IReadOnlyList<string> Urls()
    {
        var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            $"http://{Environment.MachineName.ToLowerInvariant()}:{Port}/",
        };

        try
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up ||
                    adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                foreach (UnicastIPAddressInformation address in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(address.Address))
                    {
                        urls.Add($"http://{address.Address}:{Port}/");
                    }
                }
            }
        }
        catch
        {
        }

        return urls.Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>Removes the monitor firewall rule without changing listener state.</summary>
    public void RemoveFirewallRule() =>
        SystemIntegration.RemoveWebMonitorFirewallRule(message => Log?.Invoke(message));

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Stop();
        _disposed = true;
        _requestSlots.Dispose();
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await StopAsync().ConfigureAwait(false);
        _disposed = true;
        _requestSlots.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task ListenLoopAsync(HttpListener listener, CancellationToken cancellationToken)
    {
        // The try/catch is intentionally inside the loop. A transient HttpListener failure cannot
        // silently end the monitor while the service continues to look healthy.
        while (!cancellationToken.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await listener.GetContextAsync()
                    .WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (HttpListenerException) when (
                cancellationToken.IsCancellationRequested || !listener.IsListening)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (Exception ex)
            {
                Log?.Invoke($"Web monitor accept error (recovered): {ex.Message}");
                try
                {
                    await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                continue;
            }

            if (!_requestSlots.Wait(0))
            {
                try
                {
                    context.Response.StatusCode = (int)HttpStatusCode.ServiceUnavailable;
                    context.Response.Close();
                }
                catch { }

                continue;
            }

            TrackRequest(HandleAndReleaseAsync(context, cancellationToken));
        }
    }

    private async Task HandleAndReleaseAsync(
        HttpListenerContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            await HandleRequestAsync(context, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            try { context.Response.Abort(); } catch { }
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Web monitor request error (recovered): {ex.Message}");
            try { context.Response.Abort(); } catch { }
        }
        finally
        {
            _requestSlots.Release();
        }
    }

    private void TrackRequest(Task task)
    {
        long id = Interlocked.Increment(ref _requestSequence);
        _activeRequests[id] = task;
        _ = ObserveRequestAsync(id, task);
    }

    private async Task ObserveRequestAsync(long id, Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log?.Invoke($"Web monitor request task error (recovered): {ex.Message}");
        }
        finally
        {
            _activeRequests.TryRemove(id, out _);
        }
    }

    private async Task HandleRequestAsync(
        HttpListenerContext context,
        CancellationToken cancellationToken)
    {
        string path = context.Request.Url?.AbsolutePath ?? "/";
        if (context.Request.HttpMethod == "POST" && path == "/login")
        {
            await HandleLoginAsync(context, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (path == "/logout")
        {
            string? token = context.Request.Cookies[SessionCookieName]?.Value;
            if (token is not null)
            {
                lock (_sessionLock)
                {
                    _sessions.Remove(token);
                }
            }

            Redirect(context.Response, "/");
            return;
        }

        if (context.Request.HttpMethod != "GET")
        {
            context.Response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
            context.Response.Close();
            return;
        }

        if (!IsAuthenticated(context.Request))
        {
            await WriteHtmlAsync(context.Response, LoginPage(error: false), cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        await WriteHtmlAsync(context.Response, DashboardPage(), cancellationToken).ConfigureAwait(false);
    }

    private async Task HandleLoginAsync(
        HttpListenerContext context,
        CancellationToken cancellationToken)
    {
        string? pin = await ReadFormPinAsync(context.Request, cancellationToken).ConfigureAwait(false);
        if (pin is not null && _pinService.HasPin && _pinService.Verify(pin))
        {
            string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            DateTimeOffset expires = DateTimeOffset.UtcNow.Add(SessionLifetime);
            lock (_sessionLock)
            {
                PruneSessionsLocked();
                if (_sessions.Count >= MaximumSessions)
                {
                    string oldest = _sessions.MinBy(pair => pair.Value).Key;
                    _sessions.Remove(oldest);
                }

                _sessions[token] = expires;
            }

            context.Response.Headers.Add(
                "Set-Cookie",
                $"{SessionCookieName}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={(int)SessionLifetime.TotalSeconds}");
            Redirect(context.Response, "/");
            return;
        }

        await Task.Delay(TimeSpan.FromMilliseconds(1500), cancellationToken).ConfigureAwait(false);
        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        await WriteHtmlAsync(context.Response, LoginPage(error: true), cancellationToken)
            .ConfigureAwait(false);
    }

    private bool IsAuthenticated(HttpListenerRequest request)
    {
        string? token = request.Cookies[SessionCookieName]?.Value;
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        lock (_sessionLock)
        {
            PruneSessionsLocked();
            if (!_sessions.TryGetValue(token, out DateTimeOffset expires) ||
                expires <= DateTimeOffset.UtcNow)
            {
                _sessions.Remove(token);
                return false;
            }

            // Sliding expiry keeps an actively viewed dashboard signed in while still bounding
            // abandoned session lifetime.
            _sessions[token] = DateTimeOffset.UtcNow.Add(SessionLifetime);
            return true;
        }
    }

    private void PruneSessionsLocked()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        foreach (string expired in _sessions
                     .Where(pair => pair.Value <= now)
                     .Select(pair => pair.Key)
                     .ToArray())
        {
            _sessions.Remove(expired);
        }
    }

    private static async Task<string?> ReadFormPinAsync(
        HttpListenerRequest request,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength64 > MaximumRequestBodyBytes)
        {
            return null;
        }

        using var body = new MemoryStream();
        byte[] buffer = new byte[1024];
        while (true)
        {
            int read = await request.InputStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (body.Length + read > MaximumRequestBodyBytes)
            {
                return null;
            }

            body.Write(buffer, 0, read);
        }

        string form = (request.ContentEncoding ?? Encoding.UTF8).GetString(body.ToArray());
        foreach (string field in form.Split('&'))
        {
            int equals = field.IndexOf('=');
            string key = equals < 0 ? field : field[..equals];
            if (!string.Equals(DecodeFormComponent(key), "pin", StringComparison.Ordinal))
            {
                continue;
            }

            string value = equals < 0 ? string.Empty : field[(equals + 1)..];
            try
            {
                return DecodeFormComponent(value);
            }
            catch (UriFormatException)
            {
                return null;
            }
        }

        return null;
    }

    private static string DecodeFormComponent(string value) =>
        Uri.UnescapeDataString(value.Replace('+', ' '));

    private string LoginPage(bool error)
    {
        string errorHtml = error ? "<p class=\"down\">Wrong PIN.</p>" : string.Empty;
        string noPinHtml = !_pinService.HasPin
            ? "<p class=\"down\">Set a PIN in the Drawbridge control panel before using the LAN monitor.</p>"
            : string.Empty;

        return $"""
            <!doctype html><html lang="en"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Drawbridge Monitor</title>{Css}</head><body>
            <h1>🏰 Drawbridge Monitor</h1>
            <main class="card"><p>Enter the parent PIN to see this machine's status.</p>
            {errorHtml}{noPinHtml}
            <form method="post" action="/login" autocomplete="off">
            <label>PIN <input type="password" name="pin" maxlength="256" autofocus></label>
            <button type="submit">Unlock</button></form></main></body></html>
            """;
    }

    private string DashboardPage()
    {
        bool bridgeUp = _bridgeIsUp();
        FilterMode mode = _mode();
        TimeSpan uptime = DateTimeOffset.UtcNow - _startedUtc;
        var rows = new StringBuilder();
        foreach (BlockLogEntry entry in _blockLog.Recent(50))
        {
            rows.Append("<tr><td>")
                .Append(WebUtility.HtmlEncode(entry.Timestamp.ToString("MMM d HH:mm:ss")))
                .Append("</td><td>")
                .Append(WebUtility.HtmlEncode(entry.Domain))
                .Append("</td></tr>");
        }

        if (rows.Length == 0)
        {
            rows.Append("<tr><td colspan=\"2\" class=\"muted\">Nothing blocked yet.</td></tr>");
        }

        return $"""
            <!doctype html><html lang="en"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <meta http-equiv="refresh" content="10">
            <title>Drawbridge — {WebUtility.HtmlEncode(Environment.MachineName)}</title>{Css}</head><body>
            <h1>🏰 Drawbridge on {WebUtility.HtmlEncode(Environment.MachineName)}</h1>
            <main>
            <section class="card">Bridge is <strong class="{(bridgeUp ? "up" : "down")}">
            {(bridgeUp ? "UP — filtering" : "DOWN — not filtering")}</strong>
            <p class="muted">Mode: {WebUtility.HtmlEncode(mode.ToString())} · uptime
            {(int)uptime.TotalDays}d {uptime.Hours}h {uptime.Minutes}m · {_domainCount():N0} block rules ·
            auto-refreshes every 10 seconds · <a href="/logout">log out</a></p></section>
            <section class="card"><span class="stat">{_blockLog.TodayBlocked:N0}</span> blocked today
            <span class="stat">{_blockLog.AllTimeBlocked:N0}</span> all time</section>
            <section class="card"><h2>Recent blocks</h2><table>{rows}</table></section>
            </main></body></html>
            """;
    }

    private static void Redirect(HttpListenerResponse response, string location)
    {
        ApplySecurityHeaders(response);
        response.StatusCode = (int)HttpStatusCode.SeeOther;
        response.RedirectLocation = location;
        response.Close();
    }

    private static async Task WriteHtmlAsync(
        HttpListenerResponse response,
        string html,
        CancellationToken cancellationToken)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(html);
        ApplySecurityHeaders(response);
        response.ContentType = "text/html; charset=utf-8";
        response.ContentEncoding = Encoding.UTF8;
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        response.Close();
    }

    private static void ApplySecurityHeaders(HttpListenerResponse response)
    {
        response.Headers["X-Content-Type-Options"] = "nosniff";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers["Cache-Control"] = "no-store";
        response.Headers["Content-Security-Policy"] =
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
    }

    private const string Css = """
        <style>
        body{font:15px Segoe UI,Arial,sans-serif;background:#1E2430;color:#D5DCE8;
        margin:0 auto;padding:24px;max-width:760px}h1{color:#fff;font-size:24px}
        h2{font-size:16px}.card{background:#252C3B;border-radius:9px;padding:17px;margin:0 0 14px}
        .up{color:#34D399}.down{color:#F87171}.stat{font-size:26px;font-weight:700;color:#3B82F6;
        margin-right:8px}.stat+span{margin-left:24px}.muted{color:#9AA5B8;font-size:12px}
        table{width:100%;border-collapse:collapse;font-size:13px}td{padding:5px 8px;border-bottom:1px solid #384154}
        input{padding:9px;border-radius:6px;border:1px solid #4B5568;background:#141922;color:#fff;font-size:16px}
        button{padding:9px 16px;border:0;border-radius:6px;background:#3B82F6;color:#fff;font-size:15px}
        a{color:#93B8F9}
        </style>
        """;
}
