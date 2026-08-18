using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using Drawbridge.Core;

namespace Drawbridge.Service;

internal sealed class ControlApiService : BackgroundService
{
    private const string RequiredClientHeader = "X-Drawbridge-Client";
    private const string RequiredClientHeaderValue = "Drawbridge.App";
    private const int MaximumBodyBytes = 64 * 1024;
    private static readonly TimeSpan FailedPinDelay = TimeSpan.FromMilliseconds(1500);
    private static readonly TimeSpan BodyReadTimeout = TimeSpan.FromSeconds(10);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
    };

    private readonly DnsServer _dns;
    private readonly BridgeController _bridge;
    private readonly BlocklistService _blocklists;
    private readonly BlockLogService _blockLog;
    private readonly WebMonitorService _webMonitor;
    private readonly PinService _pin;
    private readonly ServiceConfigurationStore _configuration;
    private readonly RecentLogBuffer _recentLogs;
    private readonly MigrationCoordinator _migration;
    private readonly SystemChangeCoordinator _systemChanges;
    private readonly ILogger<ControlApiService> _logger;
    private readonly string _prefix;
    private readonly SemaphoreSlim _requestSlots = new(32, 32);
    private readonly SemaphoreSlim _mutationGate = new(1, 1);
    private readonly SemaphoreSlim _pinAttemptGate = new(1, 1);
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
    private HttpListener? _listener;
    private volatile bool _stopping;

    public ControlApiService(
        DnsServer dns,
        BridgeController bridge,
        BlocklistService blocklists,
        BlockLogService blockLog,
        WebMonitorService webMonitor,
        PinService pin,
        ServiceConfigurationStore configuration,
        RecentLogBuffer recentLogs,
        MigrationCoordinator migration,
        SystemChangeCoordinator systemChanges,
        ServiceRuntimeOptions runtimeOptions,
        ILogger<ControlApiService> logger)
    {
        _dns = dns;
        _bridge = bridge;
        _blocklists = blocklists;
        _blockLog = blockLog;
        _webMonitor = webMonitor;
        _pin = pin;
        _configuration = configuration;
        _recentLogs = recentLogs;
        _migration = migration;
        _systemChanges = systemChanges;
        _logger = logger;
        _prefix = $"http://127.0.0.1:{runtimeOptions.ControlApiPort}/";
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add(_prefix);
            try
            {
                _listener.Start();
                _logger.LogInformation("Control API listening only on {Prefix}.", _prefix);
                break;
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                _listener.Close();
                _listener = null;
                _logger.LogError(exception, "Control API bind failed; retrying in five seconds.");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        while (!stoppingToken.IsCancellationRequested && _listener is { IsListening: true })
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync().WaitAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (HttpListenerException) when (stoppingToken.IsCancellationRequested || _stopping)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Control API accept error recovered.");
                try
                {
                    await Task.Delay(100, stoppingToken);
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
                catch
                {
                    // The excess client may already have disconnected.
                }

                continue;
            }

            _ = ProcessInSlotAsync(context, stoppingToken);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _stopping = true;
        try
        {
            _listener?.Close();
        }
        catch
        {
            // Closing an already-stopped HttpListener is harmless.
        }

        _listener = null;
        await base.StopAsync(cancellationToken);
    }

    private async Task ProcessInSlotAsync(
        HttpListenerContext context,
        CancellationToken cancellationToken)
    {
        bool mutationGateHeld = false;
        try
        {
            string path = NormalizePath(context.Request.Url?.AbsolutePath);
            if (IsMutation(context.Request.HttpMethod.ToUpperInvariant()) &&
                path != "/api/pin/verify")
            {
                if (!_mutationGate.Wait(0))
                {
                    await WriteJsonAsync(
                        context.Response,
                        new { error = "Another Drawbridge change is already in progress." },
                        cancellationToken,
                        HttpStatusCode.TooManyRequests);
                    return;
                }

                mutationGateHeld = true;
            }

            await HandleRequestAsync(context, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            try { context.Response.Abort(); } catch { }
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Control API outer request wrapper recovered.");
            try { context.Response.Abort(); } catch { }
        }
        finally
        {
            if (mutationGateHeld)
            {
                _mutationGate.Release();
            }

            _requestSlots.Release();
        }
    }

    private async Task HandleRequestAsync(
        HttpListenerContext context,
        CancellationToken cancellationToken)
    {
        HttpListenerRequest request = context.Request;
        HttpListenerResponse response = context.Response;
        response.Headers["Cache-Control"] = "no-store";
        response.Headers["X-Content-Type-Options"] = "nosniff";

        string path = NormalizePath(request.Url?.AbsolutePath);
        string method = request.HttpMethod.ToUpperInvariant();

        try
        {
            if ((IsMutation(method) && !string.Equals(
                     request.Headers[RequiredClientHeader],
                     RequiredClientHeaderValue,
                     StringComparison.Ordinal)) ||
                !string.IsNullOrEmpty(request.Headers["Origin"]))
            {
                throw new ApiException(
                    HttpStatusCode.Forbidden,
                    "This endpoint accepts only the Drawbridge desktop client.");
            }

            if (request.HasEntityBody && !IsJsonContentType(request.ContentType))
            {
                throw new ApiException(
                    HttpStatusCode.UnsupportedMediaType,
                    "Request bodies must use application/json.");
            }

            if (IsMutation(method) &&
                !string.Equals(path, "/api/pin/verify", StringComparison.Ordinal) &&
                _pin.HasPin)
            {
                string suppliedPin = request.Headers["X-Drawbridge-Pin"] ?? string.Empty;
                if (!await VerifyPinAttemptAsync(suppliedPin, cancellationToken))
                {
                    throw new ApiException(HttpStatusCode.Unauthorized, "A valid Drawbridge PIN is required.");
                }
            }

            if (method == "GET" && path == "/api/status")
            {
                await WriteJsonAsync(response, BuildStatus(), cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/bridge/start")
            {
                // Activation records the parent's desired state before attempting the
                // listener bind. A transient port conflict must not turn a later
                // maintenance recovery into a listener-only, system-DNS-bypassed state.
                _configuration.SetDnsRouting(true);
                bool raised = await _bridge.RaiseAsync(cancellationToken);
                if (!raised)
                {
                    if (HasAnyLoopbackDns())
                    {
                        _logger.LogError(
                            "Bridge activation failed while Windows DNS still referenced loopback; restoring automatic DNS before returning the bind failure.");
                        await _systemChanges.RunAsync(
                            () => SystemIntegration.RestoreAutomaticDns(LogSystemMessage),
                            cancellationToken);
                        if (HasAnyLoopbackDns())
                        {
                            throw new ApiException(
                                HttpStatusCode.InternalServerError,
                                "Port 53 could not be bound and Windows DNS could not be restored safely. Drawbridge will keep retrying; restore automatic DNS manually if name resolution is unavailable.");
                        }
                    }

                    throw new ApiException(
                        HttpStatusCode.ServiceUnavailable,
                        "Port 53 could not be bound after six attempts. Protection remains requested and the service will retry.");
                }

                // The endpoint is deliberately idempotent: an already-running listener still
                // reconciles adapter routing. Re-read actual state after the command rather
                // than reporting command exit codes as protection state.
                bool commandSucceeded = IsDnsRouted() || await _systemChanges.RunAsync(
                    () => SystemIntegration.PointDnsAtDrawbridge(LogSystemMessage),
                    cancellationToken);
                bool dnsRouted = IsDnsRouted();
                if (!commandSucceeded || !dnsRouted)
                {
                    _logger.LogWarning(
                        "Bridge is raised and protection remains desired, but system DNS is not fully routed yet; maintenance will retry.");
                }

                await WriteJsonAsync(
                    response,
                    new
                    {
                        bridgeUp = _dns.IsRunning,
                        dnsRouted,
                        dnsRoutingConfigured = _configuration.DnsRoutingEnabled,
                        pending = !dnsRouted,
                    },
                    cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/bridge/stop")
            {
                if (_configuration.DnsRoutingEnabled || HasAnyLoopbackDns())
                {
                    bool restored = await _systemChanges.RunAsync(
                        () => SystemIntegration.RestoreAutomaticDns(LogSystemMessage),
                        cancellationToken);
                    if (!restored && HasAnyLoopbackDns())
                    {
                        throw new ApiException(
                            HttpStatusCode.InternalServerError,
                            "The bridge remains raised because Windows DNS could not be restored safely.");
                    }

                    _configuration.SetDnsRouting(false);
                }

                await _bridge.LowerAsync(cancellationToken);
                await WriteJsonAsync(response, new { bridgeUp = false }, cancellationToken);
                return;
            }

            if (method == "GET" && path == "/api/lists")
            {
                await WriteJsonAsync(response, _blocklists.Urls, cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/lists")
            {
                JsonElement body = await ReadJsonBodyAsync(request, cancellationToken);
                string value = RequiredString(body, "value", "url");
                if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) ||
                    uri.Scheme != Uri.UriSchemeHttps)
                {
                    throw ApiException.BadRequest("List URL must be an absolute public HTTPS URL.");
                }

                if (!_blocklists.AddList(uri.AbsoluteUri))
                {
                    throw ApiException.BadRequest("List URL is unsafe, invalid, or already present.");
                }

                await WriteJsonAsync(response, new { added = uri.AbsoluteUri }, cancellationToken, HttpStatusCode.Created);
                return;
            }

            if (method == "DELETE" && path == "/api/lists")
            {
                string value = await ReadValueAsync(request, cancellationToken, "value", "url");
                _blocklists.RemoveList(value);
                await WriteJsonAsync(response, new { removed = value }, cancellationToken);
                return;
            }

            if (method == "GET" && path == "/api/rules/block")
            {
                await WriteJsonAsync(response, _blocklists.CustomDomains, cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/rules/block")
            {
                string value = await ReadValueAsync(request, cancellationToken, "value", "domain");
                if (!_blocklists.AddCustomDomain(value))
                {
                    throw ApiException.BadRequest("Domain is invalid or already present.");
                }

                await WriteJsonAsync(response, new { added = value }, cancellationToken, HttpStatusCode.Created);
                return;
            }

            if (method == "DELETE" && path == "/api/rules/block")
            {
                string value = await ReadValueAsync(request, cancellationToken, "value", "domain");
                _blocklists.RemoveCustomDomain(value);
                await WriteJsonAsync(response, new { removed = value }, cancellationToken);
                return;
            }

            if (method == "GET" && path == "/api/rules/allow")
            {
                await WriteJsonAsync(response, _blocklists.AllowedDomains, cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/rules/allow")
            {
                string value = await ReadValueAsync(request, cancellationToken, "value", "domain");
                if (!_blocklists.AddAllowedDomain(value))
                {
                    throw ApiException.BadRequest("Domain is invalid or already present.");
                }

                await WriteJsonAsync(response, new { added = value }, cancellationToken, HttpStatusCode.Created);
                return;
            }

            if (method == "DELETE" && path == "/api/rules/allow")
            {
                string value = await ReadValueAsync(request, cancellationToken, "value", "domain");
                _blocklists.RemoveAllowedDomain(value);
                await WriteJsonAsync(response, new { removed = value }, cancellationToken);
                return;
            }

            if (method == "GET" && path == "/api/mode")
            {
                await WriteJsonAsync(response, new { mode = _blocklists.Mode.ToString() }, cancellationToken);
                return;
            }

            if (method == "PUT" && path == "/api/mode")
            {
                JsonElement body = await ReadJsonBodyAsync(request, cancellationToken);
                string value = RequiredString(body, "mode", "value");
                if (!Enum.TryParse(value, true, out FilterMode mode))
                {
                    throw ApiException.BadRequest("Mode must be Blocklist or Whitelist.");
                }

                _blocklists.SetMode(mode);
                await WriteJsonAsync(response, new { mode = mode.ToString() }, cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/update-check")
            {
                int updated = await _blocklists.CheckForUpdatesAsync(cancellationToken);
                await WriteJsonAsync(
                    response,
                    new { updated, domainCount = _blocklists.BlockedDomainCount },
                    cancellationToken);
                return;
            }

            if (method == "GET" && path == "/api/logs/recent")
            {
                int count = ParseCount(request.QueryString["count"], 200, 1, 1_000);
                await WriteJsonAsync(response, _recentLogs.Recent(count), cancellationToken);
                return;
            }

            if (method == "GET" && path == "/api/blocks/daily")
            {
                int days = ParseCount(request.QueryString["days"], 14, 1, 90);
                await WriteJsonAsync(response, _blockLog.Daily(days), cancellationToken);
                return;
            }

            if (method == "GET" && path == "/api/system/dns")
            {
                await WriteJsonAsync(
                    response,
                    new
                    {
                        enabled = IsDnsRouted(),
                        configured = _configuration.DnsRoutingEnabled,
                    },
                    cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/system/dns")
            {
                bool enabled = await ReadEnabledAsync(request, cancellationToken);
                if (enabled && !_dns.IsRunning)
                {
                    throw new ApiException(
                        HttpStatusCode.Conflict,
                        "Raise the bridge before routing system DNS through Drawbridge.");
                }

                bool succeeded = await _systemChanges.RunAsync(
                    () =>
                    {
                        if (enabled)
                        {
                            bool changed = SystemIntegration.PointDnsAtDrawbridge(LogSystemMessage);
                            if (!changed)
                            {
                                SystemIntegration.RestoreAutomaticDns(LogSystemMessage);
                            }

                            return changed;
                        }

                        return SystemIntegration.RestoreAutomaticDns(LogSystemMessage);
                    },
                    cancellationToken);

                if (!succeeded)
                {
                    if (!enabled && !HasAnyLoopbackDns())
                    {
                        _configuration.SetDnsRouting(false);
                        await WriteJsonAsync(response, new { enabled = false }, cancellationToken);
                        return;
                    }

                    if (enabled && HasAnyLoopbackDns())
                    {
                        // A partial rollback must remain associated with the running bridge so
                        // the maintenance loop retries toward a protected, consistent state.
                        _configuration.SetDnsRouting(true);
                    }

                    throw new ApiException(
                        HttpStatusCode.InternalServerError,
                        enabled
                            ? "Windows did not accept every DNS change; any partial change was rolled back."
                            : "Windows did not restore automatic DNS on every active adapter.");
                }

                _configuration.SetDnsRouting(enabled);
                await WriteJsonAsync(response, new { enabled = IsDnsRouted() }, cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/webmonitor")
            {
                bool enabled = await ReadEnabledAsync(request, cancellationToken);
                if (enabled && !_pin.HasPin)
                {
                    throw new ApiException(
                        HttpStatusCode.Conflict,
                        "Set a PIN before enabling the LAN monitor.");
                }

                if (enabled)
                {
                    _webMonitor.PersistEnabled(true);
                    _webMonitor.Start();
                }
                else
                {
                    await _webMonitor.StopAsync();
                    _webMonitor.PersistEnabled(false);
                }

                _configuration.SetWebMonitor(enabled);
                await WriteJsonAsync(
                    response,
                    new { enabled = _webMonitor.IsRunning, urls = _webMonitor.Urls() },
                    cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/system/cleanup")
            {
                await _webMonitor.StopAsync();
                bool cleaned = await _systemChanges.RunAsync(
                    () => SystemIntegration.FullCleanup(LogSystemMessage),
                    cancellationToken);
                if (!cleaned)
                {
                    throw new ApiException(
                        HttpStatusCode.InternalServerError,
                        "Windows DNS cleanup was incomplete; Drawbridge has kept the safety preferences enabled.");
                }

                _webMonitor.PersistEnabled(false);
                _configuration.SetDnsRouting(false);
                _configuration.SetWebMonitor(false);
                await WriteJsonAsync(response, new { cleaned = true }, cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/pin/verify")
            {
                string value = await ReadValueAsync(request, cancellationToken, "pin", "value");
                bool valid = !_pin.HasPin || await VerifyPinAttemptAsync(value, cancellationToken);
                if (!valid)
                {
                    throw new ApiException(HttpStatusCode.Unauthorized, "PIN is incorrect.");
                }

                await WriteJsonAsync(response, new { valid = true }, cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/pin/set")
            {
                string value = await ReadValueAsync(request, cancellationToken, "pin", "value");
                if (value.Length is < 4 or > 128)
                {
                    throw ApiException.BadRequest("PIN must contain between 4 and 128 characters.");
                }

                _pin.SetPin(value);
                await WriteJsonAsync(response, new { pinSet = true }, cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/pin/remove")
            {
                if (_webMonitor.IsRunning || _configuration.WebMonitorEnabled)
                {
                    throw new ApiException(
                        HttpStatusCode.Conflict,
                        "Disable the LAN monitor before removing its PIN.");
                }

                _pin.RemovePin();
                await WriteJsonAsync(response, new { pinSet = false }, cancellationToken);
                return;
            }

            if (method == "GET" && path == "/api/migration/status")
            {
                MigrationStatus status = _migration.GetStatus(request.QueryString["sourcePath"]);
                await WriteJsonAsync(response, status, cancellationToken);
                return;
            }

            if (method == "POST" && path == "/api/migration")
            {
                JsonElement body = await ReadJsonBodyAsync(request, cancellationToken);
                string sourcePath = RequiredString(body, "sourcePath");
                int copied = await _migration.ImportAsync(sourcePath, cancellationToken);
                await WriteJsonAsync(response, new { imported = true, copied }, cancellationToken);
                return;
            }

            throw new ApiException(HttpStatusCode.NotFound, "No control API endpoint matches this request.");
        }
        catch (ApiException exception)
        {
            await WriteJsonAsync(
                response,
                new { error = exception.Message },
                cancellationToken,
                exception.StatusCode);
        }
        catch (JsonException exception)
        {
            await WriteJsonAsync(
                response,
                new { error = $"Malformed JSON: {exception.Message}" },
                cancellationToken,
                HttpStatusCode.BadRequest);
        }
        catch (ArgumentException exception)
        {
            await WriteJsonAsync(
                response,
                new { error = exception.Message },
                cancellationToken,
                HttpStatusCode.BadRequest);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            TryAbort(response);
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Control API request {Method} {Path} recovered.", method, path);
            await WriteJsonAsync(
                response,
                new { error = "The service recovered from an internal request error." },
                cancellationToken,
                HttpStatusCode.InternalServerError);
        }
    }

    private object BuildStatus() => new
    {
        bridgeUp = _dns.IsRunning,
        mode = _blocklists.Mode.ToString(),
        domainCounts = _blocklists.BlockedDomainCount,
        domainCount = _blocklists.BlockedDomainCount,
        todayBlocked = _blockLog.TodayBlocked,
        allTimeBlocked = _blockLog.AllTimeBlocked,
        uptime = DateTimeOffset.UtcNow - _startedAt,
        version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "2.0.2",
        dnsRouted = IsDnsRouted(),
        dnsRoutingConfigured = _configuration.DnsRoutingEnabled,
        webMonitorEnabled = _webMonitor.IsRunning,
        webMonitorUrls = _webMonitor.Urls(),
        pinSet = _pin.HasPin,
    };

    private bool IsDnsRouted()
    {
        try
        {
            return SystemIntegration.IsDnsPointedAtDrawbridge();
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Could not inspect adapter DNS state.");
            return false;
        }
    }

    private static bool HasAnyLoopbackDns()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().Any(adapter =>
                adapter.OperationalStatus == OperationalStatus.Up &&
                adapter.NetworkInterfaceType is
                    NetworkInterfaceType.Ethernet or
                    NetworkInterfaceType.GigabitEthernet or
                    NetworkInterfaceType.Wireless80211 &&
                !adapter.Name.Contains('*') &&
                !adapter.Name.Contains("Filter", StringComparison.OrdinalIgnoreCase) &&
                !adapter.Name.EndsWith("-0000", StringComparison.OrdinalIgnoreCase) &&
                !adapter.Description.Contains("Wi-Fi Direct", StringComparison.OrdinalIgnoreCase) &&
                adapter.GetIPProperties().DnsAddresses.Any(address =>
                    address.Equals(IPAddress.Loopback) || address.Equals(IPAddress.IPv6Loopback)));
        }
        catch
        {
            return false;
        }
    }

    private void LogSystemMessage(string message) =>
        _logger.LogInformation("System: {Message}", message);

    private static bool IsMutation(string method) =>
        method is "POST" or "PUT" or "PATCH" or "DELETE";

    private static bool IsJsonContentType(string? contentType) =>
        string.Equals(
            contentType?.Split(';', 2)[0].Trim(),
            "application/json",
            StringComparison.OrdinalIgnoreCase);

    private static string NormalizePath(string? path)
    {
        string normalized = string.IsNullOrEmpty(path) ? "/" : path;
        if (normalized.Length > 1)
        {
            normalized = normalized.TrimEnd('/');
        }

        return normalized.ToLowerInvariant();
    }

    private static int ParseCount(string? value, int fallback, int minimum, int maximum) =>
        int.TryParse(value, out int parsed) ? Math.Clamp(parsed, minimum, maximum) : fallback;

    private static async Task<bool> ReadEnabledAsync(
        HttpListenerRequest request,
        CancellationToken cancellationToken)
    {
        JsonElement body = await ReadJsonBodyAsync(request, cancellationToken);
        if (body.ValueKind == JsonValueKind.True)
        {
            return true;
        }

        if (body.ValueKind == JsonValueKind.False)
        {
            return false;
        }

        if (TryGetProperty(body, "enabled", out JsonElement enabled) &&
            enabled.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            return enabled.GetBoolean();
        }

        throw ApiException.BadRequest("JSON body must contain a Boolean 'enabled' property.");
    }

    private static async Task<string> ReadValueAsync(
        HttpListenerRequest request,
        CancellationToken cancellationToken,
        params string[] names)
    {
        string? queryValue = names
            .Select(name => request.QueryString[name])
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        if (queryValue is not null)
        {
            return queryValue.Trim();
        }

        JsonElement body = await ReadJsonBodyAsync(request, cancellationToken);
        return RequiredString(body, names);
    }

    private static async Task<JsonElement> ReadJsonBodyAsync(
        HttpListenerRequest request,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength64 > MaximumBodyBytes)
        {
            throw new ApiException(HttpStatusCode.RequestEntityTooLarge, "Request body is too large.");
        }

        using var readDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        readDeadline.CancelAfter(BodyReadTimeout);
        try
        {
            using var buffer = new MemoryStream();
            byte[] chunk = new byte[8 * 1024];
            while (true)
            {
                int read = await request.InputStream.ReadAsync(chunk, readDeadline.Token);
                if (read == 0)
                {
                    break;
                }

                if (buffer.Length + read > MaximumBodyBytes)
                {
                    throw new ApiException(HttpStatusCode.RequestEntityTooLarge, "Request body is too large.");
                }

                buffer.Write(chunk, 0, read);
            }

            if (buffer.Length == 0)
            {
                throw ApiException.BadRequest("A JSON request body is required.");
            }

            using JsonDocument document = JsonDocument.Parse(buffer.ToArray());
            return document.RootElement.Clone();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ApiException(HttpStatusCode.RequestTimeout, "Request body timed out.");
        }
    }

    private async Task<bool> VerifyPinAttemptAsync(
        string candidate,
        CancellationToken cancellationToken)
    {
        if (!_pinAttemptGate.Wait(0))
        {
            throw new ApiException(
                HttpStatusCode.TooManyRequests,
                "A PIN verification is already in progress.");
        }

        try
        {
            bool valid = _pin.Verify(candidate);
            if (!valid)
            {
                await Task.Delay(FailedPinDelay, cancellationToken);
            }

            return valid;
        }
        finally
        {
            _pinAttemptGate.Release();
        }
    }

    private static string RequiredString(JsonElement body, params string[] names)
    {
        if (body.ValueKind == JsonValueKind.String)
        {
            string? direct = body.GetString();
            if (!string.IsNullOrWhiteSpace(direct))
            {
                return direct.Trim();
            }
        }

        foreach (string name in names)
        {
            if (TryGetProperty(body, name, out JsonElement value) &&
                value.ValueKind == JsonValueKind.String &&
                !string.IsNullOrWhiteSpace(value.GetString()))
            {
                return value.GetString()!.Trim();
            }
        }

        throw ApiException.BadRequest($"JSON body must contain '{names[0]}'.");
    }

    private static bool TryGetProperty(JsonElement body, string name, out JsonElement value)
    {
        if (body.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in body.EnumerateObject())
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private static async Task WriteJsonAsync(
        HttpListenerResponse response,
        object value,
        CancellationToken cancellationToken,
        HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        try
        {
            if (!response.OutputStream.CanWrite)
            {
                return;
            }

            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
            response.StatusCode = (int)statusCode;
            response.ContentType = "application/json; charset=utf-8";
            response.ContentLength64 = bytes.Length;
            await response.OutputStream.WriteAsync(bytes, cancellationToken);
            response.Close();
        }
        catch
        {
            TryAbort(response);
        }
    }

    private static void TryAbort(HttpListenerResponse response)
    {
        try
        {
            response.Abort();
        }
        catch
        {
            // The client may already have disconnected.
        }
    }

    private sealed class ApiException : Exception
    {
        public ApiException(HttpStatusCode statusCode, string message)
            : base(message)
        {
            StatusCode = statusCode;
        }

        public HttpStatusCode StatusCode { get; }

        public static ApiException BadRequest(string message) =>
            new(HttpStatusCode.BadRequest, message);
    }
}
