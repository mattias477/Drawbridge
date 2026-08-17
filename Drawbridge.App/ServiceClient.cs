using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace Drawbridge.App;

/// <summary>Typed client for the Drawbridge loopback control API.</summary>
internal sealed class ServiceClient : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly HttpClient _httpClient;

    public ServiceClient()
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
        };
        _httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://127.0.0.1:8054/", UriKind.Absolute),
            Timeout = Timeout.InfiniteTimeSpan,
        };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Drawbridge.App/2.0");
        _httpClient.DefaultRequestHeaders.TryAddWithoutValidation("X-Drawbridge-Client", "Drawbridge.App");
    }

    public string? AuthenticationPin { get; set; }

    public Task<ServiceStatus> GetStatusAsync(CancellationToken cancellationToken = default) =>
        GetJsonAsync<ServiceStatus>("api/status", cancellationToken);

    public Task StartBridgeAsync(CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/bridge/start", new { }, authenticate: true, cancellationToken);

    public Task StopBridgeAsync(CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/bridge/stop", new { }, authenticate: true, cancellationToken);

    public Task<IReadOnlyList<string>> GetListsAsync(CancellationToken cancellationToken = default) =>
        GetStringCollectionAsync("api/lists", ["lists", "items", "urls"], cancellationToken);

    public Task AddListAsync(string value, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/lists", new { value }, authenticate: true, cancellationToken);

    public Task DeleteListAsync(string value, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Delete, "api/lists", new { value }, authenticate: true, cancellationToken);

    public Task<IReadOnlyList<string>> GetBlockRulesAsync(CancellationToken cancellationToken = default) =>
        GetStringCollectionAsync("api/rules/block", ["rules", "items", "domains"], cancellationToken);

    public Task AddBlockRuleAsync(string value, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/rules/block", new { value }, authenticate: true, cancellationToken);

    public Task DeleteBlockRuleAsync(string value, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Delete, "api/rules/block", new { value }, authenticate: true, cancellationToken);

    public Task<IReadOnlyList<string>> GetAllowRulesAsync(CancellationToken cancellationToken = default) =>
        GetStringCollectionAsync("api/rules/allow", ["rules", "items", "domains"], cancellationToken);

    public Task AddAllowRuleAsync(string value, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/rules/allow", new { value }, authenticate: true, cancellationToken);

    public Task DeleteAllowRuleAsync(string value, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Delete, "api/rules/allow", new { value }, authenticate: true, cancellationToken);

    public async Task<string> GetModeAsync(CancellationToken cancellationToken = default)
    {
        using HttpResponseMessage response = await SendAsync(HttpMethod.Get, "api/mode", null, authenticate: false, null, cancellationToken);
        string json = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(json))
        {
            return "Blocklist";
        }

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        if (root.ValueKind == JsonValueKind.String)
        {
            return root.GetString() ?? "Blocklist";
        }

        return TryGetProperty(root, "mode", out JsonElement mode) && mode.ValueKind == JsonValueKind.String
            ? mode.GetString() ?? "Blocklist"
            : "Blocklist";
    }

    public Task SetModeAsync(string mode, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Put, "api/mode", new { mode }, authenticate: true, cancellationToken);

    public Task CheckForUpdatesAsync(CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/update-check", new { }, authenticate: true, cancellationToken);

    public async Task<IReadOnlyList<LogEntry>> GetRecentLogsAsync(int count = 200, CancellationToken cancellationToken = default)
    {
        count = Math.Clamp(count, 1, 1000);
        using HttpResponseMessage response = await SendAsync(
            HttpMethod.Get,
            $"api/logs/recent?count={count.ToString(CultureInfo.InvariantCulture)}",
            null,
            authenticate: false,
            null,
            cancellationToken);
        string json = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        JsonElement items = FindArray(root, "logs", "events", "items");
        if (items.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var results = new List<LogEntry>();
        foreach (JsonElement item in items.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String)
            {
                results.Add(new LogEntry(null, "Info", string.Empty, item.GetString() ?? string.Empty));
                continue;
            }

            if (item.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string message = ReadString(item, "message", "event", "domain") ?? item.ToString();
            string level = ReadString(item, "level", "severity") ?? "Info";
            string category = ReadString(item, "category", "source") ?? string.Empty;
            DateTimeOffset? timestamp = ReadDateTime(item, "timestamp", "time", "date");
            results.Add(new LogEntry(timestamp, level, category, message));
        }

        return results;
    }

    public async Task<IReadOnlyList<DailyBlockCount>> GetDailyBlocksAsync(int days = 14, CancellationToken cancellationToken = default)
    {
        days = Math.Clamp(days, 1, 90);
        using HttpResponseMessage response = await SendAsync(
            HttpMethod.Get,
            $"api/blocks/daily?days={days.ToString(CultureInfo.InvariantCulture)}",
            null,
            authenticate: false,
            null,
            cancellationToken);
        string json = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        JsonElement items = FindArray(root, "days", "series", "items");
        var results = new List<DailyBlockCount>();
        if (items.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in items.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                string? dayValue = ReadString(item, "day", "date");
                if (!DateOnly.TryParse(dayValue, CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly day))
                {
                    continue;
                }

                long count = ReadLong(item, "count", "blocked", "value");
                results.Add(new DailyBlockCount(day, Math.Max(0, count)));
            }
        }
        else if (root.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (DateOnly.TryParse(property.Name, CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly day) &&
                    property.Value.ValueKind == JsonValueKind.Number && property.Value.TryGetInt64(out long count))
                {
                    results.Add(new DailyBlockCount(day, Math.Max(0, count)));
                }
            }
        }

        return results.OrderBy(item => item.Day).ToArray();
    }

    public Task<bool> GetSystemDnsAsync(CancellationToken cancellationToken = default) =>
        GetBooleanAsync("api/system/dns", cancellationToken);

    public Task SetSystemDnsAsync(bool enabled, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/system/dns", new { enabled }, authenticate: true, cancellationToken);

    public Task SetWebMonitorAsync(bool enabled, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/webmonitor", new { enabled }, authenticate: true, cancellationToken);

    public Task FullCleanupAsync(CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/system/cleanup", new { }, authenticate: true, cancellationToken);

    public async Task<bool> VerifyPinAsync(string pin, CancellationToken cancellationToken = default)
    {
        using HttpResponseMessage response = await SendAsync(
            HttpMethod.Post,
            "api/pin/verify",
            new { pin },
            authenticate: false,
            pin,
            cancellationToken,
            allowUnauthorized: true);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return false;
        }

        string json = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(json))
        {
            return true;
        }

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        if (root.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            return root.GetBoolean();
        }

        return !TryGetProperty(root, "valid", out JsonElement valid) || valid.ValueKind != JsonValueKind.False;
    }

    public Task SetPinAsync(string pin, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/pin/set", new { pin }, authenticate: true, cancellationToken);

    public Task RemovePinAsync(CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/pin/remove", new { }, authenticate: true, cancellationToken);

    public async Task<MigrationStatus> GetMigrationStatusAsync(string sourcePath, CancellationToken cancellationToken = default)
    {
        string path = $"api/migration/status?sourcePath={Uri.EscapeDataString(sourcePath)}";
        using HttpResponseMessage response = await SendAsync(HttpMethod.Get, path, null, authenticate: false, null, cancellationToken);
        string json = await response.Content.ReadAsStringAsync(cancellationToken);
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        bool eligible = TryGetProperty(root, "eligible", out JsonElement eligibleElement) && eligibleElement.ValueKind == JsonValueKind.True;
        bool sourceExists = TryGetProperty(root, "sourceExists", out JsonElement sourceElement) && sourceElement.ValueKind == JsonValueKind.True;
        return new MigrationStatus(eligible, sourceExists);
    }

    public Task MigrateAsync(string sourcePath, CancellationToken cancellationToken = default) =>
        SendNoResultAsync(HttpMethod.Post, "api/migration", new { sourcePath }, authenticate: true, cancellationToken);

    public void Dispose() => _httpClient.Dispose();

    private async Task<T> GetJsonAsync<T>(string path, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(HttpMethod.Get, path, null, authenticate: false, null, cancellationToken);
        T? result = await response.Content.ReadFromJsonAsync<T>(JsonOptions, cancellationToken);
        return result ?? throw new ServiceApiException("The service returned an empty response.", response.StatusCode);
    }

    private async Task<IReadOnlyList<string>> GetStringCollectionAsync(
        string path,
        string[] wrapperNames,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(HttpMethod.Get, path, null, authenticate: false, null, cancellationToken);
        string json = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement items = FindArray(document.RootElement, wrapperNames);
        if (items.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var results = new List<string>();
        foreach (JsonElement item in items.EnumerateArray())
        {
            string? value = item.ValueKind switch
            {
                JsonValueKind.String => item.GetString(),
                JsonValueKind.Object => ReadString(item, "value", "url", "domain", "rule"),
                _ => null,
            };

            if (!string.IsNullOrWhiteSpace(value))
            {
                results.Add(value);
            }
        }

        return results;
    }

    private async Task<bool> GetBooleanAsync(string path, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(HttpMethod.Get, path, null, authenticate: false, null, cancellationToken);
        string json = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        if (root.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            return root.GetBoolean();
        }

        return TryGetProperty(root, "enabled", out JsonElement enabled) && enabled.ValueKind == JsonValueKind.True;
    }

    private async Task SendNoResultAsync(
        HttpMethod method,
        string path,
        object? body,
        bool authenticate,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage ignored = await SendAsync(method, path, body, authenticate, null, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        object? body,
        bool authenticate,
        string? authenticationOverride,
        CancellationToken cancellationToken,
        bool allowUnauthorized = false)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: JsonOptions);
        }

        string? pin = authenticationOverride ?? (authenticate ? AuthenticationPin : null);
        if (!string.IsNullOrEmpty(pin))
        {
            request.Headers.TryAddWithoutValidation("X-Drawbridge-Pin", pin);
        }

        HttpResponseMessage response;
        using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCancellation.CancelAfter(GetRequestTimeout(method, path));
        try
        {
            response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead, timeoutCancellation.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new HttpRequestException("The Drawbridge service did not respond in time.");
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized && allowUnauthorized)
        {
            return response;
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            string detail = await ReadErrorAsync(response, cancellationToken);
            response.Dispose();
            throw new ServiceUnauthorizedException(string.IsNullOrWhiteSpace(detail) ? "The PIN was not accepted." : detail);
        }

        if (!response.IsSuccessStatusCode)
        {
            string detail = await ReadErrorAsync(response, cancellationToken);
            HttpStatusCode statusCode = response.StatusCode;
            response.Dispose();
            throw new ServiceApiException(
                string.IsNullOrWhiteSpace(detail) ? $"The service returned HTTP {(int)statusCode}." : detail,
                statusCode);
        }

        return response;
    }

    private static TimeSpan GetRequestTimeout(HttpMethod method, string path)
    {
        if (method == HttpMethod.Get)
        {
            return TimeSpan.FromSeconds(4);
        }

        if (path.StartsWith("api/update-check", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("api/system/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("api/webmonitor", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("api/migration", StringComparison.OrdinalIgnoreCase))
        {
            return TimeSpan.FromMinutes(2);
        }

        if (path.StartsWith("api/bridge/", StringComparison.OrdinalIgnoreCase))
        {
            return TimeSpan.FromSeconds(40);
        }

        return TimeSpan.FromSeconds(15);
    }

    private static async Task<string> ReadErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(content))
        {
            return string.Empty;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(content);
            return ReadString(document.RootElement, "error", "message", "detail") ?? content;
        }
        catch (JsonException)
        {
            return content;
        }
    }

    private static JsonElement FindArray(JsonElement root, params string[] wrapperNames)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            return root;
        }

        foreach (string name in wrapperNames)
        {
            if (TryGetProperty(root, name, out JsonElement candidate) && candidate.ValueKind == JsonValueKind.Array)
            {
                return candidate;
            }
        }

        return default;
    }

    private static bool TryGetProperty(JsonElement element, string name, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private static string? ReadString(JsonElement element, params string[] names)
    {
        foreach (string name in names)
        {
            if (TryGetProperty(element, name, out JsonElement value))
            {
                return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
            }
        }

        return null;
    }

    private static long ReadLong(JsonElement element, params string[] names)
    {
        foreach (string name in names)
        {
            if (!TryGetProperty(element, name, out JsonElement value))
            {
                continue;
            }

            if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out long number))
            {
                return number;
            }

            if (value.ValueKind == JsonValueKind.String && long.TryParse(value.GetString(), out number))
            {
                return number;
            }
        }

        return 0;
    }

    private static DateTimeOffset? ReadDateTime(JsonElement element, params string[] names)
    {
        string? value = ReadString(element, names);
        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset timestamp)
            ? timestamp
            : null;
    }
}
