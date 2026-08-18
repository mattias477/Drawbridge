using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Drawbridge.App;

internal sealed class ServiceStatus
{
    [JsonPropertyName("bridgeUp")]
    public bool BridgeUp { get; init; }

    [JsonPropertyName("mode")]
    public string Mode { get; init; } = "Blocklist";

    [JsonPropertyName("domainCounts")]
    public DomainCounts DomainCounts { get; init; } = new();

    [JsonPropertyName("todayBlocked")]
    public long TodayBlocked { get; init; }

    [JsonPropertyName("allTimeBlocked")]
    public long AllTimeBlocked { get; init; }

    [JsonPropertyName("uptime")]
    [JsonConverter(typeof(FlexibleTimeSpanConverter))]
    public TimeSpan Uptime { get; init; }

    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;

    [JsonPropertyName("dnsRouted")]
    public bool DnsRouted { get; init; }

    [JsonPropertyName("dnsRoutingConfigured")]
    public bool DnsRoutingConfigured { get; init; }

    [JsonPropertyName("webMonitorEnabled")]
    public bool WebMonitorEnabled { get; init; }

    [JsonPropertyName("webMonitorUrls")]
    public string[] WebMonitorUrls { get; init; } = [];

    [JsonPropertyName("pinSet")]
    public bool PinSet { get; init; }
}

internal sealed class ProtectionActivationResult
{
    [JsonPropertyName("bridgeUp")]
    public bool BridgeUp { get; init; }

    [JsonPropertyName("dnsRouted")]
    public bool DnsRouted { get; init; }

    [JsonPropertyName("dnsRoutingConfigured")]
    public bool DnsRoutingConfigured { get; init; }

    [JsonPropertyName("pending")]
    public bool Pending { get; init; }
}

[JsonConverter(typeof(DomainCountsConverter))]
internal sealed class DomainCounts
{
    public int Total { get; init; }

    public int Remote { get; init; }

    public int Custom { get; init; }

    public int Allowed { get; init; }
}

/// <summary>Represents one day in the block-history series.</summary>
public sealed class DailyBlockCount
{
    /// <summary>Initializes a daily block-count point.</summary>
    public DailyBlockCount(DateOnly day, long count)
    {
        Day = day;
        Count = count;
    }

    /// <summary>Gets the local calendar day.</summary>
    public DateOnly Day { get; }

    /// <summary>Gets the number of requests blocked that day.</summary>
    public long Count { get; }
}

internal sealed record LogEntry(DateTimeOffset? Timestamp, string Level, string Category, string Message)
{
    public string DisplayText
    {
        get
        {
            string timestamp = Timestamp?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "                   ";
            string level = string.IsNullOrWhiteSpace(Level) ? "INFO" : Level.ToUpperInvariant();
            string category = string.IsNullOrWhiteSpace(Category) ? string.Empty : $" [{Category}]";
            return $"{timestamp}  {level,-7}{category}  {Message}";
        }
    }
}

internal sealed record MigrationStatus(bool Eligible, bool SourceExists);

internal sealed class DomainCountsConverter : JsonConverter<DomainCounts>
{
    public override DomainCounts Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Number)
        {
            return new DomainCounts { Total = ReadNumber(ref reader) };
        }

        if (reader.TokenType == JsonTokenType.String && int.TryParse(reader.GetString(), out int stringValue))
        {
            return new DomainCounts { Total = stringValue };
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            using JsonDocument ignored = JsonDocument.ParseValue(ref reader);
            return new DomainCounts();
        }

        using JsonDocument document = JsonDocument.ParseValue(ref reader);
        JsonElement root = document.RootElement;
        int remote = ReadProperty(root, "remote", "remoteRules", "lists", "blocklists");
        int custom = ReadProperty(root, "custom", "customRules", "blocked", "blockRules");
        int allowed = ReadProperty(root, "allowed", "allowRules", "whitelist");
        int total = ReadProperty(root, "total", "domains", "domainCount");
        if (total == 0)
        {
            total = remote + custom + allowed;
        }

        return new DomainCounts
        {
            Total = total,
            Remote = remote,
            Custom = custom,
            Allowed = allowed,
        };
    }

    public override void Write(Utf8JsonWriter writer, DomainCounts value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteNumber("total", value.Total);
        writer.WriteNumber("remote", value.Remote);
        writer.WriteNumber("custom", value.Custom);
        writer.WriteNumber("allowed", value.Allowed);
        writer.WriteEndObject();
    }

    private static int ReadNumber(ref Utf8JsonReader reader)
    {
        if (reader.TryGetInt32(out int value))
        {
            return value;
        }

        return checked((int)Math.Clamp(reader.GetInt64(), 0, int.MaxValue));
    }

    private static int ReadProperty(JsonElement root, params string[] names)
    {
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (!names.Any(name => property.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (property.Value.ValueKind == JsonValueKind.Number && property.Value.TryGetInt32(out int number))
            {
                return number;
            }

            if (property.Value.ValueKind == JsonValueKind.String && int.TryParse(property.Value.GetString(), out number))
            {
                return number;
            }
        }

        return 0;
    }
}

internal sealed class FlexibleTimeSpanConverter : JsonConverter<TimeSpan>
{
    public override TimeSpan Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Number && reader.TryGetDouble(out double seconds))
        {
            return TimeSpan.FromSeconds(Math.Max(0, seconds));
        }

        if (reader.TokenType == JsonTokenType.String)
        {
            string? value = reader.GetString();
            if (TimeSpan.TryParse(value, out TimeSpan duration))
            {
                return duration;
            }

            if (double.TryParse(value, out seconds))
            {
                return TimeSpan.FromSeconds(Math.Max(0, seconds));
            }
        }

        if (reader.TokenType is JsonTokenType.StartObject or JsonTokenType.StartArray)
        {
            using JsonDocument ignored = JsonDocument.ParseValue(ref reader);
        }

        return TimeSpan.Zero;
    }

    public override void Write(Utf8JsonWriter writer, TimeSpan value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.ToString("c"));
}

internal class ServiceApiException : Exception
{
    public ServiceApiException(string message, System.Net.HttpStatusCode statusCode)
        : base(message)
    {
        StatusCode = statusCode;
    }

    public System.Net.HttpStatusCode StatusCode { get; }
}

internal sealed class ServiceUnauthorizedException : ServiceApiException
{
    public ServiceUnauthorizedException(string message)
        : base(message, System.Net.HttpStatusCode.Unauthorized)
    {
    }
}

internal sealed class ServiceRequestTimeoutException : HttpRequestException
{
    public ServiceRequestTimeoutException(string message)
        : base(message)
    {
    }
}
