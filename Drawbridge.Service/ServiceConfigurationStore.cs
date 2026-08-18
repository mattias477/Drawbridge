using System.Text.Json;
using Drawbridge.Core;

namespace Drawbridge.Service;

internal sealed class ServiceConfigurationStore
{
    private const int CurrentSchemaVersion = 1;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    private readonly object _gate = new();
    private readonly string _path;
    private readonly bool _recoverLegacyRouting;
    private ServiceConfiguration _configuration;

    public ServiceConfigurationStore(
        DrawbridgePaths paths,
        bool dataRootWasEmpty,
        bool defaultDnsRouting,
        bool recoverLegacyRouting = false)
    {
        _path = paths.ServiceConfigFile;
        _recoverLegacyRouting = recoverLegacyRouting;
        _configuration = Load(dataRootWasEmpty, defaultDnsRouting);
    }

    public bool DnsRoutingEnabled
    {
        get { lock (_gate) return _configuration.DnsRoutingEnabled; }
    }

    public bool WebMonitorEnabled
    {
        get { lock (_gate) return _configuration.WebMonitorEnabled; }
    }

    public bool MigrationEligible
    {
        get { lock (_gate) return _configuration.MigrationEligible; }
    }

    public string? RecoveryMessage { get; private set; }

    public void SetDnsRouting(bool enabled) => Update(configuration =>
        configuration with { DnsRoutingEnabled = enabled });

    public void SetWebMonitor(bool enabled) => Update(configuration =>
        configuration with { WebMonitorEnabled = enabled });

    public void CompleteMigration() => Update(configuration =>
        configuration with { MigrationEligible = false });

    private ServiceConfiguration Load(bool dataRootWasEmpty, bool defaultDnsRouting)
    {
        string json;
        try
        {
            // File.Exists deliberately returns false for access-denied paths. Reading first
            // lets us distinguish a genuinely new install from a damaged ACL and prevents a
            // saved protection preference from being silently replaced.
            json = File.ReadAllText(_path);
        }
        catch (FileNotFoundException)
        {
            return Create(defaultDnsRouting, dataRootWasEmpty);
        }
        catch (DirectoryNotFoundException)
        {
            return Create(defaultDnsRouting, dataRootWasEmpty);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidOperationException(
                "Drawbridge cannot read its service configuration. The ProgramData ACL must be repaired before startup.",
                exception);
        }
        catch (IOException exception)
        {
            throw new InvalidOperationException(
                "Drawbridge could not read its service configuration without risking the saved protection state.",
                exception);
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            if (!TryValidateShape(document.RootElement, out string shapeError))
            {
                return RecoverMalformed(defaultDnsRouting, dataRootWasEmpty, shapeError);
            }

            ServiceConfiguration? loaded = JsonSerializer.Deserialize<ServiceConfiguration>(json, JsonOptions);
            if (loaded is null)
            {
                return RecoverMalformed(defaultDnsRouting, dataRootWasEmpty, "the file contained no configuration");
            }

            if (loaded.SchemaVersion > CurrentSchemaVersion)
            {
                throw new InvalidOperationException(
                    $"The service configuration schema {loaded.SchemaVersion} is newer than this service supports.");
            }

            if (loaded.SchemaVersion < CurrentSchemaVersion)
            {
                bool restoreRouting = _recoverLegacyRouting && !loaded.DnsRoutingEnabled;
                loaded = loaded with
                {
                    SchemaVersion = CurrentSchemaVersion,
                    DnsRoutingEnabled = loaded.DnsRoutingEnabled || restoreRouting,
                };
                if (restoreRouting)
                {
                    RecoveryMessage =
                        "Restored protection after repairing ACL damage from Drawbridge 2.0.";
                }

                Save(loaded);
            }

            return loaded;
        }
        catch (JsonException exception)
        {
            return RecoverMalformed(
                defaultDnsRouting,
                dataRootWasEmpty,
                $"JSON parsing failed: {exception.Message}");
        }
        catch (NotSupportedException exception)
        {
            return RecoverMalformed(
                defaultDnsRouting,
                dataRootWasEmpty,
                $"the stored shape is unsupported: {exception.Message}");
        }
    }

    private static bool TryValidateShape(JsonElement root, out string error)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            error = "the root value was not an object";
            return false;
        }

        foreach (string requiredBoolean in new[]
                 {
                     nameof(ServiceConfiguration.DnsRoutingEnabled),
                     nameof(ServiceConfiguration.WebMonitorEnabled),
                     nameof(ServiceConfiguration.MigrationEligible),
                 })
        {
            if (!TryGetPropertyCaseInsensitive(root, requiredBoolean, out JsonElement value) ||
                value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                error = $"{requiredBoolean} was missing or was not a Boolean";
                return false;
            }
        }

        if (TryGetPropertyCaseInsensitive(
                root,
                nameof(ServiceConfiguration.SchemaVersion),
                out JsonElement schema) &&
            (schema.ValueKind != JsonValueKind.Number || !schema.TryGetInt32(out _)))
        {
            error = "SchemaVersion was not an integer";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool TryGetPropertyCaseInsensitive(
        JsonElement root,
        string name,
        out JsonElement value)
    {
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    private ServiceConfiguration Create(bool defaultDnsRouting, bool dataRootWasEmpty)
    {
        var created = new ServiceConfiguration(
            CurrentSchemaVersion,
            defaultDnsRouting,
            false,
            dataRootWasEmpty);
        Save(created);
        return created;
    }

    private ServiceConfiguration RecoverMalformed(
        bool defaultDnsRouting,
        bool dataRootWasEmpty,
        string reason)
    {
        RecoveryMessage =
            $"Recovered malformed service configuration using the protected default ({reason}).";
        return Create(defaultDnsRouting, dataRootWasEmpty);
    }

    private void Update(Func<ServiceConfiguration, ServiceConfiguration> mutation)
    {
        lock (_gate)
        {
            ServiceConfiguration updated = mutation(_configuration);
            Save(updated);
            _configuration = updated;
        }
    }

    private void Save(ServiceConfiguration configuration)
    {
        string temporary = _path + ".tmp";
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(temporary, JsonSerializer.Serialize(configuration, JsonOptions));
        File.Move(temporary, _path, true);
    }

    private sealed record ServiceConfiguration(
        int SchemaVersion,
        bool DnsRoutingEnabled,
        bool WebMonitorEnabled,
        bool MigrationEligible);
}
