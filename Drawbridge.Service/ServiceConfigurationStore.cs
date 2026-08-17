using System.Text.Json;
using Drawbridge.Core;

namespace Drawbridge.Service;

internal sealed class ServiceConfigurationStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    private readonly object _gate = new();
    private readonly string _path;
    private ServiceConfiguration _configuration;

    public ServiceConfigurationStore(
        DrawbridgePaths paths,
        bool dataRootWasEmpty,
        bool defaultDnsRouting)
    {
        _path = paths.ServiceConfigFile;
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

    public void SetDnsRouting(bool enabled) => Update(configuration =>
        configuration with { DnsRoutingEnabled = enabled });

    public void SetWebMonitor(bool enabled) => Update(configuration =>
        configuration with { WebMonitorEnabled = enabled });

    public void CompleteMigration() => Update(configuration =>
        configuration with { MigrationEligible = false });

    private ServiceConfiguration Load(bool dataRootWasEmpty, bool defaultDnsRouting)
    {
        try
        {
            if (File.Exists(_path))
            {
                return JsonSerializer.Deserialize<ServiceConfiguration>(
                       File.ReadAllText(_path), JsonOptions)
                       ?? new ServiceConfiguration(defaultDnsRouting, false, dataRootWasEmpty);
            }
        }
        catch
        {
            // A damaged preference file must not keep the filtering service down.
        }

        var created = new ServiceConfiguration(defaultDnsRouting, false, dataRootWasEmpty);
        Save(created);
        return created;
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
        bool DnsRoutingEnabled,
        bool WebMonitorEnabled,
        bool MigrationEligible);
}
