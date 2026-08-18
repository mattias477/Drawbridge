using Drawbridge.Core;

namespace Drawbridge.Service;

internal sealed class DrawbridgeWorker : BackgroundService
{
    private static readonly TimeSpan BridgeMaintenanceInterval = TimeSpan.FromSeconds(10);
    private readonly BridgeController _bridge;
    private readonly DnsServer _dns;
    private readonly BlocklistService _blocklists;
    private readonly BlockLogService _blockLog;
    private readonly WebMonitorService _webMonitor;
    private readonly ServiceConfigurationStore _configuration;
    private readonly SystemChangeCoordinator _systemChanges;
    private readonly ILogger<DrawbridgeWorker> _logger;

    public DrawbridgeWorker(
        BridgeController bridge,
        DnsServer dns,
        BlocklistService blocklists,
        BlockLogService blockLog,
        WebMonitorService webMonitor,
        ServiceConfigurationStore configuration,
        SystemChangeCoordinator systemChanges,
        ILogger<DrawbridgeWorker> logger)
    {
        _bridge = bridge;
        _dns = dns;
        _blocklists = blocklists;
        _blockLog = blockLog;
        _webMonitor = webMonitor;
        _configuration = configuration;
        _systemChanges = systemChanges;
        _logger = logger;

        _dns.Log += message => _logger.LogInformation("DNS: {Message}", message);
        _dns.Blocked += _blockLog.Record;
        _blocklists.Log += message => _logger.LogInformation("Lists: {Message}", message);
        _webMonitor.Log += message => _logger.LogInformation("Monitor: {Message}", message);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_configuration.RecoveryMessage is { } recoveryMessage)
        {
            _logger.LogWarning("Configuration: {Message}", recoveryMessage);
        }

        if (!_configuration.DnsRoutingEnabled)
        {
            _logger.LogWarning(
                "System DNS routing is disabled; the local DNS listeners may be running, but Windows traffic is not protected.");
        }

        if (_configuration.WebMonitorEnabled || _webMonitor.WasEnabled)
        {
            try
            {
                _configuration.SetWebMonitor(true);
                _webMonitor.PersistEnabled(true);
                _webMonitor.Start();
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Could not restore the LAN web monitor.");
            }
        }

        await Task.WhenAll(
            MaintainBridgeAsync(stoppingToken),
            MaintainBlocklistsAsync(stoppingToken));
    }

    private async Task MaintainBridgeAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            if (_bridge.DesiredRunning && !_dns.IsRunning)
            {
                bool raised = await _bridge.RaiseAsync(stoppingToken);
                if (!raised && _configuration.DnsRoutingEnabled)
                {
                    _logger.LogError(
                        "Bridge is unavailable; restoring automatic DNS to avoid a dead-loopback outage while retries continue.");
                    await TryRunSystemActionAsync(
                        () => SystemIntegration.RestoreAutomaticDns(LogSystemMessage),
                        "restore automatic DNS after a bind failure",
                        stoppingToken);
                }
            }

            if (_bridge.DesiredRunning && _dns.IsRunning &&
                _configuration.DnsRoutingEnabled && !IsDnsRouted())
            {
                await TryRunSystemActionAsync(
                    () => SystemIntegration.PointDnsAtDrawbridge(LogSystemMessage),
                    "apply configured system DNS routing",
                    stoppingToken);
            }

            try
            {
                await Task.Delay(BridgeMaintenanceInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task MaintainBlocklistsAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                int updated = await _blocklists.CheckForUpdatesAsync(stoppingToken);
                _logger.LogInformation(
                    "Daily blocklist check completed; {Count} list(s) updated.",
                    updated);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Daily blocklist check recovered from an error.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromDays(1), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _webMonitor.StopAsync();
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Web monitor shutdown recovered from an error.");
        }

        if (_configuration.DnsRoutingEnabled)
        {
            try
            {
                bool restored = await _systemChanges.RunAsync(
                    () => SystemIntegration.RestoreAutomaticDns(LogSystemMessage),
                    cancellationToken);
                if (!restored)
                {
                    _logger.LogError(
                        "Graceful service stop could not fully restore automatic DNS; cleanup may still be required.");
                }
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                _logger.LogError(exception, "Graceful service stop could not restore automatic DNS.");
            }
            catch (OperationCanceledException)
            {
                _logger.LogError("Graceful service stop timed out while restoring automatic DNS.");
            }
        }

        await _bridge.LowerAsync(cancellationToken);
        await base.StopAsync(cancellationToken);
    }

    private void LogSystemMessage(string message) =>
        _logger.LogInformation("System: {Message}", message);

    private async Task TryRunSystemActionAsync(
        Func<bool> action,
        string description,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!await _systemChanges.RunAsync(action, cancellationToken))
            {
                _logger.LogError("Could not {Description}; one or more Windows commands failed.", description);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Could not {Description}.", description);
        }
    }

    private bool IsDnsRouted()
    {
        try
        {
            return SystemIntegration.IsDnsPointedAtDrawbridge();
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Could not inspect adapter DNS while maintaining routing.");
            return false;
        }
    }
}
