using Drawbridge.Core;

namespace Drawbridge.Service;

internal sealed class BridgeController
{
    private const int BindAttempts = 6;
    private static readonly TimeSpan BindRetryDelay = TimeSpan.FromSeconds(5);

    private readonly DnsServer _dns;
    private readonly ILogger<BridgeController> _logger;
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private volatile bool _desiredRunning = true;

    public BridgeController(DnsServer dns, ILogger<BridgeController> logger)
    {
        _dns = dns;
        _logger = logger;
    }

    public bool DesiredRunning => _desiredRunning;

    public async Task<bool> RaiseAsync(CancellationToken cancellationToken)
    {
        _desiredRunning = true;
        await _lifecycleGate.WaitAsync(cancellationToken);
        try
        {
            if (_dns.IsRunning)
            {
                return true;
            }

            for (int attempt = 1; attempt <= BindAttempts; attempt++)
            {
                try
                {
                    _dns.Start();
                    _logger.LogInformation("Bridge raised; DNS listeners are active.");
                    return true;
                }
                catch (Exception exception) when (attempt < BindAttempts)
                {
                    _dns.Stop();
                    _logger.LogWarning(
                        exception,
                        "DNS bind attempt {Attempt}/{Total} failed; retrying in five seconds.",
                        attempt,
                        BindAttempts);
                    await Task.Delay(BindRetryDelay, cancellationToken);
                }
                catch (Exception exception)
                {
                    _dns.Stop();
                    _logger.LogError(
                        exception,
                        "DNS bind failed after {Attempts} attempts; control API remains available.",
                        BindAttempts);
                    return false;
                }
            }

            return false;
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public async Task LowerAsync(CancellationToken cancellationToken)
    {
        _desiredRunning = false;
        await _lifecycleGate.WaitAsync(cancellationToken);
        try
        {
            await _dns.StopAsync();
            _logger.LogInformation("Bridge lowered; DNS listeners are stopped.");
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }
}
