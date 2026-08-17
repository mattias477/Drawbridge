namespace Drawbridge.Service;

internal sealed class SystemChangeCoordinator
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<bool> RunAsync(Func<bool> operation, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await Task.Run(operation, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }
}

