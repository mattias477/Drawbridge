namespace Drawbridge.Service;

internal static class ServiceStartupPolicy
{
    /// <summary>
    /// Production installs default to protection when no readable preference exists, even
    /// when an upgrade or legacy import has already populated ProgramData. Explicit console
    /// roots remain isolated from the host machine's adapter configuration.
    /// </summary>
    public static bool DefaultDnsRouting(string? dataRootOverride) => dataRootOverride is null;
}
