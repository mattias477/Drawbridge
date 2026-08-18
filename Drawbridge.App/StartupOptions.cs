namespace Drawbridge.App;

/// <summary>Command-line options that control the control panel's initial presentation.</summary>
internal readonly record struct StartupOptions(bool StartHidden)
{
    /// <summary>Parses supported startup arguments without rejecting future options.</summary>
    internal static StartupOptions Parse(IEnumerable<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        bool startHidden = arguments.Any(argument =>
            string.Equals(argument, "--startup", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(argument, "--minimized", StringComparison.OrdinalIgnoreCase));
        return new StartupOptions(startHidden);
    }
}
