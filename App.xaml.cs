using System.Threading;
using System.Windows;
using Drawbridge.Core;

namespace Drawbridge;

public partial class App : Application
{
    private static Mutex? _singleInstanceMutex;
    private static bool _ownsMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Headless cleanup mode, used by the uninstaller:
        //   Drawbridge.exe --cleanup
        // Undoes every system change (DNS, login task, firewall rule) and
        // exits without showing any UI. Runs BEFORE the single-instance
        // check so it works even if a normal instance is still around.
        if (e.Args.Contains("--cleanup"))
        {
            try { SystemIntegration.FullCleanup(); } catch { /* best effort */ }
            Shutdown();
            return;
        }

        _singleInstanceMutex = new Mutex(
            initiallyOwned: true,
            name: @"Global\DrawbridgeSingleInstance",
            createdNew: out _ownsMutex);

        if (!_ownsMutex)
        {
            MessageBox.Show(
                "Drawbridge is already running — it probably started " +
                "automatically at login. Look for the castle icon by the " +
                "clock, or its window on the taskbar.\n\n" +
                "This copy will close.",
                "Drawbridge", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            if (_ownsMutex)
                _singleInstanceMutex?.ReleaseMutex();
            _singleInstanceMutex?.Dispose();
        }
        catch { /* shutting down anyway */ }

        base.OnExit(e);
    }
}