using System.IO;
using System.Threading;
using System.Windows;

namespace Drawbridge.App;

/// <summary>Application entry point and single-instance lifetime owner.</summary>
public partial class App : Application
{
    private const string MutexName = @"Local\DrawbridgeSingleInstance";
    private const string GlobalMarkerName = @"Global\Drawbridge.App.InstallerPresence";
    private Mutex? _singleInstanceMutex;
    private GlobalInstanceMarker? _globalInstanceMarker;
    private bool _ownsMutex;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        StartupOptions options = StartupOptions.Parse(e.Args);

        try
        {
            _singleInstanceMutex = new Mutex(initiallyOwned: true, MutexName, out bool createdNew);
            _ownsMutex = createdNew;
            if (!createdNew)
            {
                if (!options.StartHidden)
                {
                    MessageBox.Show(
                        "Drawbridge is already running. Look for the castle in the notification area.",
                        "Drawbridge",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }

                Shutdown();
                return;
            }

        }
        catch (Exception exception)
        {
            WriteStartupDiagnostic("single-instance initialization", exception);
            if (!options.StartHidden)
            {
                MessageBox.Show(
                    "Drawbridge could not establish its single-instance guard. See the local app log for details.",
                    "Drawbridge",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }

            Shutdown();
            return;
        }

        try
        {
            _globalInstanceMarker = GlobalInstanceMarker.Create(GlobalMarkerName);
        }
        catch (Exception exception)
        {
            // The per-session mutex remains authoritative for the tray. A hostile or
            // stale global object must not be able to suppress the user's control panel.
            WriteStartupDiagnostic("cross-session installer marker", exception);
        }

        try
        {
            var window = new MainWindow();
            MainWindow = window;
            if (options.StartHidden)
            {
                window.StartHiddenToTray();
            }
            else
            {
                window.Show();
            }
        }
        catch (Exception exception)
        {
            WriteStartupDiagnostic("control-panel initialization", exception);
            if (!options.StartHidden)
            {
                MessageBox.Show(
                    "Drawbridge could not open the control panel. See the local app log for details.",
                    "Drawbridge",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }

            Shutdown(-1);
        }
    }

    /// <inheritdoc />
    protected override void OnSessionEnding(SessionEndingCancelEventArgs e)
    {
        if (MainWindow is MainWindow window)
        {
            window.PrepareForSystemShutdown();
        }

        base.OnSessionEnding(e);
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            if (_ownsMutex)
            {
                _singleInstanceMutex?.ReleaseMutex();
            }
        }
        catch (ApplicationException)
        {
            // Ownership may already have been released during shutdown.
        }

        _globalInstanceMarker?.Dispose();
        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }

    private static void WriteStartupDiagnostic(string stage, Exception exception)
    {
        try
        {
            string directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Drawbridge");
            Directory.CreateDirectory(directory);
            File.AppendAllText(
                Path.Combine(directory, "app.log"),
                $"{DateTimeOffset.Now:O}\tStartup failure during {stage}: {exception}{Environment.NewLine}");
        }
        catch
        {
            // Diagnostics must never turn a startup failure into another crash.
        }
    }
}
