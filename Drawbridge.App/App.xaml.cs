using System.Threading;
using System.Windows;

namespace Drawbridge.App;

/// <summary>Application entry point and single-instance lifetime owner.</summary>
public partial class App : Application
{
    private const string MutexName = @"Global\DrawbridgeSingleInstance";
    private Mutex? _singleInstanceMutex;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        try
        {
            _singleInstanceMutex = new Mutex(initiallyOwned: true, MutexName, out bool createdNew);
            if (!createdNew)
            {
                MessageBox.Show(
                    "Drawbridge is already running. Look for the castle in the notification area.",
                    "Drawbridge",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                Shutdown();
                return;
            }
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show(
                "Drawbridge is already running in another Windows session.",
                "Drawbridge",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            Shutdown();
            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        window.Show();
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
            _singleInstanceMutex?.ReleaseMutex();
        }
        catch (ApplicationException)
        {
            // Ownership may already have been released during shutdown.
        }

        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }
}
