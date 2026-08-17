using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace Drawbridge.App;

/// <summary>The Drawbridge tray control panel.</summary>
public partial class MainWindow : Window
{
    private readonly ServiceClient _serviceClient = new();
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private readonly DispatcherTimer _pollTimer;
    private readonly ObservableCollection<string> _listUrls = [];
    private readonly ObservableCollection<string> _blockRules = [];
    private readonly ObservableCollection<string> _allowRules = [];
    private readonly System.Windows.Forms.NotifyIcon _notifyIcon;
    private System.Drawing.Icon? _notifyIconImage;
    private CancellationTokenSource? _pinDelayCancellation;
    private ServiceStatus? _status;
    private bool _pollInProgress;
    private bool _mutationInProgress;
    private bool _serviceStartInProgress;
    private bool _serviceOnline;
    private bool _lockStateInitialized;
    private bool _pinSet;
    private bool _locked = true;
    private bool _exitRequested;
    private bool _exitAnnouncementInProgress;
    private bool _exitAfterUnlock;
    private bool _allowSystemShutdown;
    private bool _updatingControls;
    private bool _migrationChecked;
    private bool _disposed;
    private bool? _lastTrayBridgeState;
    private int _failedUnlockAttempts;
    private string _currentMode = "Blocklist";
    private DateTimeOffset _lastConfigurationRefresh = DateTimeOffset.MinValue;
    private DateTimeOffset _lastChartRefresh = DateTimeOffset.MinValue;

    /// <summary>Initializes the control panel.</summary>
    public MainWindow()
    {
        InitializeComponent();

        ListUrlsList.ItemsSource = _listUrls;
        BlockRulesList.ItemsSource = _blockRules;
        AllowRulesList.ItemsSource = _allowRules;

        _notifyIcon = CreateNotifyIcon();
        _pollTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(2),
        };
        _pollTimer.Tick += async (_, _) => await PollServiceAsync();

        Loaded += MainWindow_OnLoaded;
        Closing += MainWindow_OnClosing;
        Closed += MainWindow_OnClosed;
        StateChanged += MainWindow_OnStateChanged;
    }

    /// <summary>Allows the window to close during Windows logout or shutdown.</summary>
    public void PrepareForSystemShutdown()
    {
        _allowSystemShutdown = true;
        _exitRequested = true;
    }

    private async void MainWindow_OnLoaded(object sender, RoutedEventArgs e)
    {
        await PollServiceAsync();
        _pollTimer.Start();
    }

    private void MainWindow_OnStateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized)
        {
            if (_pinSet && !_locked)
            {
                LockNow();
            }

            HideToTray();
        }
    }

    private void MainWindow_OnClosing(object? sender, CancelEventArgs e)
    {
        if (_allowSystemShutdown)
        {
            return;
        }

        if (_exitRequested)
        {
            if (_locked && _pinSet)
            {
                e.Cancel = true;
                _exitRequested = false;
                _exitAnnouncementInProgress = false;
                _exitAfterUnlock = true;
                ShowControlPanel();
                ConfigureLockOverlay("Unlock to exit", "Enter the control-panel PIN before exiting Drawbridge.");
            }

            return;
        }

        e.Cancel = true;
        if (!_lockStateInitialized)
        {
            ShowControlPanel();
            ShowUnknownPinState("Service status required");
            return;
        }

        if (_locked && _pinSet)
        {
            ShowControlPanel();
            LockErrorText.Text = "Unlock the control panel before closing it.";
            return;
        }

        if (_pinSet)
        {
            LockNow();
        }

        HideToTray();
    }

    private void MainWindow_OnClosed(object? sender, EventArgs e)
    {
        DisposeResources();
        if (System.Windows.Application.Current is not null)
        {
            System.Windows.Application.Current.Shutdown();
        }
    }

    private async Task PollServiceAsync()
    {
        if (_pollInProgress || _disposed)
        {
            return;
        }

        _pollInProgress = true;
        try
        {
            await PollServiceCoreAsync(_lifetimeCancellation.Token);
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            // App is exiting.
        }
        catch (Exception exception)
        {
            if (!_disposed)
            {
                ShowActionMessage($"The control panel recovered from an unexpected polling error: {exception.Message}", isError: true);
            }
        }
        finally
        {
            _pollInProgress = false;
        }
    }

    private async Task PollServiceCoreAsync(CancellationToken cancellationToken)
    {
        Task<ServiceStatus> statusTask = _serviceClient.GetStatusAsync(cancellationToken);
        Task<IReadOnlyList<LogEntry>> logsTask = _serviceClient.GetRecentLogsAsync(200, cancellationToken);
        bool statusSucceeded = false;

        try
        {
            ServiceStatus status = await statusTask;
            statusSucceeded = true;
            SetServiceOnline(status);

            if (DateTimeOffset.UtcNow - _lastConfigurationRefresh > TimeSpan.FromMinutes(1))
            {
                await RefreshConfigurationAsync(cancellationToken);
            }

            if (DateTimeOffset.UtcNow - _lastChartRefresh > TimeSpan.FromSeconds(30))
            {
                await RefreshChartAsync(cancellationToken);
            }

            if (!_migrationChecked && !_locked)
            {
                await TryOfferMigrationAsync(cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or ServiceApiException or System.Text.Json.JsonException)
        {
            SetServiceOffline(exception.Message);
        }
        catch (Exception exception)
        {
            ShowActionMessage($"Status refresh recovered: {exception.Message}", isError: true);
        }

        try
        {
            IReadOnlyList<LogEntry> logs = await logsTask;
            if (statusSucceeded)
            {
                UpdateLogs(logs);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            if (statusSucceeded)
            {
                ShowActionMessage($"Logs unavailable: {exception.Message}", isError: true);
            }
        }
    }

    private void SetServiceOnline(ServiceStatus status)
    {
        bool previousPinSet = _pinSet;
        _status = status;
        _serviceOnline = true;
        _pinSet = status.PinSet;
        if (!_pinSet)
        {
            _serviceClient.AuthenticationPin = null;
            _failedUnlockAttempts = 0;
        }

        OfflineBanner.Visibility = Visibility.Collapsed;
        PageHost.Opacity = 1;

        if (!_lockStateInitialized)
        {
            _lockStateInitialized = true;
            if (_pinSet)
            {
                LockNow();
            }
            else
            {
                SetUnlocked();
            }
        }
        else if (_pinSet && !previousPinSet && string.IsNullOrEmpty(_serviceClient.AuthenticationPin))
        {
            LockNow();
        }
        else if (!_pinSet && _locked)
        {
            SetUnlocked();
        }

        PageHost.IsEnabled = !_locked && !_mutationInProgress;
        LockStartServiceButton.Visibility = Visibility.Collapsed;
        UnlockButton.IsEnabled = true;
        UpdateStatusDisplay(status);
        UpdateSecurityDisplay();
        UpdateMonitorUrls(status.WebMonitorEnabled, status.WebMonitorUrls);
        bool protectedState = status.BridgeUp && status.DnsRouted;
        string trayStatus = protectedState
            ? "Bridge raised — filtering active"
            : status.BridgeUp
                ? "Bridge raised — system DNS not routed"
                : "Bridge lowered — filtering paused";
        UpdateTrayIcon(protectedState, trayStatus);
    }

    private void SetServiceOffline(string detail)
    {
        _serviceOnline = false;
        OfflineBanner.Visibility = Visibility.Visible;
        PageHost.IsEnabled = false;
        PageHost.Opacity = 0.58;
        StatusDot.Fill = FindBrush("DangerBrush");
        BridgeStatusText.Text = "Service not running";
        BridgeStatusDetailText.Text = "Start the Windows service to restore controls";
        BridgeButton.IsEnabled = false;
        UpdateTrayIcon(false, "Service not running");

        if (!_lockStateInitialized)
        {
            ShowUnknownPinState("Service unavailable");
        }
        else if (_locked)
        {
            LockOverlay.Visibility = Visibility.Visible;
            LockPromptPanel.Visibility = Visibility.Visible;
            LockStartServiceButton.Visibility = Visibility.Visible;
            UnlockButton.IsEnabled = false;
            LockTitleText.Text = "Service unavailable";
            LockDescriptionText.Text = "Start the service before verifying your PIN.";
        }

        if (!string.IsNullOrWhiteSpace(detail))
        {
            ActionMessageText.Text = "Waiting for the local service…";
            ActionMessageText.ToolTip = detail;
        }
    }

    private void UpdateStatusDisplay(ServiceStatus status)
    {
        bool protectedState = status.BridgeUp && status.DnsRouted;
        StatusDot.Fill = protectedState
            ? FindBrush("SuccessBrush")
            : status.BridgeUp
                ? FindBrush("WarningBrush")
                : FindBrush("DangerBrush");
        BridgeStatusText.Text = protectedState
            ? "Bridge raised"
            : status.BridgeUp
                ? "Bridge raised — DNS not routed"
                : "Bridge lowered";
        BridgeStatusDetailText.Text = protectedState
            ? $"Filtering in {status.Mode.ToLowerInvariant()} mode • system DNS routed"
            : status.BridgeUp
                ? "The DNS listener is ready, but Windows is not using it. Enable system DNS in Settings."
                : "DNS filtering is paused; the Windows service remains available";
        BridgeButton.Content = status.BridgeUp ? "Lower the bridge" : "Raise the bridge";
        BridgeButton.Style = (Style)FindResource(status.BridgeUp ? "DangerButton" : "PrimaryButton");
        BridgeButton.IsEnabled = true;
        DomainCountText.Text = status.DomainCounts.Total.ToString("N0", CultureInfo.CurrentCulture);
        TodayCountText.Text = status.TodayBlocked.ToString("N0", CultureInfo.CurrentCulture);
        AllTimeCountText.Text = status.AllTimeBlocked.ToString("N0", CultureInfo.CurrentCulture);
        VersionText.Text = string.IsNullOrWhiteSpace(status.Version) ? string.Empty : $"Service {status.Version}";
        UptimeText.Text = $"Uptime {FormatDuration(status.Uptime)}";

        _updatingControls = true;
        RouteDnsToggle.IsChecked = status.DnsRouted;
        WebMonitorToggle.IsChecked = status.WebMonitorEnabled;
        _updatingControls = false;

        ApplyModeSelection(status.Mode);
    }

    private async Task RefreshConfigurationAsync(CancellationToken cancellationToken)
    {
        try
        {
            Task<IReadOnlyList<string>> listsTask = _serviceClient.GetListsAsync(cancellationToken);
            Task<IReadOnlyList<string>> blocksTask = _serviceClient.GetBlockRulesAsync(cancellationToken);
            Task<IReadOnlyList<string>> allowsTask = _serviceClient.GetAllowRulesAsync(cancellationToken);
            Task<string> modeTask = _serviceClient.GetModeAsync(cancellationToken);
            await Task.WhenAll(listsTask, blocksTask, allowsTask, modeTask);

            ReplaceCollection(_listUrls, await listsTask);
            ReplaceCollection(_blockRules, await blocksTask);
            ReplaceCollection(_allowRules, await allowsTask);
            ApplyModeSelection(await modeTask);
            _lastConfigurationRefresh = DateTimeOffset.UtcNow;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or ServiceApiException or System.Text.Json.JsonException)
        {
            ShowActionMessage($"Rules could not be refreshed: {exception.Message}", isError: true);
        }
    }

    private async Task RefreshChartAsync(CancellationToken cancellationToken)
    {
        try
        {
            BlockChart.Series = await _serviceClient.GetDailyBlocksAsync(14, cancellationToken);
            _lastChartRefresh = DateTimeOffset.UtcNow;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or ServiceApiException or System.Text.Json.JsonException)
        {
            ShowActionMessage($"Block history unavailable: {exception.Message}", isError: true);
        }
    }

    private async Task TryOfferMigrationAsync(CancellationToken cancellationToken)
    {
        string legacyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Drawbridge");
        if (!Directory.Exists(legacyPath))
        {
            _migrationChecked = true;
            return;
        }

        try
        {
            MigrationStatus migration = await _serviceClient.GetMigrationStatusAsync(legacyPath, cancellationToken);
            _migrationChecked = true;
            if (!migration.Eligible || !migration.SourceExists)
            {
                return;
            }

            bool accepted = ConfirmationWindow.Ask(
                this,
                "Bring forward Drawbridge 1.x settings?",
                "A legacy Drawbridge profile was found. The Windows service can securely copy its settings into the new shared data store. Existing legacy files will be left untouched.",
                "Migrate settings");
            if (!accepted)
            {
                return;
            }

            bool migrated = await RunMutationAsync(
                token => _serviceClient.MigrateAsync(legacyPath, token),
                "Legacy settings migrated successfully.",
                pollAfter: false);
            if (!migrated)
            {
                return;
            }

            _lastConfigurationRefresh = DateTimeOffset.MinValue;
            await RefreshConfigurationAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or ServiceApiException or System.Text.Json.JsonException)
        {
            _migrationChecked = true;
            ShowActionMessage($"Migration could not be completed: {exception.Message}", isError: true);
        }
    }

    private void UpdateLogs(IReadOnlyList<LogEntry> logs)
    {
        string text = string.Join(Environment.NewLine, logs.Reverse().Select(entry => entry.DisplayText));
        if (!string.Equals(LogsTextBox.Text, text, StringComparison.Ordinal))
        {
            bool wasAtEnd = LogsTextBox.VerticalOffset >= LogsTextBox.ExtentHeight - LogsTextBox.ViewportHeight - 4;
            LogsTextBox.Text = text;
            if (wasAtEnd || string.IsNullOrEmpty(LogsTextBox.Text))
            {
                LogsTextBox.ScrollToEnd();
            }
        }

        LogsUpdatedText.Text = $"Updated {DateTime.Now:T}";
    }

    private async void BridgeButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (_status?.BridgeUp == true)
        {
            bool confirmed = ConfirmationWindow.Ask(
                this,
                "Lower the bridge?",
                "Filtering will pause immediately, though the Windows service will keep running. Any device using Drawbridge DNS will no longer be protected until the bridge is raised again.",
                "Lower bridge");
            if (!confirmed)
            {
                return;
            }

            await RunMutationAsync(token => _serviceClient.StopBridgeAsync(token), "Bridge lowered.");
        }
        else
        {
            await RunMutationAsync(token => _serviceClient.StartBridgeAsync(token), "Bridge raised. Filtering is active.");
        }
    }

    private async void ModeRadio_OnClick(object sender, RoutedEventArgs e)
    {
        if (_updatingControls || sender is not RadioButton radio || radio.Tag is not string requestedMode ||
            requestedMode.Equals(_currentMode, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (requestedMode.Equals("Whitelist", StringComparison.OrdinalIgnoreCase))
        {
            bool confirmed = ConfirmationWindow.Ask(
                this,
                "Enter whitelist mode?",
                "Whitelist mode blocks every domain unless it appears under Allowed domains. Drawbridge keeps a small set of Windows connectivity and update domains available, but browsers, apps, sign-ins, and updates may stop working until their domains are added.",
                "Enter whitelist mode",
                "WHITELIST");
            if (!confirmed)
            {
                ApplyModeSelection(_currentMode);
                return;
            }
        }

        bool succeeded = await RunMutationAsync(token => _serviceClient.SetModeAsync(requestedMode, token), $"Mode changed to {requestedMode}.");
        if (succeeded)
        {
            ApplyModeSelection(requestedMode);
        }
        else
        {
            ApplyModeSelection(_currentMode);
        }
    }

    private async void AddListButton_OnClick(object sender, RoutedEventArgs e)
    {
        string value = ListUrlInput.Text.Trim();
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            ShowActionMessage("Enter a complete HTTP or HTTPS blocklist URL.", isError: true);
            return;
        }

        if (await RunMutationAsync(token => _serviceClient.AddListAsync(value, token), "Remote list added."))
        {
            ListUrlInput.Clear();
            await RefreshConfigurationAsync(_lifetimeCancellation.Token);
        }
    }

    private async void DeleteListButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string value } &&
            await RunMutationAsync(token => _serviceClient.DeleteListAsync(value, token), "Remote list removed."))
        {
            await RefreshConfigurationAsync(_lifetimeCancellation.Token);
        }
    }

    private async void AddBlockRuleButton_OnClick(object sender, RoutedEventArgs e)
    {
        string? value = NormalizeDomain(BlockRuleInput.Text);
        if (value is null)
        {
            ShowActionMessage("Enter a valid domain, such as example.com.", isError: true);
            return;
        }

        if (await RunMutationAsync(token => _serviceClient.AddBlockRuleAsync(value, token), "Custom block rule added."))
        {
            BlockRuleInput.Clear();
            await RefreshConfigurationAsync(_lifetimeCancellation.Token);
        }
    }

    private async void DeleteBlockRuleButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string value } &&
            await RunMutationAsync(token => _serviceClient.DeleteBlockRuleAsync(value, token), "Custom block rule removed."))
        {
            await RefreshConfigurationAsync(_lifetimeCancellation.Token);
        }
    }

    private async void AddAllowRuleButton_OnClick(object sender, RoutedEventArgs e)
    {
        string? value = NormalizeDomain(AllowRuleInput.Text);
        if (value is null)
        {
            ShowActionMessage("Enter a valid domain, such as example.com.", isError: true);
            return;
        }

        if (await RunMutationAsync(token => _serviceClient.AddAllowRuleAsync(value, token), "Allowed domain added."))
        {
            AllowRuleInput.Clear();
            await RefreshConfigurationAsync(_lifetimeCancellation.Token);
        }
    }

    private async void DeleteAllowRuleButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string value } &&
            await RunMutationAsync(token => _serviceClient.DeleteAllowRuleAsync(value, token), "Allowed domain removed."))
        {
            await RefreshConfigurationAsync(_lifetimeCancellation.Token);
        }
    }

    private async void UpdateListsButton_OnClick(object sender, RoutedEventArgs e)
    {
        await RunMutationAsync(token => _serviceClient.CheckForUpdatesAsync(token), "Blocklist update completed.");
    }

    private async void RouteDnsToggle_OnClick(object sender, RoutedEventArgs e)
    {
        if (_updatingControls)
        {
            return;
        }

        bool requested = RouteDnsToggle.IsChecked == true;
        bool succeeded = await RunMutationAsync(token => _serviceClient.SetSystemDnsAsync(requested, token),
            requested ? "System DNS now routes through Drawbridge." : "System DNS restored to DHCP.");
        if (!succeeded)
        {
            _updatingControls = true;
            RouteDnsToggle.IsChecked = !requested;
            _updatingControls = false;
        }
    }

    private async void WebMonitorToggle_OnClick(object sender, RoutedEventArgs e)
    {
        if (_updatingControls)
        {
            return;
        }

        bool requested = WebMonitorToggle.IsChecked == true;
        if (requested && !_pinSet)
        {
            _updatingControls = true;
            WebMonitorToggle.IsChecked = false;
            _updatingControls = false;
            NavigateTo("Security");
            ShowActionMessage("Set a PIN before enabling the LAN dashboard.", isError: true);
            return;
        }

        bool succeeded = await RunMutationAsync(token => _serviceClient.SetWebMonitorAsync(requested, token),
            requested ? "LAN dashboard enabled." : "LAN dashboard disabled.");
        if (succeeded)
        {
            UpdateMonitorUrls(requested);
        }
        else
        {
            _updatingControls = true;
            WebMonitorToggle.IsChecked = !requested;
            _updatingControls = false;
        }
    }

    private async void UndoChangesButton_OnClick(object sender, RoutedEventArgs e)
    {
        bool confirmed = ConfirmationWindow.Ask(
            this,
            "Undo all system changes?",
            "This lowers the bridge, restores active adapters to automatic DNS, removes the LAN monitor firewall exposure, and disables the dashboard. Saved lists, rules, history, and PIN remain intact.",
            "Undo system changes",
            "UNDO");
        if (!confirmed)
        {
            return;
        }

        await RunMutationAsync(async token =>
        {
            await _serviceClient.FullCleanupAsync(token);
            await _serviceClient.StopBridgeAsync(token);
        }, "System DNS, monitoring, and filtering changes were undone.");
    }

    private async void SetPinButton_OnClick(object sender, RoutedEventArgs e)
    {
        string newPin = NewPinBox.Password;
        if (newPin.Length is < 4 or > 12 || !newPin.All(char.IsDigit))
        {
            ShowActionMessage("The PIN must contain 4–12 digits.", isError: true);
            return;
        }

        if (!string.Equals(newPin, ConfirmPinBox.Password, StringComparison.Ordinal))
        {
            ShowActionMessage("The new PIN entries do not match.", isError: true);
            return;
        }

        if (_pinSet && string.IsNullOrEmpty(_serviceClient.AuthenticationPin))
        {
            LockNow();
            LockErrorText.Text = "Unlock again before changing the PIN.";
            return;
        }

        if (await RunMutationAsync(
                token => _serviceClient.SetPinAsync(newPin, token),
                _pinSet ? "PIN changed." : "PIN enabled.",
                pollAfter: false))
        {
            _serviceClient.AuthenticationPin = newPin;
            _pinSet = true;
            NewPinBox.Clear();
            ConfirmPinBox.Clear();
            SetUnlocked();
            UpdateSecurityDisplay();
            await PollServiceAsync();
        }
    }

    private async void RemovePinButton_OnClick(object sender, RoutedEventArgs e)
    {
        bool confirmed = ConfirmationWindow.Ask(
            this,
            "Remove the control-panel PIN?",
            "Anyone signed in to this Windows account will be able to change filtering and DNS settings without unlocking the panel. The PIN-protected LAN dashboard will be disabled first if it is running.",
            "Remove PIN");
        if (!confirmed)
        {
            return;
        }

        if (await RunMutationAsync(async token =>
            {
                if (_status?.WebMonitorEnabled == true)
                {
                    await _serviceClient.SetWebMonitorAsync(false, token);
                }

                await _serviceClient.RemovePinAsync(token);
            }, "PIN removed."))
        {
            _serviceClient.AuthenticationPin = null;
            _pinSet = false;
            SetUnlocked();
            UpdateSecurityDisplay();
        }
    }

    private async Task<bool> RunMutationAsync(
        Func<CancellationToken, Task> operation,
        string successMessage,
        bool pollAfter = true)
    {
        if (!_serviceOnline)
        {
            ShowActionMessage("Start the Drawbridge service before making changes.", isError: true);
            return false;
        }

        if (_locked)
        {
            ShowControlPanel();
            return false;
        }

        if (_mutationInProgress)
        {
            ShowActionMessage("Another Drawbridge change is still in progress.", isError: true);
            return false;
        }

        _mutationInProgress = true;
        PageHost.IsEnabled = false;
        PageHost.Opacity = 0.82;
        try
        {
            await operation(_lifetimeCancellation.Token);
            ShowActionMessage(successMessage);
            if (pollAfter)
            {
                await PollServiceAsync();
            }

            return true;
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            return false;
        }
        catch (ServiceUnauthorizedException exception)
        {
            _serviceClient.AuthenticationPin = null;
            LockNow();
            LockErrorText.Text = exception.Message;
            return false;
        }
        catch (Exception exception) when (exception is HttpRequestException or ServiceApiException or System.Text.Json.JsonException)
        {
            ShowActionMessage(exception.Message, isError: true);
            if (exception is HttpRequestException)
            {
                SetServiceOffline(exception.Message);
            }

            return false;
        }
        finally
        {
            _mutationInProgress = false;
            PageHost.IsEnabled = _serviceOnline && !_locked;
            PageHost.Opacity = _serviceOnline ? 1 : 0.58;
        }
    }

    private async void UnlockButton_OnClick(object sender, RoutedEventArgs e) => await TryUnlockAsync();

    private async void LockPinBox_OnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && UnlockButton.IsEnabled)
        {
            e.Handled = true;
            await TryUnlockAsync();
        }
    }

    private async Task TryUnlockAsync()
    {
        if (!_serviceOnline || !UnlockButton.IsEnabled)
        {
            return;
        }

        string pin = LockPinBox.Password;
        if (string.IsNullOrWhiteSpace(pin))
        {
            LockErrorText.Text = "Enter your PIN.";
            return;
        }

        UnlockButton.IsEnabled = false;
        LockErrorText.Text = string.Empty;
        LockDelayText.Text = "Verifying…";
        try
        {
            if (await _serviceClient.VerifyPinAsync(pin, _lifetimeCancellation.Token))
            {
                _failedUnlockAttempts = 0;
                _serviceClient.AuthenticationPin = pin;
                LockPinBox.Clear();
                LockDelayText.Text = string.Empty;
                SetUnlocked();
                if (_exitAfterUnlock)
                {
                    _exitAfterUnlock = false;
                    RequestExit();
                }

                return;
            }

            _failedUnlockAttempts++;
            LockPinBox.Clear();
            LockErrorText.Text = "That PIN was not accepted.";
            int delaySeconds = Math.Min(30, _failedUnlockAttempts * 2);
            await RunPinDelayAsync(delaySeconds);
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            // App is exiting.
        }
        catch (Exception exception) when (exception is HttpRequestException or ServiceApiException or System.Text.Json.JsonException)
        {
            LockErrorText.Text = exception.Message;
            LockDelayText.Text = string.Empty;
            UnlockButton.IsEnabled = _serviceOnline;
            if (exception is HttpRequestException)
            {
                SetServiceOffline(exception.Message);
            }
        }
    }

    private async Task RunPinDelayAsync(int seconds)
    {
        _pinDelayCancellation?.Cancel();
        _pinDelayCancellation?.Dispose();
        _pinDelayCancellation = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCancellation.Token);
        CancellationToken token = _pinDelayCancellation.Token;
        try
        {
            for (int remaining = seconds; remaining > 0; remaining--)
            {
                LockDelayText.Text = $"Try again in {remaining}s";
                await Task.Delay(TimeSpan.FromSeconds(1), token);
            }
        }
        finally
        {
            if (!token.IsCancellationRequested)
            {
                LockDelayText.Text = string.Empty;
                UnlockButton.IsEnabled = _serviceOnline;
                LockPinBox.Focus();
            }
        }
    }

    private void LockNow()
    {
        if (!_pinSet)
        {
            NavigateTo("Security");
            ShowControlPanel();
            ShowActionMessage("Set a PIN before locking the control panel.", isError: true);
            return;
        }

        _locked = true;
        _serviceClient.AuthenticationPin = null;
        LockPinBox.Clear();
        LockErrorText.Text = string.Empty;
        LockDelayText.Text = string.Empty;
        LockOverlay.Visibility = Visibility.Visible;
        LockPromptPanel.Visibility = Visibility.Visible;
        LockStartServiceButton.Visibility = _serviceOnline ? Visibility.Collapsed : Visibility.Visible;
        UnlockButton.IsEnabled = _serviceOnline;
        PageHost.IsEnabled = false;
        ConfigureLockOverlay("Drawbridge is locked", "Enter your PIN to manage the gateway.");
        Dispatcher.BeginInvoke(DispatcherPriority.Input, () => LockPinBox.Focus());
    }

    private void SetUnlocked()
    {
        _locked = false;
        LockOverlay.Visibility = Visibility.Collapsed;
        PageHost.IsEnabled = _serviceOnline && !_mutationInProgress;
    }

    private void ConfigureLockOverlay(string title, string description)
    {
        LockOverlay.Visibility = Visibility.Visible;
        LockPromptPanel.Visibility = Visibility.Visible;
        LockTitleText.Text = title;
        LockDescriptionText.Text = description;
        Dispatcher.BeginInvoke(DispatcherPriority.Input, () => LockPinBox.Focus());
    }

    private void ShowUnknownPinState(string title)
    {
        _locked = true;
        PageHost.IsEnabled = false;
        LockStartServiceButton.Visibility = Visibility.Visible;
        UnlockButton.IsEnabled = false;
        ConfigureLockOverlay(
            title,
            "Start the Windows service before Drawbridge can determine whether a PIN is required.");
    }

    private async void StartServiceButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (_serviceStartInProgress)
        {
            return;
        }

        _serviceStartInProgress = true;
        try
        {
            ShowActionMessage("Requesting Windows to start the service…");
            string systemDirectory = Environment.SystemDirectory;
            string serviceControllerPath = Path.Combine(systemDirectory, "sc.exe");
            if (!File.Exists(serviceControllerPath))
            {
                throw new InvalidOperationException("Windows Service Control could not be located.");
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = serviceControllerPath,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = systemDirectory,
            };
            startInfo.ArgumentList.Add("start");
            startInfo.ArgumentList.Add("DrawbridgeService");
            using Process? process = Process.Start(startInfo);
            int serviceControlExitCode = -1;
            if (process is not null)
            {
                using var commandTimeout = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCancellation.Token);
                commandTimeout.CancelAfter(TimeSpan.FromSeconds(20));
                try
                {
                    await process.WaitForExitAsync(commandTimeout.Token);
                }
                catch (OperationCanceledException) when (!_lifetimeCancellation.IsCancellationRequested)
                {
                    throw new InvalidOperationException("Windows Service Control did not finish within 20 seconds.");
                }

                serviceControlExitCode = process.ExitCode;
                if (serviceControlExitCode != 0)
                {
                    ShowActionMessage($"Service Control returned code {serviceControlExitCode}; checking service state…", isError: true);
                }
            }

            int readinessSeconds = serviceControlExitCode == 0 ? 35 : 5;
            DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(readinessSeconds);
            Exception? lastFailure = null;
            while (DateTimeOffset.UtcNow < deadline)
            {
                try
                {
                    ServiceStatus status = await _serviceClient.GetStatusAsync(_lifetimeCancellation.Token);
                    SetServiceOnline(status);
                    ShowActionMessage("Drawbridge service is running.");
                    await PollServiceAsync();
                    return;
                }
                catch (Exception exception) when (exception is HttpRequestException or ServiceApiException or System.Text.Json.JsonException)
                {
                    lastFailure = exception;
                    await Task.Delay(TimeSpan.FromSeconds(1), _lifetimeCancellation.Token);
                }
            }

            SetServiceOffline(lastFailure?.Message ?? "The service did not become ready in time.");
            ShowActionMessage(
                serviceControlExitCode == 0
                    ? $"The service did not become ready within {readinessSeconds} seconds."
                    : $"Service Control failed with code {serviceControlExitCode}, and the service is unavailable.",
                isError: true);
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            ShowActionMessage("Service start was canceled.", isError: true);
        }
        catch (OperationCanceledException) when (_lifetimeCancellation.IsCancellationRequested)
        {
            // App is exiting.
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            ShowActionMessage($"Could not start the service: {exception.Message}", isError: true);
        }
        catch (Exception exception)
        {
            ShowActionMessage($"Service start recovered from an unexpected error: {exception.Message}", isError: true);
        }
        finally
        {
            _serviceStartInProgress = false;
        }
    }

    private void NavigationButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { CommandParameter: string page })
        {
            NavigateTo(page);
        }
    }

    private void NavigateTo(string page)
    {
        DashboardPage.Visibility = page == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        BlocklistsPage.Visibility = page == "Blocklists" ? Visibility.Visible : Visibility.Collapsed;
        SettingsPage.Visibility = page == "Settings" ? Visibility.Visible : Visibility.Collapsed;
        SecurityPage.Visibility = page == "Security" ? Visibility.Visible : Visibility.Collapsed;
        LogsPage.Visibility = page == "Logs" ? Visibility.Visible : Visibility.Collapsed;

        DashboardNav.Tag = page == "Dashboard" ? "Selected" : null;
        BlocklistsNav.Tag = page == "Blocklists" ? "Selected" : null;
        SettingsNav.Tag = page == "Settings" ? "Selected" : null;
        SecurityNav.Tag = page == "Security" ? "Selected" : null;
        LogsNav.Tag = page == "Logs" ? "Selected" : null;
    }

    private void TitleBar_OnMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (IsInsideButton(e.OriginalSource as DependencyObject))
        {
            return;
        }

        if (e.ClickCount == 2)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }
        else if (e.ButtonState == MouseButtonState.Pressed)
        {
            DragMove();
        }
    }

    private void MinimizeButton_OnClick(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void CloseButton_OnClick(object sender, RoutedEventArgs e) => Close();

    private static bool IsInsideButton(DependencyObject? element)
    {
        while (element is not null)
        {
            if (element is Button)
            {
                return true;
            }

            element = element switch
            {
                Visual => VisualTreeHelper.GetParent(element),
                System.Windows.Media.Media3D.Visual3D => VisualTreeHelper.GetParent(element),
                FrameworkContentElement contentElement => contentElement.Parent,
                _ => null,
            };
        }

        return false;
    }

    private System.Windows.Forms.NotifyIcon CreateNotifyIcon()
    {
        var menu = new System.Windows.Forms.ContextMenuStrip
        {
            BackColor = System.Drawing.Color.FromArgb(37, 44, 59),
            ForeColor = System.Drawing.Color.WhiteSmoke,
            ShowImageMargin = false,
        };
        var openItem = new System.Windows.Forms.ToolStripMenuItem("Open");
        var lockItem = new System.Windows.Forms.ToolStripMenuItem("Lock now");
        var exitItem = new System.Windows.Forms.ToolStripMenuItem("Exit");
        openItem.Click += (_, _) => Dispatcher.BeginInvoke(ShowControlPanel);
        lockItem.Click += (_, _) => Dispatcher.BeginInvoke(() =>
        {
            ShowControlPanel();
            LockNow();
        });
        exitItem.Click += (_, _) => Dispatcher.BeginInvoke(RequestExit);
        menu.Items.Add(openItem);
        menu.Items.Add(lockItem);
        menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
        menu.Items.Add(exitItem);

        _notifyIconImage = CastleIconFactory.Create(false);
        var icon = new System.Windows.Forms.NotifyIcon
        {
            Icon = _notifyIconImage,
            Text = "Drawbridge — connecting",
            ContextMenuStrip = menu,
            Visible = true,
        };
        icon.DoubleClick += (_, _) => Dispatcher.BeginInvoke(ShowControlPanel);
        return icon;
    }

    private void UpdateTrayIcon(bool bridgeUp, string tooltip)
    {
        if (_lastTrayBridgeState != bridgeUp)
        {
            System.Drawing.Icon replacement = CastleIconFactory.Create(bridgeUp);
            _notifyIcon.Icon = replacement;
            System.Drawing.Icon? previous = _notifyIconImage;
            _notifyIconImage = replacement;
            _lastTrayBridgeState = bridgeUp;
            previous?.Dispose();
        }

        string text = $"Drawbridge — {tooltip}";
        _notifyIcon.Text = text.Length <= 63 ? text : text[..63];
    }

    private void ShowControlPanel()
    {
        if (!IsVisible)
        {
            Show();
        }

        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        Activate();
        Topmost = true;
        Topmost = false;
        Focus();
    }

    private void HideToTray()
    {
        Hide();
        _notifyIcon.ShowBalloonTip(
            4000,
            "Drawbridge keeps guarding",
            "The control panel is hidden. Exiting it never stops the filtering service.",
            System.Windows.Forms.ToolTipIcon.Info);
    }

    private async void RequestExit()
    {
        if (!_lockStateInitialized)
        {
            ShowControlPanel();
            ShowUnknownPinState("Service status required before exit");
            LockErrorText.Text = "Drawbridge cannot safely exit until it has checked the PIN state.";
            return;
        }

        if (_locked && _pinSet)
        {
            _exitAfterUnlock = true;
            ShowControlPanel();
            ConfigureLockOverlay("Unlock to exit", "Enter the control-panel PIN before exiting. Filtering will continue in the Windows service.");
            return;
        }

        if (_exitAnnouncementInProgress)
        {
            return;
        }

        _exitAnnouncementInProgress = true;
        _exitRequested = true;
        _notifyIcon.ShowBalloonTip(
            3500,
            "Filtering continues",
            "Only the control panel is exiting. The Drawbridge Windows service keeps filtering in the background.",
            System.Windows.Forms.ToolTipIcon.Info);
        await Task.Delay(TimeSpan.FromSeconds(2));
        if (!_disposed)
        {
            Close();
        }
    }

    private void UpdateSecurityDisplay()
    {
        SecurityStatusText.Text = _pinSet
            ? "PIN protection is active. Closing or manually locking clears the in-memory unlock session."
            : "No PIN is set. Changes are available to anyone using this account.";
        SecurityBadgeText.Text = _pinSet ? "PROTECTED" : "NOT SET";
        SecurityBadge.Background = _pinSet
            ? new SolidColorBrush(Color.FromArgb(60, 53, 199, 129))
            : new SolidColorBrush(Color.FromArgb(60, 245, 185, 66));
        SecurityBadgeText.Foreground = _pinSet ? FindBrush("SuccessBrush") : FindBrush("WarningBrush");
        SetPinButton.Content = _pinSet ? "Change PIN" : "Set PIN";
        RemovePinButton.Visibility = _pinSet ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateMonitorUrls(bool enabled, IReadOnlyList<string>? serviceUrls = null)
    {
        if (!enabled)
        {
            MonitorUrlsText.Text = "Enable the LAN dashboard to see connection addresses.";
            return;
        }

        string[] urls = (serviceUrls ?? _status?.WebMonitorUrls ?? [])
            .Where(url => !string.IsNullOrWhiteSpace(url))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        MonitorUrlsText.Text = urls.Length == 0
            ? "The monitor is enabled; addresses will appear after the next service refresh."
            : string.Join(Environment.NewLine, urls);
    }

    private void ApplyModeSelection(string mode)
    {
        _currentMode = mode.Equals("Whitelist", StringComparison.OrdinalIgnoreCase) ? "Whitelist" : "Blocklist";
        _updatingControls = true;
        WhitelistModeRadio.IsChecked = _currentMode == "Whitelist";
        BlocklistModeRadio.IsChecked = _currentMode == "Blocklist";
        _updatingControls = false;
    }

    private void ShowActionMessage(string message, bool isError = false)
    {
        ActionMessageText.Text = message;
        ActionMessageText.Foreground = isError ? FindBrush("DangerBrush") : FindBrush("MutedTextBrush");
    }

    private Brush FindBrush(string key) => (Brush)FindResource(key);

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalDays >= 1)
        {
            return $"{(int)duration.TotalDays}d {duration.Hours}h";
        }

        if (duration.TotalHours >= 1)
        {
            return $"{(int)duration.TotalHours}h {duration.Minutes}m";
        }

        return $"{Math.Max(0, duration.Minutes)}m";
    }

    private static void ReplaceCollection(ObservableCollection<string> destination, IEnumerable<string> source)
    {
        destination.Clear();
        foreach (string item in source.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(item => item, StringComparer.OrdinalIgnoreCase))
        {
            destination.Add(item);
        }
    }

    private static string? NormalizeDomain(string input)
    {
        string candidate = input.Trim();
        if (candidate.StartsWith("||", StringComparison.Ordinal))
        {
            candidate = candidate[2..];
        }

        candidate = candidate.TrimEnd('^', '.');
        if (Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri))
        {
            candidate = uri.Host;
        }

        if (candidate.Contains('/') || candidate.Contains(' ') || candidate.Length == 0)
        {
            return null;
        }

        try
        {
            candidate = new IdnMapping().GetAscii(candidate).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return null;
        }

        return Uri.CheckHostName(candidate) is UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6
            ? candidate
            : null;
    }

    private void DisposeResources()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _pollTimer.Stop();
        _lifetimeCancellation.Cancel();
        _pinDelayCancellation?.Cancel();
        _pinDelayCancellation?.Dispose();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _notifyIconImage?.Dispose();
        _serviceClient.Dispose();
        _lifetimeCancellation.Dispose();
    }
}
