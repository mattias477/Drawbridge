using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Drawbridge.Core;

namespace Drawbridge;

public partial class MainWindow : Window
{
    private readonly BlocklistService _blocklist = new();
    private readonly PinService _pin = new();
    private readonly BlockLogService _blockLog = new();
    private readonly DnsServer _server;
    private readonly WebMonitorService _webMonitor;

    private bool _initializing = true; // suppress control events during setup
    private bool _locked;
    private int _failedAttempts;
    private DateTime _lastChartRedraw = DateTime.MinValue;

    public MainWindow()
    {
        InitializeComponent();

        _server = new DnsServer(_blocklist);
        _webMonitor = new WebMonitorService(
            _pin, _blockLog,
            bridgeIsUp: () => _server.IsRunning,
            domainCount: () => _blocklist.BlockedDomainCount);

        _server.Log += line => Dispatcher.InvokeAsync(() => AppendLog(line));
        _blocklist.Log += line => Dispatcher.InvokeAsync(() => AppendLog(line));
        _webMonitor.Log += line => Dispatcher.InvokeAsync(() => AppendLog(line));

        _server.Blocked += domain =>
        {
            _blockLog.Record(domain);
            Dispatcher.InvokeAsync(OnBlockRecorded);
        };

        _blocklist.LoadSettings();
        _blocklist.LoadMeta();
        _blockLog.Load();
        RefreshUrlListBox();
        RefreshCustomDomainsList();
        RefreshAllowedDomainsList();

        SystemDnsCheck.IsChecked = SystemIntegration.IsDnsPointedAtDrawbridge();
        RunAtLoginCheck.IsChecked = SystemIntegration.IsRunAtLoginEnabled();
        WebMonitorCheck.IsChecked = _webMonitor.WasEnabled;

        if (_blocklist.Mode == FilterMode.Whitelist)
            WhitelistModeRadio.IsChecked = true;
        else
            BlocklistModeRadio.IsChecked = true;

        _initializing = false;

        UpdatePinUi();

        if (_pin.HasPin)
            LockUi();

        Loaded += async (_, _) =>
        {
            _blocklist.RebuildFromCache();
            UpdateCountLabel();

            foreach ((DateTime time, string domain) in _blockLog.Recent(100).Reverse())
                LogList.Items.Add($"[{time:MMM d HH:mm:ss}] BLOCKED: {domain}");
            if (LogList.Items.Count > 0)
                AppendLog($"— loaded {LogList.Items.Count} blocked lookups from previous sessions —");

            UpdateBlockStats();
            RedrawChart();

            // At boot, other services can briefly hold port 53 or the
            // network stack may not be ready — retry instead of giving up.
            await StartBridgeWithRetryAsync();

            if (_webMonitor.WasEnabled && _pin.HasPin)
                StartWebMonitor();

            await CheckForUpdatesAsync();
        };
    }

    // ---------- start / stop ----------

    /// <summary>Startup path: up to 6 attempts, 5s apart, no popups.</summary>
    private async Task StartBridgeWithRetryAsync()
    {
        for (int attempt = 1; attempt <= 6 && !_server.IsRunning; attempt++)
        {
            try
            {
                _server.Start();
                SetStatus(true);
                if (attempt > 1)
                    AppendLog($"Bridge started on attempt {attempt}.");
            }
            catch (Exception ex)
            {
                AppendLog($"Start attempt {attempt}/6 failed: {ex.Message}" +
                          (attempt < 6 ? " — retrying in 5s" : ""));
                if (attempt < 6)
                    await Task.Delay(5000);
            }
        }

        if (!_server.IsRunning)
        {
            SetStatus(false);
            AppendLog("Could not start after 6 attempts. Find the conflict with: " +
                      "netstat -abno | findstr :53   (admin Command Prompt)");
        }
    }

    /// <summary>Manual start (toggle button): one attempt, with a popup on failure.</summary>
    private void StartBridge()
    {
        if (_server.IsRunning) return;

        try
        {
            _server.Start();
            SetStatus(true);
        }
        catch (Exception ex)
        {
            AppendLog($"Failed to start: {ex.Message}");
            MessageBox.Show(
                $"Couldn't start the DNS server:\n\n{ex.Message}\n\n" +
                "Port 53 may already be in use. Find the conflict with:\n" +
                "netstat -abno | findstr :53   (admin Command Prompt)",
                "Drawbridge", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void StopBridge()
    {
        if (!_server.IsRunning) return;

        _server.Stop();
        SetStatus(false);
    }

    private void SetStatus(bool up)
    {
        Brush color = up ? Brushes.MediumSeaGreen : Brushes.IndianRed;
        StatusLight.Fill = color;
        SideStatusLight.Fill = color;
        StatusText.Text = up ? $"Bridge is up — filtering DNS{ModeSuffix()}"
                             : "Bridge is down (not filtering)";
        ToggleButton.Content = up ? "Lower the Bridge (Stop)"
                                  : "Raise the Bridge (Start)";
    }

    private void ToggleButton_Click(object sender, RoutedEventArgs e)
    {
        if (_server.IsRunning) StopBridge();
        else StartBridge();
    }

    // ---------- filtering mode ----------

    private void FilterMode_Changed(object sender, RoutedEventArgs e)
    {
        if (_initializing) return;

        bool wantWhitelist = WhitelistModeRadio.IsChecked == true;
        FilterMode target = wantWhitelist ? FilterMode.Whitelist : FilterMode.Blocklist;

        if (target == _blocklist.Mode) return;

        if (wantWhitelist)
        {
            int allowedCount = _blocklist.AllowedDomains.Count;

            MessageBoxResult confirm = MessageBox.Show(
                "Whitelist mode blocks the ENTIRE internet except your " +
                $"'Allowed domains' list — currently {allowedCount} domain(s) — " +
                "plus a few Windows system essentials.\n\n" +
                "Most websites need several domains to work (a video site also " +
                "needs its image and video servers). Expect to check the Logs " +
                "tab and add domains until your approved sites work fully.\n\n" +
                (allowedCount == 0
                    ? "⚠ Your allowed list is EMPTY — virtually nothing will load.\n\n"
                    : "") +
                "Switch to whitelist mode?",
                "Drawbridge — Whitelist mode",
                MessageBoxButton.YesNo, MessageBoxImage.Warning);

            if (confirm != MessageBoxResult.Yes)
            {
                _initializing = true;
                BlocklistModeRadio.IsChecked = true;
                _initializing = false;
                return;
            }
        }

        _blocklist.SetMode(target);
        RefreshModeUi();
    }

    private void RefreshModeUi()
    {
        bool whitelist = _blocklist.Mode == FilterMode.Whitelist;
        DomainsLoadedLabel.Text = whitelist
            ? "allowed domains (whitelist mode)"
            : "domains on the blocklist";
        DomainsLoadedText.Text = whitelist
            ? $"{_blocklist.AllowedDomains.Count:N0}"
            : $"{_blocklist.BlockedDomainCount:N0}";
        SetStatus(_server.IsRunning);
    }

    private string ModeSuffix()
        => _blocklist.Mode == FilterMode.Whitelist ? " (whitelist mode)" : "";

    // ---------- prepare for uninstall ----------

    private void CleanupButton_Click(object sender, RoutedEventArgs e)
    {
        MessageBoxResult confirm = MessageBox.Show(
            "This will:\n\n" +
            "  • lower the bridge (stop filtering)\n" +
            "  • restore Windows DNS to automatic\n" +
            "  • remove the start-at-login task\n" +
            "  • remove the web monitor firewall rule\n\n" +
            "The computer will browse normally without Drawbridge, making it " +
            "safe to uninstall or upgrade. Your lists, rules, PIN, and logs " +
            "are kept.\n\nContinue?",
            "Drawbridge — undo all system changes",
            MessageBoxButton.YesNo, MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes) return;

        _initializing = true; // keep checkbox events from re-running the work
        try
        {
            StopBridge();
            SystemIntegration.RestoreAutomaticDns(AppendLog);
            SystemIntegration.DisableRunAtLogin(AppendLog);

            _webMonitor.Stop();
            _webMonitor.RemoveFirewallRule();
            _webMonitor.PersistEnabled(false);

            SystemDnsCheck.IsChecked = false;
            RunAtLoginCheck.IsChecked = false;
            WebMonitorCheck.IsChecked = false;
            WebUrlText.Text = "";

            AppendLog("Cleanup complete — this computer is back to normal DNS.");
            MessageBox.Show(
                "Done. All system changes are undone — Drawbridge can now be " +
                "closed and uninstalled safely.\n\nTo protect this computer " +
                "again later, just re-check the boxes in Settings.",
                "Drawbridge", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AppendLog($"Cleanup problem: {ex.Message}");
            MessageBox.Show($"Something didn't clean up fully:\n\n{ex.Message}",
                            "Drawbridge", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _initializing = false;
        }
    }

    // ---------- dashboard stats & chart ----------

    private void OnBlockRecorded()
    {
        UpdateBlockStats();

        if ((DateTime.UtcNow - _lastChartRedraw).TotalSeconds >= 1)
            RedrawChart();
    }

    private void UpdateBlockStats()
    {
        TodayBlockedText.Text = _blockLog.Today.ToString("N0");
        AllTimeBlockedText.Text = _blockLog.TotalRecorded.ToString("N0");
    }

    private void RedrawChart()
    {
        _lastChartRedraw = DateTime.UtcNow;

        ChartHost.Children.Clear();
        ChartHost.ColumnDefinitions.Clear();

        var days = _blockLog.LastDays(14);
        int max = Math.Max(1, days.Max(d => d.Count));

        var barBrush = new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44));
        var zeroBrush = new SolidColorBrush(Color.FromRgb(0x3B, 0x42, 0x52));

        for (int i = 0; i < days.Count; i++)
        {
            ChartHost.ColumnDefinitions.Add(new ColumnDefinition());

            (DateTime day, int count) = days[i];

            var cell = new Grid();
            cell.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            cell.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var bar = new Border
            {
                Height = count == 0 ? 3 : Math.Max(6, 105.0 * count / max),
                Background = count == 0 ? zeroBrush : barBrush,
                CornerRadius = new CornerRadius(3, 3, 0, 0),
                VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(5, 0, 5, 0),
                ToolTip = $"{day:MMM d}: {count:N0} blocked",
            };
            Grid.SetRow(bar, 0);

            var label = new TextBlock
            {
                Text = day.ToString("dd"),
                FontSize = 10,
                Foreground = new SolidColorBrush(Color.FromRgb(0x8A, 0x93, 0xA6)),
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 4, 0, 0),
            };
            Grid.SetRow(label, 1);

            cell.Children.Add(bar);
            cell.Children.Add(label);
            Grid.SetColumn(cell, i);
            ChartHost.Children.Add(cell);
        }
    }

    // ---------- web monitor ----------

    private void WebMonitorCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (_initializing) return;

        if (WebMonitorCheck.IsChecked == true)
        {
            if (!_pin.HasPin)
            {
                MessageBox.Show("Set a PIN on the Security tab first — the web " +
                                "monitor uses it to keep the logs private.",
                                "Drawbridge", MessageBoxButton.OK, MessageBoxImage.Information);
                WebMonitorCheck.IsChecked = false;
                return;
            }
            StartWebMonitor();
            _webMonitor.PersistEnabled(true);
        }
        else
        {
            _webMonitor.Stop();
            _webMonitor.PersistEnabled(false);
            WebUrlText.Text = "";
        }
    }

    private void StartWebMonitor()
    {
        try
        {
            _webMonitor.Start();
            WebUrlText.Text = "Open from another computer:  " +
                              string.Join("   or   ", _webMonitor.Urls());
        }
        catch (Exception ex)
        {
            AppendLog($"Web monitor failed to start: {ex.Message}");
            WebMonitorCheck.IsChecked = false;
        }
    }

    // ---------- tab navigation ----------

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        // Fires during InitializeComponent before the tabs exist — ignore
        if (TabLogs is null) return;

        string tab = (string)((RadioButton)sender).Tag;

        TabDashboard.Visibility = tab == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        TabBlocklists.Visibility = tab == "Blocklists" ? Visibility.Visible : Visibility.Collapsed;
        TabSettings.Visibility = tab == "Settings" ? Visibility.Visible : Visibility.Collapsed;
        TabSecurity.Visibility = tab == "Security" ? Visibility.Visible : Visibility.Collapsed;
        TabLogs.Visibility = tab == "Logs" ? Visibility.Visible : Visibility.Collapsed;
    }

    // ---------- lock / unlock ----------

    private void LockUi()
    {
        _locked = true;
        MainContent.Visibility = Visibility.Hidden;
        LockOverlay.Visibility = Visibility.Visible;
        UnlockPinBox.Clear();
        UnlockError.Text = "";
        UnlockPinBox.Focus();
    }

    private void UnlockUi()
    {
        _locked = false;
        _failedAttempts = 0;
        LockOverlay.Visibility = Visibility.Collapsed;
        MainContent.Visibility = Visibility.Visible;
    }

    private void LockNowButton_Click(object sender, RoutedEventArgs e) => LockUi();

    private void UnlockPinBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) TryUnlock();
    }

    private void UnlockButton_Click(object sender, RoutedEventArgs e) => TryUnlock();

    private async void TryUnlock()
    {
        if (_pin.Verify(UnlockPinBox.Password))
        {
            UnlockUi();
            return;
        }

        _failedAttempts++;
        int delaySeconds = Math.Min(_failedAttempts * 2, 30);

        UnlockPinBox.Clear();
        UnlockPinBox.IsEnabled = false;
        UnlockButton.IsEnabled = false;
        UnlockError.Text = $"Wrong PIN — wait {delaySeconds}s";

        await Task.Delay(TimeSpan.FromSeconds(delaySeconds));

        UnlockPinBox.IsEnabled = true;
        UnlockButton.IsEnabled = true;
        UnlockError.Text = "Try again";
        UnlockPinBox.Focus();
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (_locked)
        {
            e.Cancel = true;
            UnlockError.Text = "Unlock with the PIN to close Drawbridge";
            return;
        }
        base.OnClosing(e);
    }

    // ---------- PIN management ----------

    private void UpdatePinUi()
    {
        bool hasPin = _pin.HasPin;

        PinPanelTitle.Text = hasPin ? "PIN lock (active)" : "PIN lock (not set)";
        CurrentPinPanel.Visibility = hasPin ? Visibility.Visible : Visibility.Collapsed;
        RemovePinButton.Visibility = hasPin ? Visibility.Visible : Visibility.Collapsed;
        SetPinButton.Content = hasPin ? "Change PIN" : "Set PIN & lock";
        LockNowButton.Visibility = hasPin ? Visibility.Visible : Visibility.Collapsed;
    }

    private void SetPinButton_Click(object sender, RoutedEventArgs e)
    {
        string newPin = NewPinBox.Password;

        if (newPin.Length < 4)
        {
            MessageBox.Show("PIN must be at least 4 characters.", "Drawbridge",
                            MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (newPin != ConfirmPinBox.Password)
        {
            MessageBox.Show("The two PINs don't match.", "Drawbridge",
                            MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (_pin.HasPin && !_pin.Verify(CurrentPinBox.Password))
        {
            MessageBox.Show("Current PIN is wrong.", "Drawbridge",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _pin.SetPin(newPin);
        CurrentPinBox.Clear();
        NewPinBox.Clear();
        ConfirmPinBox.Clear();
        UpdatePinUi();
        AppendLog("PIN set — locking.");
        LockUi();
    }

    private void RemovePinButton_Click(object sender, RoutedEventArgs e)
    {
        if (!_pin.Verify(CurrentPinBox.Password))
        {
            MessageBox.Show("Enter the current PIN to remove the lock.", "Drawbridge",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (_webMonitor.IsRunning)
        {
            _webMonitor.Stop();
            _webMonitor.PersistEnabled(false);
            WebMonitorCheck.IsChecked = false;
            AppendLog("Web monitor disabled (no PIN).");
        }

        _pin.RemovePin();
        CurrentPinBox.Clear();
        NewPinBox.Clear();
        ConfirmPinBox.Clear();
        UpdatePinUi();
        AppendLog("PIN removed.");
    }

    // ---------- system protection ----------

    private void SystemDnsCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (_initializing) return;

        try
        {
            if (SystemDnsCheck.IsChecked == true)
                SystemIntegration.PointDnsAtDrawbridge(AppendLog);
            else
                SystemIntegration.RestoreAutomaticDns(AppendLog);
        }
        catch (Exception ex)
        {
            AppendLog($"DNS change failed: {ex.Message}");
        }
    }

    private void RunAtLoginCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (_initializing) return;

        try
        {
            if (RunAtLoginCheck.IsChecked == true)
                SystemIntegration.EnableRunAtLogin(AppendLog);
            else
                SystemIntegration.DisableRunAtLogin(AppendLog);
        }
        catch (Exception ex)
        {
            AppendLog($"Startup task change failed: {ex.Message}");
        }
    }

    // ---------- blocklist management ----------

    private async void AddUrlButton_Click(object sender, RoutedEventArgs e)
    {
        string url = NewUrlBox.Text.Trim();

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != "https" && uri.Scheme != "http"))
        {
            MessageBox.Show("Please enter a full URL, e.g. https://example.com/list.txt",
                            "Drawbridge", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (_blocklist.Urls.Contains(url))
        {
            MessageBox.Show("That list is already added.", "Drawbridge",
                            MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        _blocklist.AddList(url);
        NewUrlBox.Clear();
        RefreshUrlListBox();
        await CheckForUpdatesAsync(); // new list has no cache -> full download
    }

    private void RemoveUrlButton_Click(object sender, RoutedEventArgs e)
    {
        if (BlocklistUrls.SelectedItem is not string url) return;

        _blocklist.RemoveList(url); // also deletes its cache and rebuilds
        RefreshUrlListBox();
        UpdateCountLabel();
    }

    private async void CheckUpdatesButton_Click(object sender, RoutedEventArgs e)
        => await CheckForUpdatesAsync();

    private async Task CheckForUpdatesAsync()
    {
        CheckUpdatesButton.IsEnabled = false;
        try
        {
            await _blocklist.CheckForUpdatesAsync();
            UpdateCountLabel();
        }
        finally
        {
            CheckUpdatesButton.IsEnabled = true;
        }
    }

    // ---------- custom block rules ----------

    private void AddDomainButton_Click(object sender, RoutedEventArgs e)
        => AddCustomDomain();

    private void NewDomainBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) AddCustomDomain();
    }

    private void AddCustomDomain()
    {
        if (!_blocklist.AddCustomDomain(NewDomainBox.Text))
        {
            MessageBox.Show("Please enter a valid domain, e.g. example.com " +
                            "(or it may already be in the list).",
                            "Drawbridge", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        NewDomainBox.Clear();
        RefreshCustomDomainsList();
        UpdateCountLabel();
    }

    private void RemoveDomainButton_Click(object sender, RoutedEventArgs e)
    {
        if (CustomDomainsList.SelectedItem is not string domain) return;

        _blocklist.RemoveCustomDomain(domain);
        RefreshCustomDomainsList();
        UpdateCountLabel();
    }

    // ---------- allowed domains ----------

    private void AddAllowedButton_Click(object sender, RoutedEventArgs e)
        => AddAllowedDomain();

    private void NewAllowedBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) AddAllowedDomain();
    }

    private void AddAllowedDomain()
    {
        if (!_blocklist.AddAllowedDomain(NewAllowedBox.Text))
        {
            MessageBox.Show("Please enter a valid domain, e.g. example.com " +
                            "(or it may already be in the list).",
                            "Drawbridge", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        NewAllowedBox.Clear();
        RefreshAllowedDomainsList();
        UpdateCountLabel();
    }

    private void RemoveAllowedButton_Click(object sender, RoutedEventArgs e)
    {
        if (AllowedDomainsList.SelectedItem is not string domain) return;

        _blocklist.RemoveAllowedDomain(domain);
        RefreshAllowedDomainsList();
        UpdateCountLabel();
    }

    // ---------- UI helpers ----------

    private void UpdateCountLabel()
    {
        BlockedCountText.Text = $"{_blocklist.BlockedDomainCount:N0} domains loaded";
        RefreshModeUi();
    }

    private void RefreshUrlListBox()
    {
        BlocklistUrls.Items.Clear();
        foreach (string url in _blocklist.Urls)
            BlocklistUrls.Items.Add(url);
    }

    private void RefreshCustomDomainsList()
    {
        CustomDomainsList.Items.Clear();
        foreach (string domain in _blocklist.CustomDomains)
            CustomDomainsList.Items.Add(domain);
    }

    private void RefreshAllowedDomainsList()
    {
        AllowedDomainsList.Items.Clear();
        foreach (string domain in _blocklist.AllowedDomains)
            AllowedDomainsList.Items.Add(domain);
    }

    private void AppendLog(string line)
    {
        LogList.Items.Add($"[{DateTime.Now:HH:mm:ss}] {line}");

        if (LogList.Items.Count > 500)
            LogList.Items.RemoveAt(0);

        LogList.ScrollIntoView(LogList.Items[^1]);
    }

    protected override void OnClosed(EventArgs e)
    {
        _webMonitor.Stop();
        _server.Stop();
        base.OnClosed(e);
    }
}