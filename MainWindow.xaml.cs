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
    private readonly DnsServer _server;

    private bool _initializing = true; // suppress checkbox events during setup
    private bool _locked;
    private int _failedAttempts;
    private int _sessionBlocked;

    public MainWindow()
    {
        InitializeComponent();

        _server = new DnsServer(_blocklist);

        _server.Log += line => Dispatcher.InvokeAsync(() => AppendLog(line));
        _blocklist.Log += line => Dispatcher.InvokeAsync(() => AppendLog(line));

        _blocklist.LoadSettings();
        RefreshUrlListBox();

        SystemDnsCheck.IsChecked = SystemIntegration.IsDnsPointedAtDrawbridge();
        RunAtLoginCheck.IsChecked = SystemIntegration.IsRunAtLoginEnabled();
        _initializing = false;

        UpdatePinUi();

        if (_pin.HasPin)
            LockUi();

        // Launch sequence: cached lists load instantly, the bridge goes up
        // right away, then the network update check runs in the background.
        Loaded += async (_, _) =>
        {
            _blocklist.RebuildFromCache();
            UpdateCountLabel();
            StartBridge();

            await CheckForUpdatesAsync();
        };
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

        _pin.RemovePin();
        CurrentPinBox.Clear();
        NewPinBox.Clear();
        ConfirmPinBox.Clear();
        UpdatePinUi();
        AppendLog("PIN removed.");
    }

    // ---------- start / stop ----------

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
                "Port 53 may already be in use.",
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
        StatusText.Text = up ? "Bridge is up — filtering DNS"
                             : "Bridge is down (not filtering)";
        ToggleButton.Content = up ? "Lower the Bridge (Stop)"
                                  : "Raise the Bridge (Start)";
    }

    private void ToggleButton_Click(object sender, RoutedEventArgs e)
    {
        if (_server.IsRunning) StopBridge();
        else StartBridge();
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

    private void UpdateCountLabel()
    {
        BlockedCountText.Text = $"{_blocklist.BlockedDomainCount:N0} domains loaded";
        DomainsLoadedText.Text = $"{_blocklist.BlockedDomainCount:N0}";
    }

    private void RefreshUrlListBox()
    {
        BlocklistUrls.Items.Clear();
        foreach (string url in _blocklist.Urls)
            BlocklistUrls.Items.Add(url);
    }

    // ---------- logging ----------

    private void AppendLog(string line)
    {
        if (line.StartsWith("BLOCKED:"))
        {
            _sessionBlocked++;
            SessionBlockedText.Text = _sessionBlocked.ToString("N0");
        }

        LogList.Items.Add($"[{DateTime.Now:HH:mm:ss}] {line}");

        if (LogList.Items.Count > 500)
            LogList.Items.RemoveAt(0);

        LogList.ScrollIntoView(LogList.Items[^1]);
    }

    protected override void OnClosed(EventArgs e)
    {
        _server.Stop();
        base.OnClosed(e);
    }
}