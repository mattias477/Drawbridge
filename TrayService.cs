using System.Drawing;
using WinForms = System.Windows.Forms;

namespace Drawbridge;

/// <summary>
/// The system tray presence: a code-drawn castle icon (green = filtering,
/// red = down) with a context menu. Raises events; MainWindow decides what
/// they mean. Uses Windows Forms' NotifyIcon, which coexists happily with
/// WPF (see UseWindowsForms in the csproj).
/// </summary>
public class TrayService : IDisposable
{
    private readonly WinForms.NotifyIcon _icon = new();
    private readonly WinForms.ToolStripItem _lockItem;
    private readonly Icon _upIcon;
    private readonly Icon _downIcon;
    private bool _balloonShown;

    public event Action? OpenRequested;
    public event Action? LockRequested;
    public event Action? ExitRequested;

    public TrayService()
    {
        _upIcon = BuildCastleIcon(Color.MediumSeaGreen);
        _downIcon = BuildCastleIcon(Color.IndianRed);

        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Open Drawbridge", null, (_, _) => OpenRequested?.Invoke());
        _lockItem = menu.Items.Add("Lock now", null, (_, _) => LockRequested?.Invoke());
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Exit Drawbridge", null, (_, _) => ExitRequested?.Invoke());

        _icon.Icon = _downIcon;
        _icon.Text = "Drawbridge";
        _icon.ContextMenuStrip = menu;
        _icon.DoubleClick += (_, _) => OpenRequested?.Invoke();
        _icon.Visible = true;
    }

    /// <summary>Show/hide the "Lock now" menu item (only useful with a PIN).</summary>
    public bool LockMenuVisible
    {
        set => _lockItem.Visible = value;
    }

    /// <summary>Swap icon color and tooltip to match bridge state.</summary>
    public void SetStatus(bool up, string tooltip)
    {
        _icon.Icon = up ? _upIcon : _downIcon;

        // NotifyIcon tooltips are capped at 63 characters
        _icon.Text = tooltip.Length <= 63 ? tooltip : tooltip[..60] + "...";
    }

    /// <summary>One-time balloon the first time the window hides, so the
    /// user knows Drawbridge is still alive down by the clock.</summary>
    public void ShowMinimizedBalloon()
    {
        if (_balloonShown) return;
        _balloonShown = true;

        _icon.BalloonTipTitle = "Drawbridge is still running";
        _icon.BalloonTipText = "Filtering continues in the background. " +
                               "Double-click the castle icon to open.";
        _icon.ShowBalloonTip(4000);
    }

    /// <summary>Draws a little battlemented castle, tinted to taste.
    /// No .ico file needed — the logo is code.</summary>
    private static Icon BuildCastleIcon(Color color)
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        using (var wall = new SolidBrush(color))
        using (var gap = new SolidBrush(Color.FromArgb(0, 0, 0, 0)))
        {
            g.Clear(Color.Transparent);

            g.FillRectangle(wall, 3, 12, 26, 17);   // main wall
            g.FillRectangle(wall, 3, 5, 6, 7);      // left merlon
            g.FillRectangle(wall, 13, 5, 6, 7);     // middle merlon
            g.FillRectangle(wall, 23, 5, 6, 7);     // right merlon

            // doorway (transparent notch)
            g.SetClip(new Rectangle(12, 19, 8, 10));
            g.Clear(Color.Transparent);
            g.ResetClip();
        }

        return Icon.FromHandle(bmp.GetHicon());
    }

    public void Dispose()
    {
        _icon.Visible = false;  // otherwise a ghost icon lingers by the clock
        _icon.Dispose();
        _upIcon.Dispose();
        _downIcon.Dispose();
    }
}