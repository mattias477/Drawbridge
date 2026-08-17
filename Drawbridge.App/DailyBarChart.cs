using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace Drawbridge.App;

/// <summary>Draws a lightweight, dependency-free fourteen-day block chart.</summary>
public sealed class DailyBarChart : FrameworkElement
{
    private static readonly Brush GridBrush = Freeze(new SolidColorBrush(Color.FromRgb(55, 66, 85)));
    private static readonly Brush LabelBrush = Freeze(new SolidColorBrush(Color.FromRgb(154, 167, 189)));
    private static readonly Brush BarBrush = Freeze(new SolidColorBrush(Color.FromRgb(67, 101, 154)));
    private static readonly Brush AccentBrush = Freeze(new SolidColorBrush(Color.FromRgb(59, 130, 246)));
    private IReadOnlyList<DailyBlockCount> _series = [];
    private IReadOnlyList<DailyBlockCount> _normalizedSeries = [];

    /// <summary>Gets or sets the daily counts to render.</summary>
    public IReadOnlyList<DailyBlockCount> Series
    {
        get => _series;
        set
        {
            _series = value ?? [];
            _normalizedSeries = Normalize(_series);
            InvalidateVisual();
        }
    }

    /// <inheritdoc />
    protected override void OnRender(DrawingContext drawingContext)
    {
        base.OnRender(drawingContext);

        const double left = 42;
        const double top = 10;
        const double right = 8;
        const double bottom = 31;
        double width = Math.Max(0, ActualWidth - left - right);
        double height = Math.Max(0, ActualHeight - top - bottom);
        if (width <= 1 || height <= 1)
        {
            return;
        }

        IReadOnlyList<DailyBlockCount> series = _normalizedSeries.Count == 0 ? Normalize([]) : _normalizedSeries;
        long maximum = Math.Max(1, series.Max(point => point.Count));
        double pixelsPerDip = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var typeface = new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);

        for (int line = 0; line <= 3; line++)
        {
            double ratio = line / 3d;
            double y = top + height - (height * ratio);
            drawingContext.DrawLine(new Pen(GridBrush, 1), new Point(left, y), new Point(left + width, y));

            string value = Math.Round(maximum * ratio).ToString("N0", CultureInfo.CurrentCulture);
            var label = new FormattedText(value, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, typeface, 10, LabelBrush, pixelsPerDip);
            drawingContext.DrawText(label, new Point(Math.Max(0, left - label.Width - 7), y - (label.Height / 2)));
        }

        double slot = width / series.Count;
        double barWidth = Math.Max(4, Math.Min(22, slot * 0.58));
        for (int index = 0; index < series.Count; index++)
        {
            DailyBlockCount point = series[index];
            double barHeight = point.Count == 0 ? 2 : Math.Max(3, height * point.Count / maximum);
            double x = left + (slot * index) + ((slot - barWidth) / 2);
            double y = top + height - barHeight;
            Brush brush = index == series.Count - 1 ? AccentBrush : BarBrush;
            drawingContext.DrawRoundedRectangle(brush, null, new Rect(x, y, barWidth, barHeight), 3, 3);

            if (index is 0 or 3 or 6 or 9 or 13)
            {
                string day = point.Day.ToString("M/d", CultureInfo.CurrentCulture);
                var label = new FormattedText(day, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, typeface, 10, LabelBrush, pixelsPerDip);
                drawingContext.DrawText(label, new Point(left + (slot * index) + ((slot - label.Width) / 2), top + height + 8));
            }
        }
    }

    /// <inheritdoc />
    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (_normalizedSeries.Count == 0 || ActualWidth <= 50)
        {
            return;
        }

        const double left = 42;
        double width = Math.Max(1, ActualWidth - left - 8);
        int index = Math.Clamp((int)((e.GetPosition(this).X - left) / (width / _normalizedSeries.Count)), 0, _normalizedSeries.Count - 1);
        DailyBlockCount point = _normalizedSeries[index];
        ToolTip = $"{point.Day:dddd, MMM d}: {point.Count:N0} blocked";
    }

    private static IReadOnlyList<DailyBlockCount> Normalize(IReadOnlyList<DailyBlockCount> source)
    {
        var byDay = source.GroupBy(item => item.Day).ToDictionary(group => group.Key, group => group.Last().Count);
        DateOnly today = DateOnly.FromDateTime(DateTime.Today);
        return Enumerable.Range(0, 14)
            .Select(offset => today.AddDays(offset - 13))
            .Select(day => new DailyBlockCount(day, byDay.GetValueOrDefault(day)))
            .ToArray();
    }

    private static T Freeze<T>(T freezable)
        where T : Freezable
    {
        freezable.Freeze();
        return freezable;
    }
}
