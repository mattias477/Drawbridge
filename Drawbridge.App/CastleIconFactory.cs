using System.Runtime.InteropServices;

namespace Drawbridge.App;

internal static class CastleIconFactory
{
    private const int IconSize = 32;
    private const int Supersampling = 4;
    private const float DesignSize = 64f;

    public static System.Drawing.Icon Create(bool bridgeUp)
    {
        using System.Drawing.Bitmap rendered = RenderBrandMark(bridgeUp);
        IntPtr handle = rendered.GetHicon();
        try
        {
            using System.Drawing.Icon borrowed = System.Drawing.Icon.FromHandle(handle);
            return (System.Drawing.Icon)borrowed.Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    private static System.Drawing.Bitmap RenderBrandMark(bool bridgeUp)
    {
        int renderSize = IconSize * Supersampling;
        using var highResolution = new System.Drawing.Bitmap(
            renderSize,
            renderSize,
            System.Drawing.Imaging.PixelFormat.Format32bppArgb);

        using (System.Drawing.Graphics graphics = System.Drawing.Graphics.FromImage(highResolution))
        {
            graphics.Clear(System.Drawing.Color.Transparent);
            graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            graphics.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;
            graphics.CompositingQuality = System.Drawing.Drawing2D.CompositingQuality.HighQuality;
            graphics.ScaleTransform(renderSize / DesignSize, renderSize / DesignSize);
            DrawMark(graphics, bridgeUp);
        }

        var result = new System.Drawing.Bitmap(
            IconSize,
            IconSize,
            System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        using (System.Drawing.Graphics graphics = System.Drawing.Graphics.FromImage(result))
        {
            graphics.CompositingMode = System.Drawing.Drawing2D.CompositingMode.SourceCopy;
            graphics.CompositingQuality = System.Drawing.Drawing2D.CompositingQuality.HighQuality;
            graphics.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            graphics.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;
            graphics.DrawImage(
                highResolution,
                new System.Drawing.Rectangle(0, 0, IconSize, IconSize),
                0,
                0,
                renderSize,
                renderSize,
                System.Drawing.GraphicsUnit.Pixel);
        }

        return result;
    }

    private static void DrawMark(System.Drawing.Graphics graphics, bool bridgeUp)
    {
        using System.Drawing.Drawing2D.GraphicsPath background = CreateRoundedRectangle(3, 3, 58, 58, 15);
        using var backgroundBrush = new System.Drawing.Drawing2D.LinearGradientBrush(
            new System.Drawing.PointF(13, 6),
            new System.Drawing.PointF(51, 60),
            System.Drawing.Color.FromArgb(255, 41, 57, 87),
            System.Drawing.Color.FromArgb(255, 16, 23, 36));
        using var outlinePen = new System.Drawing.Pen(System.Drawing.Color.FromArgb(255, 77, 103, 146), 1.5f);
        graphics.FillPath(backgroundBrush, background);
        graphics.DrawPath(outlinePen, background);

        using var castle = new System.Drawing.Drawing2D.GraphicsPath();
        castle.AddPolygon(
        [
            new(11, 46), new(11, 28), new(14, 28), new(14, 19),
            new(20, 19), new(20, 24), new(28, 24), new(28, 18),
            new(36, 18), new(36, 24), new(44, 24), new(44, 19),
            new(50, 19), new(50, 28), new(53, 28), new(53, 46),
        ]);
        using var castleBrush = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(255, 247, 250, 255));
        graphics.FillPath(castleBrush, castle);

        using var detailBrush = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(255, 26, 36, 54));
        graphics.FillRectangle(detailBrush, 17, 31, 4, 5);
        graphics.FillRectangle(detailBrush, 43, 31, 4, 5);

        using var gate = new System.Drawing.Drawing2D.GraphicsPath();
        gate.StartFigure();
        gate.AddLine(24, 47, 24, 37);
        gate.AddBezier(24, 37, 24, 26.33f, 40, 26.33f, 40, 37);
        gate.AddLine(40, 37, 40, 47);
        gate.CloseFigure();
        using var gateBrush = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(255, 21, 31, 48));
        graphics.FillPath(gateBrush, gate);

        using var bridge = new System.Drawing.Drawing2D.GraphicsPath();
        bridge.AddPolygon([new(27, 38), new(37, 38), new(43, 54), new(21, 54)]);
        using var bridgeBrush = new System.Drawing.Drawing2D.LinearGradientBrush(
            new System.Drawing.PointF(32, 37),
            new System.Drawing.PointF(32, 54),
            System.Drawing.Color.FromArgb(255, 137, 186, 255),
            System.Drawing.Color.FromArgb(255, 77, 143, 243));
        graphics.FillPath(bridgeBrush, bridge);

        using var plankPen = new System.Drawing.Pen(System.Drawing.Color.FromArgb(210, 220, 234, 255), 1.25f)
        {
            StartCap = System.Drawing.Drawing2D.LineCap.Round,
            EndCap = System.Drawing.Drawing2D.LineCap.Round,
        };
        graphics.DrawLine(plankPen, 26, 43, 38, 43);
        graphics.DrawLine(plankPen, 24, 48, 40, 48);
        graphics.DrawLine(plankPen, 28.5f, 39.5f, 25, 53);
        graphics.DrawLine(plankPen, 35.5f, 39.5f, 39, 53);

        System.Drawing.Color statusColor = bridgeUp
            ? System.Drawing.Color.FromArgb(255, 54, 211, 145)
            : System.Drawing.Color.FromArgb(255, 248, 100, 113);
        using var badgeOutline = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(255, 13, 19, 30));
        using var statusBrush = new System.Drawing.SolidBrush(statusColor);
        graphics.FillEllipse(badgeOutline, 42, 42, 19, 19);
        graphics.FillEllipse(statusBrush, 45, 45, 13, 13);
    }

    private static System.Drawing.Drawing2D.GraphicsPath CreateRoundedRectangle(
        float x,
        float y,
        float width,
        float height,
        float radius)
    {
        var path = new System.Drawing.Drawing2D.GraphicsPath();
        float diameter = radius * 2;
        path.AddArc(x, y, diameter, diameter, 180, 90);
        path.AddArc(x + width - diameter, y, diameter, diameter, 270, 90);
        path.AddArc(x + width - diameter, y + height - diameter, diameter, diameter, 0, 90);
        path.AddArc(x, y + height - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        return path;
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);
}
