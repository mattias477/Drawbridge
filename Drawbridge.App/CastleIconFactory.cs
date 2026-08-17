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
        using System.Drawing.Drawing2D.GraphicsPath shield = CreateShieldPath();
        using var shieldBrush = new System.Drawing.Drawing2D.LinearGradientBrush(
            new System.Drawing.PointF(14, 6),
            new System.Drawing.PointF(50, 59),
            System.Drawing.Color.FromArgb(255, 36, 58, 98),
            System.Drawing.Color.FromArgb(255, 9, 19, 33));
        var blend = new System.Drawing.Drawing2D.ColorBlend
        {
            Colors =
            [
                System.Drawing.Color.FromArgb(255, 36, 58, 98),
                System.Drawing.Color.FromArgb(255, 20, 36, 62),
                System.Drawing.Color.FromArgb(255, 9, 19, 33),
            ],
            Positions = [0f, 0.58f, 1f],
        };
        shieldBrush.InterpolationColors = blend;
        using var outlinePen = new System.Drawing.Pen(System.Drawing.Color.FromArgb(255, 87, 126, 184), 1.5f);
        graphics.FillPath(shieldBrush, shield);
        graphics.DrawPath(outlinePen, shield);

        using var castleBrush = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(255, 247, 250, 255));
        graphics.FillPolygon(castleBrush,
        [
            new(12, 45), new(12, 19), new(16, 19), new(16, 23),
            new(20, 23), new(20, 19), new(24, 19), new(24, 45),
        ]);
        graphics.FillPolygon(castleBrush,
        [
            new(23, 45), new(23, 21), new(27, 21), new(27, 17),
            new(31, 17), new(31, 21), new(35, 21), new(35, 17),
            new(39, 17), new(39, 21), new(41, 21), new(41, 45),
        ]);
        graphics.FillPolygon(castleBrush,
        [
            new(40, 45), new(40, 19), new(44, 19), new(44, 23),
            new(48, 23), new(48, 19), new(52, 19), new(52, 45),
        ]);

        using var gate = new System.Drawing.Drawing2D.GraphicsPath();
        gate.StartFigure();
        gate.AddLine(24, 46, 24, 35);
        gate.AddBezier(24, 35, 24, 30.58f, 27.58f, 27, 32, 27);
        gate.AddBezier(32, 27, 36.42f, 27, 40, 30.58f, 40, 35);
        gate.AddLine(40, 35, 40, 46);
        gate.CloseFigure();
        using var gateBrush = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(255, 12, 23, 40));
        graphics.FillPath(gateBrush, gate);

        using var chainPen = new System.Drawing.Pen(System.Drawing.Color.FromArgb(224, 117, 185, 255), 1.75f)
        {
            StartCap = System.Drawing.Drawing2D.LineCap.Round,
            EndCap = System.Drawing.Drawing2D.LineCap.Round,
        };
        graphics.DrawLine(chainPen, 18, 27, 25, 47);
        graphics.DrawLine(chainPen, 46, 27, 39, 47);

        using var bridge = new System.Drawing.Drawing2D.GraphicsPath();
        bridge.AddPolygon([new(27, 35), new(37, 35), new(44, 53), new(20, 53)]);
        using var bridgeBrush = new System.Drawing.Drawing2D.LinearGradientBrush(
            new System.Drawing.PointF(32, 34),
            new System.Drawing.PointF(32, 53),
            System.Drawing.Color.FromArgb(255, 138, 203, 255),
            System.Drawing.Color.FromArgb(255, 62, 130, 245));
        using var bridgeOutline = new System.Drawing.Pen(System.Drawing.Color.FromArgb(255, 184, 221, 255), 1.15f)
        {
            LineJoin = System.Drawing.Drawing2D.LineJoin.Round,
        };
        graphics.FillPath(bridgeBrush, bridge);
        graphics.DrawPath(bridgeOutline, bridge);

        using var plankPen = new System.Drawing.Pen(System.Drawing.Color.FromArgb(194, 229, 242, 255), 1.2f)
        {
            StartCap = System.Drawing.Drawing2D.LineCap.Round,
            EndCap = System.Drawing.Drawing2D.LineCap.Round,
        };
        graphics.DrawLine(plankPen, 24.7f, 41, 39.3f, 41);
        graphics.DrawLine(plankPen, 22.5f, 47, 41.5f, 47);

        System.Drawing.Color statusColor = bridgeUp
            ? System.Drawing.Color.FromArgb(255, 54, 211, 145)
            : System.Drawing.Color.FromArgb(255, 248, 100, 113);
        using var badgeOutline = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(255, 13, 19, 30));
        using var statusBrush = new System.Drawing.SolidBrush(statusColor);
        graphics.FillEllipse(badgeOutline, 42, 42, 19, 19);
        graphics.FillEllipse(statusBrush, 45, 45, 13, 13);
    }

    private static System.Drawing.Drawing2D.GraphicsPath CreateShieldPath()
    {
        var path = new System.Drawing.Drawing2D.GraphicsPath();
        path.StartFigure();
        path.AddBezier(32, 3, 42.5f, 3, 52.5f, 6.2f, 58, 10.5f);
        path.AddLine(58, 10.5f, 58, 28.5f);
        path.AddBezier(58, 28.5f, 58, 43.2f, 48.2f, 55.6f, 32, 61);
        path.AddBezier(32, 61, 15.8f, 55.6f, 6, 43.2f, 6, 28.5f);
        path.AddLine(6, 28.5f, 6, 10.5f);
        path.AddBezier(6, 10.5f, 11.5f, 6.2f, 21.5f, 3, 32, 3);
        path.CloseFigure();
        return path;
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);
}
