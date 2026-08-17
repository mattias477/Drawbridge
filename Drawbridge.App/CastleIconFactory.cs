using System.Runtime.InteropServices;

namespace Drawbridge.App;

internal static class CastleIconFactory
{
    public static System.Drawing.Icon Create(bool bridgeUp)
    {
        const int size = 32;
        using var bitmap = new System.Drawing.Bitmap(size, size, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        using System.Drawing.Graphics graphics = System.Drawing.Graphics.FromImage(bitmap);
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        graphics.Clear(System.Drawing.Color.Transparent);

        System.Drawing.Color status = bridgeUp
            ? System.Drawing.Color.FromArgb(255, 53, 199, 129)
            : System.Drawing.Color.FromArgb(255, 240, 91, 104);
        using var statusBrush = new System.Drawing.SolidBrush(status);
        using var castleBrush = new System.Drawing.SolidBrush(System.Drawing.Color.White);
        using var detailBrush = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(230, 30, 36, 48));

        graphics.FillEllipse(statusBrush, 1, 1, 30, 30);
        graphics.FillRectangle(castleBrush, 6, 12, 20, 14);
        graphics.FillRectangle(castleBrush, 5, 8, 6, 8);
        graphics.FillRectangle(castleBrush, 13, 8, 6, 8);
        graphics.FillRectangle(castleBrush, 21, 8, 6, 8);
        graphics.FillRectangle(detailBrush, 8, 10, 2, 4);
        graphics.FillRectangle(detailBrush, 15, 10, 2, 4);
        graphics.FillRectangle(detailBrush, 23, 10, 2, 4);
        graphics.FillRectangle(detailBrush, 9, 17, 3, 3);
        graphics.FillRectangle(detailBrush, 20, 17, 3, 3);
        graphics.FillRectangle(detailBrush, 14, 20, 4, 6);

        IntPtr handle = bitmap.GetHicon();
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

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);
}
