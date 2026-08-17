[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path $PSScriptRoot '..\Drawbridge.App\Assets\Drawbridge.ico')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing.Common

function New-RoundedRectanglePath {
    param(
        [float] $X,
        [float] $Y,
        [float] $Width,
        [float] $Height,
        [float] $Radius
    )

    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $diameter = $Radius * 2
    $path.AddArc($X, $Y, $diameter, $diameter, 180, 90)
    $path.AddArc($X + $Width - $diameter, $Y, $diameter, $diameter, 270, 90)
    $path.AddArc($X + $Width - $diameter, $Y + $Height - $diameter, $diameter, $diameter, 0, 90)
    $path.AddArc($X, $Y + $Height - $diameter, $diameter, $diameter, 90, 90)
    $path.CloseFigure()
    return $path
}

function New-PolygonPath {
    param([System.Drawing.PointF[]] $Points)

    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $path.AddPolygon($Points)
    return $path
}

function New-BrandBitmap {
    param([int] $Size)

    $supersampling = if ($Size -lt 128) { 4 } else { 2 }
    $renderSize = $Size * $supersampling
    $bitmap = [System.Drawing.Bitmap]::new(
        $renderSize,
        $renderSize,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $bitmap.SetResolution(96, 96)

    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.Clear([System.Drawing.Color]::Transparent)
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $graphics.ScaleTransform($renderSize / 64.0, $renderSize / 64.0)

        $backgroundPath = New-RoundedRectanglePath 3 3 58 58 15
        $backgroundBrush = [System.Drawing.Drawing2D.LinearGradientBrush]::new(
            [System.Drawing.PointF]::new(13, 6),
            [System.Drawing.PointF]::new(51, 60),
            [System.Drawing.ColorTranslator]::FromHtml('#293957'),
            [System.Drawing.ColorTranslator]::FromHtml('#101724'))
        $outlinePen = [System.Drawing.Pen]::new(
            [System.Drawing.ColorTranslator]::FromHtml('#4D6792'), 1.5)
        try {
            $graphics.FillPath($backgroundBrush, $backgroundPath)
            $graphics.DrawPath($outlinePen, $backgroundPath)
        }
        finally {
            $outlinePen.Dispose()
            $backgroundBrush.Dispose()
            $backgroundPath.Dispose()
        }

        $castlePoints = [System.Drawing.PointF[]] @(
            [System.Drawing.PointF]::new(11, 46),
            [System.Drawing.PointF]::new(11, 28),
            [System.Drawing.PointF]::new(14, 28),
            [System.Drawing.PointF]::new(14, 19),
            [System.Drawing.PointF]::new(20, 19),
            [System.Drawing.PointF]::new(20, 24),
            [System.Drawing.PointF]::new(28, 24),
            [System.Drawing.PointF]::new(28, 18),
            [System.Drawing.PointF]::new(36, 18),
            [System.Drawing.PointF]::new(36, 24),
            [System.Drawing.PointF]::new(44, 24),
            [System.Drawing.PointF]::new(44, 19),
            [System.Drawing.PointF]::new(50, 19),
            [System.Drawing.PointF]::new(50, 28),
            [System.Drawing.PointF]::new(53, 28),
            [System.Drawing.PointF]::new(53, 46))
        $castlePath = New-PolygonPath $castlePoints
        $castleBrush = [System.Drawing.SolidBrush]::new(
            [System.Drawing.ColorTranslator]::FromHtml('#F7FAFF'))
        try {
            $graphics.FillPath($castleBrush, $castlePath)
        }
        finally {
            $castleBrush.Dispose()
            $castlePath.Dispose()
        }

        $detailBrush = [System.Drawing.SolidBrush]::new(
            [System.Drawing.ColorTranslator]::FromHtml('#1A2436'))
        try {
            $graphics.FillRectangle($detailBrush, 17, 31, 4, 5)
            $graphics.FillRectangle($detailBrush, 43, 31, 4, 5)
        }
        finally {
            $detailBrush.Dispose()
        }

        $gatePath = [System.Drawing.Drawing2D.GraphicsPath]::new()
        $gatePath.StartFigure()
        $gatePath.AddLine(24, 47, 24, 37)
        $gatePath.AddBezier(24, 37, 24, 26.333, 40, 26.333, 40, 37)
        $gatePath.AddLine(40, 37, 40, 47)
        $gatePath.CloseFigure()
        $gateBrush = [System.Drawing.SolidBrush]::new(
            [System.Drawing.ColorTranslator]::FromHtml('#151F30'))
        try {
            $graphics.FillPath($gateBrush, $gatePath)
        }
        finally {
            $gateBrush.Dispose()
            $gatePath.Dispose()
        }

        $bridgePoints = [System.Drawing.PointF[]] @(
            [System.Drawing.PointF]::new(27, 38),
            [System.Drawing.PointF]::new(37, 38),
            [System.Drawing.PointF]::new(43, 54),
            [System.Drawing.PointF]::new(21, 54))
        $bridgePath = New-PolygonPath $bridgePoints
        $bridgeBrush = [System.Drawing.Drawing2D.LinearGradientBrush]::new(
            [System.Drawing.PointF]::new(32, 37),
            [System.Drawing.PointF]::new(32, 54),
            [System.Drawing.ColorTranslator]::FromHtml('#89BAFF'),
            [System.Drawing.ColorTranslator]::FromHtml('#4D8FF3'))
        try {
            $graphics.FillPath($bridgeBrush, $bridgePath)
        }
        finally {
            $bridgeBrush.Dispose()
            $bridgePath.Dispose()
        }

        if ($Size -ge 24) {
            $plankPen = [System.Drawing.Pen]::new(
                [System.Drawing.Color]::FromArgb(210, 220, 234, 255), 1.25)
            $plankPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
            $plankPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
            try {
                $graphics.DrawLine($plankPen, 26, 43, 38, 43)
                $graphics.DrawLine($plankPen, 24, 48, 40, 48)
                $graphics.DrawLine($plankPen, 28.5, 39.5, 25, 53)
                $graphics.DrawLine($plankPen, 35.5, 39.5, 39, 53)
            }
            finally {
                $plankPen.Dispose()
            }
        }
    }
    finally {
        $graphics.Dispose()
    }

    if ($supersampling -eq 1) {
        return $bitmap
    }

    $result = [System.Drawing.Bitmap]::new(
        $Size,
        $Size,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $result.SetResolution(96, 96)
    $downsample = [System.Drawing.Graphics]::FromImage($result)
    try {
        $downsample.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
        $downsample.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $downsample.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $downsample.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $downsample.DrawImage(
            $bitmap,
            [System.Drawing.Rectangle]::new(0, 0, $Size, $Size),
            0,
            0,
            $renderSize,
            $renderSize,
            [System.Drawing.GraphicsUnit]::Pixel)
    }
    finally {
        $downsample.Dispose()
        $bitmap.Dispose()
    }

    return $result
}

$sizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
$images = [System.Collections.Generic.List[object]]::new()

try {
    foreach ($size in $sizes) {
        $bitmap = New-BrandBitmap $size
        $stream = [System.IO.MemoryStream]::new()
        try {
            $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
            $images.Add([pscustomobject]@{
                Size = $size
                Bytes = $stream.ToArray()
            })
        }
        finally {
            $stream.Dispose()
            $bitmap.Dispose()
        }
    }

    $resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
    $outputDirectory = [System.IO.Path]::GetDirectoryName($resolvedOutput)
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null

    $file = [System.IO.File]::Open(
        $resolvedOutput,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    $writer = [System.IO.BinaryWriter]::new($file)
    try {
        $writer.Write([uint16] 0) # reserved
        $writer.Write([uint16] 1) # icon
        $writer.Write([uint16] $images.Count)

        $offset = 6 + (16 * $images.Count)
        foreach ($image in $images) {
            $dimension = if ($image.Size -eq 256) { 0 } else { $image.Size }
            $writer.Write([byte] $dimension)
            $writer.Write([byte] $dimension)
            $writer.Write([byte] 0) # palette entries
            $writer.Write([byte] 0) # reserved
            $writer.Write([uint16] 1) # color planes
            $writer.Write([uint16] 32) # bits per pixel
            $writer.Write([uint32] $image.Bytes.Length)
            $writer.Write([uint32] $offset)
            $offset += $image.Bytes.Length
        }

        foreach ($image in $images) {
            $writer.Write($image.Bytes)
        }
    }
    finally {
        $writer.Dispose()
    }

    Write-Host "Generated $resolvedOutput ($($images.Count) sizes: $($sizes -join ', '))"
}
finally {
    $images.Clear()
}
