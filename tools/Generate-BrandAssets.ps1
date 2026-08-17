[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path $PSScriptRoot '..\Drawbridge.App\Assets\Drawbridge.ico')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing.Common

function New-ShieldPath {
    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $path.StartFigure()
    $path.AddBezier(32, 3, 42.5, 3, 52.5, 6.2, 58, 10.5)
    $path.AddLine(58, 10.5, 58, 28.5)
    $path.AddBezier(58, 28.5, 58, 43.2, 48.2, 55.6, 32, 61)
    $path.AddBezier(32, 61, 15.8, 55.6, 6, 43.2, 6, 28.5)
    $path.AddLine(6, 28.5, 6, 10.5)
    $path.AddBezier(6, 10.5, 11.5, 6.2, 21.5, 3, 32, 3)
    $path.CloseFigure()
    return $path
}

function New-PolygonPath {
    param([System.Drawing.PointF[]] $Points)

    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $path.AddPolygon($Points)
    return $path
}

function Fill-BrandPolygon {
    param(
        [System.Drawing.Graphics] $Graphics,
        [System.Drawing.Brush] $Brush,
        [System.Drawing.PointF[]] $Points
    )

    $path = New-PolygonPath $Points
    try {
        $Graphics.FillPath($Brush, $path)
    }
    finally {
        $path.Dispose()
    }
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

        $shieldPath = New-ShieldPath
        $shieldBrush = [System.Drawing.Drawing2D.LinearGradientBrush]::new(
            [System.Drawing.PointF]::new(14, 6),
            [System.Drawing.PointF]::new(50, 59),
            [System.Drawing.ColorTranslator]::FromHtml('#243A62'),
            [System.Drawing.ColorTranslator]::FromHtml('#091321'))
        $shieldBlend = [System.Drawing.Drawing2D.ColorBlend]::new(3)
        $shieldBlend.Colors = [System.Drawing.Color[]] @(
            [System.Drawing.ColorTranslator]::FromHtml('#243A62'),
            [System.Drawing.ColorTranslator]::FromHtml('#14243E'),
            [System.Drawing.ColorTranslator]::FromHtml('#091321'))
        $shieldBlend.Positions = [single[]] @(0, 0.58, 1)
        $shieldBrush.InterpolationColors = $shieldBlend
        $outlinePen = [System.Drawing.Pen]::new(
            [System.Drawing.ColorTranslator]::FromHtml('#577EB8'), 1.5)
        try {
            $graphics.FillPath($shieldBrush, $shieldPath)
            $graphics.DrawPath($outlinePen, $shieldPath)
        }
        finally {
            $outlinePen.Dispose()
            $shieldBrush.Dispose()
            $shieldPath.Dispose()
        }

        $castleBrush = [System.Drawing.SolidBrush]::new(
            [System.Drawing.ColorTranslator]::FromHtml('#F7FAFF'))
        try {
            Fill-BrandPolygon $graphics $castleBrush ([System.Drawing.PointF[]] @(
                [System.Drawing.PointF]::new(12, 45),
                [System.Drawing.PointF]::new(12, 19),
                [System.Drawing.PointF]::new(16, 19),
                [System.Drawing.PointF]::new(16, 23),
                [System.Drawing.PointF]::new(20, 23),
                [System.Drawing.PointF]::new(20, 19),
                [System.Drawing.PointF]::new(24, 19),
                [System.Drawing.PointF]::new(24, 45)))
            Fill-BrandPolygon $graphics $castleBrush ([System.Drawing.PointF[]] @(
                [System.Drawing.PointF]::new(23, 45),
                [System.Drawing.PointF]::new(23, 21),
                [System.Drawing.PointF]::new(27, 21),
                [System.Drawing.PointF]::new(27, 17),
                [System.Drawing.PointF]::new(31, 17),
                [System.Drawing.PointF]::new(31, 21),
                [System.Drawing.PointF]::new(35, 21),
                [System.Drawing.PointF]::new(35, 17),
                [System.Drawing.PointF]::new(39, 17),
                [System.Drawing.PointF]::new(39, 21),
                [System.Drawing.PointF]::new(41, 21),
                [System.Drawing.PointF]::new(41, 45)))
            Fill-BrandPolygon $graphics $castleBrush ([System.Drawing.PointF[]] @(
                [System.Drawing.PointF]::new(40, 45),
                [System.Drawing.PointF]::new(40, 19),
                [System.Drawing.PointF]::new(44, 19),
                [System.Drawing.PointF]::new(44, 23),
                [System.Drawing.PointF]::new(48, 23),
                [System.Drawing.PointF]::new(48, 19),
                [System.Drawing.PointF]::new(52, 19),
                [System.Drawing.PointF]::new(52, 45)))
        }
        finally {
            $castleBrush.Dispose()
        }

        $gatePath = [System.Drawing.Drawing2D.GraphicsPath]::new()
        $gatePath.StartFigure()
        $gatePath.AddLine(24, 46, 24, 35)
        $gatePath.AddBezier(24, 35, 24, 30.58, 27.58, 27, 32, 27)
        $gatePath.AddBezier(32, 27, 36.42, 27, 40, 30.58, 40, 35)
        $gatePath.AddLine(40, 35, 40, 46)
        $gatePath.CloseFigure()
        $gateBrush = [System.Drawing.SolidBrush]::new(
            [System.Drawing.ColorTranslator]::FromHtml('#0C1728'))
        try {
            $graphics.FillPath($gateBrush, $gatePath)
        }
        finally {
            $gateBrush.Dispose()
            $gatePath.Dispose()
        }

        if ($Size -ge 20) {
            $chainPen = [System.Drawing.Pen]::new(
                [System.Drawing.Color]::FromArgb(224, 117, 185, 255), 1.75)
            $chainPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
            $chainPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
            try {
                $graphics.DrawLine($chainPen, 18, 27, 25, 47)
                $graphics.DrawLine($chainPen, 46, 27, 39, 47)
            }
            finally {
                $chainPen.Dispose()
            }
        }

        $bridgePoints = [System.Drawing.PointF[]] @(
            [System.Drawing.PointF]::new(27, 35),
            [System.Drawing.PointF]::new(37, 35),
            [System.Drawing.PointF]::new(44, 53),
            [System.Drawing.PointF]::new(20, 53))
        $bridgePath = New-PolygonPath $bridgePoints
        $bridgeBrush = [System.Drawing.Drawing2D.LinearGradientBrush]::new(
            [System.Drawing.PointF]::new(32, 34),
            [System.Drawing.PointF]::new(32, 53),
            [System.Drawing.ColorTranslator]::FromHtml('#8ACBFF'),
            [System.Drawing.ColorTranslator]::FromHtml('#3E82F5'))
        $bridgeOutline = [System.Drawing.Pen]::new(
            [System.Drawing.ColorTranslator]::FromHtml('#B8DDFF'), 1.15)
        $bridgeOutline.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        try {
            $graphics.FillPath($bridgeBrush, $bridgePath)
            $graphics.DrawPath($bridgeOutline, $bridgePath)
        }
        finally {
            $bridgeOutline.Dispose()
            $bridgeBrush.Dispose()
            $bridgePath.Dispose()
        }

        if ($Size -ge 20) {
            $plankPen = [System.Drawing.Pen]::new(
                [System.Drawing.Color]::FromArgb(194, 229, 242, 255), 1.2)
            $plankPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
            $plankPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
            try {
                $graphics.DrawLine($plankPen, 24.7, 41, 39.3, 41)
                $graphics.DrawLine($plankPen, 22.5, 47, 41.5, 47)
            }
            finally {
                $plankPen.Dispose()
            }
        }
    }
    finally {
        $graphics.Dispose()
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
