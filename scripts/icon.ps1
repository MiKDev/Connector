Add-Type -AssemblyName System.Drawing
$assetDirectory = Join-Path (Split-Path $PSScriptRoot -Parent) 'assets'
New-Item -ItemType Directory -Path $assetDirectory -Force | Out-Null
$bitmap = New-Object System.Drawing.Bitmap 512,512
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.Clear([System.Drawing.Color]::Transparent)
$shape = New-Object System.Drawing.Drawing2D.GraphicsPath
$shape.AddArc(12,12,120,120,180,90)
$shape.AddArc(380,12,120,120,270,90)
$shape.AddArc(380,380,120,120,0,90)
$shape.AddArc(12,380,120,120,90,90)
$shape.CloseFigure()
$brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush ([System.Drawing.Point]::new(0,0)),([System.Drawing.Point]::new(512,512)),([System.Drawing.Color]::FromArgb(139,125,222)),([System.Drawing.Color]::FromArgb(49,48,83))
$graphics.FillPath($brush,$shape)
$outline = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(170,164,238)),3
$graphics.DrawPath($outline,$shape)
$pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(238,234,255)),26
$pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
$graphics.DrawLines($pen,[System.Drawing.Point[]]@([System.Drawing.Point]::new(145,166),[System.Drawing.Point]::new(235,251),[System.Drawing.Point]::new(145,336)))
$graphics.DrawLine($pen,278,336,368,336)
$bitmap.Save((Join-Path $assetDirectory 'icon.png'),[System.Drawing.Imaging.ImageFormat]::Png)
$small = New-Object System.Drawing.Bitmap $bitmap,256,256
$memory = New-Object System.IO.MemoryStream
$small.Save($memory,[System.Drawing.Imaging.ImageFormat]::Png)
$bytes = $memory.ToArray()
$file = [System.IO.File]::Create((Join-Path $assetDirectory 'icon.ico'))
$writer = New-Object System.IO.BinaryWriter $file
$writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]1)
$writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0)
$writer.Write([uint16]1); $writer.Write([uint16]32); $writer.Write([uint32]$bytes.Length); $writer.Write([uint32]22); $writer.Write($bytes)
$writer.Dispose(); $memory.Dispose(); $small.Dispose(); $pen.Dispose(); $outline.Dispose(); $brush.Dispose(); $shape.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
Write-Output 'Application icons generated.'
