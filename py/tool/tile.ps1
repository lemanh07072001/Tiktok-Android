# re/tool/tile.ps1 — xếp các cửa sổ CMD (title bắt đầu bằng -Prefix) thành lưới -PerRow cửa/hàng.
#   powershell -ExecutionPolicy Bypass -File tile.ps1 -PerRow 5 -Prefix "T12345_"
param([int]$PerRow = 5, [string]$Prefix = 'T', [int]$MaxWaitMs = 4000)

Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win {
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h,int x,int y,int w,int hh,bool r);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h,int c);
}
"@

$area = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea

# đợi tới khi thấy đủ (hoặc hết MaxWait) — cửa sổ có thể mọc trễ
$deadline = (Get-Date).AddMilliseconds($MaxWaitMs)
$wins = @()
do {
  $wins = @(Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -like "$Prefix*" })
  if ($wins.Count -gt 0) { Start-Sleep -Milliseconds 300 }
} while ((Get-Date) -lt $deadline -and $wins.Count -eq 0)

if ($wins.Count -eq 0) { Write-Host "tile: không thấy cửa sổ '$Prefix*'"; exit 0 }

# sort theo index trong title  T<pid>_<idx>_<user>
$wins = $wins | Sort-Object { [int]($_.MainWindowTitle -replace '^[^_]+_(\d+)_.*$','$1') }
$n = $wins.Count
$rows = [math]::Ceiling($n / $PerRow)
$cw = [int]($area.Width / $PerRow)
$ch = [int]($area.Height / $rows)

for ($i = 0; $i -lt $n; $i++) {
  $c = $i % $PerRow
  $r = [math]::Floor($i / $PerRow)
  $x = $area.X + $c * $cw
  $y = $area.Y + $r * $ch
  [Win]::ShowWindow($wins[$i].MainWindowHandle, 9) | Out-Null      # SW_RESTORE
  [Win]::MoveWindow($wins[$i].MainWindowHandle, $x, $y, $cw, $ch, $true) | Out-Null
}
Write-Host "tile: xếp $n cửa sổ ($PerRow/hàng, $rows hàng, ô ${cw}x${ch})"
