# UI-level ad-filtering acceptance: start the packaged netcap_ui with the
# built-in filter list, drive real ad URLs through the proxy it runs, print the
# status codes, and screenshot the window so the intercept table is on the record.
#
#   pwsh -File tools\ui_ads_accept.ps1 [-Port 8271] [-Out ..\ui_shot_ui_ads.png]
#
# Nothing here touches the system proxy, the routing table or any registry key:
# the client side is explicit (`curl -x`), so the machine keeps its own network.
param(
  [string]$Exe = 'D:\Demo\FilterTheWeb\ui\build\windows\x64\runner\Release\netcap_ui.exe',
  [string]$Out = 'D:\Demo\FilterTheWeb\ui_shot_ui_ads.png',
  [int]$Port = 8271
)
$ErrorActionPreference = 'Continue'
Get-Process netcap_ui, netcap -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600

$ui = Start-Process -FilePath $Exe -ArgumentList @('--serve', "127.0.0.1:$Port", '--mitm') -PassThru
Start-Sleep -Seconds 6

$targets = @(
  'http://ads.example.com/',
  'http://ad.doubleclick.net/',
  'http://googleads.g.doubleclick.net/pagead/id',
  'http://securepubads.g.doubleclick.net/tag/js/gpt.js',
  'http://www.googletagmanager.com/gtm.js',
  'http://example.com/'
)
foreach ($u in $targets) {
  $code = & curl.exe -s -o NUL -w '%{http_code}' -x "http://127.0.0.1:$Port" --max-time 25 $u
  Write-Output ("{0,-5} {1}" -f $code, $u)
}

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public struct RECT { public int L, T, R, B; }
public class WinShot {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int c);
}
"@
$proc = Get-Process -Id $ui.Id -ErrorAction SilentlyContinue
$handle = if ($proc) { $proc.MainWindowHandle } else { [IntPtr]::Zero }
if ($handle -ne [IntPtr]::Zero) {
  [WinShot]::ShowWindowAsync($handle, 9) | Out-Null
  [WinShot]::SetForegroundWindow($handle) | Out-Null
  Start-Sleep -Milliseconds 800
  $r = New-Object RECT
  [WinShot]::GetWindowRect($handle, [ref]$r) | Out-Null
  $w = $r.R - $r.L
  $h = $r.B - $r.T
  Write-Output "window ${w}x${h} at $($r.L),$($r.T)"
  $bmp = New-Object System.Drawing.Bitmap($w, $h)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
  $bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose()
  $bmp.Dispose()
  Write-Output ("captured " + (Get-Item $Out).Length + " bytes -> " + $Out)
} else {
  Write-Output 'no window handle: nothing captured'
}

Get-Process netcap_ui, netcap -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
