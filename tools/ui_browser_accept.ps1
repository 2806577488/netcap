# UI-level, real-browser ad-filtering acceptance with a *bounded* system-proxy
# takeover -- the shape the objective asks for: the interface starts the proxy,
# decrypts HTTPS, takes the system proxy over (chained through the local Clash
# port so the machine keeps its own way out), a real browser opens a page full
# of ads, and the interface's table is screenshotted.
#
#   pwsh -File tools\ui_browser_accept.ps1 [-Seconds 45]
#
# Safety rails: the desktop restore script must exist, the upstream must answer
# before anything is taken over, the takeover lasts at most N seconds, and at
# the end the registry is put back and compared against a snapshot taken at the
# start, plus a connectivity probe.
param(
  [string]$Exe = 'D:\Demo\FilterTheWeb\ui\build\windows\x64\runner\Release\netcap_ui.exe',
  [string]$Out = 'D:\Demo\FilterTheWeb\ui_shot_ui_browser.png',
  [int]$Port = 8291,
  [string]$Upstream = '127.0.0.1:7890',
  [string]$Url = 'https://blog.csdn.net/emellyduck/article/details/111030301',
  [int]$Seconds = 45
)
$ErrorActionPreference = 'Continue'
$root = 'D:\Demo\FilterTheWeb'
Set-Location $root
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

function Read-Proxy {
  $k = Get-ItemProperty $key
  [pscustomobject]@{ enable = $k.ProxyEnable; server = $k.ProxyServer; override = $k.ProxyOverride; pac = $k.AutoConfigURL }
}
function Test-Upstream([string]$addr) {
  $parts = $addr.Split(':')
  try {
    $c = New-Object System.Net.Sockets.TcpClient
    $ok = $c.ConnectAsync($parts[0], [int]$parts[1]).Wait(2000)
    $c.Close()
    return $ok
  } catch { return $false }
}

if (-not (Test-Path 'C:\Users\Czr\Desktop\netcap-restore.cmd')) { Write-Output 'REFUSING: the desktop restore script is missing'; exit 1 }
if (-not (Test-Upstream $Upstream)) { Write-Output "REFUSING: upstream $Upstream does not answer"; exit 1 }

$before = Read-Proxy
Write-Output "before: enable=$($before.enable) server=$($before.server) pac=$($before.pac)"

Get-Process netcap, netcap_ui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600

$ui = Start-Process -FilePath $Exe -ArgumentList @('--serve', "127.0.0.1:$Port", '--mitm', '--system-proxy', 'on', '--upstream', $Upstream) -PassThru
Start-Sleep -Seconds 8
$during = Read-Proxy
Write-Output "during: enable=$($during.enable) server=$($during.server) pac=$($during.pac)"

$profile = Join-Path $env:TEMP ('netcap-edge-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$edge = Start-Process -FilePath 'msedge.exe' -ArgumentList @("--user-data-dir=$profile", '--no-first-run', '--new-window', $Url) -PassThru
Start-Sleep -Seconds $Seconds

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public struct RECT { public int L, T, R, B; }
public class WinShot2 {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int c);
}
"@
$proc = Get-Process -Id $ui.Id -ErrorAction SilentlyContinue
if ($proc -and $proc.MainWindowHandle -ne [IntPtr]::Zero) {
  [WinShot2]::ShowWindowAsync($proc.MainWindowHandle, 9) | Out-Null
  [WinShot2]::SetForegroundWindow($proc.MainWindowHandle) | Out-Null
  Start-Sleep -Milliseconds 900
  $r = New-Object RECT
  [WinShot2]::GetWindowRect($proc.MainWindowHandle, [ref]$r) | Out-Null
  $w = $r.R - $r.L; $h = $r.B - $r.T
  $bmp = New-Object System.Drawing.Bitmap($w, $h)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
  $bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  Write-Output ("captured {0} bytes -> {1}" -f (Get-Item $Out).Length, $Out)
} else {
  Write-Output 'no UI window handle: nothing captured'
}

# The page itself is the other half of the evidence: the same window the user
# would look at, captured from the Edge instance that carries our one-off
# profile (its first process hands the window to a child, so match by command
# line rather than by pid).
$browserOut = [IO.Path]::ChangeExtension($Out, $null) + 'page.png'
$edgeProc = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -like '*netcap-edge-*' } |
  ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue } |
  Where-Object { $_ -and $_.MainWindowHandle -ne [IntPtr]::Zero } |
  Select-Object -First 1
if ($edgeProc) {
  [WinShot2]::ShowWindowAsync($edgeProc.MainWindowHandle, 9) | Out-Null
  [WinShot2]::SetForegroundWindow($edgeProc.MainWindowHandle) | Out-Null
  Start-Sleep -Milliseconds 900
  $rb = New-Object RECT
  [WinShot2]::GetWindowRect($edgeProc.MainWindowHandle, [ref]$rb) | Out-Null
  $wb = $rb.R - $rb.L; $hb = $rb.B - $rb.T
  $bmpB = New-Object System.Drawing.Bitmap($wb, $hb)
  $gB = [System.Drawing.Graphics]::FromImage($bmpB)
  $gB.CopyFromScreen($rb.L, $rb.T, 0, 0, $bmpB.Size)
  $bmpB.Save($browserOut, [System.Drawing.Imaging.ImageFormat]::Png)
  $gB.Dispose(); $bmpB.Dispose()
  Write-Output ("captured page {0} bytes -> {1}" -f (Get-Item $browserOut).Length, $browserOut)
} else {
  Write-Output 'no browser window found: page not captured'
}

# Stop only the browser we started, then give the proxy its chance to restore.
if ($edge -and -not $edge.HasExited) { $edge.CloseMainWindow() | Out-Null }
Get-Process netcap_ui, netcap -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800
& "$root\build\netcap.exe" --system-proxy restore 2>&1 | Select-Object -Last 2
Start-Sleep -Milliseconds 500
$after = Read-Proxy
$same = ($after.enable -eq $before.enable) -and ($after.server -eq $before.server) -and ($after.pac -eq $before.pac)
Write-Output "after:  enable=$($after.enable) server=$($after.server) pac=$($after.pac)"
Write-Output "proxy restored: $same"
$code = & curl.exe -s -o NUL -w '%{http_code}' --max-time 20 http://example.com/
Write-Output "connectivity: example.com -> $code"
