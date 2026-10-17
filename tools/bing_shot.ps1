# Look at a page through netcap in a real browser, with the same safety rails as
# tools\csdn_page_shot.ps1:
#   * refuse to run unless the desktop rescue script exists
#   * chain through the proxy that already works on this machine (Clash), so the
#     machine keeps its normal way out while the takeover is in place
#   * snapshot HKCU, take over, screenshot, stop, restore, and compare
# usage: powershell -File tools\bing_shot.ps1 [url]
param(
  [string]$Url = 'https://www.bing.com/search?q=%E6%B7%98%E5%AE%9D',
  [int]$Port = 8407,
  [string]$Out = '_bing_shot.png'
)
$ErrorActionPreference = 'Stop'
$root = 'D:\Demo\FilterTheWeb'
$exe = Join-Path $root 'build\netcap.exe'
$rules = Join-Path $root 'rules\adblock.txt'
$ca = Join-Path $root '_mitmca'
$rescue = 'C:\Users\Czr\Desktop\netcap-restore.cmd'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

function Test-Port([int]$p, [int]$timeoutMs = 400) {
  try {
    $c = New-Object System.Net.Sockets.TcpClient
    $ok = $c.ConnectAsync('127.0.0.1', $p).Wait($timeoutMs)
    $c.Close()
    return $ok
  } catch { return $false }
}

if (-not (Test-Path $rescue)) { throw "rescue script missing: $rescue" }
$upstream = ''
foreach ($candidate in 7890, 7897, 7891, 26561, 10809) {
  if (Test-Port $candidate) { $upstream = "127.0.0.1:$candidate"; break }
}
if ($upstream -eq '') { throw 'no working upstream proxy found; refusing to take over' }
Write-Host "upstream: $upstream"

$before = Get-ItemProperty $key
$snap = @{
  ProxyEnable = $before.ProxyEnable
  ProxyServer = $before.ProxyServer
  ProxyOverride = $before.ProxyOverride
  AutoConfigURL = $before.AutoConfigURL
}
Write-Host ("before: enable={0} server={1} pac={2}" -f $snap.ProxyEnable, $snap.ProxyServer, $snap.AutoConfigURL)

$jsonl = Join-Path $root '_bing_proxy.jsonl'
$errlog = Join-Path $root '_bing_proxy.err'
Remove-Item $jsonl, $errlog -ErrorAction SilentlyContinue
$args = @('--serve', "127.0.0.1:$Port", '--rules', $rules, '--ca', $ca, '--mitm',
          '--system-proxy', 'on', '--upstream', $upstream, '--jsonl', '--show-blocks')
$proc = Start-Process -FilePath $exe -ArgumentList $args -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $jsonl -RedirectStandardError $errlog
Start-Sleep -Seconds 4
$during = Get-ItemProperty $key
Write-Host ("during: enable={0} server={1}" -f $during.ProxyEnable, $during.ProxyServer)
if ($during.ProxyEnable -ne 1) { Write-Host 'takeover did not happen; aborting'; }

$profile = Join-Path $env:TEMP ('netcap-bing-' + [guid]::NewGuid().ToString('N'))
$edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
Start-Process -FilePath $edge -ArgumentList @("--user-data-dir=$profile", '--no-first-run',
  '--no-default-browser-check', '--new-window', $Url) | Out-Null
Start-Sleep -Seconds 16

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;using System.Runtime.InteropServices;
public struct RECT { public int L, T, R, B; }
public class WB { [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int c); }
"@
$mine = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" |
  Where-Object { $_.CommandLine -like "*$profile*" -and $_.CommandLine -notlike '*--type=*' }
if ($mine) {
  $w = Get-Process -Id $mine[0].ProcessId
  [WB]::ShowWindowAsync($w.MainWindowHandle, 9) | Out-Null
  [WB]::SetForegroundWindow($w.MainWindowHandle) | Out-Null
  Start-Sleep -Milliseconds 800
  $r = New-Object RECT; [WB]::GetWindowRect($w.MainWindowHandle, [ref]$r) | Out-Null
  $bmp = New-Object System.Drawing.Bitmap(($r.R - $r.L), ($r.B - $r.T))
  $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
  $bmp.Save((Join-Path $root $Out), [System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()
  Write-Host ("captured {0} bytes -> {1}" -f (Get-Item (Join-Path $root $Out)).Length, $Out)
} else {
  Write-Host 'test browser did not come up on its own profile: no capture, no other window touched'
}

Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" |
  Where-Object { $_.CommandLine -like "*$profile*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
& $exe --system-proxy restore | Out-Null
Start-Sleep -Seconds 1
$after = Get-ItemProperty $key
$same = ($after.ProxyEnable -eq $snap.ProxyEnable) -and ($after.ProxyServer -eq $snap.ProxyServer) -and
        ($after.ProxyOverride -eq $snap.ProxyOverride) -and ($after.AutoConfigURL -eq $snap.AutoConfigURL)
Write-Host ("after:  enable={0} server={1} pac={2}" -f $after.ProxyEnable, $after.ProxyServer, $after.AutoConfigURL)
Write-Host ("proxy restored: {0}" -f $same)
$code = try { (Invoke-WebRequest 'http://example.com/' -UseBasicParsing -TimeoutSec 15).StatusCode } catch { 'failed' }
Write-Host "connectivity: example.com -> $code"
Remove-Item $profile -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '--- bing events ---'
Get-Content $jsonl -ErrorAction SilentlyContinue | Where-Object { $_ -match '"type":"intercept"' } | ForEach-Object {
  $e = $_ | ConvertFrom-Json
  if ($e.host -like '*bing*') {
    "action={0} method={1} host={2} status={3} bytes={4} proc={5} detail={6}" -f `
      $e.action, $e.method, $e.host, $e.status, $e.response_bytes, $e.client_proc, $e.detail
  }
}
