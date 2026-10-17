# !!! RISKY: this briefly points the user's system proxy at netcap. !!!
#
# Takes a screenshot of the element picker in a REAL browser to prove that
# pressing the button turns the cursor into a crosshair on a page that was
# already open.  The user allows driving their own browser window (they only
# asked not to be disturbed while gaming), so this reuses the running Edge
# instead of a throw-away profile; the only things this script starts itself
# are netcap and the page load, and it cleans those up.
#
# Guards: the desktop rescue script must exist, the upstream must answer, and
# the proxy settings are snapshotted and compared afterwards.
#
#   powershell -ExecutionPolicy Bypass -File tools\picker_shot.ps1 [-Url <url>] [-Out <png>]

param(
  [string]$Url = 'https://tryblock.org/zh/adblock-test/advanced',
  [string]$Out = 'ui_shot_picker.png',
  [int]$Port = 8492
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$rescue = Join-Path ([Environment]::GetFolderPath('Desktop')) 'netcap-restore.cmd'
if (-not (Test-Path $rescue)) { throw "guard: $rescue is missing - refusing to touch the system proxy" }
$rescueOk = (Test-Connection -ComputerName 127.0.0.1 -Count 1 -Quiet)
$up = Test-NetConnection -ComputerName 127.0.0.1 -Port 7890 -InformationLevel Quiet
if (-not $up) { throw 'guard: no upstream on 127.0.0.1:7890 - refusing to take the system proxy over' }
Write-Host "guards ok: rescue script present, upstream 127.0.0.1:7890 answers"

$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$before = Get-ItemProperty $key | Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL
Write-Host ("before: enable={0} server={1} pac={2}" -f $before.ProxyEnable, $before.ProxyServer, $before.AutoConfigURL)

$userRules = Join-Path $env:APPDATA 'netcap-ui\my-rules.txt'
$flag = Join-Path $env:APPDATA 'netcap-ui\picker.on'
Remove-Item $flag -Force -ErrorAction SilentlyContinue

$exe = Join-Path $root 'ui\build\windows\x64\runner\Release\netcap.exe'
$args = @('--serve', "127.0.0.1:$Port", '--rules', 'rules\adblock.txt', '--ca', '_mitmca',
          '--mitm', '--picker', '--picker-rules', $userRules, '--picker-flag', $flag,
          '--upstream', '127.0.0.1:7890', '--system-proxy', 'on')
$proc = Start-Process -FilePath $exe -ArgumentList $args -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3

$during = Get-ItemProperty $key | Select-Object ProxyEnable, ProxyServer, AutoConfigURL
Write-Host ("during: enable={0} server={1} pac={2}" -f $during.ProxyEnable, $during.ProxyServer, $during.AutoConfigURL)

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;using System.Runtime.InteropServices;
public struct RECT { public int L, T, R, B; }
public class PW {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern void keybd_event(byte k, byte s, uint f, IntPtr e);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, IntPtr e);
}
"@

function Get-WindowTitle([IntPtr]$h) {
  $sb = New-Object System.Text.StringBuilder 512
  [void][PW]::GetWindowText($h, $sb, 512)
  return $sb.ToString()
}

try {
  # Reuse the browser the user already has open.  Edge hands the URL to the
  # running instance, which usually opens it in a *background* tab, so the
  # foreground window is not reliable: remember what the Edge windows were called
  # before, then pick the one whose title changed (that is the tab we opened).
  $beforeMap = @{}
  Get-Process msedge -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowHandle -ne 0 } |
    ForEach-Object { $beforeMap[$_.MainWindowHandle] = $_.MainWindowTitle }

  Start-Process 'msedge.exe' -ArgumentList $Url | Out-Null
  Start-Sleep -Seconds 9

  $hwnd = [IntPtr]::Zero
  $title = ''
  $after = Get-Process msedge -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 }
  foreach ($w in $after) {
    $old = ''
    if ($beforeMap.ContainsKey($w.MainWindowHandle)) { $old = $beforeMap[$w.MainWindowHandle] }
    if ($old -ne $w.MainWindowTitle -and $w.MainWindowTitle -ne '') {
      $hwnd = $w.MainWindowHandle; $title = $w.MainWindowTitle; break
    }
  }
  if ($hwnd -eq [IntPtr]::Zero -and $after.Count -ge 1) {
    # Nothing changed (the page was already open): fall back to the biggest Edge window.
    $big = $after | Sort-Object { $_.MainWindowTitle.Length } -Descending | Select-Object -First 1
    $hwnd = $big.MainWindowHandle; $title = $big.MainWindowTitle
    Write-Host 'no Edge window changed its title; falling back to the largest one'
  }
  Write-Host ("target window: '{0}'" -f $title)
  if ($hwnd -eq [IntPtr]::Zero) { Write-Host 'no Edge window to capture' }

  # Arm the picker exactly like the toolbar button does (it writes this file).
  Set-Content -Path $flag -Value '1' -NoNewline
  Start-Sleep -Seconds 4

  if ($hwnd -ne [IntPtr]::Zero) {
    [void][PW]::ShowWindowAsync($hwnd, 9)
    [PW]::keybd_event(0x12, 0, 0, [IntPtr]::Zero); [PW]::keybd_event(0x12, 0, 2, [IntPtr]::Zero)
    [void][PW]::SetForegroundWindow($hwnd)
    Start-Sleep -Milliseconds 900
    # Park the mouse in the middle of the page so the crosshair rule and the
    # hover outline have something to show.
    $r = New-Object RECT; [void][PW]::GetWindowRect($hwnd, [ref]$r)
    [void][PW]::SetCursorPos([int](($r.L + $r.R) / 2), [int](($r.T + $r.B) / 2))
    Start-Sleep -Milliseconds 900
    $bmp = New-Object System.Drawing.Bitmap(($r.R - $r.L), ($r.B - $r.T))
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
    $target = Join-Path $root $Out
    $bmp.Save($target, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host ("captured {0} bytes -> {1}" -f (Get-Item $target).Length, $target)
  }
} finally {
  Remove-Item $flag -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 800
  try { & (Join-Path $root 'build\netcap.exe') --system-proxy restore 2>&1 | Select-Object -First 3 } catch { }
  Start-Sleep -Milliseconds 500
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 500
  $after = Get-ItemProperty $key | Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL
  $same = ($after.ProxyEnable -eq $before.ProxyEnable) -and ($after.ProxyServer -eq $before.ProxyServer) -and
          ($after.ProxyOverride -eq $before.ProxyOverride) -and ($after.AutoConfigURL -eq $before.AutoConfigURL)
  Write-Host ("after:  enable={0} server={1} pac={2}" -f $after.ProxyEnable, $after.ProxyServer, $after.AutoConfigURL)
  Write-Host ("proxy restored: {0}" -f $same)
  Write-Host ("rescue script still present: {0}" -f (Test-Path $rescue))
}
