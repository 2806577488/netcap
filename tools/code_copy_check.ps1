# Checks the CSDN code-block rules end to end in a real browser:
#   - hidden "AI写代码" button
#   - "登录复制" turned into a plain "复制" that really copies the code
#   - the "运行" button untouched
#
# Safety rails, same as csdn_page_shot.ps1: the desktop rescue script must be
# there and the upstream (Clash) must answer before anything is touched; the
# system proxy is snapshotted, taken over for the duration and restored
# afterwards, then compared value by value and the connectivity is probed.
#
# The browser instance is started with a throwaway profile, is driven through
# its own window handle only, and is killed again in the finally block -- an
# earlier version picked "the first window whose title mentions CSDN", which
# could be a window the user had open, and left it behind.
#
#   pwsh -File tools/code_copy_check.ps1                      # just capture
#   pwsh -File tools/code_copy_check.ps1 -ClickX 1330 -ClickY 320   # and click 复制
param(
  [int]$ClickX = 0,
  [int]$ClickY = 0,
  [int]$Port = 8441,
  [string]$Upstream = '127.0.0.1:7890',
  [int]$Notches = 6
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$Exe  = Join-Path $root 'ui\build\windows\x64\runner\Release\netcap_ui.exe'
$Core = Join-Path $root 'build\netcap.exe'
$Edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$Url  = 'https://blog.csdn.net/emellyduck/article/details/111030301'
$Key  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

$rescue = 'C:\Users\Czr\Desktop\netcap-restore.cmd'
if (-not (Test-Path $rescue)) { throw "refusing: $rescue is missing" }
$up = $Upstream.Split(':')[0]; $upPort = [int]$Upstream.Split(':')[1]
if (-not (Test-NetConnection -ComputerName $up -Port $upPort -InformationLevel Quiet -WarningAction SilentlyContinue)) {
  throw "refusing: no upstream at $Upstream; taking the system proxy over now would cut this machine off"
}

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;using System.Runtime.InteropServices;
public struct RECT { public int L, T, R, B; }
public class WC { [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int c);
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
 [DllImport("user32.dll")] public static extern void keybd_event(byte k, byte s, uint f, IntPtr e);
 [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, IntPtr e); }
"@

function Shot([System.IntPtr]$handle, [string]$path) {
  if ($handle -eq [System.IntPtr]::Zero) { Write-Host 'no test window'; return $null }
  $r = New-Object RECT; [WC]::GetWindowRect($handle, [ref]$r) | Out-Null
  $bmp = New-Object System.Drawing.Bitmap(($r.R - $r.L), ($r.B - $r.T))
  $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
  $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()
  # Write-Host (not Write-Output): the string would otherwise be swallowed by
  # the $rect = Shot ... assignment along with the returned rectangle.
  Write-Host ("captured {0} bytes -> {1}" -f (Get-Item $path).Length, $path)
  return $r
}

# The browser we started, identified by our throwaway profile in its command
# line -- never "the first CSDN window", which may well be the user's own.
function Get-TestWindow([string]$profile) {
  $p = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue |
       Where-Object { $_.CommandLine -and $_.CommandLine.Contains($profile) -and $_.CommandLine -notlike '*--type=*' } |
       Select-Object -First 1
  if (-not $p) { return [System.IntPtr]::Zero }
  $proc = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
  if ($proc -and $proc.MainWindowHandle -ne 0) { return $proc.MainWindowHandle }
  return [System.IntPtr]::Zero
}

function Stop-TestBrowser([string]$profile) {
  $procs = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue |
           Where-Object { $_.CommandLine -and $_.CommandLine.Contains($profile) }
  foreach ($p in $procs) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 1
  Write-Host ("closed the test browser instance ({0} process(es))" -f ($procs | Measure-Object).Count)
}

Start-Process cmd -Verb RunAs -Wait -ArgumentList '/c','taskkill /F /IM netcap_ui.exe & taskkill /F /IM netcap.exe & exit 0' | Out-Null
$before = Get-ItemProperty $Key | Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL
Write-Output ("before: enable={0} server={1} pac={2}" -f $before.ProxyEnable, $before.ProxyServer, $before.AutoConfigURL)

$prof = Join-Path $env:TEMP ('netcap-code-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
try {
  Start-Process -FilePath $Exe -ArgumentList @('--serve', "127.0.0.1:$Port", '--mitm', '--system-proxy', 'on', '--upstream', $Upstream) | Out-Null
  Start-Sleep -Seconds 7
  $during = Get-ItemProperty $Key
  Write-Output ("during: enable={0} server={1} pac={2}" -f $during.ProxyEnable, $during.ProxyServer, $during.AutoConfigURL)

  Start-Process -FilePath $Edge -ArgumentList @("--user-data-dir=$prof", '--no-first-run', '--no-default-browser-check', '--new-window', $Url) | Out-Null
  Start-Sleep -Seconds 12
  Add-Type -AssemblyName System.Windows.Forms

  $h = Get-TestWindow $prof
  if ($h -eq [System.IntPtr]::Zero) {
    Write-Output "the test profile did not come up with a window; not touching any other browser"
  } else {
    # Edge may have loaded the page from an earlier run's cache (the CSS/JS we
    # inject lives in the document, so a stale copy hides this run's rules).
    [WC]::ShowWindowAsync($h, 9) | Out-Null
    [WC]::SetForegroundWindow($h) | Out-Null
    Start-Sleep -Milliseconds 600
    [System.Windows.Forms.SendKeys]::SendWait('^{F5}')
    Start-Sleep -Seconds 8

    $r = New-Object RECT; [WC]::GetWindowRect($h, [ref]$r) | Out-Null
    [WC]::SetForegroundWindow($h) | Out-Null
    [WC]::SetCursorPos($r.L + [int](($r.R - $r.L) / 2), $r.T + 500) | Out-Null
    [WC]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero); [WC]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 500
    # Page Down scrolls a whole screen per press and lands on code blocks far
    # more reliably than wheel notches do.
    for ($i = 0; $i -lt $Notches; $i++) {
      [System.Windows.Forms.SendKeys]::SendWait('{PGDN}')
      Start-Sleep -Milliseconds 250
    }
    Start-Sleep -Seconds 2
  }
  $rect = Shot $h (Join-Path $root 'ui_shot_csdn_code.png')

  if ($ClickX -gt 0 -and $rect -and $h -ne [System.IntPtr]::Zero) {
    Set-Clipboard -Value 'netcap-clipboard-probe'
    [WC]::SetForegroundWindow($h) | Out-Null
    Start-Sleep -Milliseconds 400
    [WC]::SetCursorPos($rect.L + $ClickX, $rect.T + $ClickY) | Out-Null
    [WC]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero); [WC]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 1500
    $clip = (Get-Clipboard -Raw)
    if ($null -eq $clip) { $clip = '' }
    $clip = $clip.Trim()
    Write-Output ("clipboard after click: {0} chars, first line: {1}" -f $clip.Length, ($clip -split "`n")[0])
  }
}
finally {
  Stop-TestBrowser $prof
  Start-Process cmd -Verb RunAs -Wait -ArgumentList '/c','taskkill /F /IM netcap_ui.exe & taskkill /F /IM netcap.exe & exit 0' | Out-Null
  & $Core --system-proxy restore 2>&1 | Out-Null
  $after = Get-ItemProperty $Key
  Write-Output ("after:  enable={0} server={1} pac={2}" -f $after.ProxyEnable, $after.ProxyServer, $after.AutoConfigURL)
  $same = ($before.ProxyEnable -eq $after.ProxyEnable) -and ($before.ProxyServer -eq $after.ProxyServer) -and
          ($before.ProxyOverride -eq $after.ProxyOverride) -and ($before.AutoConfigURL -eq $after.AutoConfigURL)
  Write-Output ("proxy restored: {0}" -f $same)
  $code = (& curl.exe -s -o NUL -w '%{http_code}' --max-time 15 'http://example.com/')
  Write-Output ("connectivity: example.com -> {0}" -f $code)
  Remove-Item -Recurse -Force $prof -ErrorAction SilentlyContinue
}
