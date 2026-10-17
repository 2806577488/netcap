# Proof that the packaged UI starts its proxy with the built-in filter list:
# no --rules is passed, the list must come from <exe dir>\rules\adblock.txt.
# ASCII only.  Prints the curl codes and saves a screenshot of the window.
param(
  [string]$Exe = 'D:\Demo\FilterTheWeb\ui\build\windows\x64\runner\Release\netcap_ui.exe',
  [int]$Port = 8119,
  [int]$WaitSeconds = 16,
  [string]$Shot = 'D:\Demo\FilterTheWeb\ui_shot_builtin_rules.png'
)

$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Drawing
if (-not ('Win' -as [type])) {
  Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Win {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint f);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, IntPtr e);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, IntPtr e);
}
'@
}

# Only our own instance is killed; the user's windows are left alone.
Get-Process netcap_ui, netcap -ErrorAction SilentlyContinue | ForEach-Object {
  if ($_.Path -like '*runner\Release*') { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
}

# The proxy is pre-set on the command line, so the app auto-starts it with the
# bundled list (no --rules, no browser, no system proxy change).
$proc = Start-Process -FilePath $Exe -PassThru -ArgumentList @("--serve", "127.0.0.1:$Port")
Write-Output "started netcap_ui.exe pid=$($proc.Id), waiting $WaitSeconds s"
Start-Sleep -Seconds $WaitSeconds

foreach ($url in @("http://ads.example.com/", "http://ad.doubleclick.net/", "http://example.com/")) {
  $code = & curl.exe -s -o NUL -w "%{http_code}" -x "http://127.0.0.1:$Port" $url
  Write-Output ("through the proxy: {0} -> {1}" -f $url, $code)
}
$listener = (netstat -ano | Select-String -Pattern ":$Port\s+0.0.0.0:0\s+LISTENING" | Select-Object -First 1)
Write-Output ("listening: {0}" -f [bool]$listener)

# Screenshot the window we started.
Start-Sleep -Seconds 2
$handle = (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue).MainWindowHandle
if ($handle -and $handle -ne 0) {
  [void][Win]::ShowWindowAsync($handle, 9)
  [Win]::keybd_event(0x12, 0, 0, [IntPtr]::Zero); [Win]::keybd_event(0x12, 0, 2, [IntPtr]::Zero)
  [void][Win]::SetForegroundWindow($handle)
  Start-Sleep -Milliseconds 700
  $r = New-Object Win+RECT
  [void][Win]::GetWindowRect($handle, [ref]$r)
  $w = $r.R - $r.L; $h = $r.B - $r.T
  $bmp = New-Object System.Drawing.Bitmap($w, $h)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($r.L, $r.T, 0, 0, (New-Object System.Drawing.Size($w, $h)))
  $g.Dispose()
  $bmp.Save($Shot, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
  Write-Output ("window {0},{1} {2}x{3}" -f $r.L, $r.T, $w, $h)
  Write-Output ("saved {0} bytes={1}" -f $Shot, (Get-Item $Shot).Length)
} else {
  Write-Output "no window handle for the instance we started"
}
