# Captures the graphical HTTPS filtering page.
# The UI opens that page by itself with --https-settings, so no input
# injection is needed (injected clicks are dropped for higher-integrity
# windows). Pure ASCII on purpose: Windows PowerShell 5.1 reads .ps1 as ANSI.
param(
  [string]$Out = 'D:\Demo\FilterTheWeb\ui_shot_https_page.png',
  [int]$WaitSeconds = 9
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Shot {
  [StructLayout(LayoutKind.Sequential)]
  public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
}
"@

$exe = 'D:\Demo\FilterTheWeb\ui\build\windows\x64\runner\Release\netcap_ui.exe'
$args = @('--rules', 'D:\Demo\FilterTheWeb\sample.rules', '--serve', '127.0.0.1:8096', '--ca', 'D:\Demo\FilterTheWeb\_mitmca', '--https-settings')
$p = Start-Process -FilePath $exe -ArgumentList $args -PassThru
Start-Sleep -Seconds $WaitSeconds

$h = $p.MainWindowHandle
if ($h -eq [IntPtr]::Zero) { $p.Refresh(); $h = $p.MainWindowHandle }
if ($h -eq [IntPtr]::Zero) { throw 'no main window' }

[void][Shot]::ShowWindowAsync($h, 9)
[Shot]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
[Shot]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
[void][Shot]::SetForegroundWindow($h)
Start-Sleep -Milliseconds 900

$r = New-Object Shot+RECT
[void][Shot]::GetWindowRect($h, [ref]$r)
$w = $r.Right - $r.Left
$hh = $r.Bottom - $r.Top
Write-Host "window $($r.Left),$($r.Top) ${w}x${hh}"

$bmp = New-Object System.Drawing.Bitmap($w, $hh)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object System.Drawing.Size($w, $hh)))
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "saved $Out bytes=$((Get-Item $Out).Length)"
[void]$p.CloseMainWindow()
Start-Sleep -Milliseconds 800
if (-not $p.HasExited) { $p.Kill() }
