# Screenshots the "系统接管 Takeover" block of the Flutter UI, including the new
# TUN session switches. Pure ASCII on purpose: Windows PowerShell 5.1 reads this
# file with the ANSI code page otherwise.
param(
  [string]$Exe = "D:\Demo\FilterTheWeb\ui\build\windows\x64\runner\Release\netcap_ui.exe",
  [string]$Rules = "D:\Demo\FilterTheWeb\sample.rules",
  [string]$Out = "D:\Demo\FilterTheWeb\ui_shot_takeover.png",
  [string]$Port = "127.0.0.1:8131",
  [int]$WaitSeconds = 12,
  [int]$WheelNotches = 0,
  [int]$WheelX = 1050,
  [int]$WheelY = 500,
  [int]$Width = 1500,
  [int]$Height = 1010
)

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, IntPtr extra);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, IntPtr extra);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
}
"@

$proc = Start-Process -FilePath $Exe -ArgumentList '--serve', $Port, '--rules', $Rules -PassThru
Start-Sleep -Seconds $WaitSeconds
$proc.Refresh()
$hwnd = $proc.MainWindowHandle
if ($hwnd -eq [IntPtr]::Zero) { Write-Host "no main window"; exit 1 }

[void][Win]::ShowWindowAsync($hwnd, 9)
Start-Sleep -Milliseconds 500
# The right hand pane is taller than a 720p window and its ListView does not
# react to injected wheel events here, so the window is grown by dragging its
# bottom right corner instead.
$r = New-Object Win+RECT
[void][Win]::GetWindowRect($hwnd, [ref]$r)
if ($Width -gt ($r.Right - $r.Left) -or $Height -gt ($r.Bottom - $r.Top)) {
  $edgeX = $r.Right - 4; $edgeY = $r.Bottom - 4
  $growX = $r.Left + $Width - $r.Right; $growY = $r.Top + $Height - $r.Bottom
  [void][Win]::SetCursorPos($edgeX, $edgeY)
  Start-Sleep -Milliseconds 250
  [Win]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 250
  for ($i = 1; $i -le 14; $i++) {
    [void][Win]::SetCursorPos($edgeX + [int]($growX * $i / 14), $edgeY + [int]($growY * $i / 14))
    Start-Sleep -Milliseconds 60
  }
  [Win]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 600
}
# Releasing an ALT press clears the foreground lock, otherwise the window stays
# in the background and the click/wheel events are dropped.
[Win]::keybd_event(0x12, 0, 0, [IntPtr]::Zero)
[Win]::keybd_event(0x12, 0, 2, [IntPtr]::Zero)
[void][Win]::SetForegroundWindow($hwnd)
Start-Sleep -Milliseconds 400

$r = New-Object Win+RECT
[void][Win]::GetWindowRect($hwnd, [ref]$r)
$w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
Write-Host "window $($r.Left),$($r.Top) ${w}x${h}"

if ($WheelNotches -gt 0) {
  [void][Win]::SetCursorPos($r.Left + $WheelX, $r.Top + $WheelY)
  Start-Sleep -Milliseconds 200
  $down = [uint32]4294967176   # -120 as an unsigned 32 bit value
  for ($i = 0; $i -lt $WheelNotches; $i++) {
    [Win]::mouse_event(0x0800, 0, 0, $down, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 120
  }
  Start-Sleep -Milliseconds 600
}

$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object System.Drawing.Size($w, $h)))
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "saved $Out bytes=$((Get-Item $Out).Length)"

$proc.CloseMainWindow() | Out-Null
Start-Sleep -Seconds 1
Get-Process netcap_ui -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $proc.Id } | Stop-Process -Force -ErrorAction SilentlyContinue
