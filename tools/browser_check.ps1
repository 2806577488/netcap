param([int]$Port = 8121, [string]$Root = "D:\Demo\FilterTheWeb")
$ErrorActionPreference = "Continue"
$netcap = Join-Path $Root "build\netcap.exe"
$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if (-not (Test-Path $edge)) { $edge = "C:\Program Files\Microsoft\Edge\Application\msedge.exe" }
$profileDir = Join-Path $Root "_edgeprofile"
$log = Join-Path $Root "_browser_capture.out"

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

function Shoot([string]$url, [string]$file) {
  Write-Host "opening $url"
  Start-Process -FilePath $edge -ArgumentList "--user-data-dir=$profileDir", "--no-first-run",
      "--no-default-browser-check", "--window-size=1280,800", "--proxy-server=127.0.0.1:$Port", $url |
      Out-Null
  Start-Sleep -Seconds 9
  $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
  $bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  Write-Host ("saved {0} bytes={1}" -f $file, (Get-Item $file).Length)
  # Close only the instance we started, never the user's own Edge windows.
  Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" |
      Where-Object { $_.CommandLine -like "*_edgeprofile*" } |
      ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2
}

Write-Host "starting the proxy on 127.0.0.1:$Port"
Start-Process -FilePath $netcap -ArgumentList '--serve', "127.0.0.1:$Port", '--rules', '_browser.rules',
    '--ca', '_mitmca', '--mitm', '--upstream', '127.0.0.1:7890', '--show-blocks' `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru | Out-Null
Start-Sleep -Seconds 3

Shoot "https://ads.example.com/" (Join-Path $Root "ui_shot_browser_block.png")
Shoot "https://example.com/" (Join-Path $Root "ui_shot_browser_ok.png")

Write-Host "--- control: the same two URLs through the proxy with curl ---"
curl.exe -s -o NUL -w "curl plain=%{http_code} " -x "http://127.0.0.1:$Port" http://example.com/
curl.exe -s -o NUL -w "curl blocked=%{http_code}`n" -x "http://127.0.0.1:$Port" http://ads.example.com/
Get-Process netcap -ErrorAction SilentlyContinue | Select-Object Id, StartTime | Format-Table -AutoSize | Out-String
Write-Host "--- netcap decisions (read before the process is stopped) ---"
Get-Content $log -Tail 14 -ErrorAction SilentlyContinue

Get-Process netcap -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Write-Host "--- netcap stderr ---"
Get-Content "$log.err" -Tail 8 -ErrorAction SilentlyContinue
