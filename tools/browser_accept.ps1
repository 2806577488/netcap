# Browser level acceptance for the HTTPS man in the middle proxy.
#
# The user allowed a SHORT system proxy takeover (<= 20 seconds) for this, so the
# script is written to be over quickly and to put the machine back afterwards:
#   1. refuse to run when the desktop rescue script is missing
#   2. start netcap with --system-proxy on (it snapshots the previous settings)
#   3. drive Edge over two URLs and capture the screen
#   4. read the decisions, stop netcap (which restores by itself)
#   5. if anything is still taken over, run --system-proxy restore explicitly
#   6. verify the proxy values and the connectivity are back
param(
  [string]$Root = "D:\Demo\FilterTheWeb",
  [int]$Port = 8141,
  [string]$Upstream = "127.0.0.1:7890",
  [string]$Edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
)

$rescue = Join-Path $env:USERPROFILE "Desktop\netcap-restore.cmd"
if (-not (Test-Path $rescue)) { Write-Host "ABORT: $rescue is missing"; exit 1 }

$rules = Join-Path $Root "_browser.rules"
Set-Content -Path $rules -Value "||ads.example.com^`n||doubleclick.net^`n||googletagmanager.com^" -Encoding ASCII

$profile = Join-Path $Root "_edge2"
$out = Join-Path $Root "_acc.out"
$err = Join-Path $Root "_acc.err"
$state = Join-Path $Root "_acc.state"
Remove-Item -Force $out, $err, $state -ErrorAction SilentlyContinue

function Show-Proxy([string]$when) {
  $k = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  Write-Host ("proxy {0}: Enable={1} Server='{2}' AutoConfig='{3}'" -f $when, $k.ProxyEnable, $k.ProxyServer, $k.AutoConfigURL)
}

Add-Type -AssemblyName System.Drawing
function Shoot([string]$file) {
  $bmp = New-Object System.Drawing.Bitmap(1920, 1080)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen(0, 0, 0, 0, (New-Object System.Drawing.Size(1920, 1080)))
  $bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  Write-Host "saved $file bytes=$((Get-Item $file).Length)"
}

Show-Proxy "before"
$exe = Join-Path $Root "build\netcap.exe"
$netcap = Start-Process -FilePath $exe -WorkingDirectory $Root -PassThru -RedirectStandardOutput $out -RedirectStandardError $err -ArgumentList @(
  '--serve', "127.0.0.1:$Port", '--rules', $rules, '--ca', (Join-Path $Root "_mitmca"),
  '--mitm', '--upstream', $Upstream, '--system-proxy', 'on', '--system-proxy-state', $state, '--show-blocks')
Start-Sleep -Seconds 3
Show-Proxy "during"

function Browse([string]$url, [string]$shot, [int]$wait) {
  Start-Process -FilePath $Edge -ArgumentList @("--user-data-dir=$profile", "--no-first-run", "--no-default-browser-check", "--new-window", $url) | Out-Null
  Start-Sleep -Seconds $wait
  Shoot $shot
}

Browse "https://example.com/" (Join-Path $Root "ui_shot_browser_https.png") 8
Browse "http://ads.example.com/" (Join-Path $Root "ui_shot_browser_block.png") 6

Write-Host "--- netcap decisions ---"
Get-Content $out -Tail 12 -ErrorAction SilentlyContinue

Stop-Process -Id $netcap.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
Show-Proxy "after stop"
if ((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable -eq 1) {
  & $exe --system-proxy restore --system-proxy-state $state
  Show-Proxy "after restore"
}

Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" |
  Where-Object { $_.CommandLine -like "*_edge2*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Get-Process netcap, netcap_ui -ErrorAction SilentlyContinue | Select-Object Id, ProcessName | Format-Table -AutoSize | Out-String

Write-Host "--- connectivity ---"
foreach ($u in @("http://example.com/", "https://www.deepseek.com/")) {
  $code = & curl.exe -s -o NUL -w "%{http_code}" --max-time 20 $u
  Write-Host "$u -> $code"
}
Write-Host "--- netcap stderr ---"
Get-Content $err -Tail 6 -ErrorAction SilentlyContinue
