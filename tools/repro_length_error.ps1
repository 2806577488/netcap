# Reproduction harness for the "cannot create std::vector larger than max_size()"
# crash: a short, guarded system-proxy takeover plus a real browser.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\repro_length_error.ps1 [-Seconds 35]
#
# Safety: refuses to run unless the desktop rescue script is present, always
# restores the system proxy afterwards (explicitly, even though the proxy also
# restores on exit), then prints the registry state and two connectivity checks.

param(
  [int] $Port = 8161,
  [int] $Seconds = 35,
  [string] $Repo = 'D:\Demo\FilterTheWeb',
  [string] $Edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
)

$ErrorActionPreference = 'Stop'
$rescue = Join-Path $env:USERPROFILE 'Desktop\netcap-restore.cmd'
if (-not (Test-Path $rescue)) { Write-Host "ABORT: $rescue is missing"; exit 1 }
if ($Seconds -gt 60) { Write-Host 'ABORT: keep the takeover short'; exit 1 }

function Get-ProxyState {
  $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  $p = Get-ItemProperty -Path $k
  "Enable={0} Server='{1}' AutoConfig='{2}'" -f $p.ProxyEnable, $p.ProxyServer, $p.AutoConfigURL
}

Set-Location $Repo
Remove-Item '_repro.out', '_repro.err', '_repro.state' -ErrorAction SilentlyContinue
Set-Content -Path '_probe.rules' -Value "||ads.example.com^" -Encoding ASCII

Write-Host "system proxy BEFORE: $(Get-ProxyState)"
$p = Start-Process -FilePath .\build\netcap.exe -PassThru `
  -RedirectStandardOutput _repro.out -RedirectStandardError _repro.err `
  -ArgumentList @('--serve', "127.0.0.1:$Port", '--rules', '_probe.rules', '--ca', '_mitmca',
                  '--mitm', '--upstream', '127.0.0.1:7890', '--system-proxy', 'on',
                  '--system-proxy-force', '--system-proxy-state', '_repro.state', '--show-blocks')
Start-Sleep -Seconds 4
Write-Host "system proxy DURING: $(Get-ProxyState)"
if (-not (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) {
  Write-Host 'the proxy exited early; stderr:'
  Get-Content _repro.err -Tail 12 -ErrorAction SilentlyContinue
  exit 1
}

$profile = Join-Path $Repo '_edge5'
$urls = @('https://example.com/', 'http://ads.example.com/', 'https://example.com/s.js')
foreach ($url in $urls) {
  Write-Host "opening $url"
  Start-Process $Edge -ArgumentList @("--user-data-dir=$profile", '--no-first-run',
    '--no-default-browser-check', '--new-window', $url) | Out-Null
  Start-Sleep -Seconds 5
}
$deadline = (Get-Date).AddSeconds($Seconds)
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 2
  Start-Process $Edge -ArgumentList @("--user-data-dir=$profile", '--no-first-run',
    '--no-default-browser-check', '--new-window', 'https://example.com/') | Out-Null
}

Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" |
  Where-Object { $_.CommandLine -like "*$profile*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
.\build\netcap.exe --system-proxy restore --system-proxy-state _repro.state
Write-Host "system proxy AFTER:  $(Get-ProxyState)"

Write-Host '--- dropped connections (stage + target) ---'
Select-String -Path _repro.err -Pattern 'dropping the connection' | ForEach-Object { $_.Line }
Write-Host '--- proxy decisions (tail) ---'
Get-Content _repro.out -Tail 10 -ErrorAction SilentlyContinue
Write-Host '--- connectivity ---'
"http://example.com/ -> " + (try { (Invoke-WebRequest -Uri 'http://example.com/' -UseBasicParsing -TimeoutSec 8).StatusCode } catch { 'ERR' })
"https://www.deepseek.com/ -> " + (try { (Invoke-WebRequest -Uri 'https://www.deepseek.com/' -UseBasicParsing -TimeoutSec 8).StatusCode } catch { 'ERR' })
"alive netcap: " + ((Get-Process netcap -ErrorAction SilentlyContinue) | Measure-Object).Count
"rescue script: " + (Test-Path $rescue)
