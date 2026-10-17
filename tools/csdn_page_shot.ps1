# Show what the CSDN page looks like *through* netcap: bounded system-proxy
# takeover (same rails as tools\ui_browser_accept.ps1), Edge opens the article,
# and the screen is captured twice -- top of page and after scrolling into the
# article -- so the removed promo blocks / login popup / "follow to read" gate
# are on the record.
#
#   pwsh -File tools\csdn_page_shot.ps1 [-Seconds 25]
param(
  [string]$Exe = 'D:\Demo\FilterTheWeb\ui\build\windows\x64\runner\Release\netcap_ui.exe',
  [string]$Url = 'https://blog.csdn.net/emellyduck/article/details/111030301',
  [int]$Port = 8293,
  [string]$Upstream = '127.0.0.1:7890',
  [int]$Seconds = 25
)
$ErrorActionPreference = 'Continue'
$root = 'D:\Demo\FilterTheWeb'
Set-Location $root
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

if (-not (Test-Path 'C:\Users\Czr\Desktop\netcap-restore.cmd')) { Write-Output 'REFUSING: no desktop restore script'; exit 1 }
$probe = New-Object System.Net.Sockets.TcpClient
if (-not $probe.ConnectAsync($Upstream.Split(':')[0], [int]$Upstream.Split(':')[1]).Wait(2000)) {
  Write-Output "REFUSING: upstream $Upstream does not answer"; exit 1
}
$probe.Close()
$before = Get-ItemProperty $key
Write-Output "before: enable=$($before.ProxyEnable) server=$($before.ProxyServer) pac=$($before.AutoConfigURL)"

Start-Process cmd -Verb RunAs -Wait -ArgumentList '/c','taskkill /F /IM netcap_ui.exe & taskkill /F /IM netcap.exe & exit 0' -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 700

# Note: adding -RedirectStandardOutput/-RedirectStandardError here makes
# Start-Process demand elevation ("The requested operation requires
# elevation"), so the interface is started plainly and the evidence is read off
# its own intercept table in the screenshot.
$ui = Start-Process -FilePath $Exe -ArgumentList @('--serve', "127.0.0.1:$Port", '--mitm', '--system-proxy', 'on', '--upstream', $Upstream) -PassThru
Start-Sleep -Seconds 8
$during = Get-ItemProperty $key
Write-Output "during: enable=$($during.ProxyEnable) server=$($during.ProxyServer) pac=$($during.AutoConfigURL)"

$profile = Join-Path $env:TEMP ('netcap-edge-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$edge = Start-Process -FilePath 'msedge.exe' -ArgumentList @("--user-data-dir=$profile", '--no-first-run', '--new-window', $Url) -PassThru
Start-Sleep -Seconds $Seconds

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# Only ever drive the browser we started ourselves: identify it by the throwaway
# profile in its command line.  Edge sometimes hands the URL to an already
# running instance and then --user-data-dir is ignored -- in that case the CSDN
# window on screen belongs to the user and this script must not touch it.
$testProc = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine.Contains($profile) -and $_.CommandLine -notlike '*--type=*' } |
            Select-Object -First 1
$testWin = [System.IntPtr]::Zero
if ($testProc) { $p = Get-Process -Id $testProc.ProcessId -ErrorAction SilentlyContinue; if ($p) { $testWin = $p.MainWindowHandle } }
if ($testWin -eq [System.IntPtr]::Zero) {
  Write-Output 'test browser did not come up on its own profile: no capture, no other window touched'
} else {
  $shell = New-Object -ComObject WScript.Shell
  $shell.AppActivate($testProc.ProcessId) | Out-Null
  Start-Sleep -Milliseconds 1500
}

function Capture([string]$path) {
  $bmp = New-Object System.Drawing.Bitmap(1920, 1080)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen(0, 0, 0, 0, $bmp.Size)
  $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  Write-Output ("captured {0} bytes -> {1}" -f (Get-Item $path).Length, $path)
}

if ($testWin -ne [System.IntPtr]::Zero) {
  Capture (Join-Path $root 'ui_shot_csdn_top.png')
  [System.Windows.Forms.SendKeys]::SendWait('{PGDN}{PGDN}{PGDN}{PGDN}{PGDN}{PGDN}')
  Start-Sleep -Milliseconds 1500
  Capture (Join-Path $root 'ui_shot_csdn_article.png')
}

# Close the browser instance this script started (and only that one).
Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -and $_.CommandLine.Contains($profile) } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Remove-Item -Recurse -Force $profile -ErrorAction SilentlyContinue
Get-Process netcap_ui, netcap -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800
& "$root\build\netcap.exe" --system-proxy restore 2>&1 | Select-Object -Last 1
Start-Sleep -Milliseconds 500
$after = Get-ItemProperty $key
$same = ($after.ProxyEnable -eq $before.ProxyEnable) -and ($after.ProxyServer -eq $before.ProxyServer) -and ($after.AutoConfigURL -eq $before.AutoConfigURL)
Write-Output "after:  enable=$($after.ProxyEnable) server=$($after.ProxyServer) pac=$($after.AutoConfigURL)"
Write-Output "proxy restored: $same"
Write-Output ("connectivity: example.com -> " + (& curl.exe -s -o NUL -w '%{http_code}' --max-time 20 http://example.com/))

# Proof that the page really travelled through the interface's proxy: the
# decisions it streamed on stdout (JSONL) name the article request.
# The interface is started without stdout redirection (adding one makes
# Start-Process demand elevation), so the decision evidence is its own intercept
# table in the screenshot rather than a log file.
$decisions = @()
Write-Output ("decisions mentioning blog.csdn.net: see the interface table in the screenshot (no log file is written)")
