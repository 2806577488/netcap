# netcap HTTPS MITM performance against a loopback TLS 1.3 origin:
#   * browser-side handshake cost (CONNECT + netcap's own TLS 1.3 server stack)
#   * 8 MiB download through the MITM tunnel vs plain OpenSSL to the same origin
#   * response-rewrite cost and proxy request capacity
# Run:  powershell -NoProfile -ExecutionPolicy Bypass -File tools\perf_tls.ps1
param(
  [string]$Root = 'D:\Demo\FilterTheWeb',
  [string]$Python = 'D:\DSH Desktop\resources\office-runtime\primary-runtime\dependencies\python\python.exe'
)

$ErrorActionPreference = 'Continue'
$netcap = Join-Path $Root 'build\netcap.exe'
$tlsPort = 9443
$mitmPort = 8098
$proxyRewrite = 8095
$proxyCap = 8094

function Wait-Port([int]$Port, [int]$TimeoutMs = 15000) {
  $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
  while ((Get-Date) -lt $deadline) {
    try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', $Port); $c.Close(); return $true }
    catch { Start-Sleep -Milliseconds 100 }
  }
  return $false
}
function Say([string]$Text) { Write-Host $Text }

$exe = (Get-Command openssl -ErrorAction SilentlyContinue)
if (-not $exe) {
  $candidate = 'C:\Program Files\Git\usr\bin\openssl.exe'
  if (Test-Path $candidate) { $exe = @{ Source = $candidate } } else { Say 'openssl not found'; exit 1 }
}
$openssl = $exe.Source
Say ("openssl: " + (& $openssl version))

# ---- 0. clean orphans, build rule files ----
Start-Process -FilePath 'cmd.exe' -Verb RunAs -Wait -WindowStyle Hidden `
  -ArgumentList '/c', 'taskkill /F /IM netcap_ui.exe >nul 2>&1 & taskkill /F /IM netcap.exe >nul 2>&1 & exit 0' | Out-Null
Set-Content -Path (Join-Path $Root '_perf.rules') -Value @('! perf', '||ads.example^') -Encoding ASCII
Set-Content -Path (Join-Path $Root '_perf_rewrite.rules') `
  -Value @('! rewrite benchmark', '||127.0.0.1^$replace=/hello/BYE-HELLO/', '/page$replace=/tracker/TRACKER/') -Encoding ASCII

# ---- 1. HTTPS origin on loopback (netcap CA cert) + plain origin for the HTTP probes ----
$origin = Start-Process -FilePath $Python `
  -ArgumentList (Join-Path $Root 'tools\perf_origin.py'), $tlsPort, (Join-Path $Root '_mitmca.crt'), (Join-Path $Root '_mitmca.key') `
  -WindowStyle Hidden -PassThru
if (-not (Wait-Port $tlsPort)) { Say 'https origin did not start (certificate problem?)'; exit 1 }
$originPlain = Start-Process -FilePath $Python -ArgumentList (Join-Path $Root 'tools\perf_origin.py'), 9101 `
  -WindowStyle Hidden -PassThru
if (-not (Wait-Port 9101)) { Say 'plain origin did not start'; exit 1 }

# ---- 2. proxies ----
$pm = Start-Process -FilePath $netcap -ArgumentList '--serve', "127.0.0.1:$mitmPort", '--rules', (Join-Path $Root '_perf.rules'), `
  '--ca', (Join-Path $Root '_mitmca'), '--mitm', '--mitm-insecure' -WorkingDirectory $Root -WindowStyle Hidden -PassThru
$okM = Wait-Port $mitmPort
$pr = Start-Process -FilePath $netcap -ArgumentList '--serve', "127.0.0.1:$proxyRewrite", '--rules', (Join-Path $Root '_perf_rewrite.rules') `
  -WorkingDirectory $Root -WindowStyle Hidden -PassThru
$okR = Wait-Port $proxyRewrite
$pcap = Start-Process -FilePath $netcap -ArgumentList '--serve', "127.0.0.1:$proxyCap", '--rules', (Join-Path $Root '_perf.rules') `
  -WorkingDirectory $Root -WindowStyle Hidden -PassThru
$okC = Wait-Port $proxyCap
Say ([string]::Format('== listening: mitm {0} rewrite {1} capacity {2} ==', $okM, $okR, $okC))

# ---- 3. browser-side handshake (loopback, no internet in the path) ----
$hs = @()
for ($i = 0; $i -lt 10; $i++) {
  $ms = (Measure-Command { '' | & $openssl s_client -proxy "127.0.0.1:$mitmPort" -connect "127.0.0.1:$tlsPort" `
      -servername localhost -brief 2>$null | Out-Null }).TotalMilliseconds
  $hs += $ms
}
$sorted = $hs | Sort-Object
Say ([string]::Format('== MITM handshake (loopback, both TLS legs): median {0:N0} ms | min {1:N0} | max {2:N0} (n=10) ==',
  $sorted[[int]($sorted.Count / 2)], $sorted[0], $sorted[-1]))

# ---- 4. 8 MiB through the MITM tunnel vs plain openssl ----
$req = "GET /big HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n"
$reqFile = Join-Path $Root '_perf_req.txt'
[IO.File]::WriteAllText($reqFile, $req)
$outFile = Join-Path $Root '_perf_out.bin'

$t = (Measure-Command {
    cmd /c "`"$openssl`" s_client -quiet -proxy 127.0.0.1:$mitmPort -connect 127.0.0.1:$tlsPort -servername localhost -ign_eof < `"$reqFile`" > `"$outFile`" 2>nul"
  }).TotalSeconds
$mitmBytes = (Get-Item $outFile).Length
Say ([string]::Format('== MITM 8 MiB download: {0:N2} MiB in {1:N3} s = {2:N1} MiB/s ({3:N0} Mbit/s) ==',
  ($mitmBytes / 1MB), $t, ($mitmBytes / 1MB / $t), ($mitmBytes * 8 / 1e6 / $t)))

$t = (Measure-Command {
    cmd /c "`"$openssl`" s_client -quiet -connect 127.0.0.1:$tlsPort -servername localhost -ign_eof < `"$reqFile`" > `"$outFile`" 2>nul"
  }).TotalSeconds
$directBytes = (Get-Item $outFile).Length
Say ([string]::Format('== direct 8 MiB over TLS (stock OpenSSL both ends): {0:N2} MiB in {1:N3} s = {2:N1} MiB/s ({3:N0} Mbit/s) ==',
  ($directBytes / 1MB), $t, ($directBytes / 1MB / $t), ($directBytes * 8 / 1e6 / $t)))

# ---- 5. rewrite cost (HTTP, 84 KiB page) ----
$page = Join-Path $Root '_perf_page.txt'
$t = (Measure-Command {
    cmd /c "curl.exe -s -x http://127.0.0.1:$proxyRewrite http://127.0.0.1:9101/page -o `"$page`" 2>nul"
  }).TotalSeconds
if (Test-Path $page) {
  $pageLen = (Get-Item $page).Length
  $marker = (Select-String -Path $page -Pattern 'BYE-HELLO' -SimpleMatch -List) -ne $null
  Say ([string]::Format('== rewrite page: {0} bytes in {1:N3} s | replaced marker present: {2} ==', $pageLen, $t, $marker))
} else {
  Say '== rewrite page: curl produced nothing (origin 9101 was not running) =='
}

# ---- 6. capacity: 8 worker threads x 100 requests each ----
$script = @'
import http.client, sys, threading, time
port = int(sys.argv[1]); threads = 8; each = 100
errors = []
t0 = time.perf_counter()
def worker():
    for _ in range(each):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
            c.request("GET", "http://127.0.0.1:9101/tiny")
            c.getresponse().read(); c.close()
        except Exception as exc:
            errors.append(str(exc))
ts = [threading.Thread(target=worker) for _ in range(threads)]
[t.start() for t in ts]; [t.join() for t in ts]
dt = time.perf_counter() - t0
print("== capacity: %d requests over %d threads in %.2f s = %.0f req/s | failures %d ==" % (threads*each, threads, dt, threads*each/dt, len(errors)))
if errors: print("   first error: " + errors[0])
'@
$scriptPath = Join-Path $Root '_perf_cap.py'
Set-Content -Path $scriptPath -Value $script -Encoding ASCII
& $Python $scriptPath $proxyCap

# ---- 7. teardown ----
foreach ($p in @($pm, $pr, $pcap, $origin, $originPlain)) { if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
Start-Sleep -Milliseconds 300
Remove-Item -Force -ErrorAction SilentlyContinue $reqFile, $outFile, $page, $scriptPath, `
  (Join-Path $Root '_perf.rules'), (Join-Path $Root '_perf_rewrite.rules')
Say '== done =='
