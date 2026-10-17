# netcap performance run: interception proxy (plain + HTTPS MITM), rule cost,
# response rewriting, packet-analyzer throughput, memory footprint.
# Run:  powershell -NoProfile -ExecutionPolicy Bypass -File tools\perf_plain.ps1
param(
  [string]$Root = 'D:\Demo\FilterTheWeb',
  [string]$Python = 'D:\DSH Desktop\resources\office-runtime\primary-runtime\dependencies\python\python.exe'
)

$ErrorActionPreference = 'Continue'
$netcap = Join-Path $Root 'build\netcap.exe'
$originPort = 9101
$proxyRules = 8099
$proxyEmpty = 8097
$proxyRewrite = 8095
$proxyMitm = 8098

function Wait-Port([int]$Port, [int]$TimeoutMs = 10000) {
  $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
  while ((Get-Date) -lt $deadline) {
    try {
      $c = New-Object Net.Sockets.TcpClient
      $c.Connect('127.0.0.1', $Port)
      $c.Close()
      return $true
    } catch { Start-Sleep -Milliseconds 100 }
  }
  return $false
}

function Say([string]$Text) { Write-Host $Text }

# ---- 0. no orphans (they hold the ports and hide the fresh instance) ----
Start-Process -FilePath 'cmd.exe' -Verb RunAs -Wait -WindowStyle Hidden `
  -ArgumentList '/c', 'taskkill /F /IM netcap_ui.exe >nul 2>&1 & taskkill /F /IM netcap.exe >nul 2>&1 & exit 0' | Out-Null
Start-Sleep -Milliseconds 400

# ---- 1. rule files ----
$rules = New-Object System.Collections.Generic.List[string]
$rules.Add('! netcap performance rule set')
for ($i = 0; $i -lt 5000; $i++) { $rules.Add("||ads$i.example^") }
for ($i = 0; $i -lt 200; $i++) { $rules.Add("/banner$i.gif/") }
Set-Content -Path (Join-Path $Root '_perf.rules') -Value $rules -Encoding ASCII
Set-Content -Path (Join-Path $Root '_perf_empty.rules') -Value '! empty' -Encoding ASCII
Set-Content -Path (Join-Path $Root '_perf_rewrite.rules') -Value @('! rewrite benchmark', '$replace=/hello/BYE-HELLO/') -Encoding ASCII
$ruleBytes = (Get-Item (Join-Path $Root '_perf.rules')).Length
$ruleLines = $rules.Count

# ---- 2. origin ----
$origin = Start-Process -FilePath $Python -ArgumentList (Join-Path $Root 'tools\perf_origin.py'), $originPort `
  -WindowStyle Hidden -PassThru
if (-not (Wait-Port $originPort)) { Say 'origin did not start'; exit 1 }

# ---- 3. proxies ----
$t0 = Get-Date
$pa = Start-Process -FilePath $netcap -ArgumentList '--serve', "127.0.0.1:$proxyRules", '--rules', (Join-Path $Root '_perf.rules') `
  -WorkingDirectory $Root -WindowStyle Hidden -PassThru
$okA = Wait-Port $proxyRules
$startA = ((Get-Date) - $t0).TotalMilliseconds

$t0 = Get-Date
$pb = Start-Process -FilePath $netcap -ArgumentList '--serve', "127.0.0.1:$proxyEmpty", '--rules', (Join-Path $Root '_perf_empty.rules') `
  -WorkingDirectory $Root -WindowStyle Hidden -PassThru
$okB = Wait-Port $proxyEmpty
$startB = ((Get-Date) - $t0).TotalMilliseconds

$pc = Start-Process -FilePath $netcap -ArgumentList '--serve', "127.0.0.1:$proxyRewrite", '--rules', (Join-Path $Root '_perf_rewrite.rules') `
  -WorkingDirectory $Root -WindowStyle Hidden -PassThru
$okC = Wait-Port $proxyRewrite

Start-Sleep -Milliseconds 500
$memIdle = (Get-Process -Id $pa.Id).WorkingSet64 / 1MB
$privIdle = (Get-Process -Id $pa.Id).PrivateMemorySize64 / 1MB

Say ([string]::Format('== proxy startup: {0} rules ({1:N1} KiB) {2:N0} ms | 1 rule {3:N0} ms | listening {4}/{5}/{6} ==',
  $ruleLines, ($ruleBytes / 1KB), $startA, $startB, $okA, $okB, $okC))

# ---- 4. latency + throughput ----
& $Python (Join-Path $Root 'tools\perf_bench.py') $proxyRules $proxyEmpty $proxyRewrite

$proc = Get-Process -Id $pa.Id
$memLoad = $proc.WorkingSet64 / 1MB
$cpuA = $proc.TotalProcessorTime.TotalSeconds
Say ([string]::Format('== proxy footprint: working set {0:N1} MiB idle -> {1:N1} MiB after ({2:N1} MiB private), cpu {3:N2} s ==',
  $memIdle, $memLoad, $privIdle, $cpuA))

# ---- 5. HTTPS MITM: handshake and a real page ----
$pm = Start-Process -FilePath $netcap -ArgumentList '--serve', "127.0.0.1:$proxyMitm", '--rules', (Join-Path $Root '_perf.rules'), `
  '--ca', (Join-Path $Root '_mitmca'), '--mitm', '--mitm-insecure' -WorkingDirectory $Root -WindowStyle Hidden -PassThru
$okM = Wait-Port $proxyMitm
Say ([string]::Format('== MITM proxy listening: {0} ==', $okM))

$openssl = (Get-Command openssl -ErrorAction SilentlyContinue)
if (-not $openssl) {
  $candidate = 'C:\Program Files\Git\usr\bin\openssl.exe'
  if (Test-Path $candidate) { $openssl = @{ Source = $candidate } }
}
if ($openssl -and $okM) {
  $exe = $openssl.Source
  $handshakes = @()
  for ($i = 0; $i -lt 5; $i++) {
    $ms = (Measure-Command { '' | & $exe s_client -proxy "127.0.0.1:$proxyMitm" -connect example.com:443 `
        -servername example.com -brief 2>$null | Out-Null }).TotalMilliseconds
    $handshakes += $ms
  }
  $sorted = $handshakes | Sort-Object
  Say ([string]::Format('== MITM TLS 1.3 handshake (browser side + client side to origin): median {0:N0} ms, min {1:N0}, max {2:N0} (n=5) ==',
    $sorted[[int]($sorted.Count / 2)], $sorted[0], $sorted[-1]))

  $req = "GET / HTTP/1.1`r`nHost: example.com`r`nConnection: close`r`n`r`n"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $out = ($req | & $exe s_client -quiet -proxy "127.0.0.1:$proxyMitm" -connect example.com:443 `
      -servername example.com -ign_eof 2>$null) -join "`n"
  $sw.Stop()
  $status = ($out -split "`n" | Where-Object { $_ -match '^HTTP/' } | Select-Object -First 1)
  Say ([string]::Format('== MITM full HTTPS GET example.com: {0:N0} ms, {1} bytes of plaintext, status [{2}] ==',
    $sw.Elapsed.TotalMilliseconds, $out.Length, $status))
} else {
  Say '== openssl not found: skipped the MITM timing =='
}

# ---- 6. packet analyzer throughput ----
$sample = [IO.File]::ReadAllBytes((Join-Path $Root 'sample.pcap'))
$hdr = $sample[0..23]
$body = $sample[24..($sample.Length - 1)]
$bigPath = Join-Path $Root '_perf_big.pcap'
$fs = [IO.File]::Create($bigPath)
$fs.Write($hdr, 0, 24)
for ($i = 0; $i -lt 2000; $i++) { $fs.Write($body, 0, $body.Length) }
$fs.Close()
$bigMiB = (Get-Item $bigPath).Length / 1MB

$pkts = (& $netcap -r $bigPath -q --stats 2>&1 | Select-String -Pattern 'packets seen' | Select-Object -First 1)
$tParse = (Measure-Command { & $netcap -r $bigPath -q | Out-Null }).TotalSeconds
$tFlow = (Measure-Command { & $netcap -r $bigPath --streams --http -q | Out-Null }).TotalSeconds
$tTls = (Measure-Command { & $netcap -r $bigPath --streams --http --keylog (Join-Path $Root 'sample.keys') -q | Out-Null }).TotalSeconds
$tSelf = (Measure-Command { & $netcap --selftest | Out-Null }).TotalSeconds
$tDevices = (Measure-Command { & $netcap -d -q | Out-Null }).TotalSeconds
Say ([string]::Format('== analyzer on {0:N1} MiB / {1} : parse {2:N2} s ({3:N0} MiB/s) | +flows+HTTP {4:N2} s ({5:N0} MiB/s) | +TLS decrypt {6:N2} s | --selftest {7:N2} s | -d {8:N0} ms ==',
  $bigMiB, $pkts, $tParse, ($bigMiB / $tParse), $tFlow, ($bigMiB / $tFlow), $tTls, $tSelf, ($tDevices * 1000)))

# ---- 7. teardown ----
foreach ($p in @($pa, $pb, $pc, $pm, $origin)) { if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
Start-Sleep -Milliseconds 300
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Root '_perf_big.pcap'), (Join-Path $Root '_perf.rules'), `
  (Join-Path $Root '_perf_empty.rules'), (Join-Path $Root '_perf_rewrite.rules')
Say '== done =='
