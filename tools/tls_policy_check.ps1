# Verifies the two things the TLS coverage objective claims, end to end:
#   A. the version/suite matrix against a real TLS server (1.0, 1.1, 1.2;
#      RSA key exchange, ECDHE, CBC, GCM)
#   B. certificate policy: an origin whose certificate does not cover the name
#      is relayed blind by default (the page still loads, the event carries the
#      reason) and is decrypted when the user explicitly allows it
#      (--mitm-insecure); a self-signed but name-matching origin is decrypted
#      either way and the event records the warning
#
#   pwsh -File tools\tls_policy_check.ps1
#
# Everything is loopback: no system proxy, no routes, no registry.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root
$env:Path = 'C:\ProgramData\mingw64\mingw64\bin;' + $env:Path

function New-Cert([string]$crt, [string]$key, [string]$san) {
  & openssl req -x509 -newkey rsa:2048 -nodes -keyout $key -out $crt -days 3 -subj '/CN=127.0.0.1' -addext "subjectAltName=$san" 2>$null
}
# `_s12` matches the 127.0.0.1 name, `_bad` deliberately covers another name.
if (-not (Test-Path '_s12.crt')) { New-Cert '_s12.crt' '_s12.key' 'IP:127.0.0.1' }
if (-not (Test-Path '_bad.crt')) { New-Cert '_bad.crt' '_bad.key' 'DNS:not-this-host.example' }

function Stop-All {
  Get-Process netcap, netcap_ui, openssl -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 400
}

Write-Output '--- A. version / suite matrix vs openssl s_server ---'
$cases = @(
  @{ v = '1.2'; srv = '-tls1_2'; c = 'AES128-SHA@SECLEVEL=0' },
  @{ v = '1.1'; srv = '-tls1_1'; c = 'AES128-SHA@SECLEVEL=0' },
  @{ v = '1.0'; srv = '-tls1'; c = 'AES128-SHA@SECLEVEL=0' },
  @{ v = '1.2'; srv = '-tls1_2'; c = 'AES256-SHA@SECLEVEL=0' },
  @{ v = '1.2'; srv = '-tls1_2'; c = 'ECDHE-RSA-AES128-SHA256@SECLEVEL=0' },
  @{ v = '1.2'; srv = '-tls1_2'; c = 'ECDHE-RSA-AES128-GCM-SHA256' }
)
foreach ($case in $cases) {
  Stop-All
  $srv = Start-Process -FilePath 'openssl' -ArgumentList @('s_server', '-accept', '8890', $case.srv, '-cert', '_s12.crt', '-key', '_s12.key', '-cipher', $case.c, '-www', '-quiet') -PassThru -WindowStyle Hidden -RedirectStandardError '_s12.err' -RedirectStandardOutput '_s12.out'
  Start-Sleep -Milliseconds 900
  $text = (& .\tools\tls12_probe.exe 127.0.0.1 8890 $case.v 2>&1 | Out-String)
  Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue
  $verdict = if ($text -match 'handshake ok: ([^\r\n]+)') { $Matches[1].Trim() } elseif ($text -match 'handshake failed: ([^\r\n]+)') { 'FAILED: ' + $Matches[1].Trim() } else { 'NO OUTPUT' }
  $page = if ($text -match 'HTTP/1\.0 200') { 'page 200' } else { 'no page' }
  Write-Output ("{0,-4} {1,-36} {2} [{3}]" -f $case.v, $case.c, $verdict, $page)
}

Write-Output ''
Write-Output '--- B. certificate policy (page must load in every case) ---'
function Invoke-MitmCase([string]$label, [int]$port, [string[]]$extra, [string]$crt, [string]$key) {
  Stop-All
  $srv = Start-Process -FilePath 'openssl' -ArgumentList @('s_server', '-accept', '8893', '-tls1_2', '-cert', $crt, '-key', $key, '-www', '-quiet') -PassThru -WindowStyle Hidden -RedirectStandardError '_ss.err' -RedirectStandardOutput '_ss.out'
  Start-Sleep -Milliseconds 900
  $args = @('--serve', "127.0.0.1:$port", '--rules', 'sample.rules', '--ca', '_mitmca', '--mitm', '--show-blocks') + $extra
  $proxy = Start-Process -FilePath '.\build\netcap.exe' -ArgumentList $args -PassThru -WindowStyle Hidden -RedirectStandardError "_$label.err" -RedirectStandardOutput "_$label.out"
  Start-Sleep -Seconds 2
  [IO.File]::WriteAllText('_req.txt', "GET / HTTP/1.0`r`nHost: 127.0.0.1`r`n`r`n")
  $resp = (& cmd /c "openssl s_client -quiet -CAfile _mitmca.crt -proxy 127.0.0.1:$port -connect 127.0.0.1:8893 < _req.txt 2> _cl.err" | Out-String)
  Start-Sleep -Milliseconds 500
  Stop-Process -Id $proxy.Id -Force -ErrorAction SilentlyContinue
  Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue
  $status = if ($resp -match 'HTTP/1\.[01] (\d{3})') { $Matches[1] } else { 'no-status' }
  $event = ((Get-Content "_$label.out" -Encoding UTF8 -ErrorAction SilentlyContinue) | Select-Object -First 2) -join ' ;; '
  Write-Output ("{0,-22} status={1}  {2}" -f $label, $status, $event)
}

Invoke-MitmCase 'selfsigned-default' 8261 @() '_s12.crt' '_s12.key'
Invoke-MitmCase 'selfsigned-insecure' 8262 @('--mitm-insecure') '_s12.crt' '_s12.key'
Invoke-MitmCase 'wrongname-default' 8263 @() '_bad.crt' '_bad.key'
Invoke-MitmCase 'wrongname-insecure' 8264 @('--mitm-insecure') '_bad.crt' '_bad.key'
Stop-All
