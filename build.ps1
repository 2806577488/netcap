#Requires -Version 5.1
<#
  netcap 的构建入口。做三件事，任何一步失败都以非零码退出：

    1. 编译（没有 CMakeCache.txt 时先自动跑一次 cmake 配置）；
    2. 跑 --selftest，要求 "all good"；条数比上次少会警告（有断言被删掉？）；
       注意自测在这台机器上要跑 100 秒左右（不是卡死），所以它有自己的超时
       -SelftestTimeoutSeconds（默认 300）；
    3. 把新编译出来的 netcap.exe 复制到界面可执行文件旁边
       （ui\build\windows\x64\runner\Release\netcap.exe）。

  为什么第 3 步必须在构建里做：界面找 netcap.exe 的顺序是
  NETCAP_EXE 环境变量 -> **可执行文件旁边那一份（打包副本）** -> 任一祖先目录下的
  netcap.exe / build\netcap.exe -> 当前目录 -> PATH（ui/lib/src/netcap.dart）。
  第二条永远赢过 build\netcap.exe，所以界面跑的一直是它旁边那份副本；不复制的话
  命令行是新二进制、界面是上次拷过去的旧二进制，同一个缺陷"在界面上修不好，
  在命令行里看不出来"（README「GUI 跑的是它旁边那份 netcap.exe」一节就是记这个）。

  界面正在运行时那个文件是锁着的。复制失败时脚本会明说，并且：
    - 在界面上按"停止"（或退出 netcap_ui.exe）后重跑；或者
    - .\build.ps1 -WaitSeconds 120  让它自己等（每秒试一次）。

.EXAMPLE
  .\build.ps1
.EXAMPLE
  .\build.ps1 -Reconfigure                    # 重新跑一次 cmake 配置
.EXAMPLE
  .\build.ps1 -WaitSeconds 120                # 界面还开着：等它停止后再复制
.EXAMPLE
  .\build.ps1 -SkipBuild -SkipSelftest        # 只重新复制一次
.EXAMPLE
  # README 里那套显式指定 MinGW/Ninja 的配方：
  .\build.ps1 -Reconfigure -ConfigureArgs '-DCMAKE_CXX_COMPILER="C:/ProgramData/mingw64/mingw64/bin/g++.exe"','-DCMAKE_MAKE_PROGRAM="D:/ninja/ninja.exe"'
#>
[CmdletBinding()]
param(
  # 构建目录（相对仓库根目录）
  [string] $BuildDir = 'build',
  # 传给 -DCMAKE_BUILD_TYPE（仅配置时使用）
  [string] $Config = 'Release',
  # 生成器（仅配置时使用）
  [string] $Generator = 'Ninja',
  # 额外的 cmake 配置参数，例如 -DCMAKE_CXX_COMPILER=...
  [string[]] $ConfigureArgs = @(),
  # 界面 Release 目录（里面那份 netcap.exe 就是界面实际启动的）
  [string] $UiDir = 'ui\build\windows\x64\runner\Release',
  # 即使已有 CMakeCache.txt 也重新跑一次 cmake 配置
  [switch] $Reconfigure,
  [switch] $SkipBuild,
  [switch] $SkipSelftest,
  # 不把 netcap.exe 复制到界面旁边
  [switch] $SkipUiCopy,
  # 目标文件被占用时最多等这么多秒（0 = 不等，直接报告）
  [int] $WaitSeconds = 0,
  # 自测条数必须正好等于这个数（0 = 不校验，只要求 all good）
  [int] $ExpectedChecks = 0,
  # 自测最多跑这么多秒（这台机器上实测约 100 秒；超过就杀掉并报 FAIL）
  [int] $SelftestTimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
$failed = $false

function Write-Step([string] $text) {
  Write-Host ''
  Write-Host "== $text" -ForegroundColor Cyan
}
function Write-Ok([string] $text)   { Write-Host "OK   $text" -ForegroundColor Green }
function Write-Warn([string] $text) { Write-Host "WARN $text" -ForegroundColor Yellow }
function Write-Bad([string] $text)  { Write-Host "FAIL $text" -ForegroundColor Red; $script:failed = $true }

# 两个文件是不是同一份。目标被界面独占时连读都读不了，这时返回 $null（＝不知道），
# 由调用方直接去尝试复制：别把一个"读不到"变成一串红色异常。
function Test-SameFile([string] $a, [string] $b) {
  try {
    $ha = (Get-FileHash -Path $a -Algorithm SHA256 -ErrorAction Stop).Hash
    $hb = (Get-FileHash -Path $b -Algorithm SHA256 -ErrorAction Stop).Hash
    return ($ha -eq $hb)
  } catch {
    return $null
  }
}

# --- 仓库根目录：脚本所在目录（这样从任何地方调用都对） ----------------------
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$exe = Join-Path $BuildDir 'netcap.exe'
if (-not (Test-Path $exe)) { $exe = Join-Path $BuildDir 'netcap' }   # 非 Windows

# --- 1. 配置 + 编译 ---------------------------------------------------------
if (-not $SkipBuild) {
  $cache = Join-Path $BuildDir 'CMakeCache.txt'
  $cmake = Get-Command cmake -ErrorAction SilentlyContinue
  if ($null -eq $cmake) {
    Write-Bad '找不到 cmake（PATH 里没有）'
    exit 1
  }

  if ($Reconfigure -or -not (Test-Path $cache)) {
    Write-Step "配置：cmake -S . -B $BuildDir -G $Generator -DCMAKE_BUILD_TYPE=$Config"
    $cfg = @('-S', '.', '-B', $BuildDir, '-G', $Generator, "-DCMAKE_BUILD_TYPE=$Config") + $ConfigureArgs
    & cmake @cfg
    if ($LASTEXITCODE -ne 0) { Write-Bad "cmake 配置失败（退出码 $LASTEXITCODE）"; exit 1 }
  } else {
    Write-Step "复用已有配置 $cache（要重配就加 -Reconfigure）"
  }

  Write-Step "编译：cmake --build $BuildDir"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  & cmake --build $BuildDir
  $code = $LASTEXITCODE
  $sw.Stop()
  if ($code -ne 0) { Write-Bad "编译失败（退出码 $code）"; exit 1 }
  Write-Ok ("编译通过 -- {0:n1} s" -f $sw.Elapsed.TotalSeconds)
}

if (-not (Test-Path $exe)) {
  Write-Bad "没有可执行文件：$exe"
  exit 1
}
$built = Get-Item $exe
Write-Ok ("产物 {0} -- {1:n0} 字节, {2}" -f $built.Name, $built.Length, $built.LastWriteTime)

# --- 2. 自测 ----------------------------------------------------------------
if (-not $SkipSelftest) {
  Write-Step "自测：$exe --selftest（这台机器上大约 100 秒）"
  $log = Join-Path $BuildDir 'selftest.log'

  # 拿这个退出码有三种写法，这台机器的 PowerShell 5.1 上只有一种能用：
  #   * `& $exe --selftest 2>&1 | Tee-Object ... | Select-Object -Last 3`
  #     -> $LASTEXITCODE 报过一次假的 1（日志里明明是 all good）；
  #   * `Start-Process -PassThru` + WaitForExit -> .ExitCode 永远是空的
  #     （实测连 `Start-Process cmd /c exit 7` 都读不到 7，Refresh() 也没用）；
  #   * 后台作业 -> 真退出码 + 真超时，两样都有。
  # 所以自测跑在作业里，用 Wait-Job 的超时把"卡死"和"就是慢"分开。
  # 作业在另一个 PowerShell 进程里、工作目录不是仓库根目录，所以路径要绝对。
  $exeFull = (Resolve-Path $exe).Path
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $job = Start-Job -ScriptBlock {
    param($exePath)
    $text = (& $exePath --selftest 2>&1 | Out-String)
    [pscustomobject]@{ code = $LASTEXITCODE; text = $text }
  } -ArgumentList $exeFull
  $finished = Wait-Job $job -Timeout $SelftestTimeoutSeconds
  $jobState = if ($finished) { 'Completed' } else { [string]$job.State }
  $r = $null
  if ($finished) {
    $r = Receive-Job $job -ErrorAction SilentlyContinue
    $jobState = [string]$job.State
    Remove-Job $job -Force -ErrorAction SilentlyContinue
  } else {
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
  }
  $sw.Stop()
  $code = if ($null -ne $r -and $null -ne $r.code) { $r.code } else { $null }
  $text = if ($null -ne $r) { [string]$r.text } else { '' }
  Set-Content -Path $log -Value $text -Encoding UTF8

  $count = 0
  $m = [regex]::Match($text, '(\d+)\s*/\s*(\d+)\s+checks passed')
  if ($m.Success) { $count = [int]$m.Groups[2].Value }

  $tail = Get-Content $log -Tail 3 -ErrorAction SilentlyContinue
  if ($tail) { $tail | ForEach-Object { Write-Host "     $_" } }

  if (-not $finished) {
    Write-Bad "自测超过 $SelftestTimeoutSeconds 秒还没结束（已经停掉，作业状态 $jobState）—— 确实卡住就查 $log，只是慢就加大 -SelftestTimeoutSeconds"
  } elseif ($null -eq $code) {
    Write-Bad "自测作业没有回报退出码（作业状态 $jobState）—— 见 $log"
  } elseif ($code -ne 0 -or $text -notmatch 'checks passed \(all good\)') {
    Write-Bad "自测没有全绿（退出码 $code）—— 完整输出在 $log"
  } else {
    Write-Ok ("自测全绿 -- {0}/{0}，{1:n1} s" -f $count, $sw.Elapsed.TotalSeconds)
  }

  # 条数只许涨不许跌：跌了说明有断言被顺手删掉了（本项目历史上全靠那个基准数）。
  # 只有自测真的跑完、真的报出条数时才看这件事：超时被停掉时条数是 0，
  # 那不是"断言被删了"，别报一个假的警告。
  $countFile = Join-Path $BuildDir '.selftest-count'
  $previous = 0
  if (Test-Path $countFile) {
    $raw = (Get-Content $countFile -Raw).Trim()
    if ($raw -match '^\d+$') { $previous = [int]$raw }
  }
  if ($count -gt 0) {
    if ($ExpectedChecks -gt 0 -and $count -ne $ExpectedChecks) {
      Write-Bad "自测条数 $count，期望 $ExpectedChecks"
    }
    if ($previous -gt 0 -and $count -lt $previous) {
      Write-Warn "自测条数从上次的 $previous 掉到 $count —— 有断言被删掉了？"
    } elseif ($previous -gt 0 -and $count -gt $previous) {
      Write-Ok "自测条数 $previous -> $count（新增了断言）"
    }
    if ($count -ne $previous) {
      Set-Content -Path $countFile -Value $count -Encoding ASCII
    }
  }
}

# --- 3. 把新二进制送到界面旁边 ---------------------------------------------
if (-not $SkipUiCopy) {
  Write-Step "界面副本：$UiDir\netcap.exe"
  if (-not (Test-Path $UiDir)) {
    Write-Warn "没有 $UiDir（界面还没构建过？）-- 跳过。界面构建后重跑本脚本即可"
  } else {
    $target = Join-Path $UiDir 'netcap.exe'
    if (Test-Path $target) {
      $old = Get-Item $target
      $same = Test-SameFile $exe $target
      if ($same -eq $true) {
        Write-Ok "已经是最新的（SHA256 相同，$($old.LastWriteTime)）"
      } elseif ($same -eq $false) {
        Write-Host ("     旧的：{0:n0} 字节, {1}" -f $old.Length, $old.LastWriteTime)
        Write-Host ("     新的：{0:n0} 字节, {1}" -f $built.Length, $built.LastWriteTime)
      } else {
        Write-Warn "读不到目标文件的哈希（界面正独占它？）-- 直接尝试复制"
      }
    }

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $copied = $false
    while (-not $copied) {
      try {
        Copy-Item -Path $exe -Destination $target -Force
        $copied = $true
      } catch {
        if ((Get-Date) -ge $deadline) {
          Write-Bad "复制失败（界面占着这个文件？）：$($_.Exception.Message)"
          Write-Host '     界面正在运行：在界面上按"停止"（或退出 netcap_ui.exe）后重跑本脚本，'
          Write-Host '     或者下次用 .\build.ps1 -WaitSeconds 120 让它自己等。'
          break
        }
        Write-Host '     目标被占用，等 1 秒再试（在界面上按"停止"就立刻能过）...'
        Start-Sleep -Seconds 1
      }
    }

    if ($copied) {
      $new = Get-Item $target
      $match = Test-SameFile $exe $target
      if ($match -eq $true) {
        Write-Ok ("界面旁边那份现在是 {0:n0} 字节, {1}（与 {2} 逐字节相同）" -f $new.Length, $new.LastWriteTime, $built.Name)
        Write-Host '     界面已经在跑的话，要在界面上按"停止"再按"开启"（或重启 netcap_ui.exe）才会用上它。'
      } else {
        Write-Bad '复制后 SHA256 不一致 —— 复制没有真正完成'
      }
    }
  }
}

# --- 收尾 -------------------------------------------------------------------
Write-Host ''
if ($failed) {
  Write-Host 'RESULT: FAIL' -ForegroundColor Red
  exit 1
}
Write-Host 'RESULT: PASS' -ForegroundColor Green
exit 0
