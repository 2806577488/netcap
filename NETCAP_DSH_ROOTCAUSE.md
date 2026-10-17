# netcap × DSH 通信干扰 根因报告

调查对象：`D:\Demo\FilterTheWeb`（netcap 自研本地拦截代理）与 DSH Desktop（`C:\Users\Czr\AppData\Roaming\dsh-desktop`，模型流量经 billion-context / bili 本地代理 `127.0.0.1:18787`）
调查时间：2026-10-10 17:19Z–2026-10-10 18:23Z 区间的事故与历史日志
结论状态：**根因已定位，证据链闭合（4/4 次 502 全部对齐，含 2–4 ms 级配对）**

---

## 一、一句话结论

**netcap 用 `--system-proxy on` 接管 Windows 系统代理后，DSH 的模型流量被 bili 本地代理（billion-context）按"跟随系统代理"策略转发进了 netcap 的 MITM 通道；netcap 出示自签 `_mitmca` 证书，而 bili 代理的 Node.js fetch 默认不信任 Windows 根证书库，握手直接失败（`UNABLE_TO_VERIFY_LEAF_SIGNATURE`），bili 代理遂向 DSH 回一个 HTTP 502 —— 这就是用户看到的 `DeepSeek Messages request failed (502)`。**

netcap 没有发过这个 502，也没有主动杀任何进程；它只是"接管系统代理 + 解密 HTTPS"这两件事的组合，恰好命中了 bili 代理的上游解析逻辑与 Node 的证书信任模型。所谓"DSH 自己的波动"不成立：502 是被本地链路制造出来的，且在 netcap 还原系统代理后**秒级消失**。

### 机制链（6 步）

1. **netcap 接管系统代理**：`--system-proxy on` 写 `HKCU\...\Internet Settings`（ProxyEnable/ProxyServer = `127.0.0.1:857X`）并广播设置变更。探针 stderr 原文：`system proxy now 127.0.0.1:857X (was off, bypass 10.*;172.16-31.*;192.168.*;api.steampp.net;shop.api.steampp.net)`。
2. **bili 代理按连接解析 Windows 系统代理作为上游**（`dist/index.js` 内 `resolveProxy`）：
   ```js
   const systemValue = target?.protocol==="http:" ? system.http : system.https ?? system.http;
   const systemProxy = parseFallbackProxy(systemValue, fallback.biliPort)?.url;
   if (systemProxy) return { proxy: systemProxy, source: "windows-system", ... };
   return { source: "direct", ... };
   ```
   日志实证（10/8 即存在，说明是长期行为而非新增）：`[upstream-proxy] api.deepseek.com via http://<private-host>:8090/ (source=windows-system)`。
3. **模型流量改经 netcap**：事故窗口内每一轮请求前都出现
   `[upstream-proxy] api.deepseek.com via http://<private-host>:8571/ (source=windows-system)`（probe1 期间）
   `[upstream-proxy] api.deepseek.com via http://<private-host>:8573/ (source=windows-system)`（probe2 期间）。
   即 bili 代理**每连接**重新解析系统代理，netcap 一开一关它就跟着一开一关。
4. **netcap 对 `api.deepseek.com` 做 MITM**：netcap 无 deepseek 相关规则（`rules\` 全量 grep `deepseek` 零命中），但 `--mitm` 是"所有程序解密"模式，因此仍然出示 `_mitmca` 签发的叶证书。
5. **bili 代理拒绝该证书**：
   ```
   Error: upstream request failed: kind=tls code=UNABLE_TO_VERIFY_LEAF_SIGNATURE
   message=fetch failed <- unable to verify the first certificate; if the root CA is installed
   locally, try running Node.js with --use-system-ca
   url=https://api.deepseek.com/anthropic/v1/messages proxy=http://127.0.0.1:8573/
   hint=TLS/certificate failure at CONNECT or upstream handshake — CA/proxy MITM config
   ```
   netcap CA 已装入**用户 Windows 根库**，但 Node.js 默认只用自带 CA 列表（要 `--use-system-ca` / `NODE_EXTRA_CA_CERTS`）——错误信息自己就把这条修法写出来了。`classifyUpstreamFailure()` 把它归类为 `kind=tls`（`TRANSPORT_FAILURE_LABELS.tls = "TLS handshake failure"`）。
6. **bili 代理给 DSH 回错误响应（DSH 记为 502）**，DSH 侧落盘 `DeepSeek Messages request failed (502)`。DSH 代码（`app.asar` → `out/main/index.js`，grep 命中处）里 `(502)` 只会来自真实 HTTP 状态码：`\`DeepSeek Messages request failed (${status ?? "stream error"})\``。

---

## 二、证据时间线（UTC；本地 = UTC+8）

| 时刻 (UTC) | 本地 | netcap 系统代理 | bili 代理日志（`%TEMP%\bili-proxy-18787.log`） | DSH（`harness.log`） |
|---|---|---|---|---|
| 17:18:56–17:19:11 | 01:18–01:19 | **8080**（默认端口的另一次 netcap 运行） | `upstream request failed … proxy=http://127.0.0.1:8080/` ×6 | **17:19:11.238Z session-error 502**（错误行 17:19:11.235Z，**差 3 ms**） |
| 17:19:31→17:19:32 | 01:19 | 已还原 | `forward POST` 后 **无错误**、`[acp-usage] input=15078` 成功 | 恢复正常 |
| 17:40:04–17:40:49 | 01:40 | **8571**（probe1） | 17:40:24.148Z `via http://<private-host>:8571/ (source=windows-system)` → 连续 TLS 失败 | **17:40:47.643Z 502** |
| 17:40:49–17:41:45 | 01:41 | 还原 off | 17:41:14.097Z `forward POST` → 17:41:22.726Z `acp-usage` **成功** | 无错误 |
| 17:41:45–17:43:45 | 01:41:45 | **8573**（probe2） | 17:41:53.821Z `via http://<private-host>:8573/` → 17:41:53.889Z TLS 失败；此后每轮请求全失败 | **17:42:20.480Z 502**（错误 17:42:20.476Z，**差 4 ms**） |
| 17:43:00–17:43:08 | 01:43 | 8573 仍在 | 代理实例连续重启两次（banner 17:43:01.505Z / 17:43:08.421Z，"listening on http://127.0.0.1:18787"），DSH 侧对应 `native-attach: drop … (pid 37968): owner process gone` 17:43:00.673Z、`(pid 23312)` 17:43:07.624Z | — |
| 17:43:29 | 01:43 | 8573 | 17:43:29.469Z TLS 失败（`proxy=127.0.0.1:8573/`） | **17:43:29.471Z 502**（**差 2 ms**） |
| 17:43:45–17:43:59 | 01:43:45 | 还原 off | 17:43:50.900Z `[upstream-proxy] api.deepseek.com direct (source=direct)` → 17:43:59.783Z `acp-usage` 成功 | 此后全程无 502 |

**开关级相关性**：netcap 接管期间 100% 失败、还原后 100% 成功，窗口内 4 次 DSH 502 全部能在 bili 代理日志里找到 2–4 ms 之内的对应错误行；netcap 的 `_probe2.jsonl`（`--log-file` 全量）期间却只有 QQ 遥测拦截与一次 svchost 的 NCSI 错误，**没有任何 `api.deepseek.com` 条目**。

---

## 三、为什么 netcap 日志里"看不见"DSH 流量（关键排除项）

因为流量止步于 MITM 握手：bili 代理在收到 netcap 的叶证书后立即发送 TLS alert 并断开，**客户端从未完成握手、更没发出 HTTP 请求**。而 netcap 对"MITM 握手中途被客户端放弃"走的是**静默计数分支**（只累加 `mitm_preconnect`，不打日志、不记 jsonl，见 `README.md:1452`）。这解释了：

- 为什么 `_probe2.jsonl` 里看不到 deepseek（不是"DSH 没走 netcap"，而是"netcap 没来得及记"）；
- 为什么 `_probe_dsh.out` 为 0 字节；
- 为什么"原负责该项目的模型"会得出"是 DSH 自己的波动"——他只看了 netcap 的账本，而 netcap 在这个失败模式下**天生不记账**。

**注意**：这也意味着**不能**用"netcap 日志里没有 deepseek"来证明 netcap 无辜；判定因果必须靠上面 bili 代理侧的 `proxy=http://127.0.0.1:857X/` 与时间戳配对。

---

## 四、为什么表现为"特定情况"（触发条件）

同时满足以下全部条件时才会干扰：

1. netcap 处于**系统代理接管**模式（`--system-proxy on`；`--wfp`/`--tun`/仅 `--serve` 不碰系统代理时不影响 bili 上游）；
2. netcap 开了 **HTTPS 解密（`--mitm`）**（不开则 CONNECT 直通，无证书替换）；
3. 系统代理指向的端口**正在被 netcap 监听**（`127.0.0.1:8080` 是默认端口，探针用的 8571/8573 也一样）；
4. bili 代理上游路由**当时**重新解析了系统代理（每连接解析，所以接管后几秒内就开始中招）；
5. 该时刻 bili 代理进程活着（它本轮还出现过重启抖动，见下）。

反而与之无关的因素：模型、上下文大小、规则命中（deepseek 无任何规则）、DeepSeek 服务端（服务端在此期间收到的只是"没到达的请求"）。

---

## 五、责任归属

| 方 | 判定 | 说明 |
|---|---|---|
| **netcap** | **非恶意、非"主动干扰"**，但为触发方 | 接管系统代理 + 全程序 MITM 是其公开功能；对握手中断静默是设计选择（`README.md:1452`）。附带发现两个**真实缺陷**见第七节。 |
| **bili（billion-context）** | **主因方** | ①上游无差别跟随 Windows 系统代理，且对本机 MITM 零防护；②Node 未启用系统 CA 信任（错误信息自己给出了 `--use-system-ca` 修法）；③上游失败后未自动直连回退。 |
| **DSH** | 纯受害者/上报者 | `(502)` 来自真实 HTTP 状态码，仅是如实上报。 |
| **DeepSeek 服务端** | 无责 | 无任何证据表明服务端返回过 502；此前"服务端波动"的判断是把本地上游失败误读成了服务端故障。 |

---

## 六、规避与修复建议

**A. 立即可用（不改任何代码）**
1. 用 netcap 时**不要开系统代理接管**：改用 `--serve 127.0.0.1:8080`（只影响显式设了代理的程序）或 `--wfp` / `--tun` 链路，避免污染 WinINET。
2. 必须接管时，让 bili 代理信任 netcap CA（netcap CA 已在用户根库）：
   - 给 DSH 的 bili 代理进程设 `NODE_OPTIONS=--use-system-ca`，或
   - `NODE_EXTRA_CA_CERTS=<netcap 的 _mitmca.crt 路径>`。
   代价：模型流量会被 netcap 解密（本地明文可见）。
3. 若 bili 支持上游配置（`BILLION_CONTEXT_PROXY` / 上游代理设置），把上游**钉成直连**，不让它读 WinINET。

**B. 短期加固**
4. bili 侧：上游解析的结果加**健康探测 + 失败自动回退 direct**（现有 `recover()` 只负责"代理进程本身"，不覆盖"上游路由"）。
5. bili 侧：把 `UNABLE_TO_VERIFY_LEAF_SIGNATURE` 这类 `kind=tls` 失败在日志里升级为**带修复指引的单行告警**（现在只有 error 栈）。
6. netcap 侧：给"MITM 握手中断"的静默分支加一个可选调试开关（默认静默），便于下次自证；或对 `127.0.0.1` 上的客户端做识别并提示。

**C. 根本修复**
7. bili 侧（推荐）：检测到系统代理为**本机 MITM**（证书链由本地自签 CA 签发 / 上游 TLS 校验失败）时，**自动降级直连并记忆该决策**，即"上游跟随系统代理"要有兜底，而不是把失败直接抛给 DSH。
8. netcap 侧（若希望与其它"跟随系统代理"的程序长期共存）：接管时把 `*deepseek*` 等需要保真的域名加入**TLS 直通（不解密）白名单**，或至少在 `--mitm-only` 程序清单里不默认包含 DSH。

---

## 七、附带发现（同类但独立的问题）

1. **netcap 会对 Windows NCSI 探测回 502**（真缺陷）：
   `_probe2.jsonl` 里 `error GET http://ipv6.msftncsi.com/ncsi.txt (svchost.exe) detail="the origin closed before the response head was complete" → 502`，约 01:43:32。NCSI 是 Windows 判断"有没有网"的探测，回 502 可能让系统误判断网（进而影响其它联网程序）。建议：NCSI 域直连透传或按 204/200 放行。
2. **bili 代理在故障期间连续重启两次**：17:43:01.505Z、17:43:08.421Z 两次完整启动 banner，对应 DSH 侧 `native-attach: drop (pid 37968/23312): owner process gone`，最终由 pid 18736（本地 01:43:07 启动）存活至今。**很可能**是健康探测在上游 MITM 失败期间判死并触发了 respawn（`dsh-native.js` 有 `health probe failed` / `instance id mismatch` 分支，`REARM_LIMIT 16`）；这一环建议 bili 作者自查。
3. **bili 的更新/知识通道也同时失效**：`[update] dsh profile bundle check failed: TypeError: fetch failed`、`[advisory]/[release-notes] check failed`（17:19:10、17:43:20 等）——同一 MITM 原因，非独立故障。
4. 探针期间 netcap 的 QQ 遥测拦截（`otheve.beacon.qq.com`、`h.trace.qq.com` 各 18 次 → 403）完全正常，与 DSH 无关。

---

## 八、如何自行复现/验证（建议每次 ≤2 分钟，先确认急停钥匙在桌面）

急停钥匙：`C:\Users\Czr\Desktop\netcap-restore.cmd`（本次调查时已确认存在）。

```powershell
# 1) 启动 netcap 并接管系统代理（注意用默认端口 8080 复现用户原始现象）
D:\Demo\FilterTheWeb\build\netcap.exe --serve 127.0.0.1:8080 --rules rules\adblock.txt `
  --ca _mitmca --mitm --system-proxy on --upstream 127.0.0.1:7890 --log-file D:\Demo\FilterTheWeb\_verify.jsonl

# 2) 观察 bili 代理日志（应立刻出现 via http://<private-host>:8080/ (source=windows-system)
#    并紧跟 UNABLE_TO_VERIFY_LEAF_SIGNATURE）
Get-Content "$env:TEMP\bili-proxy-18787.log" -Tail 40

# 3) 停止并还原（或点桌面急停钥匙）
# 4) 还原后应看到 [upstream-proxy] api.deepseek.com direct (source=direct)，DSH 不再报 502
```

判定标准：**netcap 接管期间 `via http://<private-host>:8080/` + TLS 失败 + DSH 502；还原后 `direct` + 成功**。若想验证"证书信任修法"，可在 bili 代理进程上加 `NODE_OPTIONS=--use-system-ca` 后重跑：此时应不再出现 `UNABLE_TO_VERIFY_LEAF_SIGNATURE`（流量被解密但链路通）。

---

## 九、证据文件清单

| 文件 | 内容 |
|---|---|
| `C:\Users\Czr\AppData\Local\Temp\bili-proxy-18787.log` | **核心证据**。bili 代理全量日志（10/5–今日，~19.9 MB / 9.6 万行+）。含 `[upstream-proxy] … (source=windows-system/direct)`、`UNABLE_TO_VERIFY_LEAF_SIGNATURE` 错误栈、两次重启 banner、`hint=TLS/certificate failure … CA/proxy MITM config` |
| `C:\Users\Czr\AppData\Roaming\dsh-desktop\logs\harness.log` | DSH 侧 4× `DeepSeek Messages request failed (502)` 及其它 bili-native 事件 |
| `D:\Demo\FilterTheWeb\_probe_dsh.err` / `_probe2.err` | netcap 探针启动信息：`system proxy now 127.0.0.1:857X`、规则计数、上游 chaining |
| `D:\Demo\FilterTheWeb\_probe2.jsonl` | netcap 全量判定日志：仅 QQ 遥测 403 与一次 NCSI 502，**无 deepseek**（因 MITM 握手中断不记账） |
| `D:\Demo\FilterTheWeb\_probe_dsh.cmd` / `_probe2.cmd` | 两次探针的完整命令行（端口 8571 / 8573） |
| `C:\Users\Czr\AppData\Roaming\dsh-desktop\harness\profiles\.generations\live\billion-context+0.1.184+346cf0ba1bf4\node_modules\billion-context\dist\index.js` | bili 代理服务端：`resolveProxy`（windows-system 来源）、`classifyUpstreamFailure`、`TRANSPORT_FAILURE_LABELS`、tunnel 的 `502 Bad Gateway` 分支 |
| `C:\Users\Czr\Desktop\QQ20261011-012241.mp4`（帧在 `D:\Demo\FilterTheWeb\_vid\`） | 用户 01:22:41–01:23:32 录制的 netcap UI 系统代理状态画面（WinRT OCR 识别出"系统代理/代理设置/已开启/已停止"） |

**核对方式**：把上表第 1、2 两个日志按时间戳对齐，即可复现本报告第二节的整张时间线。

---

## 十、修复（netcap 侧，已落地并验证）

用户下达「你修一下」后，在 netcap 源码里补上了这一环（工作区 `D:\Demo\FilterTheWeb`，改动已编译）。

### 改动 1：拒签证书记忆 + 自动盲隧道（新增默认行为）

- `src/blocker.cpp` 新增 `is_client_refusal()`（识别 TLS 引擎的 alert 措辞）、`Impl::RefusalEntry`、`std::map<std::string, RefusalEntry> client_refusals`（键 = `程序名|主机名`，拿不到程序名归 `<unattributed>`）、`note_client_refusal()`、`mitm_retired()`、`prune_refusals_locked()`、`ca_identity()`。
- `handle_mitm()` 里 `server.accept()` 失败分支：**明确回 alert 的拒签一次即判定；只把 socket 丢掉的（Node.js 就是这种，不发 alert）在 120 秒内第二次判定**。判定那一刻记一条 `action=error` 事件并写明原因——这条日志正是本次调查里最缺的（原来走的是 `connection closed` 静默分支，`_probe2.jsonl` 里才一条 deepseek 都没有）。
- CONNECT 分支：判定过的「程序 + 主机名」改走**盲隧道**，事件记 `mitm="skip"`，`detail` 写明"该程序拒绝了 netcap 证书，为让它继续工作而不解密；内容过滤对它不再适用"。按**域名**的规则仍在此前生效（`block` 的 `CONNECT` 在解密之前判定，`_probe2.jsonl` 里 QQ 遥测 403 就是证据）。
- 记忆绑定 **CA 指纹**（`ca.cert.sha256_hex()`）：换 CA 后自动重试解密；netcap 重启清空；上限 512 条、判定窗口 120 秒；过期条目会清理。
- `BlockerStats` 增 `mitm_client_refusals`，文本报告（`report()`）与统计 JSON 都会给出。

### 改动 2：开关与文档

- 新增 `--mitm-strict`（`src/main.cpp` 解析 + `include/netcap/blocker.hpp` 的 `BlockerConfig::mitm_strict`）：永不因证书被拒改隧道，保持"就是连不上"的严格行为；此时 `connection closed` 仍按预连接静默处理。
- `README.md` 三处更新：「按应用开关」一节（标题加 `--mitm-strict`，正文写明自动放过、判定门槛、CA 指纹、误触发边界）、`--help` 参数块、以及「代理健壮性」一节新增**第三半**（把本报告的现象与这条记忆串起来）。

### 验证（三步，均已跑过）

1. **编译**：`& 'D:\ninja\ninja.exe' -C D:\Demo\FilterTheWeb\build` → `[4/4] Linking CXX executable netcap.exe`，退出码 0；`build\netcap.exe --help` 里能看到 `--mitm-strict`。
2. **端到端复现（不碰系统代理，最安全）**：`build\netcap.exe --serve 127.0.0.1:8581 --rules rules\adblock.txt --ca _mitmca --mitm --upstream 127.0.0.1:7890`，客户端用 Node（自带 CA 清单，与 DSH 的 undici 同类）经该代理 `CONNECT api.deepseek.com:443` 连打 8 次：
   - attempt 1–4：`UNABLE_TO_VERIFY_LEAF_SIGNATURE`（旧行为，每次都被掐断）；
   - 期间 netcap 记两条 `action=error … "the client dropped the TLS handshake twice for this host name without answering … tunnelled without decryption from now on so it keeps working"`（一条 `client_proc=node.exe`，一条是拿不到程序名的桶——**进程归属偶尔取不到**，所以按桶各自计两次，最多 4 次失败后收敛）；
   - attempt 5–8：**`TLS OK (TLS_AES_256_GCM_SHA384)`**，判定日志里 4 条 `action=tunnel … mitm=skip … "this application refused netcap's certificate for this host name (connection closed)"`。
   - 证据留在工作区：`_fix_probe.js`（客户端，Node）、`_fix_probe.jsonl`（最近一次运行的判定日志）、`_fix_probe.err`（启动信息）。**注：这一轮用了 Node 而不是 Python——CPython 在 Windows 上会把系统根证书库读进默认 context，反而信任 netcap 的 CA，复现不出拒签。**
3. **回归**：`build\netcap.exe --selftest` → **2438/2438 checks passed**（退出码 0），既有 MITM / 预连接 / 按应用开关用例全部照旧。

### 未改动、留给 owner 决策的一项

- **NCSI 502（§七.1）没有动**：要修就得在"上游真的失败"时**伪造** NCSI 应答（让 Windows 以为有网），或把 NCSI 域整体直连透传——两者都是行为决策而不是 bug 修复，等你的意见；本轮只做了 DSH 这一条因果链的修复。

### 部署提醒

- 修复后的二进制是 `D:\Demo\FilterTheWeb\build\netcap.exe`。**UI 打包目录 `ui\build\windows\x64\runner\Release\netcap.exe` 已在本轮重新构建时同步为同一份**（见 §十一.5）；安装目录 `C:\Program Files (x86)\netcap` 按你的决定**不动**（本轮核对：这台机器上该目录其实**并不存在**——CMake 的安装前缀是它，但从来没装过，所以不存在"旧二进制"的问题）。记忆是运行期状态：换新二进制后**重启一次 netcap** 即生效，DSH 侧无需任何改动。

---

## 十一、后续三项（用户 2026-10-11 的补充决定）

用户回复了第十节留下的三个问题：**走 UI 构建**；NCSI 那件事「顺带修日志：把空括号变成真实解析原因」，并且「如果本机有 IPV6（这个机器实际上有）的情况下对 IPV6 真实处理，没用的情况下下 绕过所有 IPV6 过滤」；selftest **补一个**；安装目录**先不动、只更新 UI 打包目录**。

### 1. 先把 NCSI 502 的原因查清（再动手）

- `ipv6.msftncsi.com` 是 CNAME → `a978.i6g1.akamai.net`，**只有 AAAA 记录**（`2600:140e:3:1b::b81c:7ab` / `:7b0`），没有任何 A 记录。
- 这台机器**没有可用的全局 IPv6 地址**：`Get-NetIPAddress -AddressFamily IPv6` 只有 `fe80::…`（cfw-tap / WLAN，全部 Deprecated）与 `::1`；直连那个 AAAA 地址得到 `[WinError 10051]`（网络不可达），而同一台机器直连 IPv4 正常。
- 于是 `getaddrinfo` 必然失败，而 Windows 的 `gai_strerrorA()` 对 `WSAHOST_NOT_FOUND` 返回**空串**，日志就成了 `cannot resolve ipv6.msftncsi.com ()`——括号里什么都没有，看起来像我们把网弄坏了；同一次运行里 `http://www.msftconnecttest.com/connecttest.txt` 经我们返回 `200 Microsoft Connect Test`（IPv4 侧完全正常）。
- 之前「直连 PowerShell 能拿到 200」是 **Clash 的 PAC**（`AutoConfigURL` 还在）造成的假象，不是本机 IPv6。

### 2. 改了什么

| 位置 | 改动 |
|---|---|
| `src/origin.cpp` | 新增 `origin_gai_text()`：把 `WSAHOST_NOT_FOUND` / `WSATRY_AGAIN` / `WSANO_RECOVERY` / `WSANO_DATA` 翻成人话，**永不返回空串**；新增 `machine_has_ipv6()`：枚举 up 接口上的全局单播 IPv6，排除 loopback / link-local / site-local / Deprecated；解析失败时在该理由后追加「this machine has no usable IPv6 address」 |
| `src/blocker.cpp` | `dial_direct()` 里只印数字码的旧文案（`cannot resolve X: 11001`）统一到 `origin_gai_text()` |
| `include/netcap/sysproxy.hpp` + `src/sysproxy.cpp` | 新增纯函数 `system_proxy_bypass_auto(base, machine_has_ipv6)`：有可用 IPv6 时原样返回操作者的并列表；没有时把 `ipv6.msftncsi.com` 追加进去（空列表先补 `<local>`，已存在则不再重复追加） |
| `src/main.cpp` | `--system-proxy on` 用这个纯函数构造 bypass，并在没有可用 IPv6 时打印一行说明 |

**状态码仍然是 502，这一点没改**：上游确实取不到东西，把失败伪装成 200 更不诚实；改的是**理由**，以及「这台机器没有 IPv6 时，那个只剩 AAAA 的探测不该由代理去失败」。有可用 IPv6 的机器上行为完全不变（`origin_resolve()` 本来就同时给出 A 与 AAAA，`OriginPicker` 会一起起跑）。

### 3. 验证

- **端到端（新二进制，`--serve 127.0.0.1:8585`，不碰系统代理）**：`error GET ipv6.msftncsi.com status=502 detail=cannot resolve ipv6.msftncsi.com (the name has no address record (WSAHOST_NOT_FOUND); this machine has no usable IPv6 address)`；同一次运行里 `www.msftconnecttest.com/connecttest.txt` 仍是 `200 Microsoft Connect Test`。真实 gai 码是 **11001**。证据：`_ncsi2.py` / `_ncsi2.jsonl` / `_ncsi2.err`。
- **单元断言（都不碰注册表）**：`test_origin()` 4 条（空串、11001、11004、未知码）、`test_sysproxy()` 5 条（有/无 IPv6、空列表、显式列表、重复追加）。
- **回归**：`build\netcap.exe --selftest` → **2467/2467 checks passed**，退出码 0（上一轮 2458，本轮新增 9 条）。
- **没有做的验证**：真正的 `--system-proxy on` 接管没有实跑。按 README 的安全规矩，动系统代理的实验需要你明确同意一次（`tools/browser_accept.ps1` 就是那种 ≤20 秒的演练）；这次只做了纯函数与端到端两部分。

### 4. 新增的 selftest 用例（验证第十节改动 1 的行为）

`src/selftest.cpp` 用例 11 + 11b（插在原用例 10 之前）：

- 一个只发 `CONNECT` 就断的客户端（`Talk::run(..., false)`，模拟 Node/undici 那种「不发 alert 就丢 socket」）连打两次：第一次判定数 `mitm_client_refusals` 为 0，第二次变成 1；第三次用正常隧道客户端连，拿到 `200 Connection Established` 与 `PONG`。
- 判定后的日志：一条 `action=error`（detail 写明该程序不信任 netcap 的证书），随后一条 `action=tunnel` + `mitm=skip`；`decrypted == 2`（被拒的那两次确实进过解密路径，也只有它们）。
- 11b：`BlockerConfig::mitm_strict = true` 时打三次，**既不会隧道、也没有任何 `mitm=skip` 事件**（严格模式就是保持连不上）。
- 为了让用例成立新增了自测钩子 `InterceptProxy::set_origin_tls_ability(host, port, ability)`（`ability` 为 -1 清除）：`handle_mitm()` 只在探测到上游 TLS 能力时才与客户端握手，而用例里的源站是纯 TCP。

### 5. UI 打包

- 按你的决定：**只更新 UI 打包目录**，`C:\Program Files (x86)\netcap` 不动。
- `README.md:205` 记的机制是：`flutter build windows --release` 的 POST_BUILD 会把仓库根的 `build/netcap.exe` 复制到 `netcap_ui.exe` 旁边。改完代码后重跑了这次构建（`cd ui; & 'D:\flutter\bin\flutter.bat' build windows --release`），两份二进制现在**完全一致**：

  - `build\netcap.exe` → 7,438,006 B，2026/10/16 12:57:39，SHA-256 前 16 位 `7221D9ADE375B274`
  - `ui\build\windows\x64\runner\Release\netcap.exe` → 7,438,006 B，2026/10/16 12:58:32，SHA-256 前 16 位 `7221D9ADE375B274`

- 反过来说：第一轮 `flutter build`（NCSI 改动落地前）复制进去的是**当时**的 `build\netcap.exe`，这就是为什么必须在这个改动之后再构建一次。记忆是运行期状态：换二进制后重启一次 netcap 即生效，DSH 侧无需任何改动。
