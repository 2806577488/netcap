/// Process layer: locate `netcap.exe`, run it, and decode its JSON Lines
/// stream. The UI never links the C++ code, it drives the same executable the
/// command line uses, so behaviour and bugs are shared on purpose.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'models.dart';
import 'mitm_apps.dart';

/// Everything the UI can ask netcap to do, grouped so the argument builder is
/// the single place that knows the command line syntax.
class NetcapRequest {
  NetcapRequest({
    this.mode = SourceMode.file,
    this.path = '',
    this.device = '',
    this.filter = '',
    this.snaplen = 262144,
    this.limit = 0,
    this.hexPayload = false,
    this.hexFrame = false,
    this.promisc = false,
    this.nanosecond = false,
    this.exportPath = '',
    this.keylog = '',
    this.streams = false,
    this.http = false,
    this.follow = false,
    this.attrib = false,
    this.noAttrib = false,
    this.splitBy = '',
    this.blockFilter = '',
    this.blockMode = 'dry-run',
    this.blockMax = 32,
    this.rulesPath = '',
    this.userRules = '',
    this.extraRules = const <String>[],
    this.picker = false,
    this.pickerFlag = '',
    this.pickerRules = '',
    this.logFile = '',
    this.serve = '127.0.0.1:8080',
    this.thirdPartyCookies = false,
    this.showBlocks = false,
    this.mitm = false,
    this.mitmSkip = '',
    this.mitmOnly = '',
    this.caPrefix = '',
    this.systemProxy = false,
    this.systemProxyBypass = '',
    this.systemProxyForce = false,
    this.upstream = '',
    this.tun = false,
    this.tunTakeover = false,
    this.tunAdapter = '',
  });

  final SourceMode mode;
  final String path;
  final String device;
  final String filter;
  final int snaplen;
  final int limit; // 0 = unlimited
  final bool hexPayload;
  final bool hexFrame;
  final bool promisc;
  final bool nanosecond;
  final String exportPath;

  /// The rule list the proxy filters with (`--rules`), and where it listens
  /// (`--serve`). Only used in [SourceMode.proxy].
  final String rulesPath;
  final String serve;

  /// The user's own rules (`--rules-extra`): a small file the rules page edits.
  /// It is stacked on top of [rulesPath], so adding or removing one rule never
  /// means touching the bundled list (an update would replace that anyway).
  final String userRules;

  /// More filter lists (`--rules-extra`, repeatable).  The rules page hands in
  /// every list the user switched on, so a list is never typed as a raw path.
  final List<String> extraRules;

  /// Element picker (`--picker`): inject the picker script into documents so a
  /// click on the page appends a hiding rule.  [pickerFlag] is the file whose
  /// existence means "picking is on" — a running proxy polls it, which is how
  /// the switch in the rules page takes effect without a restart.
  final bool picker;
  final String pickerFlag;

  /// Where a pick appends its rule (the user's own list).
  final String pickerRules;

  /// The durable decision log (`--log-file`): every decision the proxy made, one
  /// JSON object per line, flushed as it happens.  Empty means "do not write
  /// one".  It is written by the proxy process itself, so the log keeps growing
  /// while the page that shows it is closed.
  final String logFile;

  /// Strip the Cookie header from third-party requests (`--third-party-cookies`).
  final bool thirdPartyCookies;

  /// Log decisions that changed nothing too (`--show-blocks`).
  final bool showBlocks;

  /// Decrypt HTTPS with the local CA (`--mitm`), leaving the listed applications
  /// alone (`--mitm-skip`) or decrypting only those (`--mitm-only`). The CA is
  /// read from `<caPrefix>.crt` / `<caPrefix>.key` (`--ca`).
  final bool mitm;
  final String mitmSkip;
  final String mitmOnly;
  final String caPrefix;

  /// Point this user's system proxy at the interception proxy for as long as it
  /// runs (`--system-proxy on`). netcap writes a snapshot of the four registry
  /// values first and puts them back on exit; a takeover with no reachable
  /// upstream is refused unless [systemProxyForce] is set. Only meaningful in
  /// [SourceMode.proxy] — the switch is applied by the process that serves.
  final bool systemProxy;
  final String systemProxyBypass;
  final bool systemProxyForce;

  /// The hop to chain every upstream connection through (`--upstream`). Required
  /// by a takeover: the tunnel steals the default route, so netcap needs to know
  /// where traffic should leave the machine from.
  final String upstream;

  /// Take the whole machine's traffic through a Wintun adapter (`--tun`), and
  /// own the default routes while this process runs (`--tun --tun-takeover`).
  /// [tunAdapter] names the adapter to create or reuse (`--tun-adapter`).
  final bool tun;
  final bool tunTakeover;
  final String tunAdapter;

  /// SSLKEYLOGFILE for TLS decryption (`--keylog`); empty means no decryption.
  final String keylog;

  /// Emit the final TCP stream report (`--streams`).
  final bool streams;

  /// Emit HTTP transactions (`--http`, or `--follow` while capturing).
  final bool http;

  /// Report each HTTP transaction as it completes instead of at the end
  /// (`--follow`). A live capture has no summary, so this is its only outlet.
  final bool follow;

  /// Resolve which process sent each packet (`--attrib`). On by default for a
  /// live capture; for a replayed file it needs this flag.
  final bool attrib;

  /// Never look at the OS endpoint tables (`--no-attrib`).
  final bool noAttrib;

  /// One pcap per process / application (`--split-by`); needs [exportPath] to
  /// be a directory.
  final String splitBy;

  /// Intercept matching traffic (`--block`). Empty means no interception at
  /// all, which is the only safe default.
  final String blockFilter;

  /// `dry-run` (default) / `cut` / `kill` / `both` (`--block-mode`).
  final String blockMode;

  /// Action cap (`--block-max`).
  final int blockMax;

  List<String> toArgs() {
    final a = <String>['--jsonl'];
    if (mode == SourceMode.proxy) {
      // The interception proxy is a program of its own: it does not read a pcap
      // and does not open a capture device, so capture options are left out.
      if (rulesPath.trim().isNotEmpty) a.addAll(['--rules', rulesPath.trim()]);
      // The user's own rules are a second file on top of the list: the engine
      // stacks them, so a rule the user adds can also *unblock* something the
      // built-in list blocks (`@@…`) or un-hide an element (`#@#…`).
      if (userRules.trim().isNotEmpty) {
        a.addAll(['--rules-extra', userRules.trim()]);
      }
      for (final extra in extraRules) {
        if (extra.trim().isNotEmpty && extra.trim() != userRules.trim()) {
          a.addAll(['--rules-extra', extra.trim()]);
        }
      }
      // Element picker: a pick has to be kept somewhere, so it is only offered
      // when there is a list to append to.
      if (picker && pickerRules.trim().isNotEmpty) {
        a.add('--picker');
        a.addAll(['--picker-rules', pickerRules.trim()]);
        if (pickerFlag.trim().isNotEmpty) a.addAll(['--picker-flag', pickerFlag.trim()]);
      }
      // --log-file: the durable record the log page reads.  It is written by the
      // proxy process, so closing the page does not stop the history.
      if (logFile.trim().isNotEmpty) {
        a.addAll(['--log-file', logFile.trim()]);
      }
      // --tun also returns without serving (the adapter is brought up, then the
      // process waits on the tunnel), so the listen address is left out whenever
      // the tunnel is in play.
      if (!(tun || tunTakeover)) {
        a.addAll(['--serve', serve.trim().isEmpty ? '127.0.0.1:8080' : serve.trim()]);
      }
      // HTTPS interception: the switch, the two per-application lists and the CA
      // to sign with. --mitm-only decryption works with the switch off, so the
      // CA has to be passed whenever either of them is in play.
      if (caPrefix.trim().isNotEmpty && (mitm || mitmOnly.trim().isNotEmpty)) {
        a.addAll(['--ca', caPrefix.trim()]);
      }
      if (mitm) a.add('--mitm');
      if (mitmSkip.trim().isNotEmpty) a.addAll(['--mitm-skip', mitmSkip.trim()]);
      if (mitmOnly.trim().isNotEmpty) a.addAll(['--mitm-only', mitmOnly.trim()]);
      if (thirdPartyCookies) a.add('--third-party-cookies');
      if (showBlocks) a.add('--show-blocks');
      // A TUN takeover replaces the proxy for this session: netcap serves one or
      // the other, never both (the tunnel owns the default route, and what it
      // relays is decided by --rules alone).  Passing --serve as well would look
      // like it worked while the proxy never started, so leave it out and keep
      // the upstream, which a takeover insists on.
      if (upstream.trim().isNotEmpty) a.addAll(['--upstream', upstream.trim()]);
      if (tun || tunTakeover) {
        a.add('--tun');
        if (tunAdapter.trim().isNotEmpty) a.addAll(['--tun-adapter', tunAdapter.trim()]);
        if (tunTakeover) a.add('--tun-takeover');
        return a;
      }
      // The zero-config path: while this process serves, it also owns the
      // current user's system proxy. netcap refuses the takeover when no
      // upstream answers, which is what keeps this from cutting the machine
      // off; --system-proxy-force is the explicit way past that check.
      if (systemProxy) {
        a.addAll(['--system-proxy', 'on']);
        if (systemProxyBypass.trim().isNotEmpty) {
          a.addAll(['--system-proxy-bypass', systemProxyBypass.trim()]);
        }
        if (systemProxyForce) a.add('--system-proxy-force');
      }
      return a;
    }
    if (mode == SourceMode.file) {
      a.addAll(['--read', path]);
    } else {
      a.addAll(['--interface', device]);
      if (!promisc) a.add('--no-promisc');
      if (limit > 0) a.addAll(['--count', '$limit']);
    }
    if (filter.trim().isNotEmpty) a.addAll(['--filter', filter.trim()]);
    if (snaplen > 0) a.addAll(['--snaplen', '$snaplen']);
    if (hexPayload) a.add('--hex');
    if (hexFrame) a.add('--hex-all');
    if (nanosecond) a.add('--nanosecond');
    if (exportPath.trim().isNotEmpty) a.addAll(['--write', exportPath.trim()]);
    if (splitBy.trim().isNotEmpty) a.addAll(['--split-by', splitBy.trim()]);
    if (attrib) a.add('--attrib');
    if (noAttrib) a.add('--no-attrib');
    if (blockFilter.trim().isNotEmpty) {
      a.addAll(['--block', blockFilter.trim()]);
      a.addAll(['--block-mode', blockMode.trim().isEmpty ? 'dry-run' : blockMode.trim()]);
      if (blockMax > 0) a.addAll(['--block-max', '$blockMax']);
    }
    if (keylog.trim().isNotEmpty) a.addAll(['--keylog', keylog.trim()]);
    if (streams) a.add('--streams');
    if (http) a.add('--http');
    if (follow) a.add('--follow');
    return a;
  }

  /// A copy of the command line, for the "命令行" view in the UI.
  String describe(String exe) {
    final parts = <String>[exe, ...toArgs()];
    return parts.map((p) => p.contains(' ') ? '"$p"' : p).join(' ');
  }
}

enum SourceMode { file, live, proxy }

/// What we know about the local CA that `--mitm` signs with: where its files
/// are, its fingerprint, and whether Windows trusts that exact certificate.
///
/// "Trusted" is decided by comparing the SHA-256 of the file with what certutil
/// prints for the subject in the current user's Root store, so an old CA with
/// the same name does not count as installed.
class CaStatus {
  const CaStatus({
    this.prefix = '',
    this.certPath = '',
    this.keyPath = '',
    this.subject = '',
    this.serial = '',
    this.sha256 = '',
    this.valid = '',
    this.exists = false,
    this.trusted = false,
    this.storeDetail = '',
    this.error = '',
  });

  final String prefix;
  final String certPath;
  final String keyPath;
  final String subject;

  /// The CA's serial number in hex: `certutil -store` prints this, so it is how
  /// an installed certificate is matched to the file on disk.
  final String serial;
  final String sha256;
  final String valid;

  /// Both files were readable by netcap.
  final bool exists;

  /// The same certificate is in the current user's Root store.
  final bool trusted;

  /// What certutil said, for the log pane.
  final String storeDetail;

  final String error;

  /// HTTPS interception can work as it stands.
  bool get ready => exists && trusted;

  /// `E4AC01FD8F10A0…` — enough to recognise the certificate in a store dialog.
  String get shortFingerprint {
    final hex = sha256.replaceAll(RegExp('[^0-9a-fA-F]'), '').toUpperCase();
    return hex.length <= 16 ? hex : '${hex.substring(0, 16)}…';
  }

  String get label {
    if (error.isNotEmpty) return '证书：无法读取';
    if (!exists) return '证书：还没有创建';
    if (!trusted) return '证书：已创建，尚未安装';
    return '证书：已安装 $shortFingerprint';
  }
}

/// Where the netcap executable came from, so the UI can explain a failure.
/// What the machine's system proxy looks like right now, as `netcap
/// --system-proxy status --json` reports it.
///
/// The UI shows all four registry values rather than a yes/no, because
/// "netcap is in charge" and "the user's own proxy/PAC is in charge" can both
/// be true-looking: [enable] is the manual proxy switch, [autoConfig] is a PAC
/// file that wins over it. netcap deletes the PAC while it serves.
class SystemProxyStatus {
  const SystemProxyStatus({
    this.available = false,
    this.readable = false,
    this.platform = '',
    this.enable = false,
    this.server = '',
    this.override = '',
    this.autoConfig = '',
    this.stateFile = '',
    this.hasSnapshot = false,
    this.note = '',
    this.error = '',
  });

  final bool available;
  final bool readable;
  final String platform;
  final bool enable;
  final String server;
  final String override;
  final String autoConfig;
  final String stateFile;
  final bool hasSnapshot;
  final String note;
  final String error;

  /// True when this user's traffic is pointed at a manual proxy right now.
  bool get manual => enable && server.trim().isNotEmpty;

  /// True when a PAC script is in charge — the case netcap has to override.
  bool get pac => autoConfig.trim().isNotEmpty;

  String get label {
    if (!available) return '本机不支持（只有 Windows 有系统代理设置）';
    if (!readable) return '读不到当前设置${error.isEmpty ? '' : '：$error'}';
    if (pac) return 'PAC 模式（PAC 优先于手动代理，接管时会被临时摘掉）';
    if (manual) return '手动代理 $server';
    return '直连（没有系统代理）';
  }

  String get detail {
    final parts = <String>[
      'ProxyEnable=${enable ? 1 : 0}',
      if (server.trim().isNotEmpty) 'ProxyServer=$server',
      if (override.trim().isNotEmpty) 'ProxyOverride=$override',
      if (autoConfig.trim().isNotEmpty) 'AutoConfigURL=$autoConfig',
      if (stateFile.trim().isNotEmpty)
        '快照${hasSnapshot ? '已存在' : '还没有'}（$stateFile）',
    ];
    return parts.join('\n');
  }

  static SystemProxyStatus fromJson(Map<String, dynamic> j) {
    // `--system-proxy status --json` writes the values as they came out of the
    // registry: ProxyEnable is a number, everything else a string.
    String text(Object? v) => v == null ? '' : '$v';
    bool flag(Object? v) {
      if (v is bool) return v;
      final t = text(v).trim().toLowerCase();
      return t == 'true' || t == '1' || t == 'yes';
    }

    return SystemProxyStatus(
      available: flag(j['available']),
      readable: flag(j['readable']),
      platform: text(j['platform']),
      enable: flag(j['enable']) || text(j['enable']).trim() == '1',
      server: text(j['server']),
      override: text(j['override']),
      autoConfig: text(j['auto_config']),
      stateFile: text(j['state_file']),
      hasSnapshot: flag(j['snapshot']),
      note: text(j['note']),
    );
  }
}

/// Where the offline rescue script lives. The UI refuses every action that can
/// change routing or the system proxy while this file is missing — the promise
/// made when the first takeover experiment cut the machine off was "there is
/// always a double-click way back".
String rescueScriptPath({String? home, String? desktop}) {
  final base = (desktop != null && desktop.trim().isNotEmpty)
      ? desktop.trim()
      : '${(home ?? '').replaceAll(RegExp(r'[\\/]+$'), '')}\\Desktop';
  return '$base\\netcap-restore.cmd';
}

class NetcapLocation {
  NetcapLocation(this.path, this.origin);
  final String path;
  final String origin;
}

class NetcapException implements Exception {
  NetcapException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// Locates and runs the netcap executable.
class NetcapRunner {
  NetcapRunner(this.location);

  final NetcapLocation location;
  Process? _process;
  bool _stopping = false;

  String get exe => location.path;
  bool get isRunning => _process != null;

  /// The built-in filter list: it ships with the app (`rules\adblock.txt`), so
  /// the proxy can start blocking without the user picking a file first.
  /// Search order is the same as [locate]'s: next to the executable, then every
  /// ancestor of the executable and of the working directory.
  static Future<String?> defaultRulesFile({List<String>? roots}) async {
    final seen = <String>{};
    final searchRoots = roots ??
        <String>[
          File(Platform.resolvedExecutable).parent.path,
          Directory.current.path,
        ];
    for (final root in searchRoots) {
      var dir = root;
      for (var depth = 0; depth < 9; depth++) {
        final candidates = <String>[
          '$dir${Platform.pathSeparator}rules${Platform.pathSeparator}adblock.txt',
          '$dir${Platform.pathSeparator}adblock.txt',
          '$dir${Platform.pathSeparator}rules/adblock.txt',
        ];
        final existing = <String>{};
        for (final candidate in candidates) {
          if (seen.add(candidate) && await File(candidate).exists()) existing.add(candidate);
        }
        final hit = pickRulesFile(candidates, existing);
        if (hit != null) return hit;
        final parent = Directory(dir).parent.path;
        if (parent == dir) break;
        dir = parent;
      }
    }
    return null;
  }

  /// Pure part of [defaultRulesFile]: the first candidate that is known to
  /// exist.  Kept free of the filesystem so the tests can drive it directly.
  static String? pickRulesFile(List<String> candidates, Set<String> existing) {
    for (final candidate in candidates) {
      if (existing.contains(candidate)) return candidate;
    }
    return null;
  }

  /// Where the interface keeps the rules the user wrote.  The bundled list has
  /// to stay untouched (an update replaces it), so everything the rules page
  /// adds lands in this small file and is passed as `--rules-extra`.
  static String defaultUserRulesPath() {
    final base = Platform.environment['APPDATA'];
    final root = (base == null || base.trim().isEmpty)
        ? Directory.systemTemp.path
        : base.trim();
    return <String>[root, 'netcap-ui', 'my-rules.txt']
        .join(Platform.pathSeparator);
  }

  /// Where the interface keeps the durable decision log (`--log-file`).  It sits
  /// next to [defaultUserRulesPath] so both live in one folder the user can find.
  static String defaultLogPath() {
    final rules = defaultUserRulesPath();
    final cut = rules.lastIndexOf(Platform.pathSeparator);
    final dir = cut < 0 ? rules : rules.substring(0, cut);
    return <String>[dir, 'filter-log.jsonl'].join(Platform.pathSeparator);
  }

  /// Validates one rule line with the engine itself (`--check-rule`), so the
  /// rules page can say *why* a line would be ignored instead of guessing.
  /// The engine exits 0 for a comment, a network rule or an element hiding
  /// rule, and 1 with `rejected: <reason>` for anything it would skip.
  Future<RuleCheck> checkRule(String line) async {
    final r = await _runTool(exe, ['--check-rule', line]);
    final text = r.output.trim();
    if (r.code == 0) return RuleCheck(ok: true, note: text);
    const prefix = 'rejected:';
    final reason = text.startsWith(prefix)
        ? text.substring(prefix.length).trim()
        : (text.isEmpty ? 'netcap 拒绝了这条规则' : text);
    return RuleCheck(ok: false, reason: reason);
  }

  /// Resolution order, most explicit first:
  ///  1. the NETCAP_EXE environment variable,
  ///  2. `netcap.exe` next to this application (a bundled copy),
  ///  3. `netcap.exe` or `build/netcap.exe` in any ancestor of the executable
  ///     (the normal case while developing: the build tree sits above `ui/`),
  ///  4. the same search starting from the current directory,
  ///  5. whatever `where netcap.exe` finds on PATH.
  static Future<NetcapLocation?> locate() async {
    final env = Platform.environment['NETCAP_EXE'];
    if (env != null && env.trim().isNotEmpty) {
      final f = File(env.trim());
      if (await f.exists()) {
        return NetcapLocation(f.path, 'NETCAP_EXE 环境变量');
      }
    }

    final seen = <String>{};
    final roots = <String>[
      File(Platform.resolvedExecutable).parent.path,
      Directory.current.path,
    ];
    for (final root in roots) {
      var dir = root;
      for (var depth = 0; depth < 9; depth++) {
        for (final rel in <String>['netcap.exe', 'build\\netcap.exe', 'build/netcap.exe']) {
          final candidate = '$dir${Platform.pathSeparator}$rel';
          if (seen.add(candidate) && await File(candidate).exists()) {
            return NetcapLocation(candidate, '在 $dir 下找到');
          }
        }
        final parent = Directory(dir).parent.path;
        if (parent == dir) break;
        dir = parent;
      }
    }

    try {
      final r = await Process.run('where', ['netcap.exe']);
      if (r.exitCode == 0) {
        final first = '${r.stdout}'
            .split(RegExp(r'\r?\n'))
            .map((s) => s.trim())
            .firstWhere((s) => s.isNotEmpty, orElse: () => '');
        if (first.isNotEmpty) return NetcapLocation(first, 'PATH');
      }
    } on ProcessException {
      // `where` missing or blocked: nothing else to try.
    }
    return null;
  }

  /// Runs netcap to completion, forwarding each decoded event. Returns the exit
  /// code. [onJson] receives every JSON object, [onStderr] every diagnostic
  /// line (netcap keeps logs on stderr whenever --jsonl is on). [onStream] and
  /// [onHttp] are convenience taps for the two reassembly event types; onJson
  /// still sees them first.
  Future<int> run(
    NetcapRequest request, {
    void Function(Map<String, dynamic> json)? onJson,
    void Function(String line)? onStderr,
    void Function(String line)? onUnknownStdout,
    void Function(StreamInfo info)? onStream,
    void Function(HttpTransactionInfo info)? onHttp,
  }) async {
    if (_process != null) {
      throw NetcapException('已有抓包进程在运行');
    }
    _stopping = false;

    final Process proc;
    try {
      proc = await Process.start(exe, request.toArgs());
    } on ProcessException catch (e) {
      throw NetcapException('无法启动 $exe: ${e.message}');
    }
    _process = proc;

    final decoder = const Utf8Decoder(allowMalformed: true);
    final stdoutDone = proc.stdout
        .transform(decoder)
        .transform(const LineSplitter())
        .listen((line) {
      final s = line.trim();
      if (s.isEmpty) return;
      try {
        final decoded = jsonDecode(s);
        if (decoded is Map<String, dynamic>) {
          onJson?.call(decoded);
          switch (decoded['type']) {
            case 'stream':
              onStream?.call(StreamInfo.fromJson(decoded));
            case 'http':
              onHttp?.call(HttpTransactionInfo.fromJson(decoded));
          }
        } else {
          onUnknownStdout?.call(s);
        }
      } on FormatException {
        onUnknownStdout?.call(s);
      }
    }).asFuture<void>();

    final stderrDone = proc.stderr
        .transform(decoder)
        .transform(const LineSplitter())
        .listen((line) {
      final s = line.trimRight();
      if (s.isNotEmpty) onStderr?.call(s);
    }).asFuture<void>();

    final code = await proc.exitCode;
    await stdoutDone;
    await stderrDone;
    _process = null;
    return code;
  }

  /// Stops a running capture. On Windows this terminates the child, so netcap
  /// does not get to print a final summary line; the UI keeps its own counters.
  void stop() {
    final p = _process;
    if (p == null) return;
    _stopping = true;
    p.kill();
  }

  bool get wasStoppedByUser => _stopping;

  /// `netcap -d --jsonl`: interface list plus the platform capture mechanism.
  Future<DeviceListing> listDevices() async {
    final devices = <DeviceInfo>[];
    Map<String, dynamic>? tail;
    final errs = <String>[];
    final code = await _runOneShot(
      ['--list-devices', '--jsonl'],
      onJson: (j) {
        switch (j['type']) {
          case 'device':
            devices.add(DeviceInfo.fromJson(j));
          case 'devices':
            tail = j;
        }
      },
      onStderr: errs.add,
    );
    if (tail == null) {
      throw NetcapException(
        '枚举网卡失败（退出码 $code）${errs.isEmpty ? '' : ': ${errs.join(' / ')}'}',
      );
    }
    return DeviceListing.fromJson(tail!, devices);
  }

  /// `netcap --generate-sample <path> --jsonl`.
  Future<int> generateSample(String path) async {
    var written = 0;
    final code = await _runOneShot(
      ['--generate-sample', path, '--jsonl'],
      onJson: (j) {
        if (j['type'] == 'sample') written = (j['packets'] as num?)?.toInt() ?? 0;
      },
    );
    if (code != 0) throw NetcapException('生成示例失败（退出码 $code）');
    return written;
  }

  /// `netcap --selftest`.
  Future<String> selftest() async {    final lines = <String>[];
    final code = await _runOneShot(
      ['--selftest', '--verbose'],
      onStdout: lines.add,
      onStderr: lines.add,
    );
    if (code != 0) {
      throw NetcapException('自检失败（退出码 $code）\n${lines.join('\n')}');
    }
    return lines.join('\n');
  }

  /// Asks netcap for the CA files and Windows for the trust store verdict.
  Future<CaStatus> caStatus({String prefix = ''}) async {
    final lines = <String>[];
    final args = <String>['--ca-show'];
    if (prefix.trim().isNotEmpty) args.addAll(['--ca', prefix.trim()]);
    final code = await _runOneShot(args, onStdout: lines.add, onStderr: lines.add);
    var certPath = '';
    var keyPath = '';
    var subject = '';
    var serial = '';
    var sha256 = '';
    var valid = '';
    for (final line in lines) {
      final text = line.trim();
      if (text.startsWith('ca certificate')) certPath = _afterColon(text);
      if (text.startsWith('ca private key')) keyPath = _afterColon(text);
      if (text.startsWith('subject')) subject = _afterColon(text);
      if (text.startsWith('serial')) serial = _afterColon(text);
      if (text.startsWith('sha-256')) sha256 = _afterColon(text);
      if (text.startsWith('valid')) valid = _afterColon(text);
    }
    if (code != 0 || sha256.isEmpty) {
      return CaStatus(
        prefix: prefix,
        error: lines.isEmpty ? 'netcap --ca-show 退出码 $code' : lines.last,
      );
    }
    final store = await _runTool(
      'certutil',
      ['-user', '-store', 'Root', subject.isEmpty ? 'netcap local CA' : subject],
    );
    // certutil prints a SHA-1 thumbprint and the serial number, never a SHA-256,
    // so trust is decided on the serial: it is unique per certificate and shows
    // up in both outputs, which means an old CA with the same name does not
    // count as installed.
    final wanted = _hexOnly(serial.isNotEmpty ? serial : sha256);
    final installed = wanted.isNotEmpty && _hexOnly(store.output).contains(wanted);
    return CaStatus(
      prefix: prefix,
      certPath: certPath,
      keyPath: keyPath,
      subject: subject,
      serial: serial,
      sha256: sha256,
      valid: valid,
      exists: true,
      trusted: store.code == 0 && installed,
      storeDetail: store.output
          .split('\n')
          .map((l) => l.trim())
          .firstWhere((l) => l.isNotEmpty, orElse: () => ''),
    );
  }

  /// Imports the CA for *this user only* (`-user Root`, no machine-wide change
  /// and no UAC prompt). The caller is expected to have asked first.
  Future<String> installCa(String certPath) async {
    final r = await _runTool('certutil', ['-addstore', '-user', 'Root', certPath]);
    if (r.code != 0) {
      throw NetcapException('安装证书失败（退出码 ${r.code}）\n${r.output.trim()}');
    }
    return r.output;
  }

  /// Removes it again by subject name, from the same user store.
  Future<String> uninstallCa({String subject = 'netcap local CA'}) async {
    final r = await _runTool('certutil', ['-delstore', '-user', 'Root', subject]);
    if (r.code != 0) {
      throw NetcapException('卸载证书失败（退出码 ${r.code}）\n${r.output.trim()}');
    }
    return r.output;
  }

  /// `netcap --ca-init`: creates the CA files (and never installs them).
  Future<String> createCa({String prefix = ''}) async {
    final lines = <String>[];
    final args = <String>['--ca-init'];
    if (prefix.trim().isNotEmpty) args.addAll(['--ca', prefix.trim()]);
    final code = await _runOneShot(args, onStdout: lines.add, onStderr: lines.add);
    if (code != 0) {
      throw NetcapException('创建 CA 失败（退出码 $code）\n${lines.join('\n')}');
    }
    return lines.join('\n');
  }

  /// `netcap --system-proxy status --json`: the four registry values plus
  /// whether a snapshot is sitting on disk. Read-only and safe to call any time.
  /// The running programs, for the HTTPS page's program picker.
  ///
  /// `--list-processes` walks a Toolhelp snapshot instead of opening process
  /// handles, so it also names processes we could never open (system ones).
  Future<List<MitmApp>> listProcesses() async {
    final text = StringBuffer();
    final code = await _runOneShot(
      ['--list-processes'],
      onStdout: text.writeln,
      onStderr: (_) {},
    );
    if (code != 0) throw NetcapException('--list-processes 退出码 $code');
    return runningAppsFromJsonl(text.toString());
  }

  Future<SystemProxyStatus> systemProxyStatus() async {
    final r = await _runTool(exe, ['--system-proxy', 'status', '--json']);
    Map<String, dynamic>? json;
    for (final raw in r.output.split('\n')) {
      final line = raw.trim();
      if (!line.startsWith('{') || !line.endsWith('}')) continue;
      try {
        final decoded = jsonDecode(line);
        if (decoded is Map<String, dynamic>) json = decoded;
      } on FormatException {
        // The human-readable lines around the JSON are not our problem.
      }
    }
    if (json == null) {
      return SystemProxyStatus(error: r.output.trim());
    }
    return SystemProxyStatus.fromJson(json);
  }

  /// `netcap --system-proxy restore`: put the snapshot back. This is the button
  /// to press when a takeover outlived its process.
  Future<String> systemProxyRestore() async {
    final lines = <String>[];
    final code = await _runOneShot(
      ['--system-proxy', 'restore'],
      onStdout: lines.add,
      onStderr: lines.add,
    );
    if (code != 0) {
      throw NetcapException('还原系统代理失败（退出码 $code）\n${lines.join('\n')}');
    }
    return lines.join('\n');
  }

  /// `netcap --system-proxy check`: decides what a takeover would chain to and
  /// whether it would be refused, without touching the registry. The proxy is
  /// never left running (the command exits 0 after printing the decision), so
  /// this only works while nothing else holds [serve].
  Future<String> systemProxyCheck({
    required String serve,
    String rules = '',
    String upstream = '',
  }) async {
    final args = <String>['--serve', serve.trim()];
    if (rules.trim().isNotEmpty) args.addAll(['--rules', rules.trim()]);
    if (upstream.trim().isNotEmpty) args.addAll(['--upstream', upstream.trim()]);
    args.addAll(['--system-proxy', 'check']);
    final lines = <String>[];
    final code = await _runOneShot(args, onStdout: lines.add, onStderr: lines.add);
    final text = lines.join('\n');
    if (code != 0) {
      throw NetcapException('检查失败（退出码 $code）\n$text');
    }
    return text;
  }

  /// `netcap --tun-check`: prints the current default routes with their
  /// effective metrics and whether a takeover would be allowed. Read-only.
  Future<String> tunCheck() async {
    final lines = <String>[];
    await _runOneShot(['--tun-check'], onStdout: lines.add, onStderr: lines.add);
    return lines.join('\n');
  }

  /// Runs a real takeover for [seconds] and streams its output. netcap adds one
  /// route, lowers its own interface metric, refuses if it cannot win, and rolls
  /// everything back when the time is up (or after 2 s without traffic), so the
  /// worst case here is a few seconds without a default route.
  Future<int> tunDrill({
    required int seconds,
    required String upstream,
    String rules = '',
    String address = '',
    void Function(String line)? onLine,
  }) {
    final args = <String>['--tun'];
    if (address.trim().isNotEmpty) {
      args.addAll(['--tun-address', address.trim()]);
    }
    args.addAll([
      '--tun-takeover',
      '--tun-seconds',
      '$seconds',
      '--upstream',
      upstream.trim(),
    ]);
    if (rules.trim().isNotEmpty) args.addAll(['--rules', rules.trim()]);
    return _runOneShot(args, onStdout: onLine, onStderr: onLine);
  }

  /// Runs a small helper program (certutil) and collects its output.
  Future<_ToolResult> _runTool(String program, List<String> args) async {
    final Process proc;
    try {
      proc = await Process.start(program, args, runInShell: false);
    } on ProcessException catch (e) {
      return _ToolResult(-1, '$program: ${e.message}');
    }
    final decoder = const Utf8Decoder(allowMalformed: true);
    final out = proc.stdout.transform(decoder).join();
    final err = proc.stderr.transform(decoder).join();
    final code = await proc.exitCode;
    final text = '${await out}\n${await err}';
    return _ToolResult(code, text);
  }

  Future<int> _runOneShot(
    List<String> args, {
    void Function(Map<String, dynamic> json)? onJson,
    void Function(String line)? onStderr,
    void Function(String line)? onStdout,
  }) async {
    final Process proc;
    try {
      proc = await Process.start(exe, args);
    } on ProcessException catch (e) {
      throw NetcapException('无法启动 $exe: ${e.message}');
    }
    final decoder = const Utf8Decoder(allowMalformed: true);
    final out = proc.stdout.transform(decoder).transform(const LineSplitter()).listen((l) {
      final s = l.trim();
      if (s.isEmpty) return;
      if (onJson != null) {
        try {
          final d = jsonDecode(s);
          if (d is Map<String, dynamic>) {
            onJson(d);
            return;
          }
        } on FormatException {
          // not a JSON line: fall through to the plain-text sink
        }
      }
      onStdout?.call(s);
    }).asFuture<void>();
    final err = proc.stderr.transform(decoder).transform(const LineSplitter()).listen((l) {
      if (l.trim().isNotEmpty) onStderr?.call(l.trim());
    }).asFuture<void>();
    final code = await proc.exitCode;
    await out;
    await err;
    return code;
  }
}

/// The upstream netcap really chains through, read from its own stderr.
///
/// netcap says it in one of two ways, and the difference matters: with an
/// explicit `--upstream` it prints "chaining every upstream connection through
/// ADDR", while a system-proxy takeover that found the proxy already in use
/// prints "chaining through ADDR so the previous path keeps working".  The
/// pane used to know only the first sentence, so a takeover that chained through
/// Clash still showed 直连 — the interface was lying about where traffic went.
/// Returns `null` when netcap never said it (it went straight out).
String? chainedUpstreamFrom(Iterable<String> logs) {
  const markers = <String>[
    'chaining every upstream connection through ',
    'chaining through ',
  ];
  for (final line in logs.toList().reversed) {
    for (final marker in markers) {
      final at = line.indexOf(marker);
      if (at < 0) continue;
      var tail = line.substring(at + marker.length).trim();
      const suffix = ' so the previous path keeps working';
      if (tail.endsWith(suffix)) {
        tail = tail.substring(0, tail.length - suffix.length).trim();
      }
      if (tail.isNotEmpty) return tail;
    }
  }
  return null;
}

/// What the interface shows after a run ends.
///
/// Stopping from the interface is **not** a failure: netcap is killed on
/// purpose, so the exit code it leaves behind says nothing about the network and
/// must never turn into an error banner.  Returns `null` when there is nothing
/// to report, otherwise the headline plus (optionally) netcap's own explanation.
String? runFailureText({
  required int code,
  required bool stoppedByUser,
  String hint = '',
}) {
  if (stoppedByUser || code == 0) return null;
  final base = 'netcap 退出码 $code · ${exitCodeHelp(code)}';
  return hint.isEmpty ? base : '$base\n$hint';
}

/// Human explanation for the exit codes netcap documents.
String exitCodeHelp(int code) {
  switch (code) {
    case 0:
      return '正常结束';
    case 1:
      // 1 is also what a killed process reports on Windows, so do not claim
      // "selftest failed" here: the proxy path never runs --selftest.
      return 'netcap 没能正常跑起来（--selftest 时这个码表示自检失败）';
    case 2:
      return '命令行或过滤器语法错误';
    case 3:
      return '打开抓包源失败（文件不存在，或实时抓包权限不足）';
    case 4:
      return '代理 / 接管没能启动（见下面 netcap 自己那行原因）';
    default:
      return '异常退出';
  }
}

/// The verdict of `netcap --check-rule` for one line the user typed.
class RuleCheck {
  const RuleCheck({required this.ok, this.note = '', this.reason = ''});

  /// True when the engine would keep the line.
  final bool ok;

  /// What the engine made of it (`ok network rule: …`, `ok comment: …`, …).
  final String note;

  /// Why it would be skipped, when [ok] is false.
  final String reason;

  /// A line that is only a comment: accepted, but it filters nothing.
  bool get isComment => ok && note.startsWith('ok comment');
}

class _ToolResult {
  _ToolResult(this.code, this.output);
  final int code;
  final String output;
}

/// The value after the first `:` of a `label : value` line. The first colon is
/// the separator even on Windows paths, because the label comes before it.
String _afterColon(String line) {
  final at = line.indexOf(':');
  return at < 0 ? '' : line.substring(at + 1).trim();
}

/// Lower-case hex only, so a fingerprint from netcap and one from certutil can
/// be compared no matter how each of them spaces it out.
String _hexOnly(String text) =>
    text.replaceAll(RegExp('[^0-9a-fA-F]'), '').toLowerCase();
