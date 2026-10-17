/// netcap UI — a Flutter desktop front end for the netcap capture tool.
///
/// The UI does not capture anything itself: it spawns `netcap.exe --jsonl`,
/// decodes the JSON Lines stream documented in src/main.cpp, and renders it.
/// That keeps one implementation of the protocol parsing and one place where
/// capture bugs can live.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'src/models.dart';
import 'src/netcap.dart';
import 'src/mitm_apps.dart';
import 'src/mitm_page.dart';
import 'src/log_merge.dart';
import 'src/rule_lists.dart';
import 'src/rules_page.dart';
import 'src/log_page.dart';
import 'src/takeover_page.dart';
import 'src/widgets.dart';

/// Analysis options the UI accepts on its own command line. They are handed to
/// netcap exactly like the matching controls in 抓包选项, so a script or a file
/// association can open the UI with the capture already analysed:
///   netcap_ui.exe cap.pcap --attrib --block "dst port 443" --block-mode cut
class UiOptions {
  const UiOptions({
    this.attrib = false,
    this.noAttrib = false,
    this.analyze = false,
    this.splitBy = '',
    this.blockFilter = '',
    this.blockMode = 'dry-run',
    this.blockMax = 32,
    this.keylog = '',
    this.rules = '',
    this.serve = '',
    this.thirdPartyCookies = false,
    this.showBlocks = false,
    this.mitm = false,
    this.noMitm = false,
    this.mitmSkip = '',
    this.mitmOnly = '',
    this.ca = '',
    this.httpsSettings = false,
    this.takeoverSettings = false,
    this.rulesSettings = false,
    this.logSettings = false,
    this.systemProxy = false,
    this.systemProxyForce = false,
    this.upstream = '',
    this.showLog = false,
  });

  final bool attrib;
  final bool noAttrib;
  final bool analyze;
  final String splitBy;
  final String blockFilter;
  final String blockMode;
  final int blockMax;
  final String keylog;

  /// `--rules <file>`: switch the UI to proxy mode with this rule list.
  final String rules;

  /// `--serve <endpoint>`: also start the proxy right away (proxy mode only).
  final String serve;
  final bool thirdPartyCookies;
  final bool showBlocks;

  /// `--mitm`: decrypt HTTPS. [noMitm] keeps the default (CA installed = on)
  /// from switching it on; the two lists are the per-application exceptions.
  final bool mitm;
  final bool noMitm;
  final String mitmSkip;
  final String mitmOnly;

  /// `--ca <prefix>`: where the CA files live.
  final String ca;

  /// `--https-settings`: open the graphical HTTPS filtering page right away.
  /// Handy as a desktop shortcut for people who never want to see the main
  /// window's raw flags.
  final bool httpsSettings;

  /// `--takeover-settings`: open the traffic-takeover page right away.
  final bool takeoverSettings;

  /// `--rules-settings`: open the rules page right away (same idea).
  final bool rulesSettings;

  /// `--log-settings` (same as `--filter-log-page`): open the filter log page on
  /// startup.  It is also how the screenshots in the README are taken, because
  /// this machine's interface runs at high integrity and refuses synthetic
  /// clicks.
  final bool logSettings;

  /// `--system-proxy on` / `--upstream <host:port>`: the two takeover fields a
  /// shortcut (or the acceptance script) can preset so the started session
  /// takes the system proxy over, chained through [upstream].
  final bool systemProxy;
  final bool systemProxyForce;
  final String upstream;

  /// `--show-log` (alias `--log`): open the netcap log window right away. Used
  /// by the screenshots and by anyone who wants the raw output without hunting
  /// for a button; the same window is behind the toolbar's 「日志」.
  final bool showLog;
}

/// Parses the UI's own command line. Non-option arguments are appended to
/// [paths] in order (capture file first, optional key log second); everything
/// else is an analysis flag that is handed straight to netcap. Unknown options
/// are ignored so a file association can pass whatever it likes.
UiOptions parseUiArgs(List<String> args, List<String> paths) {
  String? keylog;
  var attrib = false;
  var noAttrib = false;
  var analyze = false;
  var splitBy = '';
  var blockFilter = '';
  var blockMode = 'dry-run';
  var blockMax = 32;
  var rules = '';
  var serve = '';
  var thirdPartyCookies = false;
  var showBlocks = false;
  var mitm = false;
  var noMitm = false;
  var mitmSkip = '';
  var mitmOnly = '';
  var ca = '';
  var httpsSettings = false;
  var takeoverSettings = false;
  var rulesSettings = false;
  var logSettings = false;
  var systemProxy = false;
  var systemProxyForce = false;
  var upstream = '';
  var showLog = false;
  for (var i = 0; i < args.length; i++) {
    final arg = args[i];
    String value() => i + 1 < args.length ? args[++i] : '';
    switch (arg) {
      case '--attrib':
        attrib = true;
        break;
      case '--no-attrib':
        noAttrib = true;
        break;
      case '--streams' || '--http' || '--follow':
        analyze = true;
        break;
      case '--keylog':
        keylog = value();
        break;
      case '--split-by':
        splitBy = value();
        break;
      case '--block':
        blockFilter = value();
        break;
      case '--block-mode':
        blockMode = value();
        break;
      case '--block-max':
        blockMax = int.tryParse(value()) ?? 32;
        break;
      case '--rules':
        rules = value();
        break;
      case '--serve':
        serve = value();
        break;
      case '--third-party-cookies' || '--block-third-party-cookies':
        thirdPartyCookies = true;
        break;
      case '--show-blocks':
        showBlocks = true;
        break;
      case '--mitm' || '--mitm-insecure':
        mitm = true;
        break;
      case '--no-mitm':
        noMitm = true;
        mitm = false;
        break;
      case '--mitm-skip' || '--mitm-except':
        mitmSkip = value();
        break;
      case '--mitm-only':
        mitmOnly = value();
        break;
      case '--ca':
        ca = value();
        break;
      case '--https-settings' || '--https-page':
        httpsSettings = true;
        break;
      case '--takeover-settings' || '--takeover-page':
        takeoverSettings = true;
        break;
      case '--rules-settings' || '--rules-page':
        rulesSettings = true;
        break;
      case '--log-settings' || '--filter-log-page':
        logSettings = true;
        break;
      case '--show-log' || '--log':
        showLog = true;
        break;
      // The takeover page's own two fields, so a shortcut can start a session
      // that already takes the system proxy over (chained through --upstream).
      case '--system-proxy': {
        final v = value().toLowerCase();
        systemProxy = v == 'on' || v == 'true' || v == '1';
        break;
      }
      case '--system-proxy-force':
        systemProxyForce = true;
        break;
      case '--upstream':
        upstream = value();
        break;
      default:
        if (!arg.startsWith('-')) paths.add(arg);
    }
  }
  return UiOptions(
    attrib: attrib,
    noAttrib: noAttrib,
    analyze: analyze,
    splitBy: splitBy,
    blockFilter: blockFilter,
    blockMode: blockMode,
    blockMax: blockMax,
    keylog: keylog ?? '',
    rules: rules,
    serve: serve,
    thirdPartyCookies: thirdPartyCookies,
    showBlocks: showBlocks,
    mitm: mitm,
    noMitm: noMitm,
    mitmSkip: mitmSkip,
    mitmOnly: mitmOnly,
    ca: ca,
    httpsSettings: httpsSettings,
    takeoverSettings: takeoverSettings,
    rulesSettings: rulesSettings,
    logSettings: logSettings,
    systemProxy: systemProxy,
    systemProxyForce: systemProxyForce,
    upstream: upstream,
    showLog: showLog,
  );
}

void main(List<String> args) {
  // Flutter forwards the process command line to the Dart entrypoint, so the
  // application can be started as
  //   netcap_ui.exe C:\path\to\capture.pcap [C:\path\to\keys.log]
  // The optional second path is an SSLKEYLOGFILE style key log, which turns on
  // reassembly and decryption for the capture that was named first. Any of the
  // analysis flags below are passed on to netcap; unknown options are ignored.
  final paths = <String>[];
  final o = parseUiArgs(args, paths);
  runApp(NetcapApp(
    initialPath: paths.isNotEmpty ? paths.first : null,
    initialKeylog: paths.length > 1 ? paths[1] : (o.keylog.isEmpty ? null : o.keylog),
    options: o,
  ));
}

/// Both takeover switches (system proxy and TUN) can leave the machine without a
/// working default route, so the UI only offers them while the offline rescue
/// script is really sitting on the desktop, and never while a run is active.
bool takeoverAllowed({required bool rescueScript, required bool running}) =>
    rescueScript && !running;

class NetcapApp extends StatelessWidget {
  const NetcapApp({
    super.key,
    this.initialPath,
    this.initialKeylog,
    this.options = const UiOptions(),
  });

  /// A capture file named on the command line; decoded as soon as the UI is up.
  final String? initialPath;

  /// A key log named on the command line; enables decryption of that capture.
  final String? initialKeylog;

  /// Analysis flags from the UI's own command line.
  final UiOptions options;

  @override
  Widget build(BuildContext context) {
    final scheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFF2F81F7),
      brightness: Brightness.dark,
    );
    return MaterialApp(
      title: 'netcap UI',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: scheme,
        visualDensity: VisualDensity.compact,
        scaffoldBackgroundColor: const Color(0xFF0D1117),
        cardTheme: const CardThemeData(color: Color(0xFF141A22)),
        dividerTheme: const DividerThemeData(color: Color(0xFF21262D), thickness: 1),
      ),
      home: CaptureScreen(
        initialPath: initialPath,
        initialKeylog: initialKeylog,
        options: options,
      ),
    );
  }
}

class CaptureScreen extends StatefulWidget {
  const CaptureScreen({
    super.key,
    this.initialPath,
    this.initialKeylog,
    this.options = const UiOptions(),
  });

  final String? initialPath;

  /// A key log named on the command line; pre-selects it and turns on 流分析.
  final String? initialKeylog;

  /// Analysis flags from the UI's own command line.
  final UiOptions options;

  @override
  State<CaptureScreen> createState() => _CaptureScreenState();
}

class _CaptureScreenState extends State<CaptureScreen> {
  static const int _maxPackets = 20000;
  static const int _maxRows = 5000;

  NetcapLocation? _location;
  /// The user's own rules (`--rules-extra`): the rules page owns this file, and
  /// the proxy stacks it on top of the bundled list.
  final String _userRules = NetcapRunner.defaultUserRulesPath();

  /// The element picker is switched on and off by a flag file next to the user's
  /// own rules.  A running proxy polls it (so the switch takes effect without a
  /// restart) and a fresh start reads it, which is why one file is enough.
  String get _pickerFlag =>
      '${File(_userRules).parent.path}${Platform.pathSeparator}picker.on';

  bool get _picking => File(_pickerFlag).existsSync();

  Future<void> _setPicking(bool on) async {
    final file = File(_pickerFlag);
    if (on) {
      await file.parent.create(recursive: true);
      await file.writeAsString('1\n');
    } else if (await file.exists()) {
      await file.delete();
    }
    if (mounted) setState(() {});
  }

  /// The durable decision log (`--log-file`).  Turning it on is a *settings*
  /// change: the switch is read when the proxy starts, so the log page says so.
  final String _filterLog = NetcapRunner.defaultLogPath();
  bool _logToFile = false;

  NetcapRunner? _runner;
  String? _locateError;
  String _workspace = '';

  DeviceListing _devices = DeviceListing.empty;
  bool _deviceLoading = false;
  bool _selftestRunning = false;

  HelloInfo? _hello;
  SummaryInfo? _summary;
  String _lastCommand = '';

  final List<PacketRecord> _packets = [];
  final List<PacketRecord> _pending = [];
  int _evicted = 0;
  bool _dirty = false;

  /// While the 抓包工具 window is open, its own builder has to run whenever the
  /// capture stream delivers something — the dialog renders this page's state.
  void Function()? _toolSetState;
  PacketRecord? _selected;
  Timer? _flushTimer;

  bool _running = false;
  /// True when the running session was started with `--system-proxy on`: when it
  /// ends we ask netcap to put the old settings back and show the result.
  bool _usedSystemProxy = false;
  String _proxyRestoreNote = '';
  bool _stopRequested = false;
  int _exitCode = -1;
  String? _errorText;
  final List<String> _logs = [];

  /// Reassembly / decryption results, filled by the `stream` and `http` events
  /// when 流分析 is on. Both lists are capped and evict from the head.
  final List<HttpTransactionInfo> _http = [];

  /// Interception decisions: live events (`block`) plus the summary report.
  final List<BlockAction> _blocks = [];
  final List<StreamInfo> _streams = [];

  /// The local interception proxy (`--serve`): one row per decision, plus the
  /// final `intercept_summary`.
  final List<InterceptRecord> _intercepts = [];
  InterceptSummary? _interceptSummary;
  String _interceptSearch = '';
  HttpTransactionInfo? _selectedHttp;
  InterceptRecord? _selectedIntercept;
  String _keylog = '';
  bool _analyze = true;

  // The window always opens on the interception proxy.  Packet capture (pcap
  // file / live NIC) is a tool inside the app now — see _openCaptureTool — not
  // a third mode that greets everyone who starts the program.
  SourceMode _mode = SourceMode.proxy;
  String _path = '';
  String _device = '';
  final TextEditingController _pathCtrl = TextEditingController();
  final TextEditingController _filterCtrl = TextEditingController();
  final TextEditingController _searchCtrl = TextEditingController();
  final TextEditingController _exportCtrl = TextEditingController();

  /// Proxy mode only: the rule list (`--rules`) and where to listen (`--serve`).
  final TextEditingController _rulesCtrl = TextEditingController();
  /// Set when the rule list came from the bundle instead of from the user.
  String? _bundledRules;

  /// The filter-list manager: which lists the proxy loads.  The window never
  /// shows a path field — the rules page owns this (see `rule_lists.dart`).
  RuleLists? _lists;
  final TextEditingController _serveCtrl = TextEditingController(text: '127.0.0.1:8080');
  final TextEditingController _interceptSearchCtrl = TextEditingController();
  bool _thirdPartyCookies = false;
  bool _showBlocks = false;

  /// HTTPS interception (`--mitm`): the switch, the per-application exceptions
  /// (`--mitm-skip` / `--mitm-only`) and the CA the proxy signs with (`--ca`).
  /// What the graphical HTTPS page decided. This replaced the two raw
  /// `--mitm-skip` / `--mitm-only` text boxes: one model, one page, one list.
  MitmSettings _mitmSettings = const MitmSettings();
  final TextEditingController _caCtrl = TextEditingController();
  CaStatus? _ca;
  bool _caBusy = false;

  /// Zero-config takeover: while the proxy serves it also owns this user's
  /// system proxy (`--system-proxy on`), and a TUN drill can borrow the default
  /// route for a few seconds. Both can cut the machine off, so they are only
  /// offered while the desktop rescue script is actually there.
  bool _sysProxy = false;
  bool _sysProxyForce = false;
  final TextEditingController _sysProxyBypassCtrl = TextEditingController();
  SystemProxyStatus? _sysProxyStatus;
  bool _takeoverBusy = false;
  String _takeoverReport = '';
  bool _rescueScript = false;
  int _tunSeconds = 12;
  bool _tunSession = false;
  final TextEditingController _upstreamCtrl = TextEditingController();
  final TextEditingController _tunAddressCtrl = TextEditingController();
  final TextEditingController _tunAdapterCtrl = TextEditingController();
  String _search = '';
  int _snaplen = 262144;
  int _limit = 0;
  bool _hexPayload = false;
  bool _hexFrame = false;
  bool _promisc = false;
  bool _follow = true;

  /// Process attribution: on for a live capture (netcap defaults to it there),
  /// and opt-in for a replayed file because the names then come from whatever
  /// the local endpoint table happens to own.
  bool _attrib = false;
  bool _noAttrib = false;

  /// `proc` / `app` / empty, for `--split-by` (needs an export directory).
  String _splitBy = '';

  /// Interception. Empty filter = no `--block` flag at all, which is the only
  /// safe default; dry-run is the default mode even when a filter is given.
  String _blockFilter = '';
  String _blockMode = 'dry-run';
  int _blockMax = 32;

  int _tab = 0;
  final ScrollController _listScroll = ScrollController();

  @override
  void initState() {
    super.initState();
    _flushTimer = Timer.periodic(const Duration(milliseconds: 120), (_) => _flush());
    _bootstrap();
  }

  @override
  void dispose() {
    _flushTimer?.cancel();
    _runner?.stop();
    _listScroll.dispose();
    _pathCtrl.dispose();
    _filterCtrl.dispose();
    _searchCtrl.dispose();
    _exportCtrl.dispose();
    _rulesCtrl.dispose();
    _serveCtrl.dispose();

    _caCtrl.dispose();
    _sysProxyBypassCtrl.dispose();
    _upstreamCtrl.dispose();
    _tunAddressCtrl.dispose();
    _tunAdapterCtrl.dispose();
    _interceptSearchCtrl.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------- lifecycle

  Future<void> _bootstrap() async {
    final loc = await NetcapRunner.locate();
    if (!mounted) return;
    // The app ships an ad filter list (rules/adblock.txt).  Use it unless the
    // user's own command line already named one.
    final bundledRules = await NetcapRunner.defaultRulesFile();
    if (!mounted) return;
    if (loc == null) {
      setState(() {
        _locateError = '没有找到 netcap.exe。'
            '请先构建 C++ 工具（cmake --build build），'
            '或设置 NETCAP_EXE 环境变量指向该可执行文件。';
      });
      return;
    }
    setState(() {
      _location = loc;
      _runner = NetcapRunner(loc);
      _workspace = _findWorkspace(loc.path);
      final explicit = widget.initialPath;
      if (explicit != null && explicit.isNotEmpty) {
        _path = explicit;
        _mode = SourceMode.file;
      } else {
        final sample = File('$_workspace${Platform.pathSeparator}sample.pcap');
        if (sample.existsSync()) _path = sample.path;
      }
      _pathCtrl.text = _path;
      final keylog = widget.initialKeylog;
      if (keylog != null && keylog.isNotEmpty && File(keylog).existsSync()) {
        _keylog = keylog;
        _analyze = true;
      }
      // Flags from the UI's own command line, applied before the capture that
      // _bootstrap starts below, so the first run already uses them.
      final o = widget.options;
      if (o.attrib) _attrib = true;
      if (o.noAttrib) _noAttrib = true;
      if (o.analyze) _analyze = true;
      if (o.splitBy.isNotEmpty) _splitBy = o.splitBy;
      if (o.blockFilter.isNotEmpty) {
        _blockFilter = o.blockFilter;
        _blockMode = o.blockMode;
        _blockMax = o.blockMax;
      }
      // `--rules <file>` puts the UI in proxy mode; `--serve <endpoint>` on top
      // of that means "start intercepting now" (see the auto-start below).
      if (o.rules.isNotEmpty || o.serve.isNotEmpty) {
        _mode = SourceMode.proxy;
        if (o.rules.isNotEmpty) _rulesCtrl.text = o.rules;
        if (o.serve.isNotEmpty) _serveCtrl.text = o.serve;
        _thirdPartyCookies = o.thirdPartyCookies;
        _showBlocks = o.showBlocks;
        if (o.ca.isNotEmpty) _caCtrl.text = o.ca;
      }
      // `--system-proxy on` / `--upstream <addr>`: the same two fields the
      // takeover page writes, so a session started from a command line takes
      // the system proxy over exactly like one started from that page (and the
      // post-run restore check below still fires).
      if (o.systemProxy) {
        _sysProxy = true;
        _usedSystemProxy = true;
      }
      if (o.systemProxyForce) _sysProxyForce = true;
      if (o.upstream.isNotEmpty) _upstreamCtrl.text = o.upstream;
      // Nothing was asked for: fall back to the built-in list so the proxy is
      // useful the moment the user presses "启动代理".
      if (_rulesCtrl.text.trim().isEmpty && bundledRules != null) {
        _rulesCtrl.text = bundledRules;
        _bundledRules = bundledRules;
      }
    });
    if (_bundledRules != null) {
      _appendLog('内置过滤列表: $_bundledRules（在「更多设置 → 规则」里管理各个列表）');
    }
    // Which lists to load is remembered between runs ("其他软件那种管理方式":
    // a list of lists with switches, not a path field).  A command-line
    // `--rules <file>` wins and replaces the bundled list.
    final listSettings = await RuleLists.load(
      defaultRuleListsPath(),
      builtinPath: _bundledRules ?? _rulesCtrl.text.trim(),
      userRulesPath: _userRules,
    );
    if (widget.options.rules.isNotEmpty) {
      final override = widget.options.rules.trim();
      _rulesCtrl.text = override;
      // `--rules` means "use this file instead of the built-in list".  When the
      // file *is* the built-in one (the packaged app is often started that
      // way), turning the built-in row off and adding the same path as a
      // second list would show one file as two rows.
      if (RuleLists.samePath(override, listSettings.builtinPath)) {
        listSettings.builtinEnabled = true;
      } else {
        listSettings.builtinEnabled = false;
        listSettings.extra.insert(0, RuleList(path: override));
      }
    }
    _lists = listSettings;
    await _loadDevices();
    if (!mounted) return;
    // Where the CA is, then whether Windows trusts that exact certificate. The
    // answer decides the default: an installed CA turns HTTPS decryption on for
    // every application, which is what the user asked for, and the switch (or a
    // per-application list) turns it off again.
    if (_caCtrl.text.trim().isEmpty) _caCtrl.text = _defaultCaPrefix();
    await _detectCa(quiet: true);
    if (!mounted) return;
    // What the user last chose on the HTTPS page, then the command line: a
    // script that passes --mitm-only has to win over the saved file.
    var mitm = await loadMitmSettings();
    final cli = widget.options;
    if (cli.noMitm) {
      mitm = mitm.copyWith(enabled: false);
    } else if (cli.mitmOnly.isNotEmpty) {
      var only = const MitmSettings(enabled: true, scope: MitmScope.selected, apps: <MitmApp>[]);
      for (final n in _splitProcList(cli.mitmOnly)) {
        only = only.withApp(n);
      }
      mitm = only;
    } else {
      if (cli.mitm) mitm = mitm.copyWith(enabled: true, scope: MitmScope.all);
      for (final n in _splitProcList(cli.mitmSkip)) {
        mitm = mitm.withApp(n, decrypt: false);
      }
      if (cli.mitmSkip.isNotEmpty) mitm = mitm.copyWith(scope: MitmScope.all);
    }
    mitm = mitm.copyWith(caPrefix: _caCtrl.text.trim());
    if (!mounted) return;
    setState(() => _mitmSettings = mitm);
    if (_ca?.ready == true && !cli.noMitm && !cli.mitm && !mitm.active) {
      // An installed CA is the one case where opening HTTPS is the expected
      // default; the page still starts on "common programs only".
      setState(() => _mitmSettings = mitm.copyWith(enabled: true));
      _appendLog('证书已安装：HTTPS 解密默认开启（默认只看常见程序，可在「HTTPS 过滤」页增减）');
    }
    _appendLog('netcap: ${loc.path}（${loc.origin}）');
    // The rescue script is the precondition for every risky switch in the
    // takeover block, so its existence is checked before the first frame that
    // could offer one (and re-checked whenever the user presses 刷新).
    _rescueScript = await _rescueScriptPresent();
    if (!_rescueScript && mounted) {
      _appendLog('提醒：桌面上没有 netcap-restore.cmd，接管类开关已禁用（见 README「系统接管」）');
    }
    if (_mode == SourceMode.proxy) {
      _appendLog('拦截代理: 规则 ${_rulesCtrl.text}，监听 ${_serveCtrl.text}');
    } else if (_path.isNotEmpty) {
      _appendLog('抓包文件: $_path');
    }
    final explicit = widget.initialPath;
    final options = widget.options;
    // `--https-settings`: a desktop shortcut that opens straight at the page
    // people came for. It is scheduled before the capture starts, because
    // starting a run can take a moment and the page must not wait for it.
    if (options.httpsSettings) {
      unawaited(Future<void>.delayed(const Duration(milliseconds: 400), () async {
        if (mounted) await _openMitmPage();
      }));
    }
    // `--takeover-settings`: same idea for the traffic-takeover page.
    if (options.takeoverSettings) {
      unawaited(Future<void>.delayed(const Duration(milliseconds: 400), () async {
        if (mounted) await _openTakeoverPage();
      }));
    }
    // `--rules-settings`: same idea for the rules page.
    if (options.rulesSettings) {
      unawaited(Future<void>.delayed(const Duration(milliseconds: 400), () async {
        if (mounted) await _openRulesPage();
      }));
    }
    // `--log-settings`: and for the filter log page.
    if (options.logSettings) {
      unawaited(Future<void>.delayed(const Duration(milliseconds: 400), () async {
        if (mounted) await _openLogPage();
      }));
    }
    // `--show-log`: the log has its own window now, so a shortcut can open it
    // directly (the toolbar's 「日志」 does the same by hand).
    if (options.showLog) {
      unawaited(Future<void>.delayed(const Duration(milliseconds: 700), () async {
        if (mounted) await _showLogWindow();
      }));
    }
    // `--serve` means "start intercepting now"; the rules come from the command
    // line or, when that was left out, from the built-in list.
    if (options.serve.isNotEmpty && _rulesCtrl.text.trim().isNotEmpty) {
      await _start();
    } else if (explicit != null && explicit.isNotEmpty && File(explicit).existsSync()) {
      await _start();
    }
  }

  /// Walks up from the executable looking for the project folder that holds
  /// sample.pcap, so the packaged build can still pre-fill a demo capture.
  String _findWorkspace(String exePath) {
    var dir = File(exePath).parent;
    for (var i = 0; i < 8; i++) {
      if (File('${dir.path}${Platform.pathSeparator}sample.pcap').existsSync()) {
        return dir.path;
      }
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
    return File(exePath).parent.parent.path;
  }

  Future<void> _loadDevices() async {
    final runner = _runner;
    if (runner == null) return;
    setState(() => _deviceLoading = true);
    try {
      final listing = await runner.listDevices();
      if (!mounted) return;
      setState(() {
        _devices = listing;
        _deviceLoading = false;
        if (_device.isEmpty && listing.devices.isNotEmpty) {
          final def = listing.devices.where((d) => d.isDefault).toList();
          final up = listing.devices.where((d) => d.up && !d.loopback).toList();
          final pick = def.isNotEmpty
              ? def.first
              : (up.isNotEmpty ? up.first : listing.devices.first);
          _device = '${pick.index}';
        }
      });
    } on NetcapException catch (e) {
      if (!mounted) return;
      setState(() {
        _deviceLoading = false;
        _devices = DeviceListing.empty;
      });
      _appendLog('枚举网卡失败: ${e.message}');
    }
  }

  // ------------------------------------------------------------------- stream

  void _onJson(Map<String, dynamic> json) {
    switch (json['type']) {
      case 'hello':
        _hello = HelloInfo.fromJson(json);
        _dirty = true;
      case 'packet':
        _pending.add(PacketRecord.fromJson(json));
      case 'summary':
        _summary = SummaryInfo.fromJson(json);
        _dirty = true;
      case 'block':
        // A live capture has no summary, so decisions arrive one at a time.
        _blocks.add(BlockAction.fromJson(json));
        if (_blocks.length > _maxRows) {
          _blocks.removeRange(0, _blocks.length - _maxRows);
        }
        _dirty = true;
      case 'intercept':
        _intercepts.add(InterceptRecord.fromJson(json));
        if (_intercepts.length > _maxRows) {
          _intercepts.removeRange(0, _intercepts.length - _maxRows);
        }
        _dirty = true;
      case 'intercept_summary':
        _interceptSummary = InterceptSummary.fromJson(json);
        _dirty = true;
    }
  }

  void _onStream(StreamInfo info) {
    _streams.add(info);
    if (_streams.length > _maxRows) {
      _streams.removeRange(0, _streams.length - _maxRows);
    }
    _dirty = true;
  }

  void _onHttp(HttpTransactionInfo info) {
    _http.add(info);
    if (_http.length > _maxRows) {
      _http.removeRange(0, _http.length - _maxRows);
    }
    _dirty = true;
  }

  /// Called on a timer rather than per packet: a live capture can deliver
  /// thousands of packets a second and rebuilding the list per packet would
  /// starve the UI thread.
  void _flush() {
    if (!_dirty && _pending.isEmpty) return;
    if (_pending.isNotEmpty) {
      _packets.addAll(_pending);
      _pending.clear();
      if (_packets.length > _maxPackets) {
        final drop = _packets.length - _maxPackets;
        _packets.removeRange(0, drop);
        _evicted += drop;
      }
    }
    _dirty = false;
    if (!mounted) return;
    setState(() {});
    // The capture tool renders this state inside its own dialog, so it has to
    // be told to rebuild too.
    _toolSetState?.call();
    if (_follow && _listScroll.hasClients) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted || !_listScroll.hasClients) return;
        _listScroll.jumpTo(_listScroll.position.maxScrollExtent);
      });
    }
  }

  void _appendLog(String line) {
    _logs.add(line);
    if (_logs.length > 400) _logs.removeRange(0, _logs.length - 400);
    _dirty = true;
  }

  // ------------------------------------------------------------------ capture

  Future<void> _start() async {
    final runner = _runner;
    if (runner == null) {
      _snack(_locateError ?? '没有可用的 netcap.exe');
      return;
    }
    if (_running) return;
    if (_mode == SourceMode.file && _path.trim().isEmpty) {
      _snack('请先选择一个 pcap 文件');
      return;
    }
    if (_mode == SourceMode.live && _device.isEmpty) {
      _snack('请先选择网卡');
      return;
    }
    if (_mode == SourceMode.proxy && _lists?.anyEnabled != true) {
      // Look for the bundled list once more: it may appear next to a freshly
      // built executable after the window was already open.
      final fallback = await NetcapRunner.defaultRulesFile();
      if (!mounted) return;
      if (fallback == null) {
        _snack('没有可用的过滤列表：打开「更多设置 → 规则」加一个，或把内置列表打开');
        await _openRulesPage();
        return;
      }
      setState(() {
        _bundledRules = fallback;
        final lists = _lists ?? RuleLists(builtinPath: fallback, userRulesPath: _userRules);
        lists.builtinEnabled = true;
        _lists = lists;
      });
      _appendLog('使用内置过滤列表: $fallback');
    }

    // The tunnel grabs the default route, so without an upstream the machine
    // would have nowhere to send its traffic.  Refuse here instead of letting
    // netcap exit with code 4 (which looks like a crash).
    if (_tunSession && _upstreamCtrl.text.trim().isEmpty) {
      _snack('TUN 接管需要「链式上游」（例如 127.0.0.1:7890）：'
          '隧道会抢走默认路由，没有上游就等于断网');
      return;
    }

    final full = NetcapRequest(
      mode: _mode,
      path: _path.trim(),
      device: _device,
      filter: _filterCtrl.text,
      snaplen: _snaplen,
      limit: _limit,
      hexPayload: _hexPayload,
      hexFrame: _hexFrame,
      promisc: _promisc,
      exportPath: _exportCtrl.text.trim(),
      keylog: _keylog,
      // A file run can print everything at the end (--http), but a live capture
      // never gets a summary when it stops, so --follow is its only outlet.
      streams: _analyze,
      http: _analyze,
      follow: _analyze && _mode == SourceMode.live,
      // --split-by proc implies attribution on the C++ side, so the flag is
      // only added explicitly when the user asked for the process column.
      attrib: _attrib && !_noAttrib,
      noAttrib: _noAttrib,
      splitBy: _splitBy,
      blockFilter: _blockFilter,
      blockMode: _blockMode,
      blockMax: _blockMax,
      rulesPath: _lists?.rulesPath ?? _rulesCtrl.text.trim(),
      userRules: (_lists?.userRulesEnabled ?? true) ? _userRules : '',
      extraRules: (_lists?.extraPaths ?? const <String>[])
          .where((path) => path != _userRules)
          .toList(),
      // The element picker is always offered; whether it is on is the flag
      // file's business, so toggling it never needs a restart.
      picker: true,
      pickerFlag: _pickerFlag,
      pickerRules: _userRules,
      logFile: _logToFile ? _filterLog : '',
      serve: _serveCtrl.text.trim(),
      thirdPartyCookies: _thirdPartyCookies,
      showBlocks: _showBlocks,
      mitm: _mitmArgs.mitm,
      mitmSkip: _mitmArgs.skip,
      mitmOnly: _mitmArgs.only,
      caPrefix: _caCtrl.text.trim(),
      systemProxy: _sysProxy,
      systemProxyBypass: _sysProxyBypassCtrl.text.trim(),
      systemProxyForce: _sysProxyForce,
      upstream: _upstreamCtrl.text.trim(),
      tun: _tunSession,
      tunTakeover: _tunSession,
      tunAdapter: _tunAdapterCtrl.text.trim(),
    );

    setState(() {
      _running = true;
      _stopRequested = false;
      _usedSystemProxy = _sysProxy && !_tunSession;
      _proxyRestoreNote = '';
      _exitCode = -1;
      _errorText = null;
      _packets.clear();
      _pending.clear();
      _evicted = 0;
      _selected = null;
      _hello = null;
      _summary = null;
      _logs.clear();
      _streams.clear();
      _blocks.clear();
      _intercepts.clear();
      _interceptSummary = null;
      _selectedHttp = null;
      _lastCommand = full.describe(runner.exe);
    });

    var code = 0;
    try {
      code = await runner.run(
        full,
        onJson: _onJson,
        onStderr: _appendLog,
        onUnknownStdout: (l) => _appendLog('stdout: $l'),
        onStream: _onStream,
        onHttp: _onHttp,
      );
    } on NetcapException catch (e) {
      if (!mounted) return;
      setState(() {
        _running = false;
        _errorText = e.message;
      });
      if (_usedSystemProxy) await _verifyProxyRestored();
      _flush();
      return;
    }
    if (!mounted) return;
    _flush();
    setState(() {
      _running = false;
      _exitCode = code;
      // A finished file run holds the whole result already: show the first
      // packet instead of leaving the detail pane empty.
      if (_mode == SourceMode.file && _selected == null && _packets.isNotEmpty) {
        _selected = _packets.first;
      }
      // A stop from the interface is not a failure — `runFailureText` owns that
      // rule, and the exit code of a process we killed ourselves means nothing.
      _exitCode = _stopRequested ? 0 : code;
      var hint = '';
      if (!_stopRequested && code != 0) {
        // netcap knows why it failed (missing Administrator rights, a DLL that
        // is not there, an upstream that does not answer). Surface its own line
        // here instead of hiding it in the log tab, otherwise every failure
        // looks the same.
        final errorish = RegExp(
          r'(cannot|no usable|not found|missing|failed|failure|refus|denied|'
          r'needs |requires|invalid|unsupported|error|WSA|10013|管理员|'
          r'Administrator|cap_net_raw)',
          caseSensitive: false,
        );
        final line = _logs.lastWhere(
          (l) => l.startsWith('netcap:') && errorish.hasMatch(l),
          orElse: () => '',
        );
        if (line.isNotEmpty) {
          hint = line.replaceFirst(RegExp(r'^netcap:\s*'), '');
          if (hint.length > 220) hint = '${hint.substring(0, 220)}…';
        }
      }
      _errorText = runFailureText(
        code: code,
        stoppedByUser: _stopRequested,
        hint: hint,
      );
    });
    if (_usedSystemProxy) await _verifyProxyRestored();
    if (_stopRequested) {
      _appendLog('已按你的要求停止代理（系统代理按快照还原）。');
    } else if (code != 0) {
      _appendLog('退出码 $code: ${exitCodeHelp(code)}');
    }
    _flush();
  }

  void _stop() {
    if (!_running) return;
    setState(() => _stopRequested = true);
    _appendLog('用户请求停止…');
    _runner?.stop();
  }

  Future<void> _generateSample() async {
    final runner = _runner;
    if (runner == null) return;
    final target = _workspace.isEmpty
        ? 'sample.pcap'
        : '$_workspace${Platform.pathSeparator}sample.pcap';
    try {
      final n = await runner.generateSample(target);
      if (!mounted) return;
      setState(() {
        _path = target;
        _pathCtrl.text = target;
        _mode = SourceMode.file;
      });
      _appendLog('已生成示例抓包 $target（$n 个数据包）');
      _snack('已生成 $target（$n 个数据包），可以直接开始分析');
    } on NetcapException catch (e) {
      if (!mounted) return;
      _snack(e.message);
    }
  }

  Future<void> _runSelftest() async {
    final runner = _runner;
    if (runner == null) return;
    setState(() => _selftestRunning = true);
    try {
      final output = await runner.selftest();
      if (!mounted) return;
      setState(() => _selftestRunning = false);
      await showDialog<void>(
        context: context,
        builder: (_) => AlertDialog(
          title: const Text('netcap 自检'),
          content: SizedBox(
            width: 760,
            height: 460,
            child: SelectionArea(
              child: ListView(
                children: [
                  SelectableText(
                    output,
                    style: const TextStyle(fontFamily: 'Consolas', fontSize: 11.5),
                  ),
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('关闭'),
            ),
          ],
        ),
      );
    } on NetcapException catch (e) {
      if (!mounted) return;
      setState(() => _selftestRunning = false);
      _snack(e.message);
    }
  }

  void _snack(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(
          content: Text(message),
          behavior: SnackBarBehavior.floating,
          width: 620,
          duration: const Duration(seconds: 4),
        ),
      );
  }

  void _copyToClipboard(String text) {
    Clipboard.setData(ClipboardData(text: text));
    _snack('已复制到剪贴板');
  }

  // ------------------------------------------------------------------- tables

  List<PacketRecord> get _visible {
    if (_search.isEmpty) return _packets;
    return _packets.where((p) => p.matchesSearch(_search)).toList();
  }

  /// Application mix computed locally, used before a summary line arrives (and
  /// while a live capture is still running, when there will never be one).
  List<AppCount> get _liveApps {
    final summary = _summary;
    if (summary != null && summary.apps.isNotEmpty) return summary.apps;
    final map = <String, AppCount>{};
    for (final p in _packets) {
      final tag = p.appTag;
      final prev = map[tag];
      map[tag] = AppCount(
        kind: tag == 'other' ? '' : tag,
        name: tag == 'other' ? 'unknown' : tag,
        packets: (prev?.packets ?? 0) + 1,
        bytes: (prev?.bytes ?? 0) + p.len,
      );
    }
    final list = map.values.toList()
      ..sort((a, b) => b.packets.compareTo(a.packets));
    return list;
  }

  int get _matchedCount => _packets.length + _pending.length;
  int get _matchedBytes =>
      _packets.fold<int>(0, (a, p) => a + p.len) +
      _pending.fold<int>(0, (a, p) => a + p.len);

  // ---------------------------------------------------------------------- UI

  @override
  Widget build(BuildContext context) {
    final wide = MediaQuery.sizeOf(context).width >= 1080;
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 12,
        backgroundColor: const Color(0xFF11161D),
        title: Row(
          children: [
            const Icon(Icons.lan_outlined, size: 20),
            const SizedBox(width: 8),
            const Text('netcap UI', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
            const SizedBox(width: 10),
            if (_location != null)
              Tooltip(
                message: '${_location!.path}\n来源: ${_location!.origin}',
                child: Text(
                  'netcap.exe',
                  style: TextStyle(
                    fontSize: 11,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
          ],
        ),
        actions: [
          if (_selftestRunning)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 12),
              child: Center(
                child: SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(strokeWidth: 2),
                ),
              ),
            )
          else
            IconButton(
              // No hard-coded count here: --selftest grows with every release.
              tooltip: '运行 netcap 自检',
              onPressed: _runner == null ? null : _runSelftest,
              icon: const Icon(Icons.verified_outlined, size: 19),
            ),
          if (_mode != SourceMode.proxy)
            IconButton(
              tooltip: '生成示例抓包',
              onPressed: _runner == null || _running ? null : _generateSample,
              icon: const Icon(Icons.auto_awesome_motion_outlined, size: 19),
            ),
          IconButton(
            tooltip: '过滤器语法帮助',
            onPressed: () => _showFilterHelp(),
            icon: const Icon(Icons.help_outline, size: 19),
          ),
          IconButton(
            tooltip: 'HTTPS 过滤设置（哪些程序解密）',
            onPressed: _openMitmPage,
            icon: Icon(_mitmSettings.active ? Icons.lock_open_outlined : Icons.lock_outline, size: 19),
          ),
          if (_mode != SourceMode.proxy)
            IconButton(
              tooltip: '抓包选项',
              onPressed: () => _showSettings(),
              icon: const Icon(Icons.tune, size: 19),
            ),
        ],
      ),
      body: Column(
        children: [
          _sourceBar(),
          _mode == SourceMode.proxy ? _interceptBar() : _filterBar(),
          if (_errorText != null) _errorBar(_errorText!),
          const Divider(height: 1),
          Expanded(
            child: wide
                ? Row(
                    children: [
                      Expanded(
                        flex: 5,
                        child: _mode == SourceMode.proxy ? _interceptTable() : _packetTable(),
                      ),
                      const VerticalDivider(width: 1),
                      SizedBox(
                        width: 460,
                        child: _mode == SourceMode.proxy ? _interceptPane() : _detailPane(),
                      ),
                    ],
                  )
                : Column(
                    children: [
                      Expanded(
                        flex: 3,
                        child: _mode == SourceMode.proxy ? _interceptTable() : _packetTable(),
                      ),
                      const Divider(height: 1),
                      Expanded(
                        flex: 2,
                        child: _mode == SourceMode.proxy ? _interceptPane() : _detailPane(),
                      ),
                    ],
                  ),
          ),
          _statusBar(),
        ],
      ),
    );
  }

  /// The capture side of netcap (pcap file / live NIC) as a window of its own.
  ///
  /// Only the entry point changed: this dialog drives the very same capture
  /// state the main window used to show, and closing it puts the window back on
  /// the interception proxy unless a capture is still running.
  Future<void> _openCaptureTool() async {
    final bool wasProxy = _mode == SourceMode.proxy;
    if (wasProxy) {
      setState(() => _mode = SourceMode.file);
      if (_devices.devices.isEmpty) unawaited(_loadDevices());
    }
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setTool) {
          // StateSetter takes a builder callback; the page only needs "rebuild".
          _toolSetState = () => setTool(() {});
          return Dialog(
            insetPadding: const EdgeInsets.all(16),
            backgroundColor: const Color(0xFF0E1218),
            child: SizedBox(
              width: 1180,
              height: 720,
              child: Column(
                children: [
                  _toolHeader(ctx),
                  _toolSourceRow(),
                  _filterBar(),
                  if (_errorText != null) _errorBar(_errorText!),
                  const Divider(height: 1),
                  Expanded(
                    child: Row(
                      children: [
                        Expanded(child: _packetTable()),
                        const VerticalDivider(width: 1),
                        SizedBox(width: 420, child: _detailPane()),
                      ],
                    ),
                  ),
                  _statusBar(),
                ],
              ),
            ),
          );
        },
      ),
    );
    _toolSetState = null;
    if (mounted && wasProxy && !_running && _mode != SourceMode.proxy) {
      setState(() => _mode = SourceMode.proxy);
    }
  }

  Widget _toolHeader(BuildContext ctx) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 10, 6, 4),
      child: Row(
        children: [
          const Icon(Icons.travel_explore, size: 18),
          const SizedBox(width: 8),
          const Text('抓包工具',
              style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
          const SizedBox(width: 10),
          Text(
            '离线看 pcap，或实时抓一张网卡；它不改系统代理，和广告过滤互不影响',
            style: TextStyle(
              fontSize: 11,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const Spacer(),
          IconButton(
            tooltip: '生成示例抓包',
            onPressed: _runner == null || _running ? null : _generateSample,
            icon: const Icon(Icons.auto_awesome_motion_outlined, size: 18),
          ),
          IconButton(
            tooltip: '抓包选项',
            onPressed: () => _showSettings(),
            icon: const Icon(Icons.tune, size: 18),
          ),
          IconButton(
            tooltip: '关闭',
            onPressed: () => Navigator.of(ctx).pop(),
            icon: const Icon(Icons.close, size: 18),
          ),
        ],
      ),
    );
  }

  Widget _toolSourceRow() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 0, 14, 6),
      child: Wrap(
        crossAxisAlignment: WrapCrossAlignment.center,
        spacing: 10,
        runSpacing: 8,
        children: [
          SegmentedButton<SourceMode>(
            showSelectedIcon: false,
            style: const ButtonStyle(
              visualDensity: VisualDensity.compact,
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            ),
            segments: const [
              ButtonSegment(
                value: SourceMode.file,
                label: Text('pcap 文件'),
                icon: Icon(Icons.folder_open, size: 15),
              ),
              ButtonSegment(
                value: SourceMode.live,
                label: Text('实时网卡'),
                icon: Icon(Icons.settings_input_antenna, size: 15),
              ),
            ],
            selected: <SourceMode>{_mode == SourceMode.proxy ? SourceMode.file : _mode},
            onSelectionChanged:
                _running ? null : (s) => setState(() => _mode = s.first),
          ),
          SizedBox(
            width: 420,
            child: _mode == SourceMode.live
                ? _deviceDropdown()
                : Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _pathCtrl,
                          enabled: !_running,
                          style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
                          decoration: const InputDecoration(
                            isDense: true,
                            prefixIcon: Icon(Icons.description_outlined, size: 16),
                            prefixIconConstraints:
                                BoxConstraints(minWidth: 32, minHeight: 32),
                            border: OutlineInputBorder(),
                            contentPadding:
                                EdgeInsets.symmetric(horizontal: 8, vertical: 10),
                            hintText: r'选择或输入 pcap 路径',
                          ),
                          onChanged: (v) => _path = v,
                          onSubmitted: (_) {
                            if (!_running) _start();
                          },
                        ),
                      ),
                      const SizedBox(width: 6),
                      OutlinedButton(
                        onPressed: _running
                            ? null
                            : () async {
                                final picked = await FileBrowserDialog.show(
                                  context,
                                  initialDirectory: _workspace.isEmpty
                                      ? Directory.current.path
                                      : _workspace,
                                );
                                if (picked == null || !mounted) return;
                                setState(() {
                                  _path = picked;
                                  _pathCtrl.text = picked;
                                });
                              },
                        child: const Text('浏览…'),
                      ),
                    ],
                  ),
          ),
          FilledButton.icon(
            onPressed: _running ? _stop : _start,
            style: FilledButton.styleFrom(
              backgroundColor: _running ? Theme.of(context).colorScheme.error : null,
              visualDensity: VisualDensity.compact,
            ),
            icon: Icon(_running ? Icons.stop : Icons.play_arrow, size: 18),
            label: Text(_running ? '停止' : '开始捕获'),
          ),
          FilterChip(
            label: const Text('记录字节'),
            selected: _hexFrame,
            onSelected: _running ? null : (v) => setState(() => _hexFrame = v),
          ),
          FilterChip(
            label: const Text('混杂模式'),
            selected: _promisc,
            onSelected: _running || _mode != SourceMode.live
                ? null
                : (v) => setState(() => _promisc = v),
          ),
        ],
      ),
    );
  }

  Widget _sourceBar() {
    final cs = Theme.of(context).colorScheme;
    return Container(
      color: const Color(0xFF11161D),
      padding: const EdgeInsets.fromLTRB(10, 8, 10, 8),
      child: Wrap(
        crossAxisAlignment: WrapCrossAlignment.center,
        spacing: 10,
        runSpacing: 8,
        children: [
          // No source switch here any more: this bar is the interception proxy.
          // pcap files and live NICs live in the 抓包工具 window (see
          // _openCaptureTool), which borrows the same capture pipeline.
          SizedBox(
            width: _mode == SourceMode.file
                ? 380
                : (_mode == SourceMode.proxy ? 640 : 330),
            child: _mode == SourceMode.proxy
                ? _proxyControls()
                : (_mode == SourceMode.file
                ? Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _pathCtrl,
                          enabled: !_running,
                          style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
                          decoration: const InputDecoration(
                            isDense: true,
                            prefixIcon: Icon(Icons.description_outlined, size: 16),
                            prefixIconConstraints:
                                BoxConstraints(minWidth: 32, minHeight: 32),
                            border: OutlineInputBorder(),
                            contentPadding:
                                EdgeInsets.symmetric(horizontal: 8, vertical: 10),
                            hintText: r'选择或输入 pcap 路径',
                          ),
                          onChanged: (v) => _path = v,
                          onSubmitted: (_) {
                            if (!_running) _start();
                          },
                        ),
                      ),
                      const SizedBox(width: 6),
                      OutlinedButton(
                        onPressed: _running
                            ? null
                            : () async {
                                final picked = await FileBrowserDialog.show(
                                  context,
                                  initialDirectory: _workspace.isEmpty
                                      ? Directory.current.path
                                      : _workspace,
                                );
                                if (picked == null || !mounted) return;
                                setState(() {
                                  _path = picked;
                                  _pathCtrl.text = picked;
                                });
                              },
                        child: const Text('浏览…'),
                      ),
                    ],
                  )
                : _deviceDropdown()),
          ),
          // In proxy mode this one control does everything: press it and netcap
          // starts *with* the system proxy in its hands, so programs that read the
          // system proxy (browsers, IM clients, Electron apps) walk through the
          // filter instead of only the ones someone pointed at us.  A
          // separate "启动代理" button would only be a second way to do the same
          // thing, so there is none; the plain start (no takeover) lives in
          // 更多设置 for the explicit-proxy case.
          if (_mode == SourceMode.proxy)
            _running
                ? FilledButton.icon(
                    onPressed: _stop,
                    style: FilledButton.styleFrom(
                      backgroundColor: cs.error,
                      visualDensity: VisualDensity.compact,
                    ),
                    icon: const Icon(Icons.stop, size: 18),
                    label: const Text('停止并还原'),
                  )
                : Tooltip(
                    message: '点一下＝启动拦截代理，并把本机系统代理临时指向它（127.0.0.1:8080）。\n'
                        '覆盖范围：读系统代理的程序——浏览器、微信/QQ、Electron 应用等。'
                        '自己写死网络、不读系统代理的程序管不到，那需要 TUN 全接管。\n'
                        '上游不通时 netcap 会拒绝接管（不会把机器断网）；再按一次或退出即按快照还原，'
                        '桌面 netcap-restore.cmd 可离线急停。',
                    child: FilledButton.icon(
                      onPressed: _takeoverBusy ? null : _toggleAllPrograms,
                      style: FilledButton.styleFrom(visualDensity: VisualDensity.compact),
                      icon: Icon(
                        _sysProxy ? Icons.verified_user : Icons.shield_outlined,
                        size: 18,
                      ),
                      label: const Text('让所有程序走 netcap'),
                    ),
                  )
          else
            FilledButton.icon(
              onPressed: _running ? _stop : _start,
              style: FilledButton.styleFrom(
                backgroundColor: _running ? cs.error : null,
                visualDensity: VisualDensity.compact,
              ),
              icon: Icon(_running ? Icons.stop : Icons.play_arrow, size: 18),
              label: Text(_running ? '停止' : '开始捕获'),
            ),
          if (_mode != SourceMode.proxy)
          Tooltip(
            message: '为每个数据包附带完整帧字节（--hex-all），用于十六进制视图。\n'
                '实时抓包时数据量会明显增大。',
            child: FilterChip(
              label: const Text('记录字节'),
              selected: _hexFrame,
              onSelected: _running ? null : (v) => setState(() => _hexFrame = v),
            ),
          ),
          if (_mode != SourceMode.proxy)
          Tooltip(
            message: '实时抓包需要管理员权限；勾选后网卡进入混杂模式（--no-promisc 关闭）',
            child: FilterChip(
              label: const Text('混杂模式'),
              selected: _promisc,
              onSelected:
                  _running || _mode == SourceMode.file ? null : (v) => setState(() => _promisc = v),
            ),
          ),
          if (_mode == SourceMode.proxy)
            Tooltip(
              message: 'netcap 本来的抓包分析工具：打开一个 pcap 文件，或者实时抓某张网卡。\n'
                  '它在自己的窗口里做事，不碰系统代理、不影响上面的广告过滤。',
              child: OutlinedButton.icon(
                onPressed: _openCaptureTool,
                style: OutlinedButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
                icon: const Icon(Icons.travel_explore, size: 16),
                label: const Text('抓包工具', style: TextStyle(fontSize: 12)),
              ),
            ),
          Tooltip(
            message: '每一条判定的账本：拦了什么、改了什么、放行了什么。\n'
                '代理进程自己写（--log-file），所以崩了也不丢最后几条。',
            child: OutlinedButton.icon(
              onPressed: _openLogPage,
              style: OutlinedButton.styleFrom(
                visualDensity: VisualDensity.compact,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              icon: const Icon(Icons.receipt_long_outlined, size: 16),
              label: const Text('过滤日志', style: TextStyle(fontSize: 12)),
            ),
          ),
          // 密钥日志与流分析都是 pcap 侧的东西：代理模式下它们什么都不做，
          // 所以只留在抓包侧显示，代理模式的入口收在 `更多设置` 里。
          if (_mode != SourceMode.proxy) ...[
            Tooltip(
              message: 'SSLKEYLOGFILE 格式的密钥日志（--keylog）。\n'
                  '有它才能解密 TLS 1.3 / 1.2 并解析其中的 HTTPS 事务；\n'
                  '浏览器导出方式见 SSLKEYLOGFILE 环境变量。',
              child: OutlinedButton.icon(
                onPressed: _running ? null : _pickKeylog,
                style: OutlinedButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
                icon: const Icon(Icons.vpn_key_outlined, size: 16),
                label: Text(
                  _keylog.isEmpty ? '密钥日志' : _baseName(_keylog),
                  style: const TextStyle(fontSize: 12),
                ),
              ),
            ),
            Tooltip(
              message: '按 TCP 流重组、用密钥日志解密 TLS 并提取 HTTP 事务'
                  '（--streams --http；实时抓包用 --follow 随传随报）。',
              child: FilterChip(
                label: const Text('流分析'),
                selected: _analyze,
                onSelected: (v) => setState(() {
                  _analyze = v;
                  if (!v) {
                    _http.clear();
                    _streams.clear();
                    _selectedHttp = null;
                  }
                }),
              ),
            ),
          ],
          if (_mode != SourceMode.proxy)
            OutlinedButton.icon(
              onPressed: _running ? null : () => setState(() => _mode = SourceMode.proxy),
              style: OutlinedButton.styleFrom(
                visualDensity: VisualDensity.compact,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              icon: const Icon(Icons.shield_outlined, size: 16),
              label: const Text('回到拦截代理', style: TextStyle(fontSize: 12)),
            ),
          if (_mode != SourceMode.proxy && !_analyze)
            const Pill(text: '未启用重组与解密', color: Color(0xFFFFB454)),
          if (_limit > 0)
            Pill(text: '上限 $_limit 包', color: cs.primary),
        ],
      ),
    );
  }

  /// Proxy mode, deliberately reduced to what a non-technical user needs.
  /// The rule list is no longer a path box: other ad blockers show you a list of
  /// filter lists with a switch each, so this is one button that opens that page
  /// and reports what is on.  The listen address and the two request-side
  /// switches live behind "更多设置", because "filter my ads" does not need them.
  Widget _proxyControls() {
    return Row(
      children: [
        Expanded(
          flex: 3,
          child: OutlinedButton.icon(
            onPressed: _openRulesPage,
            icon: const Icon(Icons.rule_folder_outlined, size: 16),
            label: Align(
              alignment: Alignment.centerLeft,
              child: Text(
                '过滤列表：${_lists?.summary ?? '内置列表'}${_picking ? ' · 点选中' : ''}',
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontSize: 12.5),
              ),
            ),
          ),
        ),
        const SizedBox(width: 6),
        // One button, like every other ad blocker: press it, the cursor turns
        // into a crosshair *in the pages that are already open* (a small script
        // is in every page and polls the proxy), and the next click on an
        // element blocks it.  No reload, no settings page.
        Tooltip(
          message: _picking
              ? '点选中：在页面上点元素就能拦掉它。再按一次结束。\n'
                  '鼠标没变十字？那个页面是在代理开始运行之前打开的——按 Ctrl+F5 刷新一次。'
              : '按一下让当前打开的页面进入点选：鼠标变十字，点页面上任何元素即可拦掉它。\n'
                  '页面必须是在代理运行期间加载的（脚本随页面一起下来）；'
                  '如果它是启动代理之前打开的、或者来自缓存，先按 Ctrl+F5 刷新一次。',
          child: FilterChip(
            avatar: Icon(
              _picking ? Icons.colorize : Icons.colorize_outlined,
              size: 15,
              color: _picking ? const Color(0xFF7EE787) : null,
            ),
            label: Text(_picking ? '点选中' : '点选元素'),
            selected: _picking,
            onSelected: (value) => _setPicking(value),
          ),
        ),
        const SizedBox(width: 6),
        // Everything that is not "filter my ads" lives behind this one button:
        // the settings pages used to have their own toolbar buttons, which
        // crowded the bar (the pane itself is status only).
        OutlinedButton.icon(
          onPressed: _openProxyAdvanced,
          icon: const Icon(Icons.tune, size: 15),
          label: const Text('更多设置'),
        ),
        const SizedBox(width: 6),
        // The raw netcap output has its own window (see _showLogWindow): it used
        // to be pasted into the right-hand column, where it buried the counters.
        OutlinedButton.icon(
          onPressed: _showLogWindow,
          icon: const Icon(Icons.receipt_long_outlined, size: 15),
          label: Text(_logs.isEmpty ? '日志' : '日志 ${_logs.length}'),
        ),
      ],
    );
  }

  /// Asks for one more list file (the rules page passes its own picker in tests).
  Future<String?> _pickListFile() {
    return FileBrowserDialog.show(
      context,
      initialDirectory: _workspace.isEmpty ? Directory.current.path : _workspace,
    );
  }

  /// The netcap output lives in its own window: the right-hand column reports
  /// state (connection, certificate, takeover, counters), it does not print
  /// logs. Live-updating while it is open, with copy and clear.
  Future<void> _showLogWindow() async {
    await showDialog<void>(
      context: context,
      builder: (ctx) => LogWindow(
        lines: _logs,
        onCopy: () => _copyToClipboard(_logs.join('\n')),
        onClear: () {
          if (mounted) setState(_logs.clear);
        },
      ),
    );
    if (mounted) setState(() {});
  }

  /// The three set-once knobs: where to listen, drop third-party cookies, and
  /// whether to log the traffic that was let through.
  Future<void> _openProxyAdvanced() async {
    if (_running) return;
    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          title: const Text('更多设置'),
          content: SizedBox(
            width: 420,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                TextField(
                  controller: _serveCtrl,
                  style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
                  decoration: const InputDecoration(
                    isDense: true,
                    labelText: '监听地址（别的程序把代理填这里）',
                    border: OutlineInputBorder(),
                    contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 12),
                  ),
                ),
                const SizedBox(height: 10),
                Material(
                  type: MaterialType.transparency,
                  child: SwitchListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    value: _thirdPartyCookies,
                    title: const Text('去掉第三方 Cookie', style: TextStyle(fontSize: 13)),
                    subtitle: const Text('跨站请求的 Cookie 头直接不发出去（--third-party-cookies）',
                        style: TextStyle(fontSize: 11.5)),
                    onChanged: (v) {
                      setState(() => _thirdPartyCookies = v);
                      setLocal(() {});
                    },
                  ),
                ),
                Material(
                  type: MaterialType.transparency,
                  child: SwitchListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    value: _showBlocks,
                    title: const Text('记录放行的请求', style: TextStyle(fontSize: 13)),
                    subtitle: const Text('没被拦的判定也打印出来，便于排查（--show-blocks）',
                        style: TextStyle(fontSize: 11.5)),
                    onChanged: (v) {
                      setState(() => _showBlocks = v);
                      setLocal(() {});
                    },
                  ),
                ),
                const Divider(height: 22),
                const Text('设置页', style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600)),
                const SizedBox(height: 6),
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () {
                          Navigator.of(ctx).pop();
                          // Open the page once this dialog is out of the way.
                          WidgetsBinding.instance.addPostFrameCallback((_) => _openMitmPage());
                        },
                        icon: const Icon(Icons.lock_outline, size: 15),
                        label: const Text('HTTPS 过滤'),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () {
                          Navigator.of(ctx).pop();
                          WidgetsBinding.instance.addPostFrameCallback((_) => _openTakeoverPage());
                        },
                        icon: const Icon(Icons.alt_route_outlined, size: 15),
                        label: const Text('流量接管'),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () {
                          Navigator.of(ctx).pop();
                          WidgetsBinding.instance.addPostFrameCallback((_) => _openRulesPage());
                        },
                        icon: const Icon(Icons.rule, size: 15),
                        label: const Text('规则'),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () {
                          Navigator.of(ctx).pop();
                          // Open the page once this dialog is out of the way.
                          WidgetsBinding.instance.addPostFrameCallback((_) => _openLogPage());
                        },
                        icon: const Icon(Icons.receipt_long_outlined, size: 15),
                        label: const Text('过滤日志页'),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                const Text(
                    'HTTPS 过滤管「哪些程序解密」，流量接管管「所有程序是否自动走 netcap」，规则页管「拦什么」，过滤日志页看「刚才都判了什么」。',
                    style: TextStyle(fontSize: 11.5)),
                const Divider(height: 22),
                const Text('抓包与解密（pcap 侧）',
                    style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600)),
                const SizedBox(height: 6),
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: _running
                            ? null
                            : () {
                                Navigator.of(ctx).pop();
                                WidgetsBinding.instance
                                    .addPostFrameCallback((_) => _pickKeylog());
                              },
                        icon: const Icon(Icons.vpn_key_outlined, size: 15),
                        label: Text(
                          _keylog.isEmpty ? '选择密钥日志' : _baseName(_keylog),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    FilterChip(
                      label: const Text('流分析'),
                      selected: _analyze,
                      onSelected: (v) {
                        setState(() {
                          _analyze = v;
                          if (!v) {
                            _http.clear();
                            _streams.clear();
                            _selectedHttp = null;
                          }
                        });
                        setLocal(() {});
                      },
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                const Text(
                    '这两样只在 pcap 文件 / 实时网卡模式有用（密钥日志解密 TLS，流分析按 TCP 流重组并提取 HTTP），代理模式用不上，所以从工具栏收进这里。',
                    style: TextStyle(fontSize: 11.5)),
                const SizedBox(height: 6),
                Align(
                  alignment: Alignment.centerLeft,
                  child: TextButton.icon(
                    onPressed: () {
                      Navigator.of(ctx).pop();
                      WidgetsBinding.instance.addPostFrameCallback((_) => _start());
                    },
                    icon: const Icon(Icons.play_arrow, size: 16),
                    label: const Text('只启动代理（不改系统代理）'),
                  ),
                ),
                const Text('只有显式把代理填到上面那个地址的程序会走过滤（curl、手动设置了代理的浏览器等）。',
                    style: TextStyle(fontSize: 11.5)),
              ],
            ),
          ),
          actions: [
            FilledButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('完成'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _deviceDropdown() {
    if (_deviceLoading) {
      return const SizedBox(
        width: 330,
        height: 36,
        child: Center(child: LinearProgressIndicator(minHeight: 2)),
      );
    }
    if (_devices.devices.isEmpty) {
      return SizedBox(
        width: 330,
        child: Row(
          children: [
            const Text('没有枚举到网卡', style: TextStyle(fontSize: 12)),
            const SizedBox(width: 8),
            TextButton(
              onPressed: _running ? null : _loadDevices,
              child: const Text('重试'),
            ),
          ],
        ),
      );
    }
    return SizedBox(
      width: 330,
      child: Row(
        children: [
          Expanded(
            child: DropdownButtonFormField<String>(
              initialValue: _devices.devices.any((d) => '${d.index}' == _device)
                  ? _device
                  : null,
              isExpanded: true,
              style: const TextStyle(fontSize: 12),
              decoration: const InputDecoration(
                isDense: true,
                border: OutlineInputBorder(),
                contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 10),
              ),
              items: [
                for (final d in _devices.devices)
                  DropdownMenuItem<String>(
                    value: '${d.index}',
                    child: Text(
                      d.label,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(fontSize: 12),
                    ),
                  ),
              ],
              onChanged: _running ? null : (v) => setState(() => _device = v ?? ''),
            ),
          ),
          IconButton(
            tooltip: '刷新网卡列表',
            onPressed: _running ? null : _loadDevices,
            icon: const Icon(Icons.refresh, size: 18),
          ),
        ],
      ),
    );
  }

  Widget _filterBar() {
    final cs = Theme.of(context).colorScheme;
    const quick = <String>[
      'tcp',
      'udp',
      'tls',
      'http',
      'dns',
      'icmp',
      'arp',
      'ip6',
      'vlan',
      'fragment',
    ];
    return Container(
      color: const Color(0xFF0F141A),
      padding: const EdgeInsets.fromLTRB(10, 6, 10, 6),
      child: Wrap(
        crossAxisAlignment: WrapCrossAlignment.center,
        spacing: 8,
        runSpacing: 6,
        children: [
          SizedBox(
            width: 420,
            child: TextField(
              controller: _filterCtrl,
              enabled: !_running,
              style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
              decoration: InputDecoration(
                isDense: true,
                prefixIcon: const Icon(Icons.filter_alt_outlined, size: 16),
                prefixIconConstraints:
                    const BoxConstraints(minWidth: 32, minHeight: 32),
                suffixIcon: IconButton(
                  tooltip: '语法帮助',
                  icon: const Icon(Icons.help_outline, size: 15),
                  onPressed: () => _showFilterHelp(),
                ),
                border: const OutlineInputBorder(),
                contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
                hintText: '过滤器，例如 tcp and dst port 443，或 hostname example.com',
              ),
              onSubmitted: (_) {
                if (!_running) _start();
              },
            ),
          ),
          for (final q in quick)
            ActionChip(
              label: Text(q, style: const TextStyle(fontSize: 11)),
              visualDensity: VisualDensity.compact,
              onPressed: _running
                  ? null
                  : () {
                      final text = _filterCtrl.text.trim();
                      final next = text.isEmpty ? q : '$text and $q';
                      setState(() => _filterCtrl.text = next);
                    },
            ),
          const SizedBox(width: 4),
          SizedBox(
            width: 170,
            child: TextField(
              controller: _searchCtrl,
              style: const TextStyle(fontSize: 12),
              decoration: InputDecoration(
                isDense: true,
                prefixIcon: const Icon(Icons.search, size: 15),
                prefixIconConstraints:
                    const BoxConstraints(minWidth: 30, minHeight: 30),
                border: const OutlineInputBorder(),
                contentPadding: const EdgeInsets.symmetric(horizontal: 6, vertical: 10),
                hintText: '本地搜索已捕获包',
              ),
              onChanged: (v) => setState(() {
                _search = v.trim();
                _resyncSelection();
              }),
            ),
          ),
          Tooltip(
            message: '自动滚动到最新数据包',
            child: IconButton(
              isSelected: _follow,
              onPressed: () => setState(() => _follow = !_follow),
              icon: Icon(_follow ? Icons.vertical_align_bottom : Icons.pause_presentation,
                  size: 18),
            ),
          ),
          Tooltip(
            message: '清空当前列表',
            child: IconButton(
              onPressed: _running
                  ? null
                  : () => setState(() {
                        _packets.clear();
                        _pending.clear();
                        _evicted = 0;
                        _selected = null;
                        _summary = null;
                        _intercepts.clear();
                        _interceptSummary = null;
                        _selectedIntercept = null;
                      }),
              icon: const Icon(Icons.delete_outline, size: 18),
            ),
          ),
          if (_search.isNotEmpty)
            Pill(text: '本地命中 ${_visible.length}', color: cs.tertiary),
        ],
      ),
    );
  }

  Widget _errorBar(String message) {
    final cs = Theme.of(context).colorScheme;
    final livePermission = message.contains('10013') ||
        message.contains('管理员') ||
        message.contains('Administrator') ||
        message.contains('cap_net_raw');
    return Container(
      width: double.infinity,
      color: cs.error.withValues(alpha: 0.12),
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.error_outline, size: 17, color: cs.error),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SelectableText(
                  message,
                  style: TextStyle(fontSize: 12, color: cs.error, height: 1.3),
                ),
                if (livePermission)
                  Padding(
                    padding: const EdgeInsets.only(top: 3),
                    child: Text(
                      '实时抓包使用原始套接字 + SIO_RCVALL，Windows 只授予管理员进程；'
                      '请以管理员身份运行本程序，或改用「pcap 文件」模式分析已有抓包。',
                      style: TextStyle(
                        fontSize: 11.5,
                        color: cs.onSurfaceVariant,
                        height: 1.3,
                      ),
                    ),
                  ),
              ],
            ),
          ),
          IconButton(
            tooltip: '复制错误',
            onPressed: () => _copyToClipboard(message),
            icon: const Icon(Icons.copy_all_outlined, size: 16),
          ),
          IconButton(
            tooltip: '关闭',
            onPressed: () => setState(() => _errorText = null),
            icon: const Icon(Icons.close, size: 16),
          ),
        ],
      ),
    );
  }

  /// The process column only earns its width when something can fill it.
  bool get _showProc =>
      _attrib || _blockFilter.isNotEmpty || _splitBy == 'proc' || _packets.any((p) => p.hasProc);

  /// Per-process counters come from the summary; a live capture never has one.
  List<ProcCount> get _procCounts => _summary?.procs ?? const <ProcCount>[];

  /// Live `block` events when there are any, otherwise the summary report.
  List<BlockAction> get _blockActions =>
      _blocks.isNotEmpty ? _blocks : (_summary?.block.actions ?? const <BlockAction>[]);

  bool get _blockVisible => _blocks.isNotEmpty || (_summary?.block.enabled ?? false);

  // ------------------------------------------------------------- interception

  /// In proxy mode the C++ side owns the filtering, so this bar is only a local
  /// search over the decisions that already arrived.
  Widget _interceptBar() {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(8, 6, 8, 6),
      child: Row(
        children: [
          Icon(Icons.filter_alt_outlined, size: 16, color: cs.primary),
          const SizedBox(width: 8),
          Expanded(
            child: TextField(
              controller: _interceptSearchCtrl,
              style: const TextStyle(fontSize: 12),
              decoration: const InputDecoration(
                isDense: true,
                border: OutlineInputBorder(),
                contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                hintText: '本地搜索：域名、规则、动作、客户端…',
              ),
              onChanged: (v) => setState(() => _interceptSearch = v.trim()),
            ),
          ),
          const SizedBox(width: 8),
          Pill(text: '命中 ${_interceptVisible.length}', color: cs.tertiary),
          if (_thirdPartyCookies) ...[
            const SizedBox(width: 6),
            Pill(text: '去第三方 Cookie', color: cs.primary),
          ],
        ],
      ),
    );
  }

  List<InterceptRecord> get _interceptVisible {
    if (_interceptSearch.isEmpty) return _intercepts;
    return _intercepts.where((e) => e.matchesSearch(_interceptSearch)).toList();
  }

  /// How many decisions carried this action. While the proxy runs the summary
  /// does not exist yet, so the events that already arrived are counted; once
  /// it stops, the summary is authoritative (it also counts what was not logged).
  int _interceptCount(String action) {
    final s = _interceptSummary;
    if (s == null) {
      return _intercepts.where((e) => e.action == action).length;
    }
    switch (action) {
      case 'block':
        return s.blocked;
      case 'modify':
        return s.modified;
      case 'redirect':
        return s.redirected;
      case 'pass':
        return s.passed;
      case 'tunnel':
        return s.tunnels;
      case 'cancelled':
        return s.cancelled;
      case 'error':
        return s.errors;
    }
    return 0;
  }

  /// The action colours mirror the packet table's protocol colours.
  Color _actionColor(String action) {
    switch (action) {
      case 'block':
        return const Color(0xFFF85149);
      case 'modify':
      case 'redirect':
        return const Color(0xFFD29922);
      case 'tunnel':
        return const Color(0xFF8B949E);
      case 'cancelled':
        // The client hung up: grey, never red.
        return const Color(0xFF8B949E);
      case 'error':
        return const Color(0xFFFF7B72);
      default:
        return const Color(0xFF3FB950);
    }
  }

  /// Where the CA lives by default: the `_mitmca` pair next to the sample files
  /// when it exists (that is what `--ca-init --ca _mitmca` creates), else
  /// netcap's own default name, resolved against the workspace.
  String _defaultCaPrefix() {
    if (_workspace.isEmpty) return 'netcap-ca';
    final preferred = '$_workspace${Platform.pathSeparator}_mitmca';
    if (File('$preferred.crt').existsSync()) return preferred;
    return '$_workspace${Platform.pathSeparator}netcap-ca';
  }

  /// Reads the CA files and asks Windows whether that certificate is trusted.
  Future<void> _detectCa({bool quiet = false}) async {
    final runner = _runner;
    final prefix = _caCtrl.text.trim();
    if (runner == null || prefix.isEmpty) return;
    setState(() => _caBusy = true);
    try {
      final status = await runner.caStatus(prefix: prefix);
      if (!mounted) return;
      setState(() {
        _ca = status;
        _caBusy = false;
      });
      if (!quiet) _appendLog('证书: ${status.label}');
    } on NetcapException catch (e) {
      if (!mounted) return;
      setState(() => _caBusy = false);
      _appendLog('证书检测失败: ${e.message}');
    }
  }

  /// Creates the CA files (`--ca-init`). netcap never installs them itself.
  Future<void> _createCa() async {
    final runner = _runner;
    if (runner == null) return;
    try {
      final out = await runner.createCa(prefix: _caCtrl.text.trim());
      _appendLog(out.split('\n').where((l) => l.trim().isNotEmpty).take(2).join(' · '));
    } on NetcapException catch (e) {
      _appendLog(e.message);
    }
    await _detectCa();
  }

  /// Installs the CA for the current user only, after spelling out what that
  /// means: everything signed by this key becomes trusted for this account.
  Future<void> _installCa() async {
    final status = _ca;
    final runner = _runner;
    if (runner == null) return;
    if (status == null || !status.exists || status.certPath.isEmpty) {
      _appendLog('证书: 还没有 CA 文件，先点「创建 CA」');
      return;
    }
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('安装本地 CA'),
        content: Text(
          '将把这个证书加进「当前用户」的受信任根证书颁发机构：\n\n'
          '${status.certPath}\n'
          '主题：${status.subject}\n'
          'SHA-256：${status.sha256}\n\n'
          '装好之后，任何用这把私钥签发的网站证书都会被这台机器信任——'
          '这正是 HTTPS 解密能工作的原因，也是它的风险。私钥始终留在本机，'
          '不要把它复制到别处。只影响当前用户，不需要管理员。',
          style: const TextStyle(fontSize: 12.5),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('安装')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    try {
      await runner.installCa(status.certPath);
      _appendLog('已安装到当前用户根证书库（卸载：certutil -delstore -user Root "netcap local CA"）');
    } on NetcapException catch (e) {
      _appendLog(e.message);
    }
    await _detectCa();
  }

  /// Removes it again from the current user's store.
  Future<void> _uninstallCa() async {
    final runner = _runner;
    if (runner == null) return;
    try {
      await runner.uninstallCa();
      _appendLog('已从当前用户根证书库移除');
    } on NetcapException catch (e) {
      _appendLog(e.message);
    }
    await _detectCa();
  }

  /// Adds one program to the page's list, or switches the ones already there.
  /// The list is read when the proxy starts, so the UI says so rather than
  /// pretending the running proxy changed its mind.
  void _addToMitmList(String proc, {required bool skip}) {
    final name = proc.trim();
    if (name.isEmpty) return;
    if (_mitmSettings.knows(name)) {
      _appendLog('HTTPS 策略: $name 已经在清单里');
      return;
    }
    setState(() {
      _mitmSettings = _mitmSettings.copyWith(enabled: true).withApp(name, decrypt: !skip);
    });
    _appendLog('HTTPS 策略: ${skip ? '不碰' : '解密'} $name（重启代理后生效）');
  }

  /// The row action behind the application cell: exclude an app from HTTPS
  /// decryption, or make it the only one that is decrypted.
  Future<void> _showMitmAction(InterceptRecord e) async {
    final name = e.clientProc;
    if (name.isEmpty) return;
    final choice = await showDialog<String>(
      context: context,
      builder: (ctx) => SimpleDialog(
        title: Text(name, style: const TextStyle(fontSize: 14)),
        children: [
          SimpleDialogOption(
            onPressed: () => Navigator.pop(ctx, 'skip'),
            child: const Text('不碰这个程序（不解密它的 HTTPS）'),
          ),
          SimpleDialogOption(
            onPressed: () => Navigator.pop(ctx, 'only'),
            child: const Text('把这个程序加进解密名单'),
          ),
          SimpleDialogOption(
            onPressed: () => Navigator.pop(ctx, 'remove'),
            child: const Text('从清单里删掉'),
          ),
        ],
      ),
    );
    if (choice == null || !mounted) return;
    if (choice == 'skip') {
      _addToMitmList(name, skip: true);
      return;
    }
    if (choice == 'only') {
      _addToMitmList(name, skip: false);
      return;
    }
    setState(() {
      _mitmSettings = _mitmSettings.copyWith(
        apps: _mitmSettings.apps.where((a) => a.exe.toLowerCase() != name.toLowerCase()).toList(),
      );
    });
    _appendLog('HTTPS 策略: 已从清单里移除 $name（重启代理后生效）');
  }

  /// The page's choices split back into the three request fields.
  MitmArgs get _mitmArgs => mitmArgsOf(_mitmSettings);

  /// Splits a `a.exe,b.exe` argument; `|`, `;` and spaces work too.
  static List<String> _splitProcList(String text) => text
      .split(RegExp(r'[,|;\s]+'))
      .map((s) => s.trim())
      .where((s) => s.isNotEmpty)
      .toList();

  /// Opens the graphical HTTPS page (the one a non-technical user is meant to
  /// use) and stores whatever it returns, so the next proxy start obeys it.
  /// The rules page: look at the list, and add / change / delete your own rules.
  /// The decisions a *previous* session wrote to the durable log.  The log page
  /// does no IO of its own (widget tests run in fake async, where a real file
  /// read never completes), so the parent reads the file back and hands the page
  /// plain records.  Only the tail is read: the log is append-only and rotates,
  /// and nobody scrolls through a month of history in a dialog.
  Future<List<InterceptRecord>> _filterLogRecords() async {
    final out = <InterceptRecord>[];
    try {
      final file = File(_filterLog);
      if (!await file.exists()) return out;
      final lines = await file.readAsLines();
      const keep = 4000;
      final start = lines.length > keep ? lines.length - keep : 0;
      for (int i = start; i < lines.length; ++i) {
        final trimmed = lines[i].trim();
        if (trimmed.isEmpty || !trimmed.contains('"intercept"')) continue;
        try {
          final json = jsonDecode(trimmed);
          if (json is Map<String, dynamic> && json['type'] == 'intercept') {
            out.add(InterceptRecord.fromJson(json));
          }
        } catch (_) {
          // A half-written last line (the proxy was killed mid-write) is normal.
        }
      }
    } catch (_) {
      // An unreadable log is not worth an error bar: the page shows its empty
      // state and the live list keeps working.
    }
    return out;
  }

  /// The filter log: every decision the proxy made, with the rule that made it.
  /// The panel only shows what the running process has sent so far, so the page
  /// also offers the durable `--log-file` copy — which is the only way to keep a
  /// record of a session after the process is gone.
  Future<void> _openLogPage() async {
    // The freshest record is what the proxy just sent; the file holds what
    // earlier sessions wrote.  Show both (see log_merge.dart for why).
    final combined = mergeFilterLog(_intercepts, await _filterLogRecords());
    if (!mounted) return;
    await showLogPage(
      context,
      records: combined,
      logPath: _filterLog,
      writing: _logToFile,
      onWritingChanged: (value) {
        setState(() => _logToFile = value);
        _appendLog(value
            ? '过滤日志会写到 $_filterLog（重启代理后生效）'
            : '不再写过滤日志文件（重启代理后生效）');
      },
      onClear: () async {
        setState(_intercepts.clear);
        try {
          await File(_filterLog).writeAsString('');
        } catch (_) {
          // A missing or locked file is not worth an error bar: the list is what
          // the user was looking at, and it is already empty.
        }
      },
      export: _exportFilterLog,
      // Rows the file contributed are shown, but the export marks them so a
      // reader does not take last night's three rows for this session's work.
      sessionKeys: _intercepts.map(filterLogKey).toSet(),
    );
  }

  Future<String?> _exportFilterLog(String suggestedName, String contents) async {
    // Save mode: the dialog carries the file name (pre-filled) and refuses to
    // look innocent about an existing one — it says 「覆盖保存」 in that case.
    // It also opens on the desktop rather than next to the .exe, which is where
    // a person actually looks for the file afterwards.
    final home = Platform.environment['USERPROFILE'] ??
        Platform.environment['HOME'] ??
        '';
    final desktop = Directory('$home${Platform.pathSeparator}Desktop');
    final picked = await FileBrowserDialog.show(
      context,
      title: '导出过滤日志',
      initialDirectory:
          home.isNotEmpty && desktop.existsSync() ? desktop.path : null,
      extensions: const ['.txt', '.log', '.jsonl'],
      save: true,
      suggestedName: suggestedName,
    );
    if (picked == null || picked.trim().isEmpty) return null;
    final target = picked.trim();
    try {
      await File(target).writeAsString(contents);
    } catch (e) {
      if (mounted) setState(() => _errorText = '导出失败：$e');
      return null;
    }
    if (mounted) _appendLog('过滤日志已导出到 $target');
    return target;
  }

  Future<void> _openRulesPage() async {
    final runner = _runner;
    if (runner == null) return;
    // Which lists the proxy loads lives in `rule-lists.json`; the page edits it
    // and we persist on every change, so the toolbar summary always matches.
    _lists ??= RuleLists(
      builtinPath: _bundledRules ?? _rulesCtrl.text.trim(),
      userRulesPath: _userRules,
    );
    await showRulesPage(
      context,
      lists: _lists!,
      settingsPath: defaultRuleListsPath(),
      check: runner.checkRule,
      running: _running,
      picking: _picking,
      onPickingChanged: _setPicking,
      pickList: _pickListFile,
      onListsChanged: (next) async {
        _lists = next;
        await next.save(defaultRuleListsPath());
        if (mounted) setState(() {});
      },
      onRestart: () async {
        _stop();
        await Future<void>.delayed(const Duration(milliseconds: 700));
        await _start();
      },
    );
    if (mounted) setState(() {});
  }

  Future<void> _openMitmPage() async {
    final runner = _runner;
    final next = await showMitmPage(
      context,
      settings: _mitmSettings,
      caExists: _ca?.exists ?? false,
      caTrusted: _ca?.trusted ?? false,
      caDetail: _ca?.label ?? '',
      onDetect: () async {
        await _detectCa();
        return '证书：${_ca?.label ?? '未知'}';
      },
      onCreate: () async {
        await _createCa();
        return _ca?.exists == true ? '证书已创建：${_ca!.certPath}' : '证书没有创建成功，请看日志';
      },
      onInstall: () async {
        await _installCa();
        return _ca?.trusted == true ? '证书已安装到当前用户的根证书库' : '证书还没有安装（可能取消了）';
      },
      onUninstall: () async {
        await _uninstallCa();
        return _ca?.trusted == false ? '证书已移除' : '移除命令已执行，请看日志';
      },
      onListRunning: runner == null ? () async => <MitmApp>[] : runner.listProcesses,
    );
    if (next == null || !mounted) return;
    final error = await saveMitmSettings(next);
    if (!mounted) return;
    setState(() => _mitmSettings = next.copyWith(caPrefix: _caCtrl.text.trim()));
    _appendLog(
      'HTTPS 过滤: ${next.summary}${error == null ? '' : '（设置保存失败：$error）'}（重启代理后生效）',
    );
  }

  Color _mitmColor(String mitm) {
    final cs = Theme.of(context).colorScheme;
    switch (mitm) {
      case 'on':
        return cs.primary;
      case 'skip':
        return const Color(0xFFD29922);
      case 'off':
        return cs.onSurfaceVariant;
      default:
        return cs.onSurfaceVariant;
    }
  }

  Widget _interceptTable() {
    final rows = _interceptVisible;
    final cs = Theme.of(context).colorScheme;
    if (rows.isEmpty) {
      return EmptyState(
        icon: Icons.shield_outlined,
        title: _intercepts.isEmpty ? '还没有拦截记录' : '没有匹配的拦截记录',
        detail: _intercepts.isEmpty
            ? '点「启动代理」就开始用内置的广告过滤列表拦广告；'
                '再把浏览器或系统的 HTTP 代理指到这里（默认 127.0.0.1:8080）。'
                '装上证书后 HTTPS 也能看清完整网址。'
            : '换一个搜索词试试。',
      );
    }
    return Column(
      children: [
        Container(
          height: 26,
          color: const Color(0xFF161C24),
          padding: const EdgeInsets.symmetric(horizontal: 8),
          child: Row(
            children: [
              _head('#', 46),
              _head('时间', 110),
              _head('动作', 56),
              _head('方法', 52),
              _head('主机', null, flex: 3),
              _head('目标', null, flex: 4),
              _head('应用', null, flex: 2),
              _head('HTTPS', 52),
              _head('状态', 48),
              _head('规则', null, flex: 2),
            ],
          ),
        ),
        Expanded(
          child: ListView.builder(
            controller: _listScroll,
            itemExtent: 23,
            itemCount: rows.length,
            itemBuilder: (context, i) {
              final e = rows[i];
              final selected = identical(e, _selectedIntercept);
              return InkWell(
                onTap: () => setState(() => _selectedIntercept = e),
                child: Container(
                  color: selected ? cs.primary.withAlpha(36) : null,
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                  child: Row(
                    children: [
                      _cell('${_intercepts.indexOf(e) + 1}', 46,
                          color: cs.onSurfaceVariant),
                      _cell(e.time, 110, color: cs.onSurfaceVariant),
                      _cell(e.actionLabel, 56, color: _actionColor(e.action)),
                      _cell(e.method, 52, color: cs.onSurfaceVariant),
                      _cell(e.host, null, flex: 3),
                      _cell(e.target, null, flex: 4),
                      _cell(
                        e.clientProc.isEmpty ? '—' : e.clientProc,
                        null,
                        flex: 2,
                        color: e.clientProc.isEmpty ? cs.onSurfaceVariant : cs.primary,
                        onTap: e.clientProc.isEmpty ? null : () => _showMitmAction(e),
                        tooltip: e.clientProc.isEmpty
                            ? ''
                            : '按 ${e.clientProc} 设置 HTTPS 解密策略',
                      ),
                      _cell(e.mitmLabel, 52, color: _mitmColor(e.mitm)),
                      _cell(e.status > 0 ? '${e.status}' : '—', 48,
                          color: cs.onSurfaceVariant),
                      _cell(e.rule, null, flex: 2, color: cs.onSurfaceVariant),
                    ],
                  ),
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  /// The proxy prints its final summary only when it stops, so while it is
  /// still serving the panel adds up what has already arrived instead of
  /// showing a row of zeros next to a table full of events.
  InterceptSummary get _interceptTotals {
    final done = _interceptSummary;
    if (done != null) return done;
    final clients = <String>{};
    var blocked = 0, modified = 0, redirected = 0, passed = 0, tunnels = 0, errors = 0;
    var cancelled = 0;
    var bytesIn = 0, bytesOut = 0;
    for (final e in _intercepts) {
      if (e.client.isNotEmpty) clients.add(e.client);
      switch (e.action) {
        case 'block':
          blocked++;
        case 'modify':
          modified++;
        case 'redirect':
          redirected++;
        case 'pass':
          passed++;
        case 'tunnel':
          tunnels++;
        case 'error':
          errors++;
        case 'cancelled':
          cancelled++;
      }
      bytesIn += e.requestBytes;
      bytesOut += e.responseBytes;
    }
    return InterceptSummary(
      connections: clients.length,
      requests: _intercepts.length,
      blocked: blocked,
      modified: modified,
      redirected: redirected,
      passed: passed,
      tunnels: tunnels,
      errors: errors,
      cancelled: cancelled,
      bytesIn: bytesIn,
      bytesOut: bytesOut,
    );
  }

  /// True when the desktop rescue script is really there. Nothing that changes
  /// routing or the system proxy is offered until this answers true.
  Future<bool> _rescueScriptPresent() async {
    final home = Platform.environment['USERPROFILE'] ??
        Platform.environment['HOME'] ??
        '';
    if (home.trim().isEmpty) return false;
    return File(rescueScriptPath(home: home)).exists();
  }

  bool get _takeoverReady =>
      takeoverAllowed(rescueScript: _rescueScript, running: _running) && !_takeoverBusy;

  /// Reads the four registry values (and whether a snapshot exists) without
  /// changing anything.
  Future<void> _refreshSysProxy() async {
    final runner = _runner;
    if (runner == null || _takeoverBusy) return;
    setState(() => _takeoverBusy = true);
    try {
      final present = await _rescueScriptPresent();
      final status = await runner.systemProxyStatus();
      if (!mounted) return;
      setState(() {
        _rescueScript = present;
        _sysProxyStatus = status;
      });
      _appendLog('系统代理：${status.label}');
    } on NetcapException catch (e) {
      _appendLog('系统代理状态读取失败：${e.message}');
    } finally {
      if (mounted) setState(() => _takeoverBusy = false);
    }
  }

  /// Puts the snapshot back — the button for "a takeover outlived its process".
  Future<void> _restoreSysProxy() async {
    final runner = _runner;
    if (runner == null || _takeoverBusy) return;
    setState(() => _takeoverBusy = true);
    try {
      final out = await runner.systemProxyRestore();
      _appendLog('系统代理已还原\n$out');
      final status = await runner.systemProxyStatus();
      if (!mounted) return;
      setState(() => _sysProxyStatus = status);
    } on NetcapException catch (e) {
      _appendLog('还原系统代理失败：${e.message}');
    } finally {
      if (mounted) setState(() => _takeoverBusy = false);
    }
  }

  /// Asks netcap what a takeover would chain to, without touching the registry.
  Future<void> _checkSysProxy() async {
    final runner = _runner;
    if (runner == null || _takeoverBusy) return;
    setState(() {
      _takeoverBusy = true;
      _takeoverReport = '';
    });
    try {
      final text = await runner.systemProxyCheck(
        serve: _serveCtrl.text.trim(),
        rules: _rulesCtrl.text.trim(),
        upstream: _upstreamCtrl.text.trim(),
      );
      if (!mounted) return;
      setState(() => _takeoverReport = text.trim());
    } on NetcapException catch (e) {
      if (!mounted) return;
      setState(() => _takeoverReport = e.message);
    } finally {
      if (mounted) setState(() => _takeoverBusy = false);
    }
  }

  /// `--tun-check`: the read-only half of the drill — what the routes are and
  /// whether a takeover would be allowed.
  Future<void> _tunCheck() async {
    final runner = _runner;
    if (runner == null) return;
    setState(() {
      _takeoverBusy = true;
      _takeoverReport = '';
    });
    try {
      final text = await runner.tunCheck();
      if (!mounted) return;
      setState(() => _takeoverReport = text.trim());
    } finally {
      if (mounted) setState(() => _takeoverBusy = false);
    }
  }

  /// The drill itself: netcap borrows the default route for a few seconds and
  /// streams what the tunnel sees. It refuses to run without a reachable
  /// upstream and rolls the table back on the way out.
  Future<void> _tunDrill() async {
    final runner = _runner;
    if (runner == null || !_takeoverReady) return;
    final upstream = _upstreamCtrl.text.trim().isEmpty
        ? '127.0.0.1:7890'
        : _upstreamCtrl.text.trim();
    setState(() {
      _takeoverBusy = true;
      _takeoverReport = '接管中（$upstream），大约 $_tunSeconds 秒后自动还原…\n';
    });
    try {
      final code = await runner.tunDrill(
        seconds: _tunSeconds,
        upstream: upstream,
        rules: _rulesCtrl.text.trim(),
        address: _tunAddressCtrl.text.trim(),
        onLine: (line) {
          if (!mounted) return;
          setState(() => _takeoverReport = '$_takeoverReport$line\n');
        },
      );
      if (!mounted) return;
      setState(() {
        _takeoverReport = '$_takeoverReport\n演练结束（退出码 $code）；'
            '${code == 0 ? '路由已按计划还原' : '请看上面的输出，必要时双击桌面的 netcap-restore.cmd'}';
      });
    } on NetcapException catch (e) {
      if (!mounted) return;
      setState(() => _takeoverReport = '演练失败：${e.message}');
    } finally {
      if (mounted) setState(() => _takeoverBusy = false);
    }
  }

  /// One press on the capture bar: hand this user's system proxy to netcap (the
  /// same switch as the takeover page's master toggle, minus the page).
  ///
  /// Scope is "programs that honour the system proxy", not literally every
  /// process: a program with its own network stack never reads this setting, and
  /// nothing here can change that — TUN is the mode that catches those.  Pressing
  /// it while the proxy runs stops and restarts, because the flags are read at
  /// startup.
  ///
  /// Safety is not this method's job: `netcap --system-proxy on` probes the
  /// previous hop first and refuses the takeover (exit code 4) when nothing
  /// answers, and the desktop `netcap-restore.cmd` is the way back.
  Future<void> _toggleAllPrograms() async {
    final next = !_sysProxy;
    if (_running) {
      _stop();
      await Future<void>.delayed(const Duration(milliseconds: 700));
      if (!mounted) return;
    }
    setState(() {
      _sysProxy = next;
      // The system proxy and the TUN session are mutually exclusive.
      if (next && _tunSession) _tunSession = false;
    });
    _appendLog(next
        ? '接管系统代理：把它临时指向 127.0.0.1:8080，读系统代理的程序都会走过滤（退出时按快照还原）'
        : '取消接管：启动时不动系统代理，只有自己设了代理的程序会走过滤');
    if (next && _upstreamCtrl.text.trim().isEmpty) {
      _appendLog('上游留空：netcap 会自己试 127.0.0.1:7890/7897/…，都没人应答就拒绝接管（机器不会断网）');
    }
    if (!_running) await _start();
  }

  /// The live takeover state as the page's value object.  One source of truth:
  /// the page edits a copy, and what comes back is written into these fields.
  TakeoverDraft get _takeoverDraft => TakeoverDraft(
        systemProxy: _sysProxy,
        systemProxyForce: _sysProxyForce,
        bypass: _sysProxyBypassCtrl.text.trim().isEmpty
            ? '<local>'
            : _sysProxyBypassCtrl.text.trim(),
        tun: _tunSession,
        tunAdapter: _tunAdapterCtrl.text.trim(),
        upstream: _upstreamCtrl.text.trim(),
        tunAddress: _tunAddressCtrl.text.trim(),
        tunSeconds: _tunSeconds,
      );

  /// Everything about taking over the machine's traffic lives on its own page:
  /// a dozen switches and boxes next to the packet table were unreadable.
  /// The small methods below turn the existing state changes into the text the
  /// page shows in its "结果" card.
  Future<void> _openTakeoverPage() async {
    // Fill the "现在：" line before showing the page, so nobody has to press
    // refresh to find out what the machine is doing.
    if (_sysProxyStatus == null) await _refreshSysProxy();
    if (!mounted) return;
    final draft = await showTakeoverPage(
      context,
      draft: _takeoverDraft,
      rescueScript: _rescueScript,
      proxyStatusLabel: _sysProxyStatus?.label ?? '',
      proxyStatusDetail: _sysProxyStatus?.detail ?? '',
      onReadCurrent: _readSysProxyForPage,
      onCheckChain: _checkChainForPage,
      onRestoreProxy: _restoreSysProxyForPage,
      onTunCheck: _tunCheckForPage,
      onTunDrill: _tunDrillForPage,
    );
    if (draft == null || !mounted) return;
    setState(() {
      _sysProxy = draft.systemProxy;
      _sysProxyForce = draft.systemProxyForce;
      _sysProxyBypassCtrl.text = draft.bypass;
      _tunSession = draft.tun;
      _tunAdapterCtrl.text = draft.tunAdapter;
      _upstreamCtrl.text = draft.upstream;
      _tunAddressCtrl.text = draft.tunAddress;
      _tunSeconds = draft.tunSeconds;
    });
    _appendLog('流量接管: ${draft.summary}');
  }

  Future<String> _readSysProxyForPage() async {
    await _refreshSysProxy();
    final status = _sysProxyStatus;
    if (status == null) return '读不到当前用户的系统代理设置。';
    return '${status.label}\n${status.detail}';
  }

  Future<String> _checkChainForPage() async {
    if (_running) return '代理正在运行：先停止，再来检查会链到哪。';
    await _checkSysProxy();
    final text = _takeoverReport.trim();
    return text.isEmpty ? '检查完成。' : text;
  }

  /// netcap puts the old proxy settings back when it exits; this is the belt and
  /// braces.  A session that took the system proxy over ran with `--system-proxy
  /// on`, so as soon as it ends we ask netcap to restore again and show the
  /// result — "stop" should never leave the machine pointed at a proxy that is
  /// gone.
  Future<void> _verifyProxyRestored() async {
    final note = await _restoreSysProxyForPage();
    if (!mounted) return;
    setState(() => _proxyRestoreNote = note);
    _appendLog('系统代理：$note');
  }

  Future<String> _restoreSysProxyForPage() async {
    await _restoreSysProxy();
    final status = _sysProxyStatus;
    return status == null ? '已按快照还原。' : '已按快照还原：${status.label}';
  }

  Future<String> _tunCheckForPage() async {
    await _tunCheck();
    final text = _takeoverReport.trim();
    return text.isEmpty ? '预检完成。' : text;
  }

  Future<String> _tunDrillForPage(int seconds) async {
    final previous = _tunSeconds;
    setState(() => _tunSeconds = seconds);
    await _tunDrill();
    if (mounted) setState(() => _tunSeconds = previous);
    final text = _takeoverReport.trim();
    return text.isEmpty ? '演练结束（没有输出）。' : text;
  }

  /// This pane is a status pane: long paths are shown by file name only
  /// (`rules/adblock.txt`, `sample.keys`), the full path is in the tooltip of the
  /// field that owns it.

  Widget _interceptPane() {
    final cs = Theme.of(context).colorScheme;
    final s = _interceptTotals;
    final rules = <String, int>{};
    for (final e in _intercepts) {
      if (e.rule.isNotEmpty) rules[e.rule] = (rules[e.rule] ?? 0) + 1;
    }
    final top = rules.entries.toList()..sort((a, b) => b.value.compareTo(a.value));
    final sel = _selectedIntercept;
    return ListView(
      padding: const EdgeInsets.only(bottom: 12),
      children: [
        // The row you picked on the left comes first: the pane is there to
        // answer "what happened to this one", everything else is context.
        if (sel == null)
          const Padding(
            padding: EdgeInsets.fromLTRB(10, 10, 10, 0),
            // One line, not a paragraph: with nothing selected the pane belongs
            // to the session status below it.
            child: Text(
              '在左边点一条记录，这里就换成它的详细信息。',
              style: TextStyle(fontSize: 12),
            ),
          )
        else ...[
          const SectionTitle(text: '选中的这一条 Selected'),
          InfoRow(label: '时间', value: sel.time),
          InfoRow(label: '动作', value: sel.actionLabel,
              valueColor: _actionColor(sel.action)),
          InfoRow(label: '方法', value: sel.method.isEmpty ? '—' : sel.method),
          InfoRow(label: '主机', value: sel.host.isEmpty ? '—' : sel.host),
          InfoRow(label: '目标', value: sel.target.isEmpty ? '—' : sel.target),
          InfoRow(label: '客户端', value: sel.client.isEmpty ? '—' : sel.client),
          InfoRow(label: '规则', value: sel.rule.isEmpty ? '—' : sel.rule),
          InfoRow(label: '理由', value: sel.detail.isEmpty ? '—' : sel.detail,
              mono: false),
          InfoRow(label: '状态码', value: sel.status > 0 ? '${sel.status}' : '—'),
          InfoRow(label: '请求/响应', value:
              '${formatCount(sel.requestBytes)} / ${formatCount(sel.responseBytes)}'),
        ],
        const SizedBox(height: 10),
        SectionTitle(text: '当前连接 Connection'),
        InfoRow(
          label: '状态',
          value: _running
              ? (_mitmSettings.active
                  ? '正在拦截（HTTPS 解密已开）'
                  : '正在拦截（只看域名）')
              : (_stopRequested
                  ? '已停止（没有报错）'
                  : (_exitCode > 0 ? '已结束（退出码 $_exitCode）' : '就绪')),
          valueColor: _running ? cs.primary : null,
        ),
        if (_running)
          InfoRow(
            label: '监听',
            value: _serveCtrl.text.isEmpty ? '127.0.0.1:8080' : _serveCtrl.text,
            valueColor: cs.primary,
          ),
        InfoRow(label: '过滤列表', value: _lists?.summary ?? '内置列表'),
        InfoRow(
          label: '上游',
          // What netcap actually decided, not what the field above says: with an
          // empty field netcap picks a working upstream itself and says so on
          // stderr (see chainedUpstreamFrom — a takeover that chains through the
          // proxy that was already in use used to be missed here, so the pane
          // claimed 直连 while traffic was going through Clash).
          value: _running
              ? (chainedUpstreamFrom(_logs) ??
                  (_sysProxy ? '直连（没找到能接力的上游）' : '直连（没有链式上游）'))
              : (_upstreamCtrl.text.trim().isEmpty
                  ? '直连（没有链式上游）'
                  : _upstreamCtrl.text.trim()),
        ),
        // Only status down here.  Everything that *changes* a setting has its own
        // page (the buttons for those pages are in the tool bar), so this pane
        // just reports what the running proxy is doing right now.
        InfoRow(
          label: 'HTTPS 解密',
          value: _mitmSettings.summary,
          valueColor: _mitmSettings.active ? cs.primary : null,
        ),
        InfoRow(
          label: '证书',
          value: _caBusy
              ? '检测中…'
              : (_ca?.label ?? '未知').replaceFirst('证书：', ''),
          valueColor: (_ca?.ready ?? false) ? cs.primary : const Color(0xFFD29922),
        ),
        if (_ca?.exists == true && _ca!.trusted == false)
          const InfoRow(
            label: '提示',
            value: '证书还没装进当前用户的根证书库：浏览器会拒绝解密后的证书，HTTPS 只能看到域名',
          ),
        InfoRow(
          label: '系统接管',
          value: _takeoverDraft.summary,
          valueColor: (_sysProxy || _tunSession) ? cs.primary : null,
        ),
        if (_proxyRestoreNote.isNotEmpty)
          InfoRow(label: '上次还原', value: _proxyRestoreNote, valueColor: cs.primary),
        SectionTitle(text: '拦截统计 Interception'),
        if (!_running && _exitCode >= 0)
          InfoRow(
            label: _stopRequested ? '上次停止' : '退出码',
            value: _stopRequested ? '用户停止（不是报错）' : '$_exitCode',
            valueColor: _exitCode == 0 ? cs.primary : cs.error,
          ),
        InfoRow(label: '连接', value: '${s.connections}'),
        InfoRow(label: '请求', value: '${s.requests}'),
        InfoRow(
          label: '拦截',
          value: '${s.blocked}',
          valueColor: s.blocked > 0 ? const Color(0xFFF85149) : null,
        ),
        InfoRow(
          label: '改写',
          value: '${s.modified}',
          valueColor: s.modified > 0 ? const Color(0xFFD29922) : null,
        ),
        InfoRow(label: '重定向', value: '${s.redirected}'),
        InfoRow(label: '放行', value: '${s.passed}'),
        InfoRow(label: '隧道', value: '${s.tunnels}'),
        InfoRow(
          label: '中断',
          value: '${s.cancelled}',
          // Grey: the client hung up, which is not something to fix.
          valueColor: s.cancelled > 0 ? const Color(0xFF8B949E) : null,
        ),
        InfoRow(
          label: '出错',
          value: '${s.errors}',
          valueColor: s.errors > 0 ? cs.error : null,
        ),
        InfoRow(label: '上行字节', value: formatBytes(s.bytesIn)),
        InfoRow(label: '下行字节', value: formatBytes(s.bytesOut)),
        if (_interceptSummary == null && _intercepts.isNotEmpty)
          const InfoRow(
            label: '汇总',
            value: '进行中：以上是已到达的事件，停止代理后显示 netcap 的最终汇总',
          ),
        const SizedBox(height: 6),
        SectionTitle(text: '命中的规则 Rules (${top.length})'),
        if (top.isEmpty)
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            child: Text('还没有规则命中', style: TextStyle(fontSize: 12)),
          )
        else
          for (final r in top)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 1.5),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      r.key,
                      style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  Pill(text: '${r.value}', color: cs.tertiary),
                ],
              ),
            ),
      ],
    );
  }

  Widget _packetTable() {
    final rows = _visible;
    final cs = Theme.of(context).colorScheme;
    return Column(
      children: [
        Container(
          height: 26,
          color: const Color(0xFF161C24),
          padding: const EdgeInsets.symmetric(horizontal: 8),
          child: Row(
            children: [
              _head('#', 46),
              _head('时间', 110),
              _head('源', null, flex: 3),
              _head('目的', null, flex: 3),
              _head('协议', 58),
              _head('长度', 58),
              _head('应用', 62),
              if (_showProc) _head('进程', 168),
              _head('摘要', null, flex: 4),
            ],
          ),
        ),
        Expanded(
          child: rows.isEmpty
              ? EmptyState(
                  icon: _running ? Icons.downloading : Icons.inbox_outlined,
                  title: _running ? '正在等待数据包…' : '还没有捕获到数据包',
                  detail: _running
                      ? '过滤器可能把它们全部排除了。'
                      : '选择 pcap 文件或网卡后点击「开始捕获」；'
                          '也可以点「生成示例抓包」立即体验。',
                )
              : Scrollbar(
                  controller: _listScroll,
                  child: ListView.builder(
                    controller: _listScroll,
                    itemExtent: 23,
                    itemCount: rows.length,
                    itemBuilder: (context, i) {
                      final p = rows[i];
                      final selected = identical(p, _selected);
                      return _packetRow(p, i, selected, cs);
                    },
                  ),
                ),
        ),
        if (_evicted > 0)
          Container(
            width: double.infinity,
            color: const Color(0xFF161C24),
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
            child: Text(
              '列表上限 $_maxPackets 条，已丢弃最早的 $_evicted 条（摘要中的统计仍然完整）',
              style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
            ),
          ),
      ],
    );
  }

  Widget _head(String text, double? width, {int flex = 1}) {
    final style = TextStyle(
      fontSize: 11,
      fontWeight: FontWeight.w700,
      letterSpacing: 0.3,
      color: Theme.of(context).colorScheme.onSurfaceVariant,
    );
    if (width != null) {
      return SizedBox(width: width, child: Text(text, style: style));
    }
    return Expanded(flex: flex, child: Text(text, style: style));
  }

  Widget _cell(String text, double? width,
      {int flex = 1,
      Color? color,
      bool mono = true,
      TextAlign align = TextAlign.left,
      VoidCallback? onTap,
      String tooltip = ''}) {
    final style = TextStyle(
      fontFamily: mono ? 'Consolas' : null,
      fontSize: 11.5,
      color: color,
    );
    final child = Text(
      text,
      style: style,
      textAlign: align,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
    );
    Widget content = child;
    if (onTap != null) {
      content = Tooltip(
        message: tooltip,
        waitDuration: const Duration(milliseconds: 500),
        child: GestureDetector(
          behavior: HitTestBehavior.opaque,
          onTap: onTap,
          child: child,
        ),
      );
    }
    if (width != null) return SizedBox(width: width, child: content);
    return Expanded(flex: flex, child: content);
  }

  /// Keeps the detail pane on a row that is still visible: after a search or a
  /// process filter the selected packet may have been filtered out, and the
  /// detail header would otherwise name a row that is no longer in the list.
  void _resyncSelection() {
    final visible = _visible;
    if (visible.isEmpty) {
      _selected = null;
    } else if (_selected == null || !visible.contains(_selected)) {
      _selected = visible.first;
    }
  }

  /// Clicking the process of a packet narrows the list to that process. It uses
  /// the same client side search as the search box, so nothing is re-captured.
  void _filterByProcess(PacketRecord p) {
    final needle = p.proc.isNotEmpty
        ? p.proc
        : (p.procPid != 0 ? '${p.procPid}' : p.procLabel);
    setState(() {
      _search = needle;
      _searchCtrl.text = needle;
      _follow = false;
      _resyncSelection();
    });
  }

  Widget _packetRow(PacketRecord p, int index, bool selected, ColorScheme cs) {
    final bg = selected
        ? cs.primary.withValues(alpha: 0.20)
        : (index.isEven ? const Color(0x00000000) : const Color(0x0AFFFFFF));
    return InkWell(
      onTap: () => setState(() {
        _selected = p;
        _follow = false;
      }),
      // A long press on any row filters by that row's process (if it has one).
      onLongPress: p.hasProc ? () => _filterByProcess(p) : null,
      child: Container(
        color: bg,
        padding: const EdgeInsets.symmetric(horizontal: 8),
        child: Row(
          children: [
            _cell('${p.n}', 46, color: cs.onSurfaceVariant),
            _cell(p.time, 110, color: cs.onSurfaceVariant),
            _cell(p.sourceEndpoint, null, flex: 3),
            _cell(p.destEndpoint, null, flex: 3),
            SizedBox(
              width: 58,
              child: Row(
                children: [
                  if (p.malformed)
                    const Tooltip(
                      message: '畸变帧',
                      child: Icon(Icons.warning_amber_rounded, size: 13, color: Color(0xFFFFB454)),
                    ),
                  Flexible(
                    child: Text(
                      p.proto,
                      style: TextStyle(fontSize: 11.5, color: protoColor(p.proto)),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
            ),
            _cell(
              p.truncated ? '${p.len}B/${p.origlen}B' : '${p.len}B',
              58,
              color: p.truncated ? const Color(0xFFFFB454) : null,
            ),
            SizedBox(
              width: 62,
              child: Align(
                alignment: Alignment.centerLeft,
                child: Pill(text: p.appTag.toUpperCase(), color: appColor(p.appTag)),
              ),
            ),
            if (_showProc)
              _cell(
                p.procLabel,
                168,
                color: p.hasProc ? cs.primary : cs.onSurfaceVariant,
                onTap: p.hasProc ? () => _filterByProcess(p) : null,
                tooltip: p.hasProc ? '只看 ${p.procLabel} 的报文（也可长按该行）' : '',
              ),
            _cell(p.summary, null, flex: 4, color: cs.onSurfaceVariant),
          ],
        ),
      ),
    );
  }

  Widget _detailPane() {
    final p = _selected;
    // The 流与 HTTP tab only exists when there is something to look at: a capture
    // with no TCP stream and no HTTP transaction would only show two empty
    // tables, so the tab is hidden instead of advertising nothing.
    final showAnalysis = _analyze && (_streams.isNotEmpty || _http.isNotEmpty);
    final tabs = <String>[
      '详情',
      '字节',
      '原始',
      '统计',
      if (showAnalysis) '流与 HTTP',
    ];
    final tab = _tab < tabs.length ? _tab : 0;
    return Column(
      children: [
        Container(
          height: 32,
          color: const Color(0xFF11161D),
          padding: const EdgeInsets.symmetric(horizontal: 8),
          child: Row(
            children: [
              for (var i = 0; i < tabs.length; i++)
                Padding(
                  padding: const EdgeInsets.only(right: 6),
                  child: ChoiceChip(
                    label: Text(tabs[i], style: const TextStyle(fontSize: 11.5)),
                    selected: tab == i,
                    visualDensity: VisualDensity.compact,
                    onSelected: (_) => setState(() => _tab = i),
                  ),
                ),
              const Spacer(),
              if (p != null && tab < 4)
                Text(
                  '#${p.n} · ${p.time} · ${p.len}B',
                  style: TextStyle(
                    fontSize: 11,
                    fontFamily: 'Consolas',
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(child: _tabBody(p, tab)),
      ],
    );
  }

  Widget _tabBody(PacketRecord? p, int tab) {
    switch (tab) {
      case 0:
        if (p == null) {
          return const EmptyState(
            icon: Icons.touch_app_outlined,
            title: '选择一个数据包',
            detail: '左侧列表中点击任意一行，这里会显示它逐层的解析结果。',
          );
        }
        return DetailTreeView(tree: p.tree);
      case 1:
        if (p == null) return const EmptyState(icon: Icons.memory, title: '选择一个数据包');
        if (p.frameHex != null) {
          return HexDumpView(hex: p.frameHex!);
        }
        if (p.payloadHex != null) {
          return HexDumpView(hex: p.payloadHex!);
        }
        if (p.payloadHead.isNotEmpty) {
          return Column(
            children: [
              Container(
                width: double.infinity,
                color: const Color(0xFF2A2113),
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                child: const Text(
                  '仅记录了载荷前 64 字节。要看完整帧，请在工具栏勾选「记录字节」后重新捕获。',
                  style: TextStyle(fontSize: 11, color: Color(0xFFFFD08A)),
                ),
              ),
              Expanded(child: HexDumpView(hex: p.payloadHead)),
            ],
          );
        }
        return const EmptyState(
          icon: Icons.memory,
          title: '这一帧没有字节记录',
          detail: '在工具栏勾选「记录字节」（netcap --hex-all）后重新捕获即可查看。',
        );
      case 2:
        if (p == null) return const EmptyState(icon: Icons.data_object, title: '选择一个数据包');
        return SelectionArea(
          child: ListView(
            padding: const EdgeInsets.all(10),
            children: [
              Row(
                children: [
                  TextButton.icon(
                    onPressed: () =>
                        _copyToClipboard(const JsonEncoder.withIndent('  ').convert(p.raw)),
                    icon: const Icon(Icons.copy_all_outlined, size: 15),
                    label: const Text('复制 JSON'),
                  ),
                ],
              ),
              SelectableText(
                const JsonEncoder.withIndent('  ').convert(p.raw),
                style: const TextStyle(fontFamily: 'Consolas', fontSize: 11.5, height: 1.35),
              ),
            ],
          ),
        );
      case 3:
        return _statsPane();
      default:
        return _streamsPane();
    }
  }

  // ------------------------------------------------------- streams and HTTP

  String _baseName(String path) {
    final i = path.lastIndexOf('/');
    final j = path.lastIndexOf('\\');
    final k = i > j ? i : j;
    return k >= 0 ? path.substring(k + 1) : path;
  }

  Future<void> _pickKeylog() async {
    final picked = await FileBrowserDialog.show(
      context,
      initialDirectory: _workspace.isEmpty ? Directory.current.path : _workspace,
      title: '选择 SSLKEYLOGFILE 密钥日志',
      // No extension filter: the browser names this file however it likes.
      extensions: const <String>[],
    );
    if (picked == null || !mounted) return;
    setState(() => _keylog = picked);
    _appendLog('密钥日志: $picked');
  }

  Widget _streamsPane() {
    final cs = Theme.of(context).colorScheme;
    final sel = _selectedHttp;
    return Column(
      children: [
        Expanded(
          flex: 3,
          child: Column(
            children: [
              Container(
                height: 26,
                color: const Color(0xFF11161D),
                padding: const EdgeInsets.symmetric(horizontal: 8),
                child: Row(
                  children: [
                    _head('方法', 56),
                    _head('主机 / URL', null, flex: 4),
                    _head('状态', 64),
                    _head('请求/响应', 96),
                    _head('流', 52),
                    _head('标记', 56),
                  ],
                ),
              ),
              const Divider(height: 1),
              Expanded(
                child: _http.isEmpty
                    ? EmptyState(
                        icon: Icons.language_outlined,
                        title: '还没有 HTTP 事务',
                        detail: _keylog.isEmpty
                            ? '明文 HTTP 会被自动识别；HTTPS 需要密钥日志才能解密。'
                                '点击工具栏「密钥日志」选择 SSLKEYLOGFILE 后重新捕获。'
                            : '已选择密钥日志「${_baseName(_keylog)}」，'
                                '捕获到明文或可解密的 HTTP 事务后会显示在这里。',
                      )
                    : ListView.builder(
                        padding: EdgeInsets.zero,
                        itemCount: _http.length,
                        itemBuilder: (_, i) => _httpRow(_http[i], _http[i] == sel, cs),
                      ),
              ),
              if (sel != null)
                SizedBox(
                  height: 168,
                  child: SingleChildScrollView(child: _httpDetail(sel, cs)),
                ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          flex: 2,
          child: Column(
            children: [
              Container(
                height: 26,
                color: const Color(0xFF11161D),
                padding: const EdgeInsets.symmetric(horizontal: 8),
                child: Row(
                  children: [
                    _head('#', 40),
                    _head('客户端 → 服务端', null, flex: 4),
                    _head('协议', 96),
                    _head('包', 44),
                    _head('明文', 72),
                    _head('SNI / 密码套件', null, flex: 3),
                  ],
                ),
              ),
              const Divider(height: 1),
              Expanded(
                child: _streams.isEmpty
                    ? EmptyState(
                        icon: Icons.timeline,
                        title: _analyze ? '还没有 TCP 流' : '未启用重组与解密',
                        detail: _analyze
                            ? '流报告在捕获结束后输出（实时抓包则在传输完成时）。'
                                'HTTPS 内容需要密钥日志才能解密。'
                            : '点击工具栏「流分析」开关，重新捕获即可看到 TCP 流与 HTTP 事务。',
                      )
                    : ListView.builder(
                        padding: EdgeInsets.zero,
                        itemCount: _streams.length,
                        itemBuilder: (_, i) => _streamRow(_streams[i], cs),
                      ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _httpRow(HttpTransactionInfo t, bool selected, ColorScheme cs) {
    final bg = selected
        ? cs.primary.withValues(alpha: 0.20)
        : (t.decrypted ? const Color(0x0A3FB950) : const Color(0x00000000));
    final url = t.url.isNotEmpty ? t.url : (t.host.isNotEmpty ? t.host : '—');
    return InkWell(
      onTap: () => setState(() => _selectedHttp = selected ? null : t),
      child: Container(
        height: 23,
        color: bg,
        padding: const EdgeInsets.symmetric(horizontal: 8),
        child: Row(
          children: [
            _cell(t.method.isEmpty ? '—' : t.method, 56, color: cs.primary),
            _cell(url, null, flex: 4),
            _cell(t.statusLabel, 64, color: t.status >= 400 ? cs.error : null),
            _cell(t.bytesLabel, 96, color: cs.onSurfaceVariant),
            _cell(t.streamId == null ? '—' : '#${t.streamId}', 52, color: cs.onSurfaceVariant),
            SizedBox(
              width: 56,
              child: Row(
                children: [
                  if (t.decrypted)
                    const Pill(text: '解密', color: Color(0xFF3FB950)),
                  if (t.http2)
                    const Padding(
                      padding: EdgeInsets.only(left: 3),
                      child: Pill(text: 'h2', color: Color(0xFF58A6FF)),
                    ),
                  if (t.truncated)
                    const Padding(
                      padding: EdgeInsets.only(left: 3),
                      child: Icon(Icons.content_cut, size: 11, color: Color(0xFFFFB454)),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _httpDetail(HttpTransactionInfo t, ColorScheme cs) {
    return Container(
      width: double.infinity,
      color: const Color(0xFF0F141A),
      padding: const EdgeInsets.fromLTRB(10, 6, 10, 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            t.summary.isNotEmpty ? t.summary : t.label,
            style: const TextStyle(fontFamily: 'Consolas', fontSize: 11.5),
          ),
          const SizedBox(height: 4),
          InfoRow(label: '传输', value: t.transport.isEmpty ? '—' : t.transport),
          InfoRow(
            label: '状态行',
            value: t.statusLine.isNotEmpty ? t.statusLine : t.statusLabel,
          ),
          InfoRow(label: '主机', value: t.host.isEmpty ? '—' : t.host),
          InfoRow(
            label: '内容类型',
            value: t.contentType.isEmpty ? '—' : t.contentType,
          ),
          InfoRow(
            label: '字节',
            value: '请求 ${t.requestBytes}B / 响应 ${t.responseBytes}B',
          ),
          InfoRow(label: '时长', value: '${t.durationMs} ms'),
          InfoRow(
            label: '完整度',
            value: t.complete ? '请求与响应均完整' : '不完整（可能已截断）',
            valueColor: t.complete ? null : const Color(0xFFFFB454),
          ),
          if (t.client.isNotEmpty || t.server.isNotEmpty)
            InfoRow(label: '连接', value: '${t.client} → ${t.server}'),
          if (t.note.isNotEmpty) InfoRow(label: '备注', value: t.note),
        ],
      ),
    );
  }

  Widget _streamRow(StreamInfo s, ColorScheme cs) {
    return Container(
      height: 23,
      padding: const EdgeInsets.symmetric(horizontal: 8),
      child: Row(
        children: [
          _cell('#${s.index}', 40, color: cs.onSurfaceVariant),
          _cell(s.endpoints, null, flex: 4),
          _cell(
            s.protocolLabel,
            96,
            color: s.truncated ? const Color(0xFFFFB454) : protoColor(s.protocolLabel),
          ),
          _cell('${s.packets}', 44, color: cs.onSurfaceVariant, align: TextAlign.right),
          _cell(formatBytes(s.plaintextBytes), 72,
              color: cs.onSurfaceVariant, align: TextAlign.right),
          Expanded(
            flex: 3,
            child: Row(
              children: [
                Flexible(
                  child: Text(
                    s.tls
                        ? (s.sni.isNotEmpty ? s.sni : (s.cipher.isNotEmpty ? s.cipher : '—'))
                        : '—',
                    style: TextStyle(
                      fontFamily: 'Consolas',
                      fontSize: 11.5,
                      color: cs.onSurfaceVariant,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                if (s.tls && s.tlsVersion.isNotEmpty) ...[
                  const SizedBox(width: 6),
                  Text(
                    s.tlsVersion,
                    style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant),
                  ),
                ],
                if (s.decrypted)
                  const Padding(
                    padding: EdgeInsets.only(left: 6),
                    child: Pill(text: '解密', color: Color(0xFF3FB950)),
                  )
                else if (s.tls && s.keysAvailable)
                  const Padding(
                    padding: EdgeInsets.only(left: 6),
                    child: Pill(text: '有密钥', color: Color(0xFF58A6FF)),
                  )
                else if (s.tls && !s.keysAvailable)
                  const Padding(
                    padding: EdgeInsets.only(left: 6),
                    child: Pill(text: '无密钥', color: Color(0xFFFFB454)),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _statsPane() {
    final cs = Theme.of(context).colorScheme;
    final summary = _summary;
    final hello = _hello;
    final apps = _liveApps;
    final maxPackets = apps.isEmpty
        ? 1
        : apps.map((a) => a.packets).reduce((a, b) => a > b ? a : b);

    return SelectionArea(
      child: ListView(
        padding: const EdgeInsets.only(bottom: 16),
        children: [
          if (hello != null) ...[
            const SectionTitle(text: '来源 Source'),
            InfoRow(label: '工具', value: hello.tool),
            InfoRow(label: '模式', value: hello.live ? '实时抓包' : 'pcap 文件'),
            InfoRow(label: '来源', value: hello.source),
            InfoRow(label: '描述', value: hello.described),
            InfoRow(label: '链路类型', value: '${hello.linktypeName} (${hello.linktype})'),
            InfoRow(
              label: '过滤器',
              value: hello.filter.isEmpty ? '（无，全部匹配）' : hello.filter,
            ),
            InfoRow(label: 'snaplen', value: '${hello.snaplen}'),
            InfoRow(label: '时间戳', value: hello.nanosecond ? '纳秒' : '微秒'),
            InfoRow(label: '重组', value: hello.reassembly ? '已启用' : '未启用'),
            InfoRow(
              label: '密钥日志',
              value: hello.keylog.isEmpty
                  ? '未指定（HTTPS 无法解密）'
                  : '${_baseName(hello.keylog)} · '
                      '${hello.keylogLoaded ? '已加载 ${hello.keylogEntries} 条密钥' : '未能加载密钥'}',
              valueColor: hello.keylog.isEmpty
                  ? null
                  : (hello.keylogLoaded ? const Color(0xFF3FB950) : const Color(0xFFFFB454)),
            ),
          ],
          const SectionTitle(text: '统计 Statistics'),
          InfoRow(
            label: '匹配数据包',
            value: formatCount(summary?.matched ?? _matchedCount),
            mono: false,
          ),
          InfoRow(
            label: '匹配字节',
            value: formatBytes(summary?.bytes ?? _matchedBytes),
            mono: false,
          ),
          if (summary != null) ...[
            InfoRow(label: '源数据包总数', value: formatCount(summary.sourcePackets), mono: false),
            InfoRow(label: '被过滤掉', value: formatCount(summary.seen - summary.matched), mono: false),
            InfoRow(
              label: '畸变帧',
              value: formatCount(summary.malformed),
              mono: false,
              valueColor: summary.malformed > 0 ? const Color(0xFFFFB454) : null,
            ),
            InfoRow(
              label: 'IPv4 分片重组',
              value: '${summary.fragSeen} 见 / ${summary.fragCompleted} 完成 / '
                  '${summary.fragDropped} 丢弃 / ${summary.fragPending} 待续',
              mono: false,
            ),
            InfoRow(
              label: '内核丢弃',
              value: summary.kernelStats ? formatCount(summary.kernelDrops) : '不可用（此平台无计数）',
              mono: false,
            ),
            if (summary.writePath.isNotEmpty)
              InfoRow(
                label: '已写出',
                value: '${formatCount(summary.written)} 包 → ${summary.writePath}',
                mono: false,
              ),
            InfoRow(
              label: 'TCP 流',
              value: '${formatCount(summary.streams)} 条 · TLS ${formatCount(summary.tlsStreams)} 条 · '
                  '已解密 ${formatCount(summary.decryptedStreams)} 条'
                  '${summary.reassembly ? '' : '（重组已关闭）'}',
              mono: false,
            ),
            InfoRow(
              label: 'HTTP 事务',
              value: '${formatCount(summary.httpTransactions)} 条 '
                  '（HTTP/1.1 ${formatCount(summary.http1Streams)} 流 · '
                  'HTTP/2 ${formatCount(summary.http2Transactions)} 事务 · '
                  '解密 ${formatCount(summary.httpDecryptedTransactions)}）',
              mono: false,
            ),
            InfoRow(
              label: '已重组字节',
              value: formatBytes(summary.reassembledBytes),
              mono: false,
            ),
            InfoRow(
              label: '密钥',
              value: summary.keylogLabel,
              mono: false,
              valueColor: summary.keysLoaded ? const Color(0xFF3FB950) : null,
            ),
            if (summary.interrupted)
              const InfoRow(
                label: '结束原因',
                value: '被中断（收到 SIGINT）',
                mono: false,
                valueColor: Color(0xFFFFB454),
              ),
          ] else if (_running)
            const InfoRow(label: '统计', value: '实时抓包中，停止后由 netcap 输出最终摘要', mono: false),
          const SectionTitle(text: '应用层分布 Applications'),
          if (apps.isEmpty)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 10),
              child: Text('暂无数据', style: TextStyle(fontSize: 12)),
            )
          else
            for (final a in apps)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 2),
                child: Row(
                  children: [
                    SizedBox(
                      width: 58,
                      child: Pill(text: a.label.toUpperCase(), color: appColor(a.label)),
                    ),
                    const SizedBox(width: 6),
                    Expanded(
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(3),
                        child: LinearProgressIndicator(
                          value: a.packets / maxPackets,
                          minHeight: 8,
                          backgroundColor: const Color(0xFF1B222C),
                          valueColor: AlwaysStoppedAnimation<Color>(appColor(a.label)),
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    SizedBox(
                      width: 112,
                      child: Text(
                        '${formatCount(a.packets)} 包 · ${formatBytes(a.bytes)}',
                        style: const TextStyle(fontFamily: 'Consolas', fontSize: 11),
                        textAlign: TextAlign.right,
                      ),
                    ),
                  ],
                ),
              ),
          if (_procCounts.isNotEmpty) ...[
            const SectionTitle(text: '进程分布 Processes'),
            for (final p in _procCounts)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 2),
                child: Row(
                  children: [
                    SizedBox(
                      width: 168,
                      child: Text(
                        p.display,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontFamily: 'Consolas', fontSize: 11.5),
                      ),
                    ),
                    Expanded(
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(3),
                        child: LinearProgressIndicator(
                          value: (p.packets / maxPackets).clamp(0.0, 1.0),
                          minHeight: 8,
                          backgroundColor: const Color(0xFF1B222C),
                          valueColor: const AlwaysStoppedAnimation<Color>(Color(0xFF7EE787)),
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    SizedBox(
                      width: 112,
                      child: Text(
                        '${formatCount(p.packets)} 包 · ${formatBytes(p.bytes)}',
                        style: const TextStyle(fontFamily: 'Consolas', fontSize: 11),
                        textAlign: TextAlign.right,
                      ),
                    ),
                  ],
                ),
              ),
          ],
          if (_blockVisible) ...[
            const SectionTitle(text: '拦截 Interception'),
            InfoRow(
              label: '策略',
              value: _summary?.block.enabled == true
                  ? '${_summary!.block.mode} · 命中 ${_summary!.block.matched} · 执行 ${_summary!.block.performed} · 跳过 ${_summary!.block.skipped} · 失败 ${_summary!.block.failed}'
                  : '$_blockMode · 本次运行共 ${_blockActions.length} 条判定',
              mono: true,
            ),
            if ((_summary?.block.lastError ?? '').isNotEmpty)
              InfoRow(
                label: '最后错误',
                value: _summary!.block.lastError,
                mono: true,
                valueColor: const Color(0xFFFF7B72),
              ),
            for (final b in _blockActions)
              InfoRow(
                label: '${b.state} ${b.mode}',
                value: '${b.target}${b.process.isEmpty ? '' : '  ${b.process}'}  ${b.detail}',
                mono: true,
                valueColor: b.state == 'fail' ? const Color(0xFFFF7B72) : null,
              ),
          ],
          if ((_summary?.splitFiles ?? const <SplitFile>[]).isNotEmpty) ...[
            const SectionTitle(text: '分文件 Split files'),
            for (final s in _summary!.splitFiles)
              InfoRow(
                label: s.file,
                value: '${formatCount(s.packets)} 包 · ${formatBytes(s.bytes)}',
                mono: true,
              ),
          ],
          if (_lastCommand.isNotEmpty) ...[
            const SectionTitle(
              text: '命令行 Command line',
              trailing: SizedBox.shrink(),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 10),
              child: SelectableText(
                _lastCommand,
                style: TextStyle(
                  fontFamily: 'Consolas',
                  fontSize: 11.5,
                  color: cs.onSurfaceVariant,
                  height: 1.35,
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _statusBar() {
    final cs = Theme.of(context).colorScheme;
    final state = _running
        ? (_stopRequested
            ? '正在停止'
            : (_mode == SourceMode.proxy ? '正在拦截' : '正在捕获'))
        : (_exitCode < 0
            ? '就绪'
            : (_stopRequested ? '已停止' : '已结束（退出码 $_exitCode）'));
    final dotColor = _running
        ? const Color(0xFF3FB950)
        : (_exitCode == 0 || _exitCode < 0 ? cs.onSurfaceVariant : cs.error);
    return Container(
      height: 26,
      color: const Color(0xFF11161D),
      padding: const EdgeInsets.symmetric(horizontal: 10),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(color: dotColor, shape: BoxShape.circle),
          ),
          const SizedBox(width: 6),
          Text(state, style: const TextStyle(fontSize: 11.5)),
          const SizedBox(width: 14),
          if (_mode == SourceMode.proxy) ...[
            Text(
              '拦截 ${_interceptCount('block')} · 改写 ${_interceptCount('modify')} · '
                  '放行 ${_interceptCount('pass') + _interceptCount('tunnel')}',
              style: TextStyle(fontSize: 11.5, fontFamily: 'Consolas', color: cs.onSurfaceVariant),
            ),
            const SizedBox(width: 14),
            if (_running)
              Text(
                '监听 ${_serveCtrl.text.isEmpty ? '127.0.0.1:8080' : _serveCtrl.text}',
                style: TextStyle(fontSize: 11.5, fontFamily: 'Consolas', color: cs.primary),
              )
            else if (_interceptSummary != null)
              Text(
                '请求 ${_interceptSummary!.requests} · 出错 ${_interceptSummary!.errors}',
                style: TextStyle(fontSize: 11.5, fontFamily: 'Consolas', color: cs.onSurfaceVariant),
              ),
          ] else ...[
            Text('匹配 ${formatCount(_matchedCount)} 包',
                style: const TextStyle(fontSize: 11.5, fontFamily: 'Consolas')),
            const SizedBox(width: 12),
            Text(formatBytes(_matchedBytes),
                style: const TextStyle(fontSize: 11.5, fontFamily: 'Consolas')),
          ],
          // No stream and no transaction is nothing to report, and `流 0 ·
          // 解密 0 · HTTP 0` next to a capture that has neither is just noise.
          if (_mode != SourceMode.proxy &&
              _summary != null &&
              (_summary!.streams > 0 || _summary!.httpTransactions > 0)) ...[
            const SizedBox(width: 14),
            Text(
              '流 ${_summary!.streams} · 解密 ${_summary!.decryptedStreams} · '
                  'HTTP ${_summary!.httpTransactions}'
                  '${_summary!.keysLoaded ? ' · 密钥 ${_summary!.keylogEntries}' : ''}',
              style: TextStyle(fontSize: 11.5, fontFamily: 'Consolas', color: cs.onSurfaceVariant),
            ),
          ] else if (_http.isNotEmpty || _streams.isNotEmpty) ...[
            const SizedBox(width: 14),
            Text(
              'HTTP ${_http.length} · 流 ${_streams.length}',
              style: TextStyle(fontSize: 11.5, fontFamily: 'Consolas', color: cs.onSurfaceVariant),
            ),
          ],
          if (_devices.devices.isNotEmpty) ...[
            const SizedBox(width: 14),
            Text(
              '网卡 ${_devices.devices.length} 个'
              '${_devices.mechanismAvailable ? '' : '（实时抓包不可用）'}',
              style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant),
            ),
          ],
          const Spacer(),
          if (_errorText != null)
            Text(
              '出错',
              style: TextStyle(fontSize: 11.5, color: cs.error),
            )
          else if (_location != null)
            Text(
              _location!.path,
              style: TextStyle(fontSize: 11, fontFamily: 'Consolas', color: cs.onSurfaceVariant),
            ),
        ],
      ),
    );
  }

  // ------------------------------------------------------------------ dialogs

  Future<void> _showSettings() async {
    final exportCtrl = TextEditingController(text: _exportCtrl.text);
    var snaplen = _snaplen;
    var limit = _limit;
    var hexPayload = _hexPayload;
    var hexFrame = _hexFrame;
    var promisc = _promisc;
    var attrib = _attrib;
    var noAttrib = _noAttrib;
    var splitBy = _splitBy;
    var blockMode = _blockMode;
    var blockMax = _blockMax;
    final blockCtrl = TextEditingController(text: _blockFilter);
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setLocal) => AlertDialog(
          title: const Text('抓包选项'),
          content: SizedBox(
            width: 520,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const SizedBox(width: 150, child: Text('snaplen')),
                    SizedBox(
                      width: 130,
                      child: TextFormField(
                        initialValue: '$snaplen',
                        decoration: const InputDecoration(isDense: true),
                        onChanged: (v) => snaplen = int.tryParse(v) ?? snaplen,
                      ),
                    ),
                    const SizedBox(width: 16),
                    const Text('每包最多捕获的字节数', style: TextStyle(fontSize: 11)),
                  ],
                ),
                const SizedBox(height: 10),
                Row(
                  children: [
                    const SizedBox(width: 150, child: Text('包数上限')),
                    SizedBox(
                      width: 130,
                      child: TextFormField(
                        initialValue: '$limit',
                        decoration:
                            const InputDecoration(isDense: true, hintText: '0 = 不限制'),
                        onChanged: (v) => limit = int.tryParse(v) ?? limit,
                      ),
                    ),
                    const SizedBox(width: 16),
                    const Text('实时抓包时的 --count', style: TextStyle(fontSize: 11)),
                  ],
                ),
                const SizedBox(height: 10),
                const Divider(),
                SwitchListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  value: hexFrame,
                  onChanged: (v) => setLocal(() => hexFrame = v),
                  title: const Text('记录完整帧字节 (--hex-all)', style: TextStyle(fontSize: 13)),
                  subtitle: const Text('十六进制视图可显示整帧', style: TextStyle(fontSize: 11)),
                ),
                SwitchListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  value: hexPayload,
                  onChanged: (v) => setLocal(() => hexPayload = v),
                  title: const Text('记录载荷字节 (--hex)', style: TextStyle(fontSize: 13)),
                  subtitle: const Text('仅传输层载荷', style: TextStyle(fontSize: 11)),
                ),
                SwitchListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  value: promisc,
                  onChanged: (v) => setLocal(() => promisc = v),
                  title: const Text('网卡混杂模式', style: TextStyle(fontSize: 13)),
                  subtitle: const Text('仅实时抓包有效', style: TextStyle(fontSize: 11)),
                ),
                SwitchListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  value: attrib,
                  onChanged: (v) => setLocal(() {
                    attrib = v;
                    if (v) noAttrib = false;
                  }),
                  title: const Text('归属到进程 (--attrib)', style: TextStyle(fontSize: 13)),
                  subtitle: const Text(
                    '用系统端点表反查每个包属于哪个程序（读文件时名字仅供参考）',
                    style: TextStyle(fontSize: 11),
                  ),
                ),
                SwitchListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  value: noAttrib,
                  onChanged: (v) => setLocal(() {
                    noAttrib = v;
                    if (v) attrib = false;
                  }),
                  title: const Text('完全不做归属 (--no-attrib)', style: TextStyle(fontSize: 13)),
                  subtitle: const Text('实时抓包默认会查表；打开此项可关掉',
                      style: TextStyle(fontSize: 11)),
                ),
                const Divider(),
                const Text('拦截 Interception', style: TextStyle(fontWeight: FontWeight.w600)),
                const SizedBox(height: 6),
                Row(
                  children: [
                    const SizedBox(width: 150, child: Text('--block 过滤器')),
                    Expanded(
                      child: TextFormField(
                        controller: blockCtrl,
                        style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
                        decoration: const InputDecoration(
                          isDense: true,
                          hintText: '留空 = 不拦截，例如 proc chrome and dst port 443',
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    const SizedBox(width: 150, child: Text('--block-mode')),
                    SizedBox(
                      width: 150,
                      child: DropdownButton<String>(
                        value: blockMode,
                        isDense: true,
                        underline: const SizedBox.shrink(),
                        items: const [
                          DropdownMenuItem(value: 'dry-run', child: Text('dry-run 只报告')),
                          DropdownMenuItem(value: 'cut', child: Text('cut 切断连接')),
                          DropdownMenuItem(value: 'kill', child: Text('kill 结束进程')),
                          DropdownMenuItem(value: 'both', child: Text('both 两者都做')),
                        ],
                        onChanged: (v) => setLocal(() => blockMode = v ?? blockMode),
                      ),
                    ),
                    const SizedBox(width: 16),
                    const Text('--block-max', style: TextStyle(fontSize: 12)),
                    const SizedBox(width: 8),
                    SizedBox(
                      width: 70,
                      child: TextFormField(
                        initialValue: '$blockMax',
                        decoration: const InputDecoration(isDense: true),
                        onChanged: (v) => blockMax = int.tryParse(v) ?? blockMax,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 6),
                const Text(
                  'cut / kill 会真的动手：需要管理员权限，只对 IPv4 TCP 生效，且永不碰本程序自己。'
                  '不确定时先留 dry-run，界面会把每条判定连同原因列出来。',
                  style: TextStyle(fontSize: 11, color: Color(0xFFFFB454)),
                ),
                const Divider(),
                Row(
                  children: [
                    const SizedBox(width: 150, child: Text('导出 pcap')),
                    Expanded(
                      child: TextFormField(
                        controller: exportCtrl,
                        style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
                        decoration: const InputDecoration(
                          isDense: true,
                          hintText: r'留空则不导出，例如 D:\out.pcap；分文件记录时写目录',
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                Row(
                  children: [
                    const SizedBox(width: 150, child: Text('分文件记录')),
                    SizedBox(
                      width: 150,
                      child: DropdownButton<String>(
                        value: splitBy,
                        isDense: true,
                        underline: const SizedBox.shrink(),
                        items: const [
                          DropdownMenuItem(value: '', child: Text('关闭')),
                          DropdownMenuItem(value: 'proc', child: Text('按进程 (--split-by proc)')),
                          DropdownMenuItem(value: 'app', child: Text('按应用 (--split-by app)')),
                        ],
                        onChanged: (v) => setLocal(() => splitBy = v ?? ''),
                      ),
                    ),
                    const SizedBox(width: 16),
                    const Expanded(
                      child: Text(
                        '上面的导出 pcap 要写成一个目录，例如 D:\\cap；结束后目录里会有 index.json',
                        style: TextStyle(fontSize: 11),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(),
              child: const Text('取消'),
            ),
            FilledButton(
              onPressed: () {
                setState(() {
                  _snaplen = snaplen;
                  _limit = limit;
                  _hexPayload = hexPayload;
                  _hexFrame = hexFrame;
                  _promisc = promisc;
                  _exportCtrl.text = exportCtrl.text;
                  _attrib = attrib;
                  _noAttrib = noAttrib;
                  _splitBy = splitBy;
                  _blockFilter = blockCtrl.text.trim();
                  _blockMode = blockMode;
                  _blockMax = blockMax;
                });
                Navigator.of(dialogContext).pop();
              },
              child: const Text('保存'),
            ),
          ],
        ),
      ),
    );
    exportCtrl.dispose();
    blockCtrl.dispose();
  }

  Future<void> _showFilterHelp() async {
    await showDialog<void>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('过滤器语法'),
        content: SizedBox(
          width: 720,
          height: 520,
          child: SelectionArea(
            child: ListView(
              children: const [
                SelectableText(
                  _filterHelp,
                  style: TextStyle(
                    fontFamily: 'Consolas',
                    fontSize: 12,
                    height: 1.45,
                  ),
                ),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => _copyToClipboard(_filterHelp),
            child: const Text('复制'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('关闭'),
          ),
        ],
      ),
    );
  }
}

const String _filterHelp = r'''
netcap 过滤表达式（在 netcap 内部求值，不是 BPF；因此可以匹配 TLS SNI / HTTP Host / URL）

连接词
  and       两个条件都成立              tcp and port 443
  or        任一条件成立                tls or http
  not / !   取反                        not arp
  空格      等同于 and                  tcp port 80
  括号      分组                        (tcp or udp) and not port 22

协议
  ip  ip4  ipv4  ip6  ipv6        按网络层版本
  tcp  udp  icmp  icmp6  icmpv6   按传输层
  arp  vlan  fragment  frag       以太网 / 分片
  http  tls  https  ssl  dns  quic  ssh  dhcp  mdns   按应用层识别

地址与端口
  host 10.0.0.5            任一端为该 IP（必须是 IP 字面量）
  src host 10.0.0.5        仅源地址
  dst host 2001:db8::1     仅目的地址
  net 10.0.0.0/24          任一端落在该网段
  port 443                 任一端端口
  src port 51000           仅源端口
  dst port 443             仅目的端口
  portrange 8000-8100      端口区间

以太网与传输层细节
  vlan 100                 VLAN 标签 ID（裸 vlan 表示"存在 VLAN 标签"）
  tcpflags syn             SYN 置位
  tcpflags syn-ack         SYN 与 ACK 都置位
  tcpflags fin,psh         任一命名标志置位均可
  tcpflags 0x12/0xff       掩码匹配（只写 0x12 表示该值精确相等）
  len > 1000               帧长度比较（< <= > >= = !=）
  ttl < 5                  IPv4 TTL / IPv6 hop limit 比较

应用层字符串（大小写不敏感）
  hostname example.com     HTTP Host / TLS SNI / DNS 查询名 的子串
  url /login                HTTP 请求目标（路径+查询）子串
  payload netcap           载荷中的二进制子串

示例
  tcp and dst port 443 and hostname example.com
  tls and hostname github.com
  http and url api
  udp and port 53 and not mdns
  ip6 and icmp6
  (tcp or udp) and not port 22 and not arp
  len > 1000 and ip
''';
