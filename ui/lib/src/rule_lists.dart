// Which filter lists the proxy loads, and where they live.
//
// Design brief (from the user): "这个没必要了 规则借鉴其他软件那种管理方式" — no
// ad blocker asks you to type the path of a rules file into its main window.
// They show a list of filter lists with a switch each, plus a box for your own
// rules.  So the main window has no path field any more, and the rules page owns
// this little model:
//
//   * the bundled list (EasyList + EasyPrivacy, shipped next to netcap.exe),
//   * "my rules" — the short file the user maintains by hand,
//   * any number of extra list files the user adds.
//
// Each one can be switched off; whatever is on is handed to netcap as `--rules`
// (the first enabled list) plus one `--rules-extra` per remaining list.  The
// choice is remembered in `%APPDATA%\netcap-ui\rule-lists.json`.
import 'dart:convert';
import 'dart:io';

/// Reads a text file (injectable: widget tests must not touch the disk).
typedef ListReadFile = Future<String> Function(String path);

/// Writes a text file (same reason).
typedef ListWriteFile = Future<void> Function(String path, String text);

/// One list that can be switched on or off.
class RuleList {
  RuleList({required this.path, this.enabled = true});

  /// Empty for the bundled list until the caller fills it in — that keeps the
  /// remembered file independent of where the app happens to be installed.
  String path;
  bool enabled;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'path': path,
    'enabled': enabled,
  };

  static RuleList fromJson(Object? value) {
    if (value is Map) {
      return RuleList(
        path: '${value['path'] ?? ''}',
        enabled: value['enabled'] != false,
      );
    }
    // Older/looser shapes: a bare string is a path that was on.
    return RuleList(path: '$value');
  }
}

class RuleLists {
  RuleLists({
    required this.builtinPath,
    required this.userRulesPath,
    this.builtinEnabled = true,
    this.userRulesEnabled = true,
    List<RuleList>? extra,
  }) : extra = extra ?? <RuleList>[];

  /// The list shipped with the app (`rules/adblock.txt` next to netcap.exe).
  final String builtinPath;

  /// `%APPDATA%\netcap-ui\my-rules.txt`.
  final String userRulesPath;

  bool builtinEnabled;
  bool userRulesEnabled;
  final List<RuleList> extra;

  /// The list netcap should treat as its base list.  The bundled one wins when
  /// it is on; otherwise the first enabled extra list takes that slot, because
  /// `--serve` refuses to start without a base list.
  String get rulesPath {
    if (builtinEnabled) return builtinPath;
    for (final list in extra) {
      if (list.enabled && list.path.trim().isNotEmpty) return list.path;
    }
    return '';
  }

  /// Everything else, in order, for repeated `--rules-extra`.
  List<String> get extraPaths {
    final out = <String>[];
    final base = rulesPath;
    for (final list in extra) {
      if (list.enabled && list.path.trim().isNotEmpty && list.path != base) {
        out.add(list.path);
      }
    }
    if (userRulesEnabled && userRulesPath.trim().isNotEmpty) out.add(userRulesPath);
    return out;
  }

  bool get anyEnabled =>
      builtinEnabled || extra.any((list) => list.enabled && list.path.trim().isNotEmpty);

  /// Plain-language summary for the status pane: no paths, no flags.
  String get summary {
    final parts = <String>[];
    if (builtinEnabled) parts.add('内置列表');
    if (userRulesEnabled) parts.add('我的规则');
    final others = extra.where((list) => list.enabled && list.path.trim().isNotEmpty).length;
    if (others == 1) {
      parts.add('1 个自定列表');
    } else if (others > 1) {
      parts.add('$others 个自定列表');
    }
    if (parts.isEmpty) return '没有启用任何列表';
    return parts.join(' + ');
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
    'version': 1,
    'builtin': builtinEnabled,
    'userRules': userRulesEnabled,
    'extra': extra.map((list) => list.toJson()).toList(),
  };

  static RuleLists fromJson(
    Object? value, {
    required String builtinPath,
    required String userRulesPath,
  }) {
    if (value is! Map) {
      return RuleLists(builtinPath: builtinPath, userRulesPath: userRulesPath);
    }
    final raw = value['extra'];
    final extra = <RuleList>[];
    bool builtinEnabled = value['builtin'] != false;
    if (raw is List) {
      for (final item in raw) {
        final list = RuleList.fromJson(item);
        if (list.path.trim().isEmpty) continue;
        // A list that points at the built-in file is the same list, not a
        // second one: fold it back into the built-in toggle so the page never
        // shows the same file twice (that duplicate row confused the user).
        if (samePath(list.path, builtinPath)) {
          if (list.enabled) builtinEnabled = true;
          continue;
        }
        extra.add(list);
      }
    }
    return RuleLists(
      builtinPath: builtinPath,
      userRulesPath: userRulesPath,
      builtinEnabled: builtinEnabled,
      userRulesEnabled: value['userRules'] != false,
      extra: extra,
    );
  }

  /// Windows paths are case-insensitive and can be spelled with either slash;
  /// two spellings of one file must not become two rows.
  static bool samePath(String a, String b) {
    String norm(String p) => p.replaceAll('/', r'\').trim().toLowerCase();
    final na = norm(a);
    return na.isNotEmpty && na == norm(b);
  }

  /// Reads the remembered choice.  A missing or broken file means "everything
  /// on", which is what a fresh install should do.
  static Future<RuleLists> load(
    String settingsPath, {
    required String builtinPath,
    required String userRulesPath,
    ListReadFile? readFile,
    ListWriteFile? writeFile,
  }) async {
    final read = readFile ?? (String p) => File(p).readAsString();
    try {
      final text = await read(settingsPath);
      return RuleLists.fromJson(
        jsonDecode(text),
        builtinPath: builtinPath,
        userRulesPath: userRulesPath,
      );
    } catch (_) {
      return RuleLists(builtinPath: builtinPath, userRulesPath: userRulesPath);
    }
  }

  Future<void> save(
    String settingsPath, {
    ListReadFile? readFile,
    ListWriteFile? writeFile,
  }) async {
    final write = writeFile ?? (String p, String t) => File(p).writeAsString(t);
    if (writeFile == null) {
      final dir = File(settingsPath).parent;
      if (!await dir.exists()) await dir.create(recursive: true);
    }
    await write(settingsPath, const JsonEncoder.withIndent('  ').convert(toJson()));
  }

  /// Counts the lines the engine will actually look at.  Comments, blank lines
  /// and `[Adblock Plus 2.0]` headers do not filter anything, so they are not
  /// counted — the number is meant to match what the list really blocks.
  static int countRules(String text) {
    var n = 0;
    for (final raw in text.split('\n')) {
      final line = raw.trim();
      if (line.isEmpty || line.startsWith('!') || line.startsWith('[')) continue;
      n++;
    }
    return n;
  }
}

/// Default location of the remembered choice.
String defaultRuleListsPath() {
  final appData = Platform.environment['APPDATA'];
  final base = (appData == null || appData.isEmpty)
      ? Directory.systemTemp.path
      : '$appData${Platform.pathSeparator}netcap-ui';
  return '$base${Platform.pathSeparator}rule-lists.json';
}
