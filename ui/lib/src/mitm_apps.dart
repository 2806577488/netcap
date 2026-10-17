// The program list behind the graphical HTTPS page.
//
// Why this exists: opening (decrypting) HTTPS traffic is the one setting that
// can break a banking site or a chat client, so the page offers a plain list of
// programs instead of the raw `--mitm-skip` / `--mitm-only` strings.  The
// defaults are the programs a normal person's HTTPS traffic comes from
// (browsers, chat clients, and their Chinese counterparts), because that is
// where ad filtering actually does something.
import 'dart:convert';
import 'dart:io';

/// How much of the machine's HTTPS traffic netcap is allowed to open.
enum MitmScope {
  /// Only the programs on the list; everything else stays an opaque tunnel.
  /// This is the default because it is the safe one.
  selected,

  /// Every program except the ones switched off on the list.
  all,
}

/// One program the user has an opinion about.
class MitmApp {
  const MitmApp({required this.exe, this.label = '', this.decrypt = true});

  /// The image name, e.g. `msedge.exe` — exactly what `--mitm-only` takes.
  final String exe;

  /// A friendly name for the page, e.g. `Edge 浏览器`.  May be empty.
  final String label;

  /// Whether this program's HTTPS is opened.  What "off" means depends on the
  /// [MitmScope]: on [MitmScope.selected] an off program is simply not on the
  /// only-list, on [MitmScope.all] it goes to `--mitm-skip`.
  final bool decrypt;

  /// What the page shows next to the switch.
  String get title => label.trim().isNotEmpty ? label.trim() : exe;

  MitmApp copyWith({String? exe, String? label, bool? decrypt}) => MitmApp(
        exe: exe ?? this.exe,
        label: label ?? this.label,
        decrypt: decrypt ?? this.decrypt,
      );

  Map<String, Object?> toJson() => {'exe': exe, 'label': label, 'decrypt': decrypt};

  /// Returns null instead of throwing: a hand-edited file must not take the
  /// page (or the app) down.
  static MitmApp? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final exe = (raw['exe'] ?? '').toString().trim();
    if (exe.isEmpty) return null;
    return MitmApp(
      exe: exe,
      label: (raw['label'] ?? '').toString().trim(),
      decrypt: raw['decrypt'] == null ? true : _truthy(raw['decrypt']),
    );
  }

  @override
  String toString() => 'MitmApp($exe, decrypt: $decrypt)';
}

bool _truthy(Object? v) {
  if (v is bool) return v;
  if (v is num) return v != 0;
  final s = v.toString().trim().toLowerCase();
  return s == 'true' || s == '1' || s == 'yes' || s == 'on';
}

/// The programs switched on by default: where a normal person's HTTPS lives.
const List<MitmApp> kCommonApps = <MitmApp>[
  MitmApp(exe: 'msedge.exe', label: 'Edge 浏览器'),
  MitmApp(exe: 'chrome.exe', label: '谷歌浏览器 Chrome'),
  MitmApp(exe: 'firefox.exe', label: 'Firefox 火狐'),
  MitmApp(exe: 'brave.exe', label: 'Brave 浏览器'),
  MitmApp(exe: 'opera.exe', label: 'Opera 浏览器'),
  MitmApp(exe: '360se.exe', label: '360 安全浏览器'),
  MitmApp(exe: '360chrome.exe', label: '360 极速浏览器'),
  MitmApp(exe: 'QQBrowser.exe', label: 'QQ 浏览器'),
  MitmApp(exe: 'SogouExplorer.exe', label: '搜狗浏览器'),
  MitmApp(exe: 'WeChat.exe', label: '微信'),
  MitmApp(exe: 'QQ.exe', label: 'QQ'),
  MitmApp(exe: 'TIM.exe', label: 'TIM'),
  MitmApp(exe: 'DingTalk.exe', label: '钉钉'),
  MitmApp(exe: 'Telegram.exe', label: 'Telegram'),
  MitmApp(exe: 'Discord.exe', label: 'Discord'),
];

/// What the user chose on the HTTPS page.
class MitmSettings {
  const MitmSettings({
    this.enabled = true,
    this.scope = MitmScope.selected,
    this.apps = kCommonApps,
    this.caPrefix = '',
  });

  final bool enabled;
  final MitmScope scope;
  final List<MitmApp> apps;
  final String caPrefix;

  /// Programs whose HTTPS we open.
  List<String> get decryptList => apps.where((a) => a.decrypt).map((a) => a.exe).toList();

  /// Programs we must hand back untouched.
  List<String> get skipList => apps.where((a) => !a.decrypt).map((a) => a.exe).toList();

  /// `--mitm-only` value (only meaningful while [scope] is [MitmScope.selected]).
  String get onlyValue => scope == MitmScope.selected ? decryptList.join(',') : '';

  /// `--mitm-skip` value (only meaningful while [scope] is [MitmScope.all]).
  String get skipValue => scope == MitmScope.all ? skipList.join(',') : '';

  /// True when this program's HTTPS is opened.
  bool decrypts(String exe) {
    final on = decryptList.map((e) => e.toLowerCase()).toSet();
    final off = skipList.map((e) => e.toLowerCase()).toSet();
    final key = exe.trim().toLowerCase();
    return scope == MitmScope.all ? !off.contains(key) : on.contains(key);
  }

  /// Whether decryption happens at all.  A selected-scope list with everything
  /// switched off means "no decryption": passing `--mitm` alone would open
  /// *every* program, which is the opposite of what the page shows.
  bool get active => enabled && (scope == MitmScope.all || decryptList.isNotEmpty);

  /// A one-line answer for the status row, in plain language.
  String get summary {
    if (!enabled) return '已关闭：只做纯隧道，看不到加密内容';
    if (scope == MitmScope.all) {
      return skipList.isEmpty
          ? '开启：这台电脑上的所有程序'
          : '开启：所有程序，除了 ${skipList.length} 个';
    }
    if (decryptList.isEmpty) return '没有选中任何程序，等于关闭';
    return '开启：${decryptList.length} 个程序';
  }

  /// The netcap arguments this page turns into.  Empty when nothing should be
  /// decrypted, so the proxy stays a plain tunnel.
  List<String> toArgs() {
    if (!active) return const <String>[];
    final args = <String>[];
    if (caPrefix.trim().isNotEmpty) args.addAll(['--ca', caPrefix.trim()]);
    args.add('--mitm');
    if (onlyValue.isNotEmpty) args.addAll(['--mitm-only', onlyValue]);
    if (skipValue.isNotEmpty) args.addAll(['--mitm-skip', skipValue]);
    return args;
  }

  /// Adds one program (or replaces its label), keeping the list order and
  /// matching image names case-insensitively.
  MitmSettings withApp(String exe, {String label = '', bool decrypt = true}) {
    final name = exe.trim();
    if (name.isEmpty) return this;
    final next = <MitmApp>[];
    var replaced = false;
    for (final a in apps) {
      if (a.exe.toLowerCase() == name.toLowerCase()) {
        next.add(MitmApp(exe: a.exe, label: label.trim().isEmpty ? a.label : label.trim(), decrypt: decrypt));
        replaced = true;
      } else {
        next.add(a);
      }
    }
    if (!replaced) next.add(MitmApp(exe: name, label: label.trim(), decrypt: decrypt));
    return copyWith(apps: next);
  }

  /// Turns one program on or off (used by the switch and by a click on the
  /// interception table's 应用 column).
  MitmSettings setDecrypt(String exe, bool decrypt) {
    final name = exe.trim();
    if (name.isEmpty) return this;
    var found = false;
    final next = <MitmApp>[];
    for (final a in apps) {
      if (a.exe.toLowerCase() == name.toLowerCase()) {
        next.add(a.copyWith(decrypt: decrypt));
        found = true;
      } else {
        next.add(a);
      }
    }
    if (!found) next.add(MitmApp(exe: name, decrypt: decrypt));
    return copyWith(apps: next);
  }

  /// Does the list know this program at all?
  bool knows(String exe) {
    final key = exe.trim().toLowerCase();
    return apps.any((a) => a.exe.toLowerCase() == key);
  }

  MitmSettings copyWith({bool? enabled, MitmScope? scope, List<MitmApp>? apps, String? caPrefix}) =>
      MitmSettings(
        enabled: enabled ?? this.enabled,
        scope: scope ?? this.scope,
        apps: apps ?? this.apps,
        caPrefix: caPrefix ?? this.caPrefix,
      );

  Map<String, Object?> toJson() => {
        'enabled': enabled,
        'scope': scope == MitmScope.all ? 'all' : 'selected',
        'ca_prefix': caPrefix,
        'apps': apps.map((a) => a.toJson()).toList(),
      };

  static MitmSettings fromJson(Object? raw) {
    if (raw is! Map) return const MitmSettings();
    final list = <MitmApp>[];
    final rawApps = raw['apps'];
    if (rawApps is List) {
      for (final item in rawApps) {
        final app = MitmApp.fromJson(item);
        if (app != null) list.add(app);
      }
    }
    return MitmSettings(
      enabled: raw['enabled'] == null ? true : _truthy(raw['enabled']),
      scope: (raw['scope'] ?? '').toString().trim().toLowerCase() == 'all' ? MitmScope.all : MitmScope.selected,
      apps: list.isEmpty ? kCommonApps : list,
      caPrefix: (raw['ca_prefix'] ?? '').toString().trim(),
    );
  }
}

/// The three fields the runner already knows how to pass on.
class MitmArgs {
  const MitmArgs({required this.mitm, this.skip = '', this.only = ''});
  final bool mitm;
  final String skip;
  final String only;
  @override
  String toString() => 'MitmArgs(mitm: $mitm, skip: "$skip", only: "$only")';
}

/// Splits [MitmSettings.toArgs] back into the fields `NetcapRequest` takes, so
/// the page's choices travel through the same (already tested) argument path.
MitmArgs mitmArgsOf(MitmSettings settings) {
  final args = settings.toArgs();
  var mitm = false;
  var skip = '';
  var only = '';
  for (var i = 0; i < args.length; i++) {
    final a = args[i];
    if (a == '--mitm') {
      mitm = true;
    } else if (a == '--mitm-skip' && i + 1 < args.length) {
      skip = args[++i];
    } else if (a == '--mitm-only' && i + 1 < args.length) {
      only = args[++i];
    }
  }
  return MitmArgs(mitm: mitm, skip: skip, only: only);
}

/// Reads the running programs out of `netcap --list-processes` output.
///
/// The line shape is `{"type":"process","name":"msedge.exe","pid":1234}`;
/// anything else is ignored, and duplicates (one browser spawns many
/// processes) collapse into a single entry.
List<MitmApp> runningAppsFromJsonl(String output, {List<String> skipExe = const ['netcap.exe', 'netcap_ui.exe']}) {
  final seen = <String>{};
  final out = <MitmApp>[];
  final skip = skipExe.map((e) => e.toLowerCase()).toSet();
  for (final line in const LineSplitter().convert(output)) {
    final text = line.trim();
    if (text.isEmpty || !text.startsWith('{')) continue;
    Object? decoded;
    try {
      decoded = jsonDecode(text);
    } on FormatException {
      continue;
    }
    if (decoded is! Map) continue;
    if ((decoded['type'] ?? '').toString() != 'process') continue;
    final name = (decoded['name'] ?? '').toString().trim();
    if (name.isEmpty) continue;
    final key = name.toLowerCase();
    if (skip.contains(key) || !seen.add(key)) continue;
    out.add(MitmApp(exe: name));
  }
  out.sort((a, b) => a.exe.toLowerCase().compareTo(b.exe.toLowerCase()));
  return out;
}

/// Where the page remembers the user's choices.  `%APPDATA%\netcap-ui` is the
/// normal place; an installed build without a writable install directory still
/// has a profile directory, so this never depends on the current directory.
String mitmSettingsPath() {
  final env = Platform.environment;
  final base = (env['APPDATA'] ?? '').trim().isNotEmpty
      ? env['APPDATA']!.trim()
      : ((env['USERPROFILE'] ?? env['HOME'] ?? '').trim());
  if (base.isEmpty) return 'mitm-settings.json';
  return '$base${Platform.pathSeparator}netcap-ui${Platform.pathSeparator}mitm-settings.json';
}

/// Loads the saved page settings; a missing or broken file yields the defaults.
Future<MitmSettings> loadMitmSettings({String? path}) async {
  try {
    final file = File(path ?? mitmSettingsPath());
    if (!await file.exists()) return const MitmSettings();
    return MitmSettings.fromJson(jsonDecode(await file.readAsString()));
  } catch (_) {
    return const MitmSettings();
  }
}

/// Saves the page settings; failures are reported to the caller, never thrown
/// out of a button handler.
Future<String?> saveMitmSettings(MitmSettings settings, {String? path}) async {
  try {
    final file = File(path ?? mitmSettingsPath());
    await file.parent.create(recursive: true);
    await file.writeAsString(const JsonEncoder.withIndent('  ').convert(settings.toJson()));
    return null;
  } catch (e) {
    return '$e';
  }
}
