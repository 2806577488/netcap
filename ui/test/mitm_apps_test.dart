import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/mitm_apps.dart';

void main() {
  group('the HTTPS page model', () {
    test('starts on the common programs only', () {
      const s = MitmSettings();
      expect(s.enabled, isTrue);
      expect(s.scope, MitmScope.selected);
      expect(s.apps, kCommonApps);
      expect(s.decryptList, contains('msedge.exe'));
      expect(s.decryptList, contains('WeChat.exe'));
      expect(s.active, isTrue);
      expect(s.knows('chrome.exe'), isTrue);
      expect(s.knows('chrome.exe'.toUpperCase()), isTrue);
      expect(s.knows('bank.exe'), isFalse);
    });

    test('turns the list into --mitm-only while it is the only scope', () {
      const s = MitmSettings(apps: [
        MitmApp(exe: 'msedge.exe', decrypt: true),
        MitmApp(exe: 'bank.exe', decrypt: false),
      ]);
      expect(s.onlyValue, 'msedge.exe');
      expect(s.skipValue, isEmpty);
      expect(s.toArgs(), ['--mitm', '--mitm-only', 'msedge.exe']);
    });

    test('turns the list into --mitm-skip in the all scope', () {
      const s = MitmSettings(scope: MitmScope.all, apps: [
        MitmApp(exe: 'msedge.exe', decrypt: true),
        MitmApp(exe: 'bank.exe', decrypt: false),
      ]);
      expect(s.onlyValue, isEmpty);
      expect(s.skipValue, 'bank.exe');
      expect(s.toArgs(), ['--mitm', '--mitm-skip', 'bank.exe']);
      expect(s.decrypts('msedge.exe'), isTrue);
      expect(s.decrypts('bank.exe'), isFalse);
      expect(s.decrypts('something-else.exe'), isTrue);
    });

    test('puts the CA in front of the decryption flags', () {
      const s = MitmSettings(caPrefix: '_mitmca');
      expect(s.toArgs().take(3).toList(), ['--ca', '_mitmca', '--mitm']);
    });

    test('switching the master switch off passes nothing to netcap', () {
      const s = MitmSettings(enabled: false);
      expect(s.active, isFalse);
      expect(s.toArgs(), isEmpty);
      expect(s.summary, contains('关闭'));
    });

    test('a selected list with everything off is not "decrypt everything"', () {
      const s = MitmSettings(apps: [MitmApp(exe: 'msedge.exe', decrypt: false)]);
      expect(s.decryptList, isEmpty);
      expect(s.active, isFalse);
      expect(s.toArgs(), isEmpty);
      expect(s.summary, contains('没有选中'));
    });

    test('adding a program keeps the list order and matches names case-insensitively', () {
      var s = const MitmSettings(apps: [MitmApp(exe: 'msedge.exe', label: 'Edge 浏览器')]);
      s = s.withApp('bank.exe', label: '网银');
      expect(s.apps.length, 2);
      expect(s.apps.last.label, '网银');
      expect(s.knows('BANK.EXE'), isTrue);
      final again = s.withApp('bank.exe', label: '网银客户端', decrypt: false);
      expect(again.apps.length, 2);
      expect(again.apps.last.label, '网银客户端');
      expect(again.apps.last.decrypt, isFalse);
      // An empty name is ignored rather than producing a nameless row.
      expect(s.withApp('   ').apps.length, 2);
    });

    test('the switch and the "加入" button both go through setDecrypt', () {
      var s = const MitmSettings(apps: [MitmApp(exe: 'msedge.exe')]);
      s = s.setDecrypt('msedge.exe', false);
      expect(s.decryptList, isEmpty);
      s = s.setDecrypt('msedge.exe', true);
      expect(s.decryptList, ['msedge.exe']);
      // A program that is not on the list yet gets added, not ignored.
      s = s.setDecrypt('game.exe', true);
      expect(s.knows('game.exe'), isTrue);
      expect(s.decrypts('game.exe'), isTrue);
    });

    test('the summary is a sentence a normal person can read', () {
      expect(const MitmSettings().summary, contains('个程序'));
      expect(const MitmSettings(scope: MitmScope.all).summary, contains('所有程序'));
      expect(
        const MitmSettings(scope: MitmScope.all, apps: [MitmApp(exe: 'bank.exe', decrypt: false)]).summary,
        contains('除了 1 个'),
      );
    });

    test('settings survive a save and load round trip', () {
      const s = MitmSettings(
        enabled: false,
        scope: MitmScope.all,
        caPrefix: '_mitmca',
        apps: [
          MitmApp(exe: 'msedge.exe', label: 'Edge 浏览器', decrypt: true),
          MitmApp(exe: 'bank.exe', decrypt: false),
        ],
      );
      final back = MitmSettings.fromJson(s.toJson());
      expect(back.enabled, isFalse);
      expect(back.scope, MitmScope.all);
      expect(back.caPrefix, '_mitmca');
      expect(back.apps.length, 2);
      expect(back.apps.first.label, 'Edge 浏览器');
      expect(back.apps.last.decrypt, isFalse);
    });

    test('a hand-edited or broken file falls back to the defaults', () {
      expect(MitmSettings.fromJson(null).apps, kCommonApps);
      expect(MitmSettings.fromJson('nonsense').scope, MitmScope.selected);
      // Unknown scope strings, string booleans and half-filled rows.
      final s = MitmSettings.fromJson({
        'enabled': '1',
        'scope': 'ALL',
        'apps': [
          {'exe': 'msedge.exe'},
          {'label': '没有 exe 名字'},
          'junk',
        ],
      });
      expect(s.enabled, isTrue);
      expect(s.scope, MitmScope.all);
      expect(s.apps.length, 1);
      expect(s.apps.first.decrypt, isTrue);
    });

    test('the runner fields are split out of the argument list', () {
      final args = mitmArgsOf(const MitmSettings(caPrefix: '_mitmca'));
      expect(args.mitm, isTrue);
      expect(args.only, contains('msedge.exe'));
      expect(args.skip, isEmpty);
      final none = mitmArgsOf(const MitmSettings(enabled: false));
      expect(none.mitm, isFalse);
      expect(none.only, isEmpty);
    });
  });

  group('reading netcap --list-processes', () {
    const sample = '{"type":"process","name":"msedge.exe","pid":100}\n'
        '{"type":"process","name":"MsEdge.exe","pid":101}\n'
        '{"type":"process","name":"netcap.exe","pid":102}\n'
        '{"type":"process","name":"netcap_ui.exe","pid":103}\n'
        '{"type":"process","name":"chrome.exe","pid":104}\n'
        '{"type":"processes","count":5}\n'
        'not json at all\n';

    test('keeps one entry per program and drops our own processes', () {
      final apps = runningAppsFromJsonl(sample);
      expect(apps.map((a) => a.exe).toList(), ['chrome.exe', 'msedge.exe']);
    });

    test('survives junk, empty output and a JSON array', () {
      expect(runningAppsFromJsonl(''), isEmpty);
      expect(runningAppsFromJsonl('[]\n{}\n{"type":"process",}\n'), isEmpty);
      final skipped = runningAppsFromJsonl(sample, skipExe: const []);
      expect(skipped.map((a) => a.exe).toList(), ['chrome.exe', 'msedge.exe', 'netcap.exe', 'netcap_ui.exe']);
    });

    test('a picked program shows the image name when there is no friendly name', () {
      const app = MitmApp(exe: 'weird-thing.exe');
      expect(app.title, 'weird-thing.exe');
      expect(const MitmApp(exe: 'x.exe', label: '有名字').title, '有名字');
    });
  });

  group('the saved settings file', () {
    test('writes where it says it writes, and reads it back', () async {
      final dir = await Directory.systemTemp.createTemp('netcap-mitm-test');
      final path = '${dir.path}${Platform.pathSeparator}mitm.json';
      const s = MitmSettings(scope: MitmScope.all, apps: [MitmApp(exe: 'bank.exe', decrypt: false)]);
      expect(await saveMitmSettings(s, path: path), isNull);
      expect(File(path).existsSync(), isTrue);
      final back = await loadMitmSettings(path: path);
      expect(back.scope, MitmScope.all);
      expect(back.skipValue, 'bank.exe');
      await dir.delete(recursive: true);
    });

    test('a missing or unreadable file gives the defaults instead of an error', () async {
      final missing = await loadMitmSettings(path: 'no-such-directory\\nothing.json');
      expect(missing.apps, kCommonApps);
      final dir = await Directory.systemTemp.createTemp('netcap-mitm-bad');
      final path = '${dir.path}${Platform.pathSeparator}mitm.json';
      await File(path).writeAsString('{ this is not json');
      final broken = await loadMitmSettings(path: path);
      expect(broken.enabled, isTrue);
      expect(broken.apps, kCommonApps);
      // Saving under a path that is a plain file cannot work: the caller gets
      // the reason back instead of an exception.
      final blocker = File('${dir.path}${Platform.pathSeparator}blocker');
      await blocker.writeAsString('not a directory');
      final err = await saveMitmSettings(
        const MitmSettings(),
        path: '${blocker.path}${Platform.pathSeparator}x.json',
      );
      expect(err, isNotNull);
      await dir.delete(recursive: true);
    });

    test('the default location lives under the user profile', () {
      final path = mitmSettingsPath();
      expect(path.endsWith('mitm-settings.json'), isTrue);
      expect(path.toLowerCase().contains('netcap-ui'), isTrue);
    });
  });
}
