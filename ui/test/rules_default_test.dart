import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/netcap.dart';

/// The app ships an ad filter list (`rules/adblock.txt`) so the proxy is useful
/// without the user picking a file.  These tests pin the lookup rules.
void main() {
  group('the built-in filter list', () {
    test('pickRulesFile takes the first candidate that exists', () {
      const candidates = <String>['a/adblock.txt', 'b/adblock.txt'];
      expect(
        NetcapRunner.pickRulesFile(candidates, <String>{'b/adblock.txt'}),
        'b/adblock.txt',
      );
      expect(
        NetcapRunner.pickRulesFile(
          candidates,
          <String>{'a/adblock.txt', 'b/adblock.txt'},
        ),
        'a/adblock.txt',
      );
      expect(NetcapRunner.pickRulesFile(candidates, <String>{}), isNull);
    });

    test('defaultRulesFile walks up from the directory it is given', () async {
      final root = await Directory.systemTemp.createTemp('netcap-rules-');
      try {
        final nested = Directory(
          '${root.path}${Platform.pathSeparator}deep${Platform.pathSeparator}deeper',
        );
        await nested.create(recursive: true);
        final rules = Directory('${root.path}${Platform.pathSeparator}rules');
        await rules.create(recursive: true);
        final file = File('${rules.path}${Platform.pathSeparator}adblock.txt');
        await file.writeAsString('! test list\n||ads.example.com^\n');

        expect(await NetcapRunner.defaultRulesFile(roots: <String>[nested.path]), file.path);
      } finally {
        if (await root.exists()) await root.delete(recursive: true);
      }
    });

    test('a directory without a list reports nothing, it does not throw', () async {
      final root = await Directory.systemTemp.createTemp('netcap-norules-');
      try {
        expect(await NetcapRunner.defaultRulesFile(roots: <String>[root.path]), isNull);
      } finally {
        if (await root.exists()) await root.delete(recursive: true);
      }
    });

    test('the workspace really does ship the list', () async {
      // Guards the packaging path used by ui/windows/runner/CMakeLists.txt.
      final fromRepo = File(
        '${Directory.current.parent.path}${Platform.pathSeparator}rules'
        '${Platform.pathSeparator}adblock.txt',
      );
      expect(await fromRepo.exists(), isTrue,
          reason: 'expected ${fromRepo.path} to exist (run from ui/)');
      final text = await fromRepo.readAsString();
      expect(text.length, greaterThan(100000));
      expect(text.contains('||dup.baidustatic.com^'), isTrue);
      expect(text.contains('blog.csdn.net##.simple-ad-slot'), isTrue);
    });
  });
}
