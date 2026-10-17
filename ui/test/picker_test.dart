// The element picker: a click on a page appends a hiding rule.  These tests
// cover the two halves the interface owns — the command line it builds and the
// switch that turns it on — because the C++ side has its own self-test.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/netcap.dart';
import 'package:netcap_ui/src/rule_lists.dart';
import 'package:netcap_ui/src/rules_page.dart';

void main() {
  test('the picker only reaches the command line when it can keep the rule', () {
    final withList = NetcapRequest(
      mode: SourceMode.proxy,
      rulesPath: 'builtin.txt',
      picker: true,
      pickerFlag: r'C:\x\picker.on',
      pickerRules: r'C:\x\my-rules.txt',
    );
    final args = withList.toArgs();
    expect(args, contains('--picker'));
    expect(args, containsAllInOrder(<String>['--picker-rules', r'C:\x\my-rules.txt']));
    expect(args, containsAllInOrder(<String>['--picker-flag', r'C:\x\picker.on']));

    // Without a list to append to, picking would hide an element for this
    // session only — that is worse than not offering it at all.
    final without = NetcapRequest(
      mode: SourceMode.proxy,
      rulesPath: 'builtin.txt',
      picker: true,
    );
    expect(without.toArgs(), isNot(contains('--picker')));
  });

  testWidgets('the rules page offers the picker and hands the change back', (tester) async {
    tester.view.physicalSize = const Size(1000, 1600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);

    bool? seen;
    await tester.pumpWidget(MaterialApp(
      home: RulesPage(
        lists: RuleLists(builtinPath: 'adblock.txt', userRulesPath: 'my-rules.txt'),
        settingsPath: 'rule-lists.json',
        check: (String line) async => const RuleCheck(ok: true, note: 'ok network rule'),
        picking: false,
        onPickingChanged: (bool on) async {
          seen = on;
        },
        readFile: (String path) async => '',
        writeFile: (String path, String text) async {},
      ),
    ));
    await tester.pump();

    final label = find.text('在页面上点选元素');
    expect(label, findsOneWidget);
    // The switch sits next to that label, not the per-list switches above it.
    final row = find.ancestor(of: label, matching: find.byType(Row)).first;
    await tester.tap(find.descendant(of: row, matching: find.byType(Switch)));
    await tester.pump();
    expect(seen, isTrue);

    // Without a callback there is nothing to write the flag file with, so the
    // page must not pretend to offer it.
    await tester.pumpWidget(MaterialApp(
      home: RulesPage(
        lists: RuleLists(builtinPath: 'adblock.txt', userRulesPath: 'my-rules.txt'),
        settingsPath: 'rule-lists.json',
        check: (String line) async => const RuleCheck(ok: true, note: 'ok network rule'),
        readFile: (String path) async => '',
        writeFile: (String path, String text) async {},
      ),
    ));
    await tester.pump();
    expect(find.text('在页面上点选元素'), findsNothing);
  });
}
