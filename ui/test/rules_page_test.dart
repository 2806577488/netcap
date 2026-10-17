// The rules page: the user has to be able to see, add, change and delete rules
// without opening the bundled list in a text editor.
//
// The page's two file seams are injected here (an in-memory map): real file IO
// inside the fake-async zone of a widget test never completes.
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/netcap.dart';
import 'package:netcap_ui/src/rule_lists.dart';
import 'package:netcap_ui/src/rules_page.dart';

void main() {
  late Map<String, String> files;
  const userPath = r'C:\fake\netcap-ui\my-rules.txt';
  const basePath = r'C:\fake\rules\adblock.txt';
  const settingsPath = r'C:\fake\netcap-ui\rule-lists.json';

  setUp(() {
    files = <String, String>{
      basePath:
          '! built in\n||ads.example.com^\nexample.com##.ad-box\n||tracker.example^\n',
    };
  });

  String userFile() => files[userPath] ?? '';

  Future<void> pumpPage(
    WidgetTester tester, {
    RuleCheckRunner? check,
    bool running = false,
    Future<void> Function()? onRestart,
  }) async {
    tester.view.physicalSize = const Size(1400, 1100);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    final lists = RuleLists(builtinPath: basePath, userRulesPath: userPath);
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (ctx) => TextButton(
              onPressed: () => showRulesPage(
                ctx,
                lists: lists,
                settingsPath: settingsPath,
                check: check ??
                    (line) async =>
                        RuleCheck(ok: true, note: 'ok network rule: $line'),
                running: running,
                onRestart: onRestart,
                readFile: (path) async {
                  final text = files[path];
                  if (text == null) {
                    throw FileSystemException('no such file', path);
                  }
                  return text;
                },
                writeFile: (path, text) async => files[path] = text,
              ),
              child: const Text('open'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();
  }

  testWidgets('my rules are listed and an added rule lands in the file', (
    tester,
  ) async {
    files[userPath] = '||start.example^\n';
    await pumpPage(tester);

    expect(find.text('||start.example^'), findsOneWidget);
    expect(find.textContaining('还没有自己的规则'), findsNothing);

    await tester.enterText(find.byType(TextField).first, '||new.example^');
    // The lists card sits above this one, so scroll the button into view first
    // (the dialog is height-capped, a tap on an off-screen widget goes nowhere).
    await tester.ensureVisible(find.text('添加'));
    await tester.pump();
    await tester.tap(find.text('添加'));
    // One frame for _addRule's setState plus a short settle for the save: the
    // status line is state that a later rebuild would drop, so do not use
    // pumpAndSettle here.
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));

    expect(find.text('||new.example^'), findsOneWidget);
    expect(userFile(), contains('||new.example^'));
    // The green status line is transient page state; the rejection test below
    // covers that path.  What matters here is the durable pair: the row and
    // the file.
  });

  testWidgets('a rule the engine rejects is explained and not saved', (
    tester,
  ) async {
    await pumpPage(
      tester,
      check: (line) async => const RuleCheck(ok: false, reason: 'line too long'),
    );

    await tester.enterText(find.byType(TextField).first, 'x' * 40);
    await tester.ensureVisible(find.text('添加'));
    await tester.pump();
    await tester.tap(find.text('添加'));
    await tester.pumpAndSettle();

    expect(find.textContaining('这条规则 netcap 用不了'), findsOneWidget);
    expect(find.textContaining('line too long'), findsOneWidget);
    expect(userFile(), isNot(contains('xxxx')));
  });

  testWidgets('a rule can be deleted again', (tester) async {
    files[userPath] = '||start.example^\n';
    await pumpPage(tester);

    await tester.tap(find.byTooltip('删除这条'));
    await tester.pumpAndSettle();

    expect(find.text('||start.example^'), findsNothing);
    expect(userFile(), isNot(contains('start.example')));
    expect(find.textContaining('还没有自己的规则'), findsOneWidget);
  });

  testWidgets('a built-in rule is disabled with one press, and enabled again', (
    tester,
  ) async {
    await pumpPage(tester);

    await tester.enterText(find.byType(TextField).last, 'ad-box');
    await tester.pumpAndSettle();
    expect(find.text('example.com##.ad-box'), findsOneWidget);

    await tester.ensureVisible(find.text('禁用'));
    await tester.pump();
    await tester.tap(find.text('禁用'));
    await tester.pumpAndSettle();
    expect(userFile(), contains('example.com#@#.ad-box'));
    expect(find.textContaining('禁用的规则'), findsOneWidget);

    // Two of them on purpose: the built-in hit row and the user's own
    // exception line can both switch it back on.
    expect(find.text('启用'), findsNWidgets(2));
    await tester.ensureVisible(find.text('启用').first);
    await tester.pump();
    await tester.tap(find.text('启用').first);
    await tester.pumpAndSettle();
    expect(userFile(), isNot(contains('#@#')));
  });

  testWidgets('the restart button shows up only while the proxy runs', (
    tester,
  ) async {
    await pumpPage(tester, running: true, onRestart: () async {});
    expect(find.text('按新规则重启代理'), findsOneWidget);
  });

  testWidgets('with the proxy stopped there is nothing to restart', (
    tester,
  ) async {
    await pumpPage(tester);
    expect(find.text('按新规则重启代理'), findsNothing);
  });

  test('an exception is the other marker on the same rule', () {
    expect(ruleExceptionFor('||ads.example.com^'), '@@||ads.example.com^');
    expect(ruleExceptionFor('example.com##.ad-box'), 'example.com#@#.ad-box');
    expect(ruleExceptionFor('example.com#@#.ad-box'), 'example.com##.ad-box');
    expect(ruleIsException('@@||ads.example.com^'), isTrue);
    expect(ruleIsException('example.com#@#.ad-box'), isTrue);
    expect(ruleIsException('example.com##.ad-box'), isFalse);
  });

  test('the request stacks the user rules on top of the list', () {
    final args = NetcapRequest(
      mode: SourceMode.proxy,
      rulesPath: r'C:\x\adblock.txt',
      userRules: r'C:\y\my-rules.txt',
    ).toArgs();
    final at = args.indexOf('--rules-extra');
    expect(at, greaterThan(-1));
    expect(args[at + 1], r'C:\y\my-rules.txt');

    final without = NetcapRequest(
      mode: SourceMode.proxy,
      rulesPath: 'a.txt',
    ).toArgs();
    expect(without.contains('--rules-extra'), isFalse);
  });

  test('the user rules file lives next to the other interface settings', () {
    final path = NetcapRunner.defaultUserRulesPath();
    expect(path.endsWith('my-rules.txt'), isTrue);
    expect(path.contains('netcap-ui'), isTrue);
  });

  test('the decision log sits in that same folder', () {
    final rules = NetcapRunner.defaultUserRulesPath();
    final log = NetcapRunner.defaultLogPath();
    expect(log.endsWith('filter-log.jsonl'), isTrue);
    // Same directory, so the user finds both in one place.
    final cut = rules.lastIndexOf(Platform.pathSeparator);
    expect(log.startsWith(rules.substring(0, cut)), isTrue);
  });
}
