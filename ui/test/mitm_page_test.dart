import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/mitm_apps.dart';
import 'package:netcap_ui/src/mitm_page.dart';

void main() {
  Future<void> open(
    WidgetTester tester, {
    MitmSettings settings = const MitmSettings(),
    bool caExists = true,
    bool caTrusted = true,
    String caDetail = '证书：已安装 E4AC01FD8F10A043…',
  }) async {
    // The page is a tall, lazily built list: give it a phone-sized window and
    // scroll for the cards below the fold (see reveal()).
    tester.view.physicalSize = const Size(900, 700);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(MaterialApp(
      home: MitmPage(
        settings: settings,
        caExists: caExists,
        caTrusted: caTrusted,
        caDetail: caDetail,
        onDetect: () async => '证书检测完成',
        onCreate: () async => '证书已创建：_mitmca.crt',
        onInstall: () async => '证书已安装到当前用户的根证书库',
        onUninstall: () async => '证书已移除',
        onListRunning: () async => const [MitmApp(exe: 'chrome.exe'), MitmApp(exe: 'steam.exe')],
      ),
    ));
    await tester.pumpAndSettle();
  }

  /// Scrolls the page until [finder] is on screen (the body is a ListView).
  Future<void> reveal(WidgetTester tester, Finder finder) async {
    await tester.scrollUntilVisible(finder, 240,
        scrollable: find.byType(Scrollable).first, maxScrolls: 40);
    await tester.pumpAndSettle();
  }

  testWidgets('the page speaks plain language instead of flag names', (tester) async {
    await open(tester);
    expect(find.text('HTTPS 过滤'), findsOneWidget);
    expect(find.text('看懂 HTTPS（解密加密流量）'), findsOneWidget);
    expect(find.text('1. 证书（浏览器凭什么相信我们）'), findsOneWidget);
    expect(find.text('2. 过滤哪些程序'), findsOneWidget);
    expect(find.text('常见程序（推荐）'), findsOneWidget);
    expect(find.text('这台电脑上的所有程序'), findsOneWidget);
    // No raw flag spelled out as the only explanation.
    expect(find.textContaining('--mitm-only'), findsNothing);
    // The card that explains what each program switch does, and the entry
    // points a non-technical user needs.
    await reveal(tester, find.text('3. 程序清单'));
    expect(find.text('3. 程序清单'), findsOneWidget);
    expect(find.text('添加程序…'), findsOneWidget);
    expect(find.text('从正在运行的程序里挑…'), findsOneWidget);
    expect(find.text('高级（给懂命令行的人）'), findsOneWidget);
  });

  testWidgets('the master switch flips the explanation under it', (tester) async {
    await open(tester);
    expect(find.textContaining('开着：'), findsOneWidget);
    await tester.tap(find.byType(Switch).first);
    await tester.pumpAndSettle();
    expect(find.textContaining('关着：'), findsOneWidget);
  });

  testWidgets('choosing "all programs" keeps the list usable', (tester) async {
    await open(tester);
    await tester.tap(find.text('这台电脑上的所有程序'));
    await tester.pumpAndSettle();
    await reveal(tester, find.text('3. 程序清单'));
    expect(find.textContaining('所有程序默认解密'), findsOneWidget);
  });

  testWidgets('one program can be switched off without touching the rest', (tester) async {
    await open(tester, settings: const MitmSettings(apps: [
      MitmApp(exe: 'msedge.exe', label: 'Edge 浏览器'),
      MitmApp(exe: 'bank.exe', label: '网银'),
    ]));
    await reveal(tester, find.text('2 / 2'));
    expect(find.text('2 / 2'), findsOneWidget);
    await tester.tap(find.byType(Switch).last);
    await tester.pumpAndSettle();
    expect(find.text('1 / 2'), findsOneWidget);
  });

  testWidgets('a missing certificate invites the user to install one', (tester) async {
    await open(tester, caExists: false, caTrusted: false, caDetail: '证书：还没有创建');
    expect(find.text('还没有证书'), findsOneWidget);
    expect(find.text('一键安装证书'), findsOneWidget);
    await tester.tap(find.text('一键安装证书'));
    await tester.pumpAndSettle();
    // The card reports what happened and the badge follows it.
    expect(find.text('证书已安装到当前用户的根证书库'), findsOneWidget);
    expect(find.text('已安装'), findsOneWidget);
  });

  testWidgets('the running-programs picker can add a program', (tester) async {
    await open(tester, settings: const MitmSettings(apps: [MitmApp(exe: 'msedge.exe')]));
    await reveal(tester, find.text('从正在运行的程序里挑…'));
    await tester.tap(find.text('从正在运行的程序里挑…'));
    await tester.pumpAndSettle();
    expect(find.text('正在运行的程序'), findsOneWidget);
    await tester.tap(find.text('steam.exe'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, '添加'));
    await tester.pumpAndSettle();
    await reveal(tester, find.text('steam.exe'));
    expect(find.text('steam.exe'), findsOneWidget);
  });

  testWidgets('the advanced fold shows the command line it will produce', (tester) async {
    await open(tester, settings: const MitmSettings(caPrefix: '_mitmca'));
    await reveal(tester, find.text('高级（给懂命令行的人）'));
    await tester.tap(find.text('高级（给懂命令行的人）'));
    await tester.pumpAndSettle();
    expect(find.textContaining('--mitm-only'), findsWidgets);
    expect(find.textContaining('--ca _mitmca'), findsOneWidget);
  });
}
