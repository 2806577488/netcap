// The 过滤日志 page: a non-technical user has to be able to see what the
// interception proxy decided, search it, filter it, export it and clear it.
//
// The page owns no files: the export, the clear and the 记到文件 switch all go
// back to the caller through injected callbacks, because real file IO inside
// the fake-async zone of a widget test never completes.  Nothing in here calls
// pumpAndSettle on an indefinite animation, so the suite cannot hang.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/log_merge.dart';
import 'package:netcap_ui/src/log_page.dart';
import 'package:netcap_ui/src/models.dart';

/// One decision, with only the fields a test cares about spelled out.
InterceptRecord rec({
  required int tsUs,
  required String action,
  required String url,
  required String host,
  String method = 'GET',
  String rule = '',
  String detail = '',
  int status = 0,
  int requestBytes = 0,
  int responseBytes = 0,
  String clientProc = '',
  String mitm = '',
}) {
  return InterceptRecord(
    tsUs: tsUs,
    action: action,
    method: method,
    url: url,
    host: host,
    client: '',
    rule: rule,
    detail: detail,
    status: status,
    requestBytes: requestBytes,
    responseBytes: responseBytes,
    clientProc: clientProc,
    mitm: mitm,
  );
}

void main() {
  Future<void> pumpLog(
    WidgetTester tester, {
    required List<InterceptRecord> records,
    String logPath = '',
    bool writing = false,
    ValueChanged<bool>? onWritingChanged,
    Future<void> Function()? onClear,
    LogExport? export,
    Set<String>? sessionKeys,
  }) async {
    tester.view.physicalSize = const Size(1400, 1100);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (ctx) => TextButton(
              onPressed: () => showLogPage(
                ctx,
                records: records,
                logPath: logPath,
                writing: writing,
                onWritingChanged: onWritingChanged,
                onClear: onClear,
                export: export,
                sessionKeys: sessionKeys,
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

  final blocked = rec(
    tsUs: 3000000,
    action: 'block',
    url: 'https://ads.example.com/banner.js',
    host: 'ads.example.com',
    rule: '||ads.example.com^',
    detail: '规则命中：内置列表里的广告域名',
    status: 403,
    requestBytes: 12,
    responseBytes: 0,
    clientProc: 'chrome.exe',
  );
  final modified = rec(
    tsUs: 2000000,
    action: 'modify',
    url: 'https://news.example.com/index.html',
    host: 'news.example.com',
    rule: 'example.com##.ad-box',
    detail: '改写了网页内容：去掉广告位',
    status: 200,
    requestBytes: 320,
    responseBytes: 4096,
    clientProc: 'msedge.exe',
  );
  final passed = rec(
    tsUs: 1000000,
    action: 'pass',
    url: 'https://shop.example.com/cart',
    host: 'shop.example.com',
    status: 200,
    requestBytes: 64,
    responseBytes: 512,
  );

  testWidgets('an empty log shows the header and the empty state', (
    tester,
  ) async {
    await pumpLog(tester, records: const <InterceptRecord>[]);

    expect(find.text('过滤日志'), findsOneWidget);
    expect(
      find.text('这里是 netcap 每一次判断的记录：拦了什么、改了什么、放行了什么。'),
      findsOneWidget,
    );
    expect(find.text('显示 0 / 共 0 条'), findsOneWidget);
    expect(find.text('还没有记录'), findsWidgets);
  });

  testWidgets('a record shows its host, url, rule and badge', (tester) async {
    await pumpLog(tester, records: <InterceptRecord>[blocked]);

    expect(find.text('ads.example.com'), findsOneWidget);
    expect(find.text('https://ads.example.com/banner.js'), findsOneWidget);
    expect(find.text('||ads.example.com^'), findsOneWidget);
    expect(find.text('chrome.exe'), findsOneWidget);
    expect(find.text('403'), findsOneWidget);
    // The chip and the row badge both say 拦截.
    expect(find.text('拦截'), findsNWidgets(2));
    // The detail is only there once the row is opened.
    expect(find.text('规则命中：内置列表里的广告域名'), findsNothing);
  });

  testWidgets('the search box filters by host and by rule', (tester) async {
    await pumpLog(tester, records: <InterceptRecord>[blocked, modified, passed]);
    expect(find.text('显示 3 / 共 3 条'), findsOneWidget);

    await tester.enterText(find.byType(TextField), 'news.example.com');
    await tester.pump();
    expect(find.text('https://news.example.com/index.html'), findsOneWidget);
    expect(find.text('https://ads.example.com/banner.js'), findsNothing);
    expect(find.text('显示 1 / 共 3 条'), findsOneWidget);

    // matchesSearch also walks the rule text.
    await tester.enterText(find.byType(TextField), '||ads.example.com^');
    await tester.pump();
    expect(find.text('https://ads.example.com/banner.js'), findsOneWidget);
    expect(find.text('https://news.example.com/index.html'), findsNothing);

    await tester.enterText(find.byType(TextField), 'nothing-matches-this');
    await tester.pump();
    expect(find.text('没有匹配的记录'), findsOneWidget);
    expect(find.text('显示 0 / 共 3 条'), findsOneWidget);
  });

  testWidgets('the 拦截 chip keeps only blocked records', (tester) async {
    await pumpLog(tester, records: <InterceptRecord>[blocked, modified, passed]);

    await tester.tap(find.widgetWithText(ChoiceChip, '拦截'));
    await tester.pump();

    expect(find.text('https://ads.example.com/banner.js'), findsOneWidget);
    expect(find.text('https://news.example.com/index.html'), findsNothing);
    expect(find.text('https://shop.example.com/cart'), findsNothing);
    expect(find.text('显示 1 / 共 3 条'), findsOneWidget);

    await tester.tap(find.widgetWithText(ChoiceChip, '全部'));
    await tester.pump();
    expect(find.text('显示 3 / 共 3 条'), findsOneWidget);
  });

  testWidgets('the 改写 chip keeps only rewritten records', (tester) async {
    await pumpLog(tester, records: <InterceptRecord>[blocked, modified, passed]);

    await tester.tap(find.widgetWithText(ChoiceChip, '改写'));
    await tester.pump();

    expect(find.text('https://news.example.com/index.html'), findsOneWidget);
    expect(find.text('https://ads.example.com/banner.js'), findsNothing);
    expect(find.text('https://shop.example.com/cart'), findsNothing);
    expect(find.text('显示 1 / 共 3 条'), findsOneWidget);
  });

  testWidgets('the 出错 and 隧道 chips find nothing in a log without them', (
    tester,
  ) async {
    await pumpLog(tester, records: <InterceptRecord>[blocked, modified, passed]);

    await tester.tap(find.widgetWithText(ChoiceChip, '隧道'));
    await tester.pump();
    expect(find.text('没有匹配的记录'), findsOneWidget);
    expect(find.text('显示 0 / 共 3 条'), findsOneWidget);

    await tester.tap(find.widgetWithText(ChoiceChip, '出错'));
    await tester.pump();
    expect(find.text('没有匹配的记录'), findsOneWidget);
  });

  testWidgets('the counters show the whole log per action', (tester) async {
    await pumpLog(tester, records: <InterceptRecord>[
      blocked,
      modified,
      passed,
      rec(
        tsUs: 1500000,
        action: 'block',
        url: 'https://track.example.com/p.gif',
        host: 'track.example.com',
      ),
    ]);

    expect(find.text('显示 4 / 共 4 条'), findsOneWidget);
    expect(find.text('拦截 2 · 改写 1 · 放行 1'), findsOneWidget);

    // Filtering changes what is shown, never the totals of the log.
    await tester.tap(find.widgetWithText(ChoiceChip, '拦截'));
    await tester.pump();
    expect(find.text('显示 2 / 共 4 条'), findsOneWidget);
    expect(find.text('拦截 2 · 改写 1 · 放行 1'), findsOneWidget);
  });

  testWidgets('tapping a row reveals its detail and the byte counts', (
    tester,
  ) async {
    await pumpLog(tester, records: <InterceptRecord>[
      passed,
      blocked,
      modified,
    ]);

    expect(find.text('改写了网页内容：去掉广告位'), findsNothing);
    // Newest first: the modify event (tsUs 2s) is the second row.
    await tester.tap(find.byKey(const ValueKey<String>('log-row-1')));
    await tester.pump();

    expect(find.text('改写了网页内容：去掉广告位'), findsOneWidget);
    expect(find.text('请求 320 B · 响应 4.0 KiB'), findsOneWidget);
    expect(find.text('example.com##.ad-box'), findsNWidgets(2));

    // Tapping the same row again folds it back up.
    await tester.tap(find.byKey(const ValueKey<String>('log-row-1')));
    await tester.pump();
    expect(find.text('改写了网页内容：去掉广告位'), findsNothing);
  });

  testWidgets('导出… calls export once with the report text', (tester) async {
    var calls = 0;
    String? suggestedName;
    String? contents;
    await pumpLog(
      tester,
      records: <InterceptRecord>[passed, blocked],
      export: (String name, String text) async {
        calls++;
        suggestedName = name;
        contents = text;
        return r'C:\fake\netcap-filter-log-20261011-1530.txt';
      },
    );

    await tester.tap(find.text('导出…'));
    await tester.pumpAndSettle();

    expect(calls, 1);
    expect(suggestedName, matches(RegExp(r'^netcap-filter-log-\d{8}-\d{4}\.txt$')));
    expect(contents, contains('https://ads.example.com/banner.js'));
    expect(contents, contains('# 共 2 条 · 拦截 1 · 放行 1'));
    expect(contents, contains('拦截  GET  https://ads.example.com/banner.js'));
    // Newest first in the file too.
    expect(
      contents!.indexOf('banner.js') < contents!.indexOf('shop.example.com'),
      isTrue,
    );
    expect(find.textContaining('已导出到'), findsOneWidget);
  });

  testWidgets('清空 asks first, and confirming calls onClear once', (
    tester,
  ) async {
    var cleared = 0;
    await pumpLog(
      tester,
      records: <InterceptRecord>[blocked],
      onClear: () async => cleared++,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, '清空'));
    await tester.pumpAndSettle();
    expect(find.text('清空日志？'), findsOneWidget);
    expect(cleared, 0);

    await tester.tap(find.widgetWithText(FilledButton, '清空'));
    await tester.pumpAndSettle();
    expect(cleared, 1);
    expect(find.text('清空日志？'), findsNothing);
  });

  testWidgets('cancelling 清空 never calls onClear', (tester) async {
    var cleared = 0;
    await pumpLog(
      tester,
      records: <InterceptRecord>[blocked],
      onClear: () async => cleared++,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, '清空'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(TextButton, '取消'));
    await tester.pumpAndSettle();

    expect(cleared, 0);
    expect(find.text('清空日志？'), findsNothing);
    expect(find.text('https://ads.example.com/banner.js'), findsOneWidget);
  });

  testWidgets('flipping 记到文件 reports the new value', (tester) async {
    final seen = <bool>[];
    await pumpLog(
      tester,
      records: <InterceptRecord>[blocked],
      logPath: r'C:\fake\netcap-filter-log.txt',
      onWritingChanged: seen.add,
    );

    expect(find.byType(Switch), findsOneWidget);
    await tester.tap(find.byType(Switch));
    await tester.pump();
    expect(seen, <bool>[true]);

    await tester.tap(find.byType(Switch));
    await tester.pump();
    expect(seen, <bool>[true, false]);

    // The switch renders from the page's own state after the flip.
    expect(tester.widget<Switch>(find.byType(Switch)).value, isFalse);
  });

  testWidgets('an unwired log file reads 还没有选文件', (tester) async {
    await pumpLog(tester, records: const <InterceptRecord>[], logPath: '');
    expect(find.text('还没有选文件'), findsOneWidget);
  });

  testWidgets('a wired log file shows its path in monospace', (tester) async {
    await pumpLog(
      tester,
      records: const <InterceptRecord>[],
      logPath: r'C:\Users\me\netcap-filter-log.txt',
    );
    expect(find.text(r'C:\Users\me\netcap-filter-log.txt'), findsOneWidget);
    expect(find.text('还没有选文件'), findsNothing);
  });

  testWidgets('several hundred rows build lazily, newest first', (
    tester,
  ) async {
    final many = <InterceptRecord>[
      for (var i = 0; i < 300; i++)
        rec(
          tsUs: 1000000 + i,
          action: 'pass',
          url: 'https://host$i.example.com/page',
          host: 'host$i.example.com',
        ),
    ];
    await pumpLog(tester, records: many);

    expect(find.text('显示 300 / 共 300 条'), findsOneWidget);
    expect(find.text('host299.example.com'), findsOneWidget);
    // Far away rows were never built.
    expect(find.text('host0.example.com'), findsNothing);

    await tester.drag(find.byType(ListView), const Offset(0, -4000));
    await tester.pump();
    expect(find.text('host299.example.com'), findsNothing);
  });

  testWidgets('a client that hung up reads 中断, never 出错', (tester) async {
    final gone = rec(
      tsUs: 3000000,
      action: 'cancelled',
      url: 'http://www.bing.com/?q=360',
      host: 'www.bing.com',
      status: 302,
      detail:
          'body (0 replace(s), 1 style(s)); '
          'the client closed before the response was sent',
    );
    await pumpLog(tester, records: <InterceptRecord>[gone, blocked]);

    // The chip for every action is always there; the badge only appears on a row.
    expect(find.text('中断'), findsNWidgets(2));
    expect(
      find.text('http://www.bing.com/?q=360'),
      findsOneWidget,
      reason: 'the hung-up request is still listed',
    );

    await tester.tap(find.text('中断').first);
    await tester.pump();
    expect(find.text('显示 1 / 共 2 条'), findsOneWidget);
  });

  testWidgets('the export marks rows that came out of the file', (
    tester,
  ) async {
    String? written;
    final old = rec(
      tsUs: 500000,
      action: 'block',
      url: 'http://tracker.example.net/pixel.gif',
      host: 'tracker.example.net',
      rule: '||tracker.example.net^',
      status: 403,
    );
    await pumpLog(
      tester,
      records: <InterceptRecord>[blocked, old],
      sessionKeys: <String>{filterLogKey(blocked)},
      export: (String name, String text) async {
        written = text;
        return r'C:\fake\netcap-filter-log-20261010-1741.txt';
      },
    );

    await tester.tap(find.text('导出…'));
    await tester.pumpAndSettle();

    expect(written, isNotNull);
    expect(
      written,
      contains('# 其中 1 条来自上次会话（filter-log.jsonl），行首标了 [上次]。'),
    );
    final lines = written!.split('\n');
    expect(
      lines.where((line) => line.startsWith('[上次] ')),
      hasLength(1),
      reason: 'only the row that came out of the file is marked',
    );
    expect(
      lines.firstWhere((line) => line.contains('banner.js')).startsWith('[上次]'),
      isFalse,
      reason: "this session's own rows stay unmarked",
    );
  });

  testWidgets('a tracking URL does not turn the export into a wall of text', (
    tester,
  ) async {
    String? written;
    final long = rec(
      tsUs: 600000,
      action: 'block',
      url: 'http://tracker.example.net/p?${'x' * 400}',
      host: 'tracker.example.net',
      rule: '||tracker.example.net^${'y' * 400}',
      status: 403,
    );
    await pumpLog(
      tester,
      records: <InterceptRecord>[long],
      export: (String name, String text) async {
        written = text;
        return r'C:\fake\netcap-filter-log-20261010-1742.txt';
      },
    );

    await tester.tap(find.text('导出…'));
    await tester.pumpAndSettle();

    expect(written, isNotNull);
    expect(written, contains('… (+'), reason: 'over-long columns say how much they hid');
    expect(
      written!.contains('x' * 400),
      isFalse,
      reason: 'the raw query string stays out of the readable export',
    );
    expect(written!.contains('y' * 400), isFalse, reason: 'so does the raw rule');
  });

  testWidgets('rows from the file are marked on screen, not only in the export', (
    tester,
  ) async {
    final old = rec(
      tsUs: 500000,
      action: 'block',
      url: 'http://tracker.example.net/pixel.gif',
      host: 'tracker.example.net',
      rule: '||tracker.example.net^',
      status: 403,
    );
    // An empty set is how the caller says "this session has produced nothing".
    await pumpLog(
      tester,
      records: <InterceptRecord>[blocked, old],
      sessionKeys: <String>{},
    );

    expect(find.text('[上次] ${blocked.time}'), findsOneWidget);
    expect(find.text('[上次] ${old.time}'), findsOneWidget);
    expect(
      find.text('其中 2 条来自上次会话（filter-log.jsonl），行首标了 [上次]。'),
      findsOneWidget,
    );
  });
}
