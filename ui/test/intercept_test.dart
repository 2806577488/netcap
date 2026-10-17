// Tests for the interception panel: the JSONL contract that `--serve` emits,
// the proxy-mode command line, and the panel itself.
//
// The fixtures are copied verbatim from a real run of
//
//   netcap.exe --jsonl --rules sample.rules --serve 127.0.0.1:8098 --show-blocks
//
// driven with `curl.exe -x http://127.0.0.1:8098` (one blocked request, one
// passed-through 404, one CONNECT tunnel).
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/main.dart';
import 'package:netcap_ui/src/models.dart';
import 'package:netcap_ui/src/netcap.dart';
import 'package:netcap_ui/src/widgets.dart';

const String _blocked =
    '{"type":"intercept","action":"block","method":"GET","url":"http://ads.example.com/banner.gif",'
    '"host":"ads.example.com","client":"127.0.0.1:27461","rule":"||ads.example.com^","detail":"",'
    '"status":403,"ts_us":1791461927680513,"request_bytes":140,"response_bytes":292}';

const String _passed =
    '{"type":"intercept","action":"pass","method":"GET","url":"http://example.com/index.html",'
    '"host":"example.com","client":"127.0.0.1:27462","rule":"","detail":"","status":404,'
    '"ts_us":1791461927706597,"request_bytes":132,"response_bytes":853}';

const String _tunnel =
    '{"type":"intercept","action":"tunnel","method":"CONNECT","url":"https://example.com/",'
    '"host":"example.com:443","client":"127.0.0.1:27464","rule":"","detail":"","status":200,'
    '"ts_us":1791461928465300,"request_bytes":113,"response_bytes":60}';

const String _summary =
    '{"type":"intercept_summary","connections":3,"requests":3,"blocked":1,"modified":0,'
    '"redirected":0,"passed":1,"tunnels":1,"errors":0,"bytes_in":1205,"bytes_out":385}';

void main() {
  group('intercept records', () {
    test('a blocked request keeps its rule and status', () {
      final r = InterceptRecord.fromJson(
          Map<String, dynamic>.from(jsonDecodeMap(_blocked)));

      expect(r.action, 'block');
      expect(r.actionLabel, '拦截');
      expect(r.method, 'GET');
      expect(r.url, 'http://ads.example.com/banner.gif');
      expect(r.host, 'ads.example.com');
      expect(r.client, '127.0.0.1:27461');
      expect(r.rule, '||ads.example.com^');
      expect(r.status, 403);
      expect(r.requestBytes, 140);
      expect(r.responseBytes, 292);
      expect(r.tsUs, 1791461927680513);
      expect(r.time, isNot('—'));
      expect(r.target, r.url);
    });

    test('a pass reports the status the origin sent, not 200', () {
      final r = InterceptRecord.fromJson(
          Map<String, dynamic>.from(jsonDecodeMap(_passed)));

      expect(r.action, 'pass');
      expect(r.actionLabel, '放行');
      expect(r.status, 404);
      expect(r.rule, isEmpty);
    });

    test('a tunnel is labelled as such and falls back to the host', () {
      final r = InterceptRecord.fromJson(
          Map<String, dynamic>.from(jsonDecodeMap(_tunnel)));

      expect(r.action, 'tunnel');
      expect(r.actionLabel, '隧道');
      expect(r.method, 'CONNECT');
      expect(r.host, 'example.com:443');
    });

    test('an unknown action still gets a label and stays searchable', () {
      final r = InterceptRecord.fromJson(<String, dynamic>{
        'action': 'error',
        'host': 'broken.example',
        'detail': 'upstream refused the connection',
      });

      expect(r.actionLabel, '出错');
      expect(r.time, '—'); // no timestamp in the record
      expect(r.target, 'broken.example');
      expect(r.matchesSearch('refused'), isTrue);
      expect(r.matchesSearch('nothing-like-this'), isFalse);
    });

    test('a missing field never throws', () {
      final r = InterceptRecord.fromJson(<String, dynamic>{});
      expect(r.action, isEmpty);
      expect(r.status, 0);
      expect(r.matchesSearch(''), isTrue);
    });

    test('the summary parses the counters the CLI prints', () {
      final s = InterceptSummary.fromJson(
          Map<String, dynamic>.from(jsonDecodeMap(_summary)));

      expect(s.connections, 3);
      expect(s.requests, 3);
      expect(s.blocked, 1);
      expect(s.passed, 1);
      expect(s.tunnels, 1);
      expect(s.errors, 0);
      expect(s.bytesIn, 1205);
      expect(s.bytesOut, 385);
      expect(InterceptSummary.empty.requests, 0);
    });
  });

  group('the interception command line', () {
    test('proxy mode asks for the rules file and the listening address', () {
      final r = NetcapRequest(
        mode: SourceMode.proxy,
        rulesPath: 'sample.rules',
        serve: '127.0.0.1:8099',
      );

      expect(r.toArgs(), ['--jsonl', '--rules', 'sample.rules', '--serve', '127.0.0.1:8099']);
    });

    test('the two switches are only added when they are on', () {
      final off = NetcapRequest(mode: SourceMode.proxy, rulesPath: 'r.rules');
      final on = NetcapRequest(
        mode: SourceMode.proxy,
        rulesPath: 'r.rules',
        thirdPartyCookies: true,
        showBlocks: true,
      );

      expect(off.toArgs(), isNot(contains('--third-party-cookies')));
      expect(off.toArgs(), isNot(contains('--show-blocks')));
      expect(on.toArgs(), contains('--third-party-cookies'));
      expect(on.toArgs(), contains('--show-blocks'));
    });

    test('the decision log is only asked for when the interface wants one', () {
      final off = NetcapRequest(mode: SourceMode.proxy, rulesPath: 'r.rules');
      final on = NetcapRequest(
        mode: SourceMode.proxy,
        rulesPath: 'r.rules',
        logFile: r'C:\Users\me\AppData\Roaming\netcap-ui\filter-log.jsonl',
      );

      expect(off.toArgs(), isNot(contains('--log-file')));
      expect(on.toArgs(), contains('--log-file'));
      // The path follows the flag, so the proxy writes where the page reads.
      final args = on.toArgs();
      expect(args[args.indexOf('--log-file') + 1], endsWith('filter-log.jsonl'));
      // It belongs to the proxy: capturing a pcap never writes a decision log.
      expect(NetcapRequest(mode: SourceMode.file, logFile: 'x.jsonl').toArgs(),
          isNot(contains('--log-file')));
    });

    test('an empty address falls back to the loopback default', () {
      final r = NetcapRequest(mode: SourceMode.proxy, rulesPath: 'r.rules', serve: '  ');
      expect(r.toArgs(), ['--jsonl', '--rules', 'r.rules', '--serve', '127.0.0.1:8080']);
    });

    test('proxy mode never asks for a capture source', () {
      final r = NetcapRequest(mode: SourceMode.proxy, rulesPath: 'r.rules');
      final args = r.toArgs();

      expect(args, isNot(contains('--read')));
      expect(args, isNot(contains('--interface')));
      expect(args, isNot(contains('--snaplen')));
      expect(args.first, '--jsonl');
    });
  });

  group('the UI command line knows the interceptor flags', () {
    test('--rules puts the window straight into proxy mode', () {
      final paths = <String>[];
      final o = parseUiArgs(['--rules', 'sample.rules', '--serve', '127.0.0.1:8099'], paths);

      expect(o.rules, 'sample.rules');
      expect(o.serve, '127.0.0.1:8099');
      expect(o.thirdPartyCookies, isFalse);
      expect(o.showBlocks, isFalse);
      expect(paths, isEmpty);
    });

    test('the cookie and logging switches survive parsing', () {
      final paths = <String>[];
      final o = parseUiArgs(['--third-party-cookies', '--show-blocks'], paths);

      expect(o.thirdPartyCookies, isTrue);
      expect(o.showBlocks, isTrue);
    });

    test('a dangling --rules does not crash', () {
      final paths = <String>[];
      final o = parseUiArgs(['--rules'], paths);
      expect(o.rules, isEmpty);
    });

    test('--system-proxy on and --upstream seed the takeover fields', () {
      final o = parseUiArgs([
        '--rules',
        'sample.rules',
        '--serve',
        '127.0.0.1:8281',
        '--mitm',
        '--system-proxy',
        'on',
        '--upstream',
        '127.0.0.1:7890',
      ], <String>[]);

      expect(o.systemProxy, isTrue);
      expect(o.upstream, '127.0.0.1:7890');
      expect(o.mitm, isTrue);
      expect(parseUiArgs(['--system-proxy', 'off'], <String>[]).systemProxy, isFalse);
      expect(parseUiArgs(['--system-proxy-force'], <String>[]).systemProxyForce, isTrue);
    });

    test('--show-log opens the log window on start-up', () {
      expect(parseUiArgs(['--show-log'], <String>[]).showLog, isTrue);
      expect(parseUiArgs(['--log'], <String>[]).showLog, isTrue);
      expect(parseUiArgs(['--rules', 'a.txt'], <String>[]).showLog, isFalse);
    });
  });

  group('the interception panel', () {
    testWidgets('the window opens on the interceptor view', (tester) async {
      // A tall viewport so the whole status pane builds: it is a lazy ListView,
      // and below the fold its children are never created.
      tester.view.physicalSize = const Size(1200, 2400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);
      await tester.pumpWidget(const NetcapApp());
      await tester.pump(const Duration(milliseconds: 50));

      // There is no source switch any more: this window *is* the interception
      // proxy, and packet capture moved into 抓包工具 (its own test below).
      expect(find.text('pcap 文件'), findsNothing);
      expect(find.text('实时网卡'), findsNothing);
      expect(find.text('拦截代理'), findsNothing);
      expect(find.text('抓包工具'), findsOneWidget);
      expect(find.text('还没有捕获到数据包'), findsNothing);

      // The interceptor view: the rule list, one button for the set-once knobs
      // (address, third-party cookies, logging), its own table and pane.
      // The rule list is no longer a path box: it is a button that opens the
      // list manager, so the bar only shows what is switched on.
      // The toolbar button, the summary row and the hint text all mention it.
      expect(find.textContaining('过滤列表'), findsWidgets);
      expect(find.text('浏览…'), findsNothing);
      expect(find.text('更多设置'), findsOneWidget);
      // One control does the whole thing in this panel: it starts the proxy
      // *with* the system proxy in its hands (there is no separate 启动代理).
      expect(find.text('让系统代理走 netcap'), findsOneWidget);
      // The capture-only actions (生成示例抓包, 抓包选项) belong to the pcap side
      // and are not in this panel; the "every program through netcap" takeover
      // is a single chip instead of a page.
      expect(find.text('让系统代理走 netcap'), findsOneWidget);
      expect(find.byIcon(Icons.tune), findsOneWidget); // 更多设置, not 抓包选项
      expect(find.text('还没有拦截记录'), findsOneWidget);
      // The pane is *status only*: the settings pages are opened from the tool
      // bar, so nothing that changes a setting (and no settings button) is left
      // in this column.
      expect(find.text('当前连接 Connection'), findsOneWidget);
      expect(find.text('HTTPS 解密'), findsOneWidget);
      // The pane answers "what happened to the row I picked": with nothing
      // picked it says so, and the full command line is no longer dumped here.
      expect(find.textContaining('在左边点一条记录'), findsOneWidget);
      expect(find.text('命令行 Command'), findsNothing);
      expect(find.text('打开 HTTPS 过滤设置'), findsNothing);
      expect(find.text('打开接管设置'), findsNothing);
      expect(find.text('HTTPS 解密 Decryption'), findsNothing);
      expect(find.text('流量接管 Takeover'), findsNothing);
      expect(find.text('检测证书'), findsNothing);
      expect(find.text('创建 CA'), findsNothing);
      expect(find.text('装进当前用户'), findsNothing);
      expect(find.text('卸载证书'), findsNothing);
      // ... and the settings pages live *inside* 更多设置 now: the tool bar
      // only keeps what "filter my ads" needs.
      expect(find.text('HTTPS 过滤'), findsNothing);
      // pcap-side controls do nothing in proxy mode: 密钥日志 and 流分析 moved
      // into 更多设置, and their slot now holds the decision log.
      expect(find.text('密钥日志'), findsNothing);
      expect(find.text('流分析'), findsNothing);
      expect(find.text('过滤日志'), findsOneWidget);
      expect(find.text('流量接管'), findsNothing);
      expect(find.text('规则'), findsNothing);
      expect(find.text('还没有捕获到数据包'), findsNothing);
      // The raw netcap output is *not* part of the pane any more: it has its own
      // window behind the toolbar's 日志 button.
      expect(find.textContaining('netcap 日志'), findsNothing);
      expect(find.text('日志'), findsOneWidget);

      await tester.tap(find.text('更多设置'));
      await tester.pump(const Duration(milliseconds: 200));
      expect(find.text('设置页'), findsOneWidget);
      expect(find.text('HTTPS 过滤'), findsOneWidget);
      expect(find.text('流量接管'), findsOneWidget);
      expect(find.text('规则'), findsOneWidget);
      expect(find.text('过滤日志'), findsOneWidget);
      await tester.tap(find.text('完成'));
      await tester.pump(const Duration(milliseconds: 200));

      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('抓包工具 keeps the packet side in a window of its own',
        (tester) async {
      tester.view.physicalSize = const Size(1400, 1000);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);
      await tester.pumpWidget(const NetcapApp());
      await tester.pump(const Duration(milliseconds: 50));

      // The packet side is not in the main window any more.
      expect(find.text('开始捕获'), findsNothing);
      expect(find.text('记录字节'), findsNothing);

      await tester.tap(find.text('抓包工具'));
      await tester.pump(const Duration(milliseconds: 300));

      expect(find.text('抓包工具'), findsWidgets); // the dialog header
      // The main window underneath also switches to the file side while the
      // tool is open, so these labels can appear twice.
      expect(find.text('pcap 文件'), findsWidgets);
      expect(find.text('实时网卡'), findsWidgets);
      expect(find.text('开始捕获'), findsWidgets);
      expect(find.text('记录字节'), findsWidgets);
      expect(find.textContaining('还没有捕获到数据包'), findsWidgets);

      await tester.tap(find.byTooltip('关闭'));
      await tester.pump(const Duration(milliseconds: 400));

      // Closing the tool leaves the window on the proxy.
      expect(find.text('让系统代理走 netcap'), findsOneWidget);
      expect(find.text('开始捕获'), findsNothing);

      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('the log lives in its own window', (tester) async {
      tester.view.physicalSize = const Size(1200, 2400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);
      await tester.pumpWidget(const NetcapApp());
      await tester.pump(const Duration(milliseconds: 50));

      expect(find.byType(LogWindow), findsNothing);
      await tester.tap(find.text('日志'));
      await tester.pump(const Duration(milliseconds: 50));
      await tester.pump(const Duration(milliseconds: 600));

      expect(find.byType(LogWindow), findsOneWidget);
      expect(find.textContaining('运行日志（'), findsOneWidget);
      expect(find.text('复制全部'), findsOneWidget);
      expect(find.text('清空'), findsOneWidget);

      await tester.tap(find.text('关闭'));
      // A pop needs a frame to start, a few hundred ms to animate and one more
      // frame before the route leaves the tree.
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 400));
      await tester.pump(const Duration(milliseconds: 200));
      expect(find.byType(LogWindow), findsNothing);

      await tester.pumpWidget(const SizedBox.shrink());
    });
  });

  group('what the interface says when a run ends', () {
    test('stopping on purpose is never an error', () {
      // The exit code of a process we killed ourselves is meaningless, so a
      // user stop must not produce a banner — whatever the code happens to be.
      expect(runFailureText(code: 1, stoppedByUser: true), isNull);
      expect(
        runFailureText(
          code: 3,
          stoppedByUser: true,
          hint: 'raw socket creation failed: ...(WSA error 10013)',
        ),
        isNull,
      );
    });

    test('a clean exit says nothing either', () {
      expect(runFailureText(code: 0, stoppedByUser: false), isNull);
    });

    test('a real failure keeps the code and netcap\'s own reason', () {
      final text = runFailureText(
        code: 3,
        stoppedByUser: false,
        hint: 'raw socket creation failed: ...(WSA error 10013)',
      );
      expect(text, isNotNull);
      expect(text, contains('退出码 3'));
      expect(text, contains('打开抓包源失败'));
      expect(text, contains('WSA error 10013'));
      // Without a hint it is still the headline, never null.
      expect(runFailureText(code: 4, stoppedByUser: false), contains('退出码 4'));
    });
  });

  group('HTTPS decryption policy', () {
    test('the proxy command line carries the mitm switches', () {
      final plain = NetcapRequest(
        mode: SourceMode.proxy,
        rulesPath: 'sample.rules',
        serve: '127.0.0.1:8099',
      ).toArgs();
      expect(plain, isNot(contains('--mitm')));

      final on = NetcapRequest(
        mode: SourceMode.proxy,
        rulesPath: 'sample.rules',
        serve: '127.0.0.1:8099',
        mitm: true,
        mitmSkip: 'bank.exe,pinapp',
        mitmOnly: 'msedge.exe',
        caPrefix: r'D:\Demo\FilterTheWeb\_mitmca',
      ).toArgs();
      expect(on, containsAllInOrder(['--ca', r'D:\Demo\FilterTheWeb\_mitmca']));
      expect(on, contains('--mitm'));
      expect(on, containsAllInOrder(['--mitm-skip', 'bank.exe,pinapp']));
      expect(on, containsAllInOrder(['--mitm-only', 'msedge.exe']));

      // --mitm-only decrypts on its own, so the CA argument must travel with it.
      final only = NetcapRequest(
        mode: SourceMode.proxy,
        rulesPath: 'sample.rules',
        serve: '127.0.0.1:8099',
        mitmOnly: 'msedge.exe',
        caPrefix: 'C:/ca/netcap',
      ).toArgs();
      expect(only, containsAllInOrder(['--ca', 'C:/ca/netcap']));
      expect(only, isNot(contains('--mitm')));
      expect(only, containsAllInOrder(['--mitm-only', 'msedge.exe']));

      // Nothing to decrypt and no CA prefix: neither switch is passed.
      final off = NetcapRequest(
        mode: SourceMode.proxy,
        rulesPath: 'sample.rules',
        serve: '127.0.0.1:8099',
      ).toArgs();
      expect(off, isNot(contains('--ca')));
      expect(off, isNot(contains('--mitm-skip')));
      expect(off, isNot(contains('--mitm-only')));
    });

    test('an intercept event carries the application and the mitm verdict', () {
      final opened = InterceptRecord.fromJson(jsonDecodeMap(
          '{"type":"intercept","action":"tunnel","method":"CONNECT",'
          '"url":"https://example.com/","host":"example.com:443",'
          '"client":"127.0.0.1:27464","client_proc":"msedge.exe","mitm":"on",'
          '"rule":"","detail":"","status":200,"ts_us":1791461928465300,'
          '"request_bytes":113,"response_bytes":60}'));
      expect(opened.clientProc, 'msedge.exe');
      expect(opened.mitm, 'on');
      expect(opened.mitmLabel, '解密');
      expect(opened.matchesSearch('msedge'), isTrue);

      final skipped = InterceptRecord.fromJson(jsonDecodeMap(
          '{"type":"intercept","action":"tunnel","client_proc":"bank.exe",'
          '"mitm":"skip"}'));
      expect(skipped.clientProc, 'bank.exe');
      expect(skipped.mitmLabel, '跳过');

      // A record without the new keys must not throw and must read as "unknown".
      final bare = InterceptRecord.fromJson(jsonDecodeMap('{"type":"intercept"}'));
      expect(bare.clientProc, '');
      expect(bare.mitmLabel, '—');
      expect(bare.matchesSearch('msedge'), isFalse);
    });

    test('the CA status explains what the user has to do', () {
      const missing = CaStatus(prefix: 'netcap-ca');
      expect(missing.ready, isFalse);
      expect(missing.label, '证书：还没有创建');
      expect(missing.shortFingerprint, '');

      const created = CaStatus(
          prefix: 'netcap-ca', certPath: r'D:\ca\_mitmca.crt', exists: true);
      expect(created.ready, isFalse);
      expect(created.label, '证书：已创建，尚未安装');

      const installed = CaStatus(
        prefix: r'D:\ca\_mitmca',
        certPath: r'D:\ca\_mitmca.crt',
        exists: true,
        trusted: true,
        sha256: 'e4:ac:01:fd:8f:10:a0:43:96:fd:76:30:bc:cf:a6:a8:c9:e9:ba:fa',
      );
      expect(installed.ready, isTrue);
      expect(installed.shortFingerprint, 'E4AC01FD8F10A043…');
      expect(installed.label, '证书：已安装 E4AC01FD8F10A043…');

      const broken = CaStatus(error: 'could not read');
      expect(broken.ready, isFalse);
      expect(broken.label, '证书：无法读取');
    });
  });
}

/// Small helper so the fixture constants can stay one-per-line and readable.
Map<String, dynamic> jsonDecodeMap(String line) =>
    Map<String, dynamic>.from(jsonDecode(line) as Map<String, dynamic>);
