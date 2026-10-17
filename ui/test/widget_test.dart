// Smoke test for the application shell: it must build and show its main
// controls without a capture running, and it must shut down cleanly (the
// screen owns a periodic timer, so a leak would fail the pending-timer check).

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/main.dart';

void main() {
  testWidgets('the capture screen renders its controls', (tester) async {
    // The real window is 1280x720; the default 800x600 test view is shorter
    // than the right-hand pane, and that pane builds its rows lazily — a
    // section below the fold would simply not exist for the finder.
    tester.view.physicalSize = const Size(1280, 720);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(const NetcapApp());
    await tester.pump();

    expect(find.text('netcap UI'), findsOneWidget);
    // The window opens on the interception proxy — no three-way source switch,
    // and the packet-capture controls now live behind 抓包工具.
    expect(find.text('让系统代理走 netcap'), findsOneWidget);
    expect(find.text('抓包工具'), findsOneWidget);
    expect(find.text('开始捕获'), findsNothing);
    expect(find.text('pcap 文件'), findsNothing);
    expect(find.text('实时网卡'), findsNothing);
    expect(find.text('拦截代理'), findsNothing);
    expect(find.text('当前连接 Connection'), findsOneWidget);
    expect(find.text('拦截统计 Interception'), findsOneWidget);
    expect(find.textContaining('还没有拦截记录'), findsOneWidget);

    // The 流与 HTTP tab is only offered once a TCP stream or an HTTP
    // transaction exists; without one it would only show two empty tables.
    // (The positive direction is covered by the integration tests, which run
    // the real netcap.exe and see streams and transactions.)
    expect(find.text('流与 HTTP'), findsNothing);

    // Tear the tree down so the periodic flush timer is cancelled.
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(milliseconds: 200));
  });

  testWidgets('the filter help dialog documents the DSL', (tester) async {
    await tester.pumpWidget(const NetcapApp());
    await tester.pump();

    await tester.tap(find.byTooltip('过滤器语法帮助'));
    await tester.pumpAndSettle();

    expect(find.text('过滤器语法'), findsOneWidget);
    expect(find.textContaining('hostname example.com'), findsWidgets);

    await tester.tap(find.text('关闭'));
    await tester.pumpAndSettle();
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(milliseconds: 200));
  });
}
