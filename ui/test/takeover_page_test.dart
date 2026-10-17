import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/takeover_page.dart';

/// The takeover page is where every "change how this machine reaches the
/// network" switch lives.  These tests pin down the three things that matter:
/// the page stays readable for someone who is not an administrator, nothing can
/// take over without the desktop escape hatch, and saving/cancelling hand back
/// exactly what the caller expects.
void main() {
  TakeoverDraft? returned;
  final calls = <String>[];

  Widget harness({
    TakeoverDraft draft = const TakeoverDraft(),
    bool rescue = true,
  }) {
    returned = null;
    calls.clear();
    return MaterialApp(
      home: Builder(
        builder: (ctx) => Scaffold(
          body: Center(
            child: ElevatedButton(
              onPressed: () async {
                returned = await showTakeoverPage(
                  ctx,
                  draft: draft,
                  rescueScript: rescue,
                  proxyStatusLabel: 'PAC 模式',
                  proxyStatusDetail: 'ProxyEnable=0\nProxyServer=127.0.0.1:26561',
                  onReadCurrent: () async {
                    calls.add('read');
                    return '读到了：PAC 模式';
                  },
                  onCheckChain: () async {
                    calls.add('chain');
                    return '链式上游 127.0.0.1:7890 能连上';
                  },
                  onRestoreProxy: () async {
                    calls.add('restore');
                    return '已按快照还原';
                  },
                  onTunCheck: () async {
                    calls.add('check');
                    return '预检：会新增一条默认路由';
                  },
                  onTunDrill: (seconds) async {
                    calls.add('drill$seconds');
                    return '演练 $seconds 秒结束';
                  },
                );
              },
              child: const Text('open'),
            ),
          ),
        ),
      ),
    );
  }

  Future<void> open(WidgetTester tester, {TakeoverDraft? draft, bool rescue = true}) async {
    tester.view.physicalSize = const Size(1200, 1100);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(harness(draft: draft ?? const TakeoverDraft(), rescue: rescue));
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();
  }

  Future<void> reveal(WidgetTester tester, Finder finder) async {
    await tester.scrollUntilVisible(finder, 220,
        scrollable: find.byType(Scrollable).first, maxScrolls: 40);
    await tester.pumpAndSettle();
  }

  Future<void> expandAdvanced(WidgetTester tester) async {
    await tester.tap(find.text('高级（一般不用改）'));
    await tester.pumpAndSettle();
  }

  testWidgets('the first screen is one switch and plain words', (tester) async {
    await open(tester);
    expect(find.text('让所有程序都走过滤'), findsOneWidget);
    expect(find.text('自动让系统代理走 netcap'), findsOneWidget);
    expect(find.textContaining('netcap-restore.cmd'), findsWidgets);
    expect(find.textContaining('PAC 模式'), findsWidgets);
    expect(find.text('取消不会改动任何设置'), findsOneWidget);
    // No command line terms on the first screen: they live in the fold.
    expect(find.textContaining('--system-proxy on'), findsNothing);
    expect(find.textContaining('--tun-takeover'), findsNothing);
    expect(find.text('高级（一般不用改）'), findsOneWidget);
  });

  testWidgets('the switch drives the summary line', (tester) async {
    await open(tester);
    await tester.tap(find.byType(SwitchListTile).at(0)); // system proxy
    await tester.pumpAndSettle();
    expect(find.text('所有程序自动走过滤（自动设置系统代理）'), findsOneWidget);

    await expandAdvanced(tester);
    await tester.tap(find.byType(SwitchListTile).at(2)); // tun takes over
    await tester.pumpAndSettle();
    expect(find.text('所有程序自动走过滤（备用方式：虚拟网卡）'), findsOneWidget);

    await tester.tap(find.byType(SwitchListTile).at(2)); // back to no takeover
    await tester.pumpAndSettle();
    expect(find.text('取消不会改动任何设置'), findsOneWidget);

    await tester.tap(find.byType(SwitchListTile).at(0)); // the proxy again
    await tester.pumpAndSettle();
    expect(find.text('所有程序自动走过滤（自动设置系统代理）'), findsOneWidget);
  });

  testWidgets('without the rescue script nothing can take over', (tester) async {
    await open(tester, rescue: false);
    expect(find.textContaining('所以这个开关被禁用了'), findsOneWidget);
    await expandAdvanced(tester);
    for (final tile in tester.widgetList<SwitchListTile>(find.byType(SwitchListTile))) {
      expect(tile.onChanged, isNull);
    }
    await reveal(tester, find.textContaining('演练 12 秒后自动还原'));
    final drill = tester.widget<FilledButton>(
        find.widgetWithText(FilledButton, '演练 12 秒后自动还原'));
    expect(drill.onPressed, isNull);
  });

  testWidgets('a read-only check never touches the machine', (tester) async {
    await open(tester);
    await expandAdvanced(tester);
    await reveal(tester, find.text('只读预检（--tun-check）'));
    await tester.tap(find.text('只读预检（--tun-check）'));
    await tester.pumpAndSettle();
    expect(calls, ['check']);
    await reveal(tester, find.text('预检：会新增一条默认路由'));
    expect(find.text('预检：会新增一条默认路由'), findsOneWidget);
  });

  testWidgets('the drill uses the chosen duration and shows the output', (tester) async {
    await open(tester);
    await expandAdvanced(tester);
    await reveal(tester, find.text('5 秒'));
    await tester.tap(find.text('5 秒'));
    await tester.pumpAndSettle();
    await tester.tap(find.textContaining('演练 5 秒后自动还原'));
    await tester.pumpAndSettle();
    expect(calls, ['drill5']);
    await reveal(tester, find.text('演练 5 秒结束'));
    expect(find.text('演练 5 秒结束'), findsOneWidget);
  });

  testWidgets('the restore button is reachable from the safety strip', (tester) async {
    await open(tester);
    await tester.tap(find.text('现在还原'));
    await tester.pumpAndSettle();
    expect(calls, ['restore']);
  });

  testWidgets('saving hands the edited draft back', (tester) async {
    await open(tester);
    await tester.tap(find.byType(SwitchListTile).at(0)); // system proxy on
    await tester.pumpAndSettle();
    await expandAdvanced(tester);
    await reveal(tester, find.widgetWithText(TextField, '链式上游（--upstream）：接管时必须填'));
    await tester.enterText(
        find.widgetWithText(TextField, '链式上游（--upstream）：接管时必须填'), '127.0.0.1:7890');
    await tester.pumpAndSettle();
    await tester.tap(find.text('保存'));
    await tester.pumpAndSettle();
    expect(returned, isNotNull);
    expect(returned!.systemProxy, isTrue);
    expect(returned!.upstream, '127.0.0.1:7890');
  });

  testWidgets('cancelling changes nothing', (tester) async {
    await open(tester);
    await tester.tap(find.byType(SwitchListTile).at(0));
    await tester.pumpAndSettle();
    await tester.tap(find.text('取消'));
    await tester.pumpAndSettle();
    expect(returned, isNull);
  });

  test('the draft turns into the flags netcap expects', () {
    const off = TakeoverDraft();
    expect(off.args, isEmpty);
    expect(off.summary, contains('只有自己设了代理的程序会走过滤'));

    const proxy = TakeoverDraft(systemProxy: true, upstream: '127.0.0.1:7890');
    expect(proxy.args,
        ['--system-proxy', 'on', '--system-proxy-bypass', '<local>',
         '--upstream', '127.0.0.1:7890']);
    expect(proxy.summary, contains('自动设置系统代理'));

    const forced = TakeoverDraft(
        systemProxy: true, systemProxyForce: true, bypass: '<local>');
    expect(forced.args,
        ['--system-proxy', 'on', '--system-proxy-bypass', '<local>', '--system-proxy-force']);

    const tun = TakeoverDraft(
        tun: true, tunAdapter: 'netcap2', tunAddress: '10.7.0.1/24', upstream: '127.0.0.1:7890');
    expect(
        tun.args,
        ['--tun', '--tun-takeover', '--tun-adapter', 'netcap2', '--tun-address', '10.7.0.1/24',
         '--tun-seconds', '12', '--upstream', '127.0.0.1:7890']);
    expect(tun.summary, contains('备用方式：虚拟网卡'));
  });
}
