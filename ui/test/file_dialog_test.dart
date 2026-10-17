// The export dialog used to be an open-file browser with a path box: picking an
// existing file overwrote it without a word. These pin the save behaviour.
//
// Everything here is **synchronous** file IO on purpose: `testWidgets` runs in
// a fake-async zone, so an awaited `Directory.createTemp()` / `writeAsString()`
// never completes and the test hangs (see the warning in log_page.dart).
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/widgets.dart';

void main() {
  testWidgets('save mode names the file and warns before overwriting',
      (tester) async {
    final dir = Directory.systemTemp.createTempSync('netcap-dlg');
    final sep = Platform.pathSeparator;
    File('${dir.path}${sep}plain.txt').writeAsStringSync('keep me');
    String? picked;

    await tester.pumpWidget(MaterialApp(
      home: Builder(
        builder: (ctx) => TextButton(
          onPressed: () async {
            picked = await FileBrowserDialog.show(
              ctx,
              initialDirectory: dir.path,
              title: '导出过滤日志',
              extensions: const ['.txt'],
              save: true,
              suggestedName: 'netcap-filter-log-20261010-1741.txt',
            );
          },
          child: const Text('open'),
        ),
      ),
    ));
    await tester.tap(find.text('open'));
    await tester.pump(const Duration(milliseconds: 300));

    // The suggested name is filled in, and the target is spelled out.
    expect(
        find.text(
            '保存到：${dir.path}${sep}netcap-filter-log-20261010-1741.txt'),
        findsOneWidget);
    expect(find.text('保存'), findsOneWidget);

    // Pointing it at a file that exists turns the button into an explicit
    // 覆盖保存 and says which file it would replace.
    await tester.enterText(find.byType(TextField).last, 'plain.txt');
    await tester.pump();
    expect(find.text('覆盖保存'), findsOneWidget);
    expect(find.textContaining('已经有同名文件'), findsOneWidget);

    await tester.tap(find.text('覆盖保存'));
    await tester.pump(const Duration(milliseconds: 300));
    expect(picked, '${dir.path}${sep}plain.txt');

    dir.deleteSync(recursive: true);
  });

  testWidgets('open mode still refuses to return anything without a selection',
      (tester) async {
    final dir = Directory.systemTemp.createTempSync('netcap-dlg2');
    final sep = Platform.pathSeparator;
    File('${dir.path}${sep}a.pcap').writeAsStringSync('x');

    await tester.pumpWidget(MaterialApp(
      home: Builder(
        builder: (ctx) => TextButton(
          onPressed: () async {
            await FileBrowserDialog.show(ctx, initialDirectory: dir.path);
          },
          child: const Text('open'),
        ),
      ),
    ));
    await tester.tap(find.text('open'));
    await tester.pump(const Duration(milliseconds: 300));

    // The default title is also 「选择文件」, so look at the button itself.
    expect(find.widgetWithText(FilledButton, '选择文件'), findsOneWidget);
    expect(find.text('使用 a.pcap'), findsNothing);
    await tester.tap(find.text('a.pcap'));
    await tester.pump();
    expect(find.text('使用 a.pcap'), findsOneWidget);

    dir.deleteSync(recursive: true);
  });
}
