// The 过滤日志 page shows the live session plus the durable file; this pins
// the merging rules (order, de-duplication, file-only rows).
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/log_merge.dart';
import 'package:netcap_ui/src/models.dart';

InterceptRecord rec(int tsUs, String action, String host, [String url = '']) =>
    InterceptRecord(
      tsUs: tsUs,
      action: action,
      method: 'GET',
      url: url,
      host: host,
      client: '',
      rule: '',
      detail: '',
      status: 0,
      requestBytes: 0,
      responseBytes: 0,
    );

void main() {
  test('the newest decision is first, whatever the source', () {
    final merged = mergeFilterLog(
      <InterceptRecord>[rec(2000, 'modify', 'b.com')],
      <InterceptRecord>[
        rec(1000, 'modify', 'example.com'),
        rec(3000, 'block', 'ads.example.com'),
      ],
    );
    expect(merged.map((r) => r.host).toList(),
        <String>['ads.example.com', 'b.com', 'example.com']);
  });

  test('the same decision from both sources is listed once', () {
    final live = <InterceptRecord>[
      rec(5000, 'block', 'ad.doubleclick.net', 'http://ad.doubleclick.net/'),
    ];
    final fromFile = <InterceptRecord>[
      rec(5000, 'block', 'ad.doubleclick.net', 'http://ad.doubleclick.net/'),
      rec(4000, 'block', 'ads.example.com'),
    ];
    final merged = mergeFilterLog(live, fromFile);
    expect(merged.length, 2);
    expect(merged.first.host, 'ad.doubleclick.net');
  });

  test('an older file is still worth showing when the session is empty', () {
    final merged = mergeFilterLog(
      const <InterceptRecord>[],
      <InterceptRecord>[rec(1000, 'modify', 'example.com')],
    );
    expect(merged.length, 1);
    expect(merged.single.host, 'example.com');
  });
}
