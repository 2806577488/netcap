// Widget and formatting tests. These run headless: no capture process is
// started, so they stay fast and deterministic.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/widgets.dart';

Widget _host(Widget child) => MaterialApp(
      home: Scaffold(body: SizedBox(width: 900, height: 400, child: child)),
    );

void main() {
  group('formatting helpers', () {
    test('formatBytes', () {
      expect(formatBytes(0), '0 B');
      expect(formatBytes(999), '999 B');
      expect(formatBytes(1571), '1.5 KiB');
      expect(formatBytes(5 * 1024 * 1024), '5.0 MiB');
    });

    test('formatCount groups thousands', () {
      expect(formatCount(0), '0');
      expect(formatCount(1234), '1,234');
      expect(formatCount(1234567), '1,234,567');
    });

    test('hexToBytes tolerates separators and odd input', () {
      expect(hexToBytes('48656c6c6f'), [0x48, 0x65, 0x6c, 0x6c, 0x6f]);
      expect(hexToBytes('48 65-6c'), [0x48, 0x65, 0x6c]);
      expect(hexToBytes('486'), [0x48]);
      expect(hexToBytes(''), isEmpty);
    });

    test('protocol colours are distinct', () {
      expect(protoColor('TCP'), isNot(protoColor('UDP')));
      expect(appColor('TLS'), isNot(appColor('HTTP')));
    });
  });

  group('HexDumpView', () {
    testWidgets('renders offsets, hex and ASCII', (tester) async {
      await tester.pumpWidget(_host(const HexDumpView(hex: '48656c6c6f2c20776f726c6421')));
      expect(find.textContaining('00000000'), findsOneWidget);
      expect(find.textContaining('48 65 6c 6c 6f'), findsOneWidget);
      expect(find.textContaining('|Hello, world!|'), findsOneWidget);
    });

    testWidgets('wraps at sixteen bytes per row', (tester) async {
      final hex = List.generate(20, (i) => i.toRadixString(16).padLeft(2, '0')).join();
      await tester.pumpWidget(_host(HexDumpView(hex: hex)));
      expect(find.textContaining('00000000'), findsOneWidget);
      expect(find.textContaining('00000010'), findsOneWidget);
      expect(find.textContaining('20 字节'), findsOneWidget);
    });

    testWidgets('explains an empty payload instead of rendering nothing', (tester) async {
      await tester.pumpWidget(_host(const HexDumpView(hex: '')));
      expect(find.text('没有字节内容'), findsOneWidget);
    });

    testWidgets('notes truncation when the payload is longer than the cap', (tester) async {
      final hex = List.generate(64, (i) => (i & 0xff).toRadixString(16).padLeft(2, '0')).join();
      await tester.pumpWidget(_host(HexDumpView(hex: hex, maxBytes: 16)));
      expect(find.textContaining('仅显示前 16 字节'), findsOneWidget);
    });
  });

  group('DetailTreeView', () {
    testWidgets('groups fields by protocol layer in order', (tester) async {
      await tester.pumpWidget(_host(const DetailTreeView(tree: {
        'frame.time': '00:00:01.000000',
        'eth.src': '00:11:22:33:44:55',
        'ip.src': '10.0.0.5',
        'tcp.dst_port': '443 (https)',
        'tls.sni': 'example.com',
      })));
      expect(find.text('帧 Frame'), findsOneWidget);
      expect(find.text('以太网 Ethernet'), findsOneWidget);
      expect(find.text('IPv4'), findsOneWidget);
      expect(find.text('TCP'), findsOneWidget);
      expect(find.text('TLS'), findsOneWidget);
      expect(find.text('example.com'), findsOneWidget);
    });

    testWidgets('shows a placeholder for an empty tree', (tester) async {
      await tester.pumpWidget(_host(const DetailTreeView(tree: {})));
      expect(find.text('没有解析细节'), findsOneWidget);
    });
  });

  group('Pill', () {
    testWidgets('renders its label', (tester) async {
      await tester.pumpWidget(_host(const Pill(text: 'TLS', color: Color(0xFF6EE787))));
      expect(find.text('TLS'), findsOneWidget);
    });
  });
}
