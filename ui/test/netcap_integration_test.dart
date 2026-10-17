// End-to-end test of the UI's data path: it starts the real netcap.exe, reads
// the JSON Lines stream it produces and checks the decoded result. This is the
// test that proves the Flutter front end and the C++ back end still agree.
//
// `flutter test` runs on the host VM, so dart:io and Process.start work.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/models.dart';
import 'package:netcap_ui/src/netcap.dart';

void main() {
  late NetcapLocation location;
  late NetcapRunner runner;
  late Directory tmp;

  setUpAll(() async {
    final found = await NetcapRunner.locate();
    expect(found, isNotNull,
        reason: 'netcap.exe must exist (build it with: cmake --build build)');
    location = found!;
    runner = NetcapRunner(location);
    tmp = await Directory.systemTemp.createTemp('netcap_ui_test');
  });

  tearDownAll(() async {
    if (tmp.existsSync()) await tmp.delete(recursive: true);
  });

  test('--jsonl file capture decodes into the UI model', () async {
    final pcap = '${tmp.path}${Platform.pathSeparator}sample.pcap';
    final generated = await runner.generateSample(pcap);
    expect(generated, 25);

    final hello = <HelloInfo>[];
    final packets = <PacketRecord>[];
    final summary = <SummaryInfo>[];
    final logs = <String>[];

    final code = await runner.run(
      NetcapRequest(mode: SourceMode.file, path: pcap, hexFrame: true),
      onJson: (j) {
        switch (j['type']) {
          case 'hello':
            hello.add(HelloInfo.fromJson(j));
          case 'packet':
            packets.add(PacketRecord.fromJson(j));
          case 'summary':
            summary.add(SummaryInfo.fromJson(j));
        }
      },
      onStderr: logs.add,
    );

    expect(code, 0, reason: logs.join('\n'));
    expect(hello, hasLength(1));
    expect(hello.single.live, isFalse);
    expect(hello.single.linktypeName, 'Ethernet');

    expect(packets, hasLength(25));
    expect(summary, hasLength(1));
    expect(summary.single.seen, 25);
    expect(summary.single.matched, 25);
    expect(summary.single.fragCompleted, 1);

    // ARP: no IP header, but real protocol addresses in the endpoint columns.
    final arp = packets.firstWhere((p) => p.proto == 'ARP');
    expect(arp.ipVersion, 0);
    expect(arp.src, '10.0.0.5');
    expect(arp.dst, '10.0.0.1');
    expect(arp.tree['arp.op'], '1 (request)');
    expect(arp.summary, '1 (request)');

    // TLS ClientHello with SNI, decoded through the ordered detail tree.
    final tls = packets.firstWhere((p) => p.app == 'TLS');
    expect(tls.proto, 'TCP');
    expect(tls.dport, 443);
    expect(tls.tlsSni, 'example.com');
    expect(tls.hostname, 'example.com');
    expect(tls.tree['tls.supported_version'], 'TLS 1.3');
    expect(tls.frameHex, isNotNull);
    expect(tls.sourceEndpoint, '10.0.0.5:51000');

    // HTTP request and response.
    final get = packets.firstWhere((p) => p.httpMethod == 'GET');
    expect(get.httpUri, '/index.html');
    expect(get.tree['http.host'], 'example.com');
    final ok = packets.firstWhere((p) => p.httpStatus == 200);
    expect(ok.tree['http.server'], isNotNull);

    // DNS query and answer, plus the IPv6 sample.
    expect(packets.any((p) => p.dnsQname == 'www.example.com'), isTrue);
    expect(packets.any((p) => p.ipVersion == 6), isTrue);

    // Application mix in the final summary.
    expect(summary.single.apps.any((a) => a.kind == 'HTTP' && a.packets == 2), isTrue);

    // The UI shows netcap's own log lines; they must be on stderr, never mixed
    // into the JSON stream.
    expect(logs.any((l) => l.contains('netcap:')), isTrue);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('the display filter is applied by netcap', () async {
    final pcap = '${tmp.path}${Platform.pathSeparator}sample.pcap';
    final packets = <PacketRecord>[];
    final code = await runner.run(
      NetcapRequest(mode: SourceMode.file, path: pcap, filter: 'tls or http'),
      onJson: (j) {
        if (j['type'] == 'packet') packets.add(PacketRecord.fromJson(j));
      },
    );
    expect(code, 0);
    // The filter must admit TLS and HTTP and nothing outside them. The added
    // TLS session carries opaque application records with no app tag (""),
    // which netcap still routes through the tls branch of the filter.
    final apps = packets.map((p) => p.app).toSet();
    expect(apps, containsAll(<String>{'TLS', 'HTTP'}));
    expect(apps.difference(<String>{'TLS', 'HTTP', ''}), isEmpty);

    final dns = <PacketRecord>[];
    await runner.run(
      NetcapRequest(mode: SourceMode.file, path: pcap, filter: 'hostname www.example.com'),
      onJson: (j) {
        if (j['type'] == 'packet') dns.add(PacketRecord.fromJson(j));
      },
    );
    expect(dns, isNotEmpty);
    expect(dns.every((p) => p.hostname == 'www.example.com'), isTrue);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a bad filter reports exit code 2 with an explanation', () async {
    final pcap = '${tmp.path}${Platform.pathSeparator}sample.pcap';
    final logs = <String>[];
    final code = await runner.run(
      NetcapRequest(mode: SourceMode.file, path: pcap, filter: 'host not-an-ip'),
      onStderr: logs.add,
    );
    expect(code, 2);
    expect(exitCodeHelp(code), contains('过滤器'));
    expect(logs.join('\n'), contains('not-an-ip'));
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('device enumeration fills the live-capture dropdown', () async {
    final listing = await runner.listDevices();
    expect(listing.devices, isNotEmpty);
    expect(listing.count, listing.devices.length);
    for (final d in listing.devices) {
      expect(d.name, isNotEmpty);
      expect(d.label, contains(d.name));
    }
    expect(listing.mechanism, isNotEmpty);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a missing pcap file fails with exit code 3', () async {
    final code = await runner.run(
      NetcapRequest(
        mode: SourceMode.file,
        path: '${tmp.path}${Platform.pathSeparator}does-not-exist.pcap',
      ),
      onStderr: (_) {},
    );
    expect(code, 3);
    expect(exitCodeHelp(code), contains('抓包源'));
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('--jsonl and "-w -" are rejected together', () async {
    final pcap = '${tmp.path}${Platform.pathSeparator}sample.pcap';
    final code = await runner.run(
      NetcapRequest(mode: SourceMode.file, path: pcap, exportPath: '-'),
      onStderr: (_) {},
    );
    expect(code, 2);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('--keylog --streams --http decode reassembly into the UI models', () async {
    final dir = tmp.path;
    final pcap = '$dir${Platform.pathSeparator}sample.pcap';
    final keys = '$dir${Platform.pathSeparator}sample.keys';
    await runner.generateSample(pcap);
    expect(File(keys).existsSync(), isTrue,
        reason: 'netcap -g writes the key log next to the sample capture');

    final http = <HttpTransactionInfo>[];
    final streams = <StreamInfo>[];
    final summary = <SummaryInfo>[];
    final logs = <String>[];

    final code = await runner.run(
      NetcapRequest(
        mode: SourceMode.file,
        path: pcap,
        keylog: keys,
        streams: true,
        http: true,
      ),
      onJson: (j) {
        if (j['type'] == 'summary') summary.add(SummaryInfo.fromJson(j));
      },
      onStream: streams.add,
      onHttp: http.add,
      onStderr: logs.add,
    );

    expect(code, 0, reason: logs.join('\n'));
    expect(http, hasLength(2));
    final secureHttp = http.firstWhere((h) => h.host == 'secure.example.com');
    expect(secureHttp.status, 200);
    expect(secureHttp.decrypted, isTrue);
    expect(secureHttp.label, 'GET /secure');
    expect(secureHttp.statusLabel, '200 OK');
    expect(secureHttp.complete, isTrue);
    // The plaintext HTTP/1.1 flow in the same capture is analysed as well.
    final plainHttp = http.firstWhere((h) => h.host == 'example.com');
    expect(plainHttp.decrypted, isFalse);
    expect(plainHttp.label, 'GET /index.html');
    expect(plainHttp.status, 200);

    expect(streams, hasLength(4));
    final secure = streams.firstWhere((s) => s.decrypted);
    expect(secure.index, 4);
    expect(secure.sni, 'secure.example.com');
    expect(secure.tlsVersion, 'TLS 1.3');
    expect(secure.plaintextBytes, greaterThan(0));
    // The undecrypted TLS flow is still reported, flagged as key-less.
    expect(streams.any((s) => s.tls && !s.decrypted), isTrue);

    expect(summary.single.streams, 4);
    expect(summary.single.decryptedStreams, 1);
    expect(summary.single.http1Streams, 2);
    expect(summary.single.httpTransactions, 2);
    expect(summary.single.keysLoaded, isTrue);
    expect(summary.single.reassembledBytes, greaterThan(0));
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('--follow reports a live transaction exactly once', () async {
    final dir = tmp.path;
    final pcap = '$dir${Platform.pathSeparator}sample.pcap';
    final keys = '$dir${Platform.pathSeparator}sample.keys';
    await runner.generateSample(pcap);

    final http = <HttpTransactionInfo>[];
    final code = await runner.run(
      NetcapRequest(
        mode: SourceMode.file,
        path: pcap,
        keylog: keys,
        http: true,
        follow: true,
      ),
      onHttp: http.add,
    );

    expect(code, 0);
    // --http and --follow together must not double-report a transaction.
    expect(http, hasLength(2));
    expect(http.where((h) => h.host == 'secure.example.com'), hasLength(1));
    expect(http.where((h) => h.host == 'example.com'), hasLength(1));
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('the request builder produces the documented command line', () {
    final request = NetcapRequest(
      mode: SourceMode.live,
      device: '22',
      filter: 'tcp and dst port 443',
      limit: 100,
      hexFrame: true,
      exportPath: r'D:\out.pcap',
    );
    expect(
      request.toArgs(),
      [
        '--jsonl',
        '--interface', '22',
        '--no-promisc',
        '--count', '100',
        '--filter', 'tcp and dst port 443',
        '--snaplen', '262144',
        '--hex-all',
        '--write', r'D:\out.pcap',
      ],
    );
    final file = NetcapRequest(mode: SourceMode.file, path: r'D:\a b.pcap', hexPayload: true);
    expect(file.toArgs(), ['--jsonl', '--read', r'D:\a b.pcap', '--snaplen', '262144', '--hex']);
    expect(file.describe(r'C:\x\netcap.exe'), contains('"D:\\a b.pcap"'));

    final analysis = NetcapRequest(
      mode: SourceMode.file,
      path: r'D:\a b.pcap',
      keylog: r'D:\keys.log',
      streams: true,
      http: true,
      follow: true,
    );
    expect(analysis.toArgs(), [
      '--jsonl',
      '--read', r'D:\a b.pcap',
      '--snaplen', '262144',
      '--keylog', r'D:\keys.log',
      '--streams',
      '--http',
      '--follow',
    ]);
    // An empty key log path must not produce a dangling --keylog.
    expect(
      NetcapRequest(mode: SourceMode.file, path: r'D:\a b.pcap', keylog: '  ').toArgs(),
      isNot(contains('--keylog')),
    );
  });
}
