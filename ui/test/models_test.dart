// Parsing tests for the JSON Lines contract emitted by `netcap --jsonl`.
//
// The fixtures below are byte-for-byte excerpts of real netcap output, so a
// change to the C++ side that breaks the UI contract fails here first.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/models.dart';

const String _hello = '{"type":"hello","tool":"netcap 1.0","live":false,'
    '"source":"sample.pcap","described":"pcap file \'sample.pcap\', linktype Ethernet",'
    '"linktype":1,"linktype_name":"Ethernet","filter":"tls","snaplen":262144,'
    '"nanosecond":false}';

const String _tlsPacket = '{"type":"packet","n":2,"ts_us":1700000000000551,'
    '"time":"22:13:20.000551","len":137,"origlen":137,"linktype":1,"truncated":false,'
    '"malformed":false,"reason":"","ip_version":4,"src":"10.0.0.5","dst":"93.184.216.34",'
    '"proto":"TCP","sport":51000,"dport":443,"sport_name":"","dport_name":"https",'
    '"flags":".S......","app":"TLS","app_name":"TLS",'
    '"app_summary":"TLS ClientHello ver=TLS 1.2 SNI=example.com","hostname":"example.com",'
    '"tls_sni":"example.com","payload_len":79,"payload_head":"160301004a",'
    '"frame_hex":"52540012345600112233445508004500007b","tree":{'
    '"frame.time":"22:13:20.000551","frame.length":"137 bytes captured",'
    '"ip.version":"4","ip.src":"10.0.0.5","ip.dst":"93.184.216.34",'
    '"tcp.src_port":"51000","tcp.dst_port":"443 (https)","tcp.mss":"1460",'
    '"app.kind":"TLS","tls.sni":"example.com","tls.supported_version":"TLS 1.3",'
    '"payload.length":"79 bytes"}}';

const String _arpPacket = '{"type":"packet","n":1,"ts_us":1700000000000120,'
    '"time":"22:13:20.000120","len":42,"origlen":42,"linktype":1,"truncated":false,'
    '"malformed":false,"reason":"","ip_version":0,"src":"10.0.0.5","dst":"10.0.0.1",'
    '"proto":"ARP","sport":0,"dport":0,"sport_name":"","dport_name":"","flags":"",'
    '"app":"","app_name":"unknown","app_summary":"","hostname":"","payload_len":0,'
    '"payload_head":"","tree":{"frame.time":"22:13:20.000120",'
    '"frame.length":"42 bytes captured","frame.linktype":"Ethernet (1)",'
    '"eth.dst":"ff:ff:ff:ff:ff:ff","eth.src":"00:11:22:33:44:55",'
    '"eth.ethertype":"0x0806 (ARP)","arp.op":"1 (request)",'
    '"arp.sender":"10.0.0.5  00:11:22:33:44:55",'
    '"arp.target":"10.0.0.1  00:00:00:00:00:00","payload.length":"0 bytes"}}';

const String _malformedPacket = '{"type":"packet","n":9,"time":"00:00:00.000000",'
    '"len":3,"origlen":3,"truncated":true,"malformed":true,"reason":"runt ethernet frame",'
    '"ip_version":0,"src":"","dst":"","proto":"","flags":"","app":"","app_name":"unknown",'
    '"payload_len":0,"payload_head":"","tree":{}}';

const String _summary = '{"type":"summary","seen":15,"matched":2,"bytes":195,'
    '"malformed":0,"source_packets":15,"kernel_stats":false,"kernel_drops":0,'
    '"frag_seen":1,"frag_completed":1,"frag_dropped":0,"frag_pending":0,"written":0,'
    '"write_path":"","interrupted":false,"apps":['
    '{"kind":"TLS","name":"TLS","packets":2,"bytes":195},'
    '{"kind":"","name":"unknown","packets":5,"bytes":278}]}';

const String _devices = '{"type":"devices","count":2,"mechanism_available":true,'
    '"mechanism":"raw IPv4 socket with SIO_RCVALL","requirement":"Administrator"}';

const String _device = '{"type":"device","index":22,"name":"WLAN","description":"Intel AX201",'
    '"address":"192.168.0.24","mac":"1e:00:45:70:e5:9d","family":4,"up":true,'
    '"loopback":false,"default":true}';

Map<String, dynamic> _decode(String json) => jsonDecode(json) as Map<String, dynamic>;

// The same hello line once --keylog was given: reassembly and the key log are
// announced up front.
const String _helloAnalysis = '{"type":"hello","tool":"netcap 1.0","live":false,'
    '"source":"sample.pcap","described":"pcap file \'sample.pcap\', linktype Ethernet",'
    '"linktype":1,"linktype_name":"Ethernet","filter":"","snaplen":262144,'
    '"nanosecond":false,"reassembly":true,"keylog":"sample.keys","keylog_loaded":true,'
    '"keylog_entries":4}';

const String _httpTransaction = '{"type":"http","stream":4,"http2":false,"decrypted":true,'
    '"client":"10.0.0.5:52000","server":"93.184.216.34:443","transport":"HTTPS/1.1 (decrypted)",'
    '"host":"secure.example.com","method":"GET","target":"/secure",'
    '"url":"https://secure.example.com/secure","version":"HTTP/1.1","status":200,'
    '"status_line":"HTTP/1.1 200 OK","content_type":"text/plain","request_bytes":0,'
    '"response_bytes":11,"request_complete":true,"response_complete":true,"websocket":false,'
    '"truncated":false,"start_us":1700000000073511,"end_us":1700000000073721,"duration_ms":0,'
    '"note":"decrypted",'
    '"summary":"GET https://secure.example.com/secure -> 200 OK [11B] (decrypted)"}';

// An HTTP/2 record is the only kind that carries stream_id.
const String _http2Transaction = '{"type":"http","stream_id":1,"http2":true,"decrypted":true,'
    '"host":"h2.example.com","method":"POST","target":"/api","status":0,'
    '"request_bytes":37,"response_bytes":0,"request_complete":true,"response_complete":false}';

const String _stream = '{"type":"stream","index":4,"client":"10.0.0.5:52000",'
    '"server":"93.184.216.34:443","protocol":"HTTPS/1.1","app":"HTTP",'
    '"sni":"secure.example.com","alpn":"http/1.1","tls":true,"decrypted":true,"http":true,'
    '"http2":false,"websocket":false,"keys_available":true,"truncated":false,'
    '"tls_version_id":772,"tls_version":"TLS 1.3","cipher_id":4865,'
    '"cipher":"TLS_AES_128_GCM_SHA256","packets":10,"client_bytes":248,"server_bytes":271,'
    '"plaintext_bytes":184,"records":6,"retransmits":0,"out_of_order":1,"overlaps":0,"gaps":1,'
    '"transactions":1,"first_us":1700000000072651,"last_us":1700000000073951,"note":""}';

const String _summaryAnalysis = '{"type":"summary","seen":25,"matched":25,"bytes":2638,'
    '"malformed":0,"source_packets":25,"kernel_stats":false,"kernel_drops":0,"frag_seen":1,'
    '"frag_completed":1,"frag_dropped":0,"frag_pending":0,"written":0,"write_path":"",'
    '"interrupted":false,"streams":4,"reassembly":true,"tls_streams":2,"decrypted_streams":1,'
    '"http1_streams":2,"http2_streams":0,"http_transactions":2,'
    '"http_decrypted_transactions":1,"http2_transactions":0,"reassembled_bytes":833,'
    '"keys_loaded":true,"keylog_entries":4,"apps":['
    '{"kind":"TLS","name":"TLS","packets":11,"bytes":1146},'
    '{"kind":"","name":"unknown","packets":6,"bytes":394}]}';

void main() {
  group('hello', () {
    test('carries source metadata', () {
      final h = HelloInfo.fromJson(_decode(_hello));
      expect(h.tool, 'netcap 1.0');
      expect(h.live, isFalse);
      expect(h.linktype, 1);
      expect(h.linktypeName, 'Ethernet');
      expect(h.filter, 'tls');
      expect(h.snaplen, 262144);
      expect(h.nanosecond, isFalse);
    });

    test('an older hello without the reassembly fields still parses', () {
      final h = HelloInfo.fromJson(_decode(_hello));
      expect(h.reassembly, isFalse);
      expect(h.keylog, '');
      expect(h.keylogLoaded, isFalse);
      expect(h.keylogEntries, 0);
    });

    test('carries reassembly and key log metadata', () {
      final h = HelloInfo.fromJson(_decode(_helloAnalysis));
      expect(h.reassembly, isTrue);
      expect(h.keylog, 'sample.keys');
      expect(h.keylogLoaded, isTrue);
      expect(h.keylogEntries, 4);
    });
  });

  group('packet', () {
    test('decodes transport and application fields', () {
      final p = PacketRecord.fromJson(_decode(_tlsPacket));
      expect(p.n, 2);
      expect(p.time, '22:13:20.000551');
      expect(p.len, 137);
      expect(p.ipVersion, 4);
      expect(p.src, '10.0.0.5');
      expect(p.dst, '93.184.216.34');
      expect(p.proto, 'TCP');
      expect(p.dport, 443);
      expect(p.dportName, 'https');
      expect(p.flags, '.S......');
      expect(p.app, 'TLS');
      expect(p.tlsSni, 'example.com');
      expect(p.hostname, 'example.com');
      expect(p.frameHex, startsWith('525400123456'));
      expect(p.summary, contains('SNI=example.com'));
      expect(p.sourceEndpoint, '10.0.0.5:51000');
      expect(p.destEndpoint, '93.184.216.34:443 https');
    });

    test('keeps the ordered detail tree as strings', () {
      final p = PacketRecord.fromJson(_decode(_tlsPacket));
      expect(p.tree.keys.first, 'frame.time');
      expect(p.tree['tcp.mss'], '1460');
      expect(p.tree['tls.supported_version'], 'TLS 1.3');
      expect(p.tree.values.every((v) => v.isNotEmpty), isTrue);
    });

    test('ARP frames expose their protocol addresses, not "?"', () {
      final p = PacketRecord.fromJson(_decode(_arpPacket));
      expect(p.ipVersion, 0);
      expect(p.proto, 'ARP');
      expect(p.src, '10.0.0.5');
      expect(p.dst, '10.0.0.1');
      expect(p.appTag, 'other');
      expect(p.sourceEndpoint, '10.0.0.5');
      expect(p.summary, '1 (request)');
      expect(p.tree['arp.sender'], '10.0.0.5  00:11:22:33:44:55');
    });

    test('malformed frames are still renderable', () {
      final p = PacketRecord.fromJson(_decode(_malformedPacket));
      expect(p.malformed, isTrue);
      expect(p.truncated, isTrue);
      expect(p.summary, contains('runt ethernet frame'));
      expect(p.sourceEndpoint, '—');
    });

    test('local search matches endpoints, host and summary', () {
      final p = PacketRecord.fromJson(_decode(_tlsPacket));
      expect(p.matchesSearch('example.com'), isTrue);
      expect(p.matchesSearch('93.184'), isTrue);
      expect(p.matchesSearch('tls'), isTrue);
      expect(p.matchesSearch('nope'), isFalse);
      expect(p.matchesSearch(''), isTrue);
    });

    test('missing optional fields never throw', () {
      final p = PacketRecord.fromJson(_decode('{"type":"packet","n":1}'));
      expect(p.n, 1);
      expect(p.src, '');
      expect(p.tree, isEmpty);
      expect(p.httpStatus, isNull);
      expect(p.appTag, 'other');
    });
  });

  group('summary', () {
    test('decodes counters and the application mix', () {
      final s = SummaryInfo.fromJson(_decode(_summary));
      expect(s.seen, 15);
      expect(s.matched, 2);
      expect(s.bytes, 195);
      expect(s.sourcePackets, 15);
      expect(s.fragCompleted, 1);
      expect(s.apps.length, 2);
      expect(s.apps.first.kind, 'TLS');
      expect(s.apps.first.packets, 2);
      // The catch-all bucket has an empty tag in the protocol; the UI names it.
      expect(s.apps[1].kind, '');
      expect(s.apps[1].label, 'other');
    });
  });

  group('devices', () {
    test('decodes an interface row', () {
      final d = DeviceInfo.fromJson(_decode(_device));
      expect(d.index, 22);
      expect(d.name, 'WLAN');
      expect(d.up, isTrue);
      expect(d.isDefault, isTrue);
      expect(d.label, startsWith('★ WLAN'));
      expect(d.label, contains('192.168.0.24'));
    });

    test('decodes the listing trailer', () {
      final l = DeviceListing.fromJson(
        _decode(_devices),
        [DeviceInfo.fromJson(_decode(_device))],
      );
      expect(l.count, 2);
      expect(l.mechanismAvailable, isTrue);
      expect(l.mechanism, contains('SIO_RCVALL'));
      expect(l.requirement, 'Administrator');
      expect(l.devices.single.name, 'WLAN');
    });
  });

  group('http transaction', () {
    test('decodes a decrypted HTTP/1.1 transaction', () {
      final t = HttpTransactionInfo.fromJson(_decode(_httpTransaction));
      expect(t.streamId, isNull); // H1 records use "stream", not "stream_id"
      expect(t.http2, isFalse);
      expect(t.decrypted, isTrue);
      expect(t.client, '10.0.0.5:52000');
      expect(t.server, '93.184.216.34:443');
      expect(t.transport, 'HTTPS/1.1 (decrypted)');
      expect(t.host, 'secure.example.com');
      expect(t.method, 'GET');
      expect(t.target, '/secure');
      expect(t.url, 'https://secure.example.com/secure');
      expect(t.version, 'HTTP/1.1');
      expect(t.status, 200);
      expect(t.statusLine, 'HTTP/1.1 200 OK');
      expect(t.contentType, 'text/plain');
      expect(t.requestBytes, 0);
      expect(t.responseBytes, 11);
      expect(t.requestComplete, isTrue);
      expect(t.responseComplete, isTrue);
      expect(t.websocket, isFalse);
      expect(t.truncated, isFalse);
      expect(t.startUs, 1700000000073511);
      expect(t.endUs, 1700000000073721);
      expect(t.durationMs, 0);
      expect(t.note, 'decrypted');
      expect(t.summary, contains('200 OK [11B]'));

      expect(t.label, 'GET /secure');
      expect(t.statusLabel, '200 OK');
      expect(t.complete, isTrue);
      expect(t.bytesLabel, '0B/11B');
    });

    test('an HTTP/2 record keeps its stream id', () {
      final t = HttpTransactionInfo.fromJson(_decode(_http2Transaction));
      expect(t.streamId, 1);
      expect(t.http2, isTrue);
      expect(t.label, 'POST /api');
      expect(t.bytesLabel, '37B/0B');
    });

    test('a response-less transaction labels its status with an em dash', () {
      final t = HttpTransactionInfo.fromJson(_decode(_http2Transaction));
      expect(t.status, 0);
      expect(t.statusLabel, '—');
      expect(t.complete, isFalse);
    });

    test('missing fields never throw', () {
      final t = HttpTransactionInfo.fromJson(_decode('{"type":"http"}'));
      expect(t.streamId, isNull);
      expect(t.method, '');
      expect(t.status, 0);
      expect(t.statusLabel, '—');
      expect(t.complete, isFalse);
      expect(t.bytesLabel, '0B/0B');
      expect(t.label, isNotEmpty);
    });
  });

  group('stream', () {
    test('decodes a decrypted TLS stream', () {
      final s = StreamInfo.fromJson(_decode(_stream));
      expect(s.index, 4);
      expect(s.client, '10.0.0.5:52000');
      expect(s.server, '93.184.216.34:443');
      expect(s.protocol, 'HTTPS/1.1');
      expect(s.app, 'HTTP');
      expect(s.sni, 'secure.example.com');
      expect(s.alpn, 'http/1.1');
      expect(s.tls, isTrue);
      expect(s.decrypted, isTrue);
      expect(s.http, isTrue);
      expect(s.http2, isFalse);
      expect(s.websocket, isFalse);
      expect(s.keysAvailable, isTrue);
      expect(s.truncated, isFalse);
      expect(s.tlsVersionId, 772);
      expect(s.tlsVersion, 'TLS 1.3');
      expect(s.cipherId, 4865);
      expect(s.cipher, 'TLS_AES_128_GCM_SHA256');
      expect(s.packets, 10);
      expect(s.clientBytes, 248);
      expect(s.serverBytes, 271);
      expect(s.plaintextBytes, 184);
      expect(s.records, 6);
      expect(s.retransmits, 0);
      expect(s.outOfOrder, 1);
      expect(s.overlaps, 0);
      expect(s.gaps, 1);
      expect(s.transactions, 1);
      expect(s.firstUs, 1700000000072651);
      expect(s.lastUs, 1700000000073951);
      expect(s.note, '');

      expect(s.endpoints, '10.0.0.5:52000 → 93.184.216.34:443');
      expect(s.protocolLabel, 'HTTPS/1.1');
      expect(s.durationMs, 1);
    });

    test('falls back when netcap leaves protocol or endpoints out', () {
      final plain = StreamInfo.fromJson(_decode('{"type":"stream","index":2}'));
      expect(plain.index, 2);
      expect(plain.protocolLabel, 'TCP');
      expect(plain.endpoints, '—');
      expect(plain.packets, 0);
      expect(plain.durationMs, 0);

      final h2 = StreamInfo.fromJson(_decode('{"type":"stream","index":3,"http":true,"http2":true}'));
      expect(h2.protocolLabel, 'HTTP/2');
    });
  });

  group('summary analysis fields', () {
    test('decodes the reassembly counters', () {
      final s = SummaryInfo.fromJson(_decode(_summaryAnalysis));
      expect(s.seen, 25);
      expect(s.streams, 4);
      expect(s.reassembly, isTrue);
      expect(s.tlsStreams, 2);
      expect(s.decryptedStreams, 1);
      expect(s.http1Streams, 2);
      expect(s.http2Streams, 0);
      expect(s.httpTransactions, 2);
      expect(s.httpDecryptedTransactions, 1);
      expect(s.http2Transactions, 0);
      expect(s.reassembledBytes, 833);
      expect(s.keysLoaded, isTrue);
      expect(s.keylogEntries, 4);
      expect(s.keylogLabel, '已加载 4 条密钥');
    });

    test('an older summary without them still parses', () {
      final s = SummaryInfo.fromJson(_decode(_summary));
      expect(s.streams, 0);
      expect(s.reassembly, isFalse);
      expect(s.keysLoaded, isFalse);
      expect(s.keylogEntries, 0);
      expect(s.keylogLabel, '未加载');
    });
  });

  test('every fixture line is valid JSON', () {
    for (final line in [
      _hello,
      _helloAnalysis,
      _tlsPacket,
      _arpPacket,
      _malformedPacket,
      _summary,
      _summaryAnalysis,
      _httpTransaction,
      _http2Transaction,
      _stream,
      _device,
      _devices,
    ]) {
      expect(() => jsonDecode(line), returnsNormally);
    }
  });
}
