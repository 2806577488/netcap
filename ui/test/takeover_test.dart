/// Tests for the takeover plumbing: the system-proxy options that ride along
/// with the proxy command line, the registry snapshot the UI renders, and the
/// one guard that stands between those switches and a machine with no default
/// route.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/main.dart';
import 'package:netcap_ui/src/netcap.dart';

void main() {
  group('the system proxy options', () {
    test('stay out of the command line unless they are asked for', () {
      final r = NetcapRequest(mode: SourceMode.proxy, serve: '127.0.0.1:8080');
      final args = r.toArgs();
      expect(args, isNot(contains('--system-proxy')));
      expect(args, isNot(contains('--system-proxy-force')));
    });

    test('turn into --system-proxy on with the bypass list', () {
      final r = NetcapRequest(
        mode: SourceMode.proxy,
        serve: '127.0.0.1:8099',
        rulesPath: 'sample.rules',
        systemProxy: true,
        systemProxyBypass: '10.*;192.168.*',
      );
      final args = r.toArgs();
      expect(args.sublist(args.indexOf('--system-proxy'), args.indexOf('--system-proxy') + 2),
          ['--system-proxy', 'on']);
      expect(args.sublist(args.indexOf('--system-proxy-bypass'),
          args.indexOf('--system-proxy-bypass') + 2), [
        '--system-proxy-bypass',
        '10.*;192.168.*',
      ]);
      expect(args, isNot(contains('--system-proxy-force')));
    });

    test('only add the force flag when the user insisted', () {
      final r = NetcapRequest(
        mode: SourceMode.proxy,
        systemProxy: true,
        systemProxyForce: true,
      );
      final args = r.toArgs();
      expect(args, contains('--system-proxy-force'));
      // The force flag without the takeover would be meaningless, so the switch
      // is what pulls it in.
      expect(args, contains('--system-proxy'));
    });

    test('a capture run never carries them', () {
      final r = NetcapRequest(
        mode: SourceMode.file,
        path: 'sample.pcap',
        systemProxy: true,
        systemProxyForce: true,
      );
      final args = r.toArgs();
      expect(args, isNot(contains('--system-proxy')));
      expect(args, isNot(contains('--system-proxy-force')));
    });
  });

  group('the chain upstream', () {
    test('rides along with a proxy session', () {
      final r = NetcapRequest(
        mode: SourceMode.proxy,
        serve: '127.0.0.1:8099',
        upstream: ' 127.0.0.1:7890 ',
      );
      final args = r.toArgs();
      expect(args.sublist(args.indexOf('--upstream'), args.indexOf('--upstream') + 2),
          ['--upstream', '127.0.0.1:7890']);
    });

    test('stays out when it is empty', () {
      final r = NetcapRequest(mode: SourceMode.proxy, serve: '127.0.0.1:8099');
      expect(r.toArgs(), isNot(contains('--upstream')));
    });

    test('a capture run never carries it', () {
      final r = NetcapRequest(mode: SourceMode.file, path: 'sample.pcap', upstream: '127.0.0.1:7890');
      expect(r.toArgs(), isNot(contains('--upstream')));
    });
  });

  group('the TUN session', () {
    test('brings the adapter up without taking the routes', () {
      final r = NetcapRequest(
        mode: SourceMode.proxy,
        serve: '127.0.0.1:8099',
        rulesPath: 'sample.rules',
        upstream: '127.0.0.1:7890',
        tun: true,
      );
      final args = r.toArgs();
      expect(args, contains('--tun'));
      expect(args, isNot(contains('--tun-takeover')));
      expect(args.sublist(args.indexOf('--upstream'), args.indexOf('--upstream') + 2),
          ['--upstream', '127.0.0.1:7890']);
      expect(args, contains('--rules'));
    });

    test('a takeover replaces the proxy for the session', () {
      final r = NetcapRequest(
        mode: SourceMode.proxy,
        serve: '127.0.0.1:8099',
        rulesPath: 'sample.rules',
        upstream: '127.0.0.1:7890',
        tun: true,
        tunTakeover: true,
        tunAdapter: 'netcap2',
      );
      final args = r.toArgs();
      expect(args, contains('--tun'));
      expect(args, contains('--tun-takeover'));
      expect(args.sublist(args.indexOf('--tun-adapter'), args.indexOf('--tun-adapter') + 2),
          ['--tun-adapter', 'netcap2']);
      // netcap serves the tunnel or the proxy, never both: asking for --serve
      // here would silently never start the proxy.
      expect(args, isNot(contains('--serve')));
      expect(args, isNot(contains('--system-proxy')));
    });

    test('the system proxy switches do not ride along with a takeover', () {
      final r = NetcapRequest(
        mode: SourceMode.proxy,
        serve: '127.0.0.1:8099',
        upstream: '127.0.0.1:7890',
        systemProxy: true,
        tun: true,
        tunTakeover: true,
      );
      expect(r.toArgs(), isNot(contains('--system-proxy')));
    });

    test('a capture run never carries them', () {
      final r = NetcapRequest(
        mode: SourceMode.file,
        path: 'sample.pcap',
        tun: true,
        tunTakeover: true,
        tunAdapter: 'netcap2',
      );
      final args = r.toArgs();
      expect(args, isNot(contains('--tun')));
      expect(args, isNot(contains('--tun-takeover')));
      expect(args, isNot(contains('--tun-adapter')));
    });
  });

  group('the registry snapshot', () {
    test('reads the values netcap prints', () {
      final s = SystemProxyStatus.fromJson(const {
        'event': 'system_proxy',
        'mode': 'status',
        'available': true,
        'readable': true,
        'state_file': 'netcap_sysproxy.state',
        'snapshot': false,
        'enable': 0,
        'server': '127.0.0.1:26561',
        'override': '10.*;172.16.*',
        'auto_config': 'http://127.0.0.1:49772/pac?t=1',
      });
      expect(s.available, isTrue);
      expect(s.manual, isFalse); // ProxyEnable is 0
      expect(s.pac, isTrue); // the PAC URL has priority over the manual proxy
      expect(s.label, contains('PAC'));
      expect(s.detail, contains('ProxyServer=127.0.0.1:26561'));
      expect(s.detail, contains('AutoConfigURL='));
      expect(s.detail, contains('快照还没有'));
    });

    test('manual mode is recognised from ProxyEnable = "1"', () {
      final s = SystemProxyStatus.fromJson(const {
        'available': true,
        'readable': true,
        'enable': '1',
        'server': '127.0.0.1:8089',
        'auto_config': '',
      });
      expect(s.manual, isTrue);
      expect(s.pac, isFalse);
      expect(s.label, contains('127.0.0.1:8089'));
    });

    test('an unreadable machine says so instead of pretending', () {
      final s = SystemProxyStatus.fromJson(const {
        'available': false,
        'readable': false,
      });
      expect(s.available, isFalse);
      expect(s.label, contains('只有 Windows'));
    });
  });

  group('the rescue script', () {
    test('lives on the desktop', () {
      expect(rescueScriptPath(home: r'C:\Users\Czr'),
          r'C:\Users\Czr\Desktop\netcap-restore.cmd');
      // A trailing separator must not double up.
      expect(rescueScriptPath(home: r'C:\Users\Czr\'),
          r'C:\Users\Czr\Desktop\netcap-restore.cmd');
      expect(rescueScriptPath(home: 'C:/Users/Czr'),
          'C:/Users/Czr\\Desktop\\netcap-restore.cmd');
    });

    test('an explicit desktop wins', () {
      expect(rescueScriptPath(home: r'C:\Users\Czr', desktop: r'D:\Desk'),
          r'D:\Desk\netcap-restore.cmd');
    });

    test('gates every risky switch', () {
      expect(takeoverAllowed(rescueScript: true, running: false), isTrue);
      expect(takeoverAllowed(rescueScript: false, running: false), isFalse);
      expect(takeoverAllowed(rescueScript: true, running: true), isFalse);
      expect(takeoverAllowed(rescueScript: false, running: true), isFalse);
    });
  });
}
