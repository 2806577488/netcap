// The 上游 row has to report where traffic really goes.  netcap says it in one
// of two sentences, and for a long time the pane only understood the first one:
// a system-proxy takeover that chained through the proxy already in use printed
// "chaining through … so the previous path keeps working" and the interface kept
// showing 直连.  That is a lie about the network path, so it gets its own tests.
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/netcap.dart';

void main() {
  group('where netcap chains to', () {
    test('an explicit --upstream is read back', () {
      final logs = <String>[
        'netcap: 112162 rule(s): …',
        'netcap: chaining every upstream connection through 127.0.0.1:7890',
        'netcap: point the browser or the system HTTP proxy at http://127.0.0.1:8080',
      ];
      expect(chainedUpstreamFrom(logs), '127.0.0.1:7890');
    });

    test('a takeover that found Clash is read back, without the explanation', () {
      final logs = <String>[
        'netcap: chaining through 127.0.0.1:7890 so the previous path keeps working',
      ];
      expect(chainedUpstreamFrom(logs), '127.0.0.1:7890');
    });

    test('the newest sentence wins', () {
      final logs = <String>[
        'netcap: chaining through 127.0.0.1:7890 so the previous path keeps working',
        'netcap: chaining every upstream connection through 127.0.0.1:7897',
      ];
      expect(chainedUpstreamFrom(logs), '127.0.0.1:7897');
    });

    test('no sentence means netcap went straight out', () {
      expect(chainedUpstreamFrom(const <String>['netcap: listening on 127.0.0.1:8080']),
          isNull);
      expect(chainedUpstreamFrom(const <String>[]), isNull);
    });
  });
}
