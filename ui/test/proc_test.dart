// Process attribution, per-process splitting and interception: the model side
// (pure parsing) plus the real command line against the real netcap.exe.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/main.dart';
import 'package:netcap_ui/src/models.dart';
import 'package:netcap_ui/src/netcap.dart';

void main() {
  group('the UI command line', () {
    test('analysis flags and paths are separated', () {
      final paths = <String>[];
      final o = parseUiArgs([
        r'D:\cap.pcap',
        r'D:\keys.log',
        '--attrib',
        '--streams',
        '--block',
        'tcp and dst port 443',
        '--block-mode',
        'cut',
        '--block-max',
        '9',
        '--split-by',
        'app',
        '--unknown-flag',
      ], paths);
      expect(paths, [r'D:\cap.pcap', r'D:\keys.log']);
      expect(o.attrib, isTrue);
      expect(o.analyze, isTrue);
      expect(o.blockFilter, 'tcp and dst port 443');
      expect(o.blockMode, 'cut');
      expect(o.blockMax, 9);
      expect(o.splitBy, 'app');
      expect(o.noAttrib, isFalse);
    });

    test('the default is no interception at all', () {
      final paths = <String>[];
      final o = parseUiArgs(['cap.pcap'], paths);
      expect(o.blockFilter, isEmpty);
      expect(o.blockMode, 'dry-run');
      expect(o.blockMax, 32);
      expect(o.attrib, isFalse);
      expect(paths, ['cap.pcap']);
    });

    test('--keylog is accepted as a flag as well as a path', () {
      final paths = <String>[];
      final o = parseUiArgs(['cap.pcap', '--keylog', 'k.log'], paths);
      expect(o.keylog, 'k.log');
      expect(paths, ['cap.pcap']);
    });

    test('a dangling flag does not crash', () {
      final paths = <String>[];
      final o = parseUiArgs(['--block'], paths);
      expect(o.blockFilter, isEmpty);
      expect(paths, isEmpty);
    });
  });

  group('models', () {
    test('a packet carries its process attribution', () {
      final p = PacketRecord.fromJson(<String, dynamic>{
        'type': 'packet',
        'n': 7,
        'proc': 'chrome.exe',
        'proc_path': r'C:\Program Files\Google\Chrome\chrome.exe',
        'proc_pid': 1234,
        'proc_dir': 'out',
      });
      expect(p.proc, 'chrome.exe');
      expect(p.procPid, 1234);
      expect(p.procPath, contains('Chrome'));
      expect(p.procDir, 'out');
      expect(p.hasProc, isTrue);
      // Name first, PID in brackets: that is what the process column shows, and
      // it is the string clicking the cell feeds to the local search.
      expect(p.procLabel, 'chrome.exe (1234)');
      expect(p.matchesSearch('1234'), isTrue);
      // The local search box looks at the process too.
      expect(p.matchesSearch('chrome'), isTrue);
      expect(p.matchesSearch(r'program files'), isTrue);
    });

    test('an unattributed packet says so instead of showing a zero pid', () {
      final p = PacketRecord.fromJson(<String, dynamic>{'type': 'packet', 'n': 1});
      expect(p.hasProc, isFalse);
      expect(p.procLabel, '—');
      expect(p.procPid, 0);
    });

    test('a pid without an image name still has a label', () {
      final p = PacketRecord.fromJson(
          <String, dynamic>{'type': 'packet', 'n': 2, 'proc_pid': 5044});
      expect(p.hasProc, isTrue);
      expect(p.procLabel, 'pid 5044');
      // Clicking the process column feeds this string to the local search.
      expect(p.matchesSearch('5044'), isTrue);
      expect(p.matchesSearch('9999'), isFalse);
    });

    test('the summary reports processes, split files and interception', () {
      final s = SummaryInfo.fromJson(<String, dynamic>{
        'type': 'summary',
        'seen': 25,
        'attribution': true,
        'procs': [
          {
            'pid': 4,
            'name': 'System',
            'label': 'System',
            'packets': 2,
            'bytes': 303,
            'flows': 0,
            'transactions': 0
          },
          {'pid': 5044, 'name': '', 'label': 'pid 5044', 'packets': 1, 'bytes': 94},
        ],
        'split_by': 'app',
        'split_files': [
          {'key': 'app-TLS', 'file': 'app-TLS.pcap', 'packets': 11, 'bytes': 1146},
        ],
        'block': {
          'enabled': true,
          'mode': 'dry-run',
          'matched': 6,
          'attempted': 0,
          'performed': 0,
          'failed': 0,
          'skipped': 0,
          'last_error': '',
          'actions': [
            {
              'target': 'tcp 10.0.0.5:51000 -> 93.184.216.34:443',
              'process': '',
              'pid': 0,
              'mode': 'dry-run',
              'performed': false,
              'skipped': false,
              'reason': 'dry run: nothing was touched',
              'error': '',
            }
          ],
        },
      });
      expect(s.attribution, isTrue);
      expect(s.procs, hasLength(2));
      expect(s.procs.first.display, 'System');
      expect(s.procs.last.display, 'pid 5044');
      expect(s.splitBy, 'app');
      expect(s.splitFiles.single.file, 'app-TLS.pcap');
      expect(s.block.enabled, isTrue);
      expect(s.block.mode, 'dry-run');
      expect(s.block.matched, 6);
      expect(s.block.actions.single.state, 'dry');
      expect(s.block.actions.single.detail, 'dry run: nothing was touched');
    });

    test('a summary without the new keys still parses', () {
      final s = SummaryInfo.fromJson(<String, dynamic>{'type': 'summary', 'seen': 3});
      expect(s.attribution, isFalse);
      expect(s.procs, isEmpty);
      expect(s.splitBy, isEmpty);
      expect(s.splitFiles, isEmpty);
      expect(s.block.enabled, isFalse);
      expect(s.block, isA<BlockReport>());
    });

    test('a block action reports done / dry / skip / fail', () {
      Map<String, dynamic> a(Map<String, dynamic> extra) => <String, dynamic>{
            'target': 'tcp 1.1.1.1:1 -> 2.2.2.2:2',
            'mode': 'cut',
            ...extra,
          };
      expect(BlockAction.fromJson(a({'performed': true})).state, 'done');
      expect(BlockAction.fromJson(a({})).state, 'dry');
      expect(BlockAction.fromJson(a({'skipped': true})).state, 'skip');
      final failed = BlockAction.fromJson(a({'error': 'SetTcpEntry failed'}));
      expect(failed.state, 'fail');
      expect(failed.detail, 'SetTcpEntry failed');
    });
  });

  group('netcap arguments', () {
    test('toArgs carries attribution, splitting and interception', () {
      final args = NetcapRequest(
        mode: SourceMode.live,
        device: '1',
        exportPath: r'D:\cap',
        splitBy: 'app',
        attrib: true,
        blockFilter: 'proc chrome and dst port 443',
        blockMode: 'cut',
        blockMax: 5,
      ).toArgs();
      expect(args, contains('--attrib'));
      expect(args, containsAllInOrder(['--write', r'D:\cap', '--split-by', 'app']));
      expect(
        args,
        containsAllInOrder([
          '--block',
          'proc chrome and dst port 443',
          '--block-mode',
          'cut',
          '--block-max',
          '5',
        ]),
      );
    });

    test('no block filter means no interception flag at all', () {
      final args = NetcapRequest(mode: SourceMode.file, path: 'x.pcap').toArgs();
      expect(args.where((a) => a.startsWith('--block')), isEmpty);
      expect(args, isNot(contains('--split-by')));
      expect(args, isNot(contains('--attrib')));
    });

    test('--no-attrib and --attrib are mutually exclusive by construction', () {
      final args =
          NetcapRequest(mode: SourceMode.file, path: 'x.pcap', noAttrib: true).toArgs();
      expect(args, contains('--no-attrib'));
      expect(args, isNot(contains('--attrib')));
    });
  });

  group('netcap.exe end to end', () {
    late NetcapRunner runner;
    late Directory tmp;
    late String sample;

    setUpAll(() async {
      final found = await NetcapRunner.locate();
      expect(found, isNotNull,
          reason: 'netcap.exe must exist (build it with: cmake --build build)');
      runner = NetcapRunner(found!);
      tmp = await Directory.systemTemp.createTemp('netcap_proc_test');
      sample = '${tmp.path}${Platform.pathSeparator}sample.pcap';
      expect(await runner.generateSample(sample), 25);
    });

    tearDownAll(() async {
      if (tmp.existsSync()) await tmp.delete(recursive: true);
    });

    test('--block dry-run reports every decision and touches nothing', () async {
      final decisions = <BlockAction>[];
      final summary = <SummaryInfo>[];
      final logs = <String>[];
      final code = await runner.run(
        NetcapRequest(
          mode: SourceMode.file,
          path: sample,
          blockFilter: 'tcp and dst port 443',
          blockMode: 'dry-run',
        ),
        onJson: (j) {
          switch (j['type']) {
            case 'block':
              decisions.add(BlockAction.fromJson(j));
            case 'summary':
              summary.add(SummaryInfo.fromJson(j));
          }
        },
        onStderr: logs.add,
      );
      expect(code, 0, reason: logs.join('\n'));
      expect(decisions, isNotEmpty);
      expect(decisions.map((d) => d.state).toSet(), {'dry'});
      expect(decisions.first.target, contains('->'));
      expect(summary.single.block.enabled, isTrue);
      expect(summary.single.block.mode, 'dry-run');
      expect(summary.single.block.matched, decisions.length);
      expect(summary.single.block.attempted, 0);
      expect(summary.single.block.performed, 0);
      expect(summary.single.block.failed, 0);
      expect(summary.single.block.lastError, isEmpty);
    });

    test('--attrib is reported as enabled in the summary', () async {
      final summary = <SummaryInfo>[];
      final packets = <PacketRecord>[];
      final logs = <String>[];
      final code = await runner.run(
        NetcapRequest(mode: SourceMode.file, path: sample, attrib: true),
        onJson: (j) {
          switch (j['type']) {
            case 'packet':
              packets.add(PacketRecord.fromJson(j));
            case 'summary':
              summary.add(SummaryInfo.fromJson(j));
          }
        },
        onStderr: logs.add,
      );
      expect(code, 0, reason: logs.join('\n'));
      expect(summary.single.attribution, isTrue);
      expect(packets, hasLength(25));
      // Whatever the local endpoint table happens to own, every attributed
      // packet must carry a usable label (names are machine dependent).
      for (final p in packets.where((p) => p.hasProc)) {
        expect(p.procLabel, isNotEmpty);
        expect(p.procLabel, isNot('—'));
      }
    });

    test('--split-by app writes one pcap per application plus index.json', () async {
      final dir = '${tmp.path}${Platform.pathSeparator}bysplit';
      final summary = <SummaryInfo>[];
      final logs = <String>[];
      final code = await runner.run(
        NetcapRequest(
          mode: SourceMode.file,
          path: sample,
          exportPath: dir,
          splitBy: 'app',
        ),
        onJson: (j) {
          if (j['type'] == 'summary') summary.add(SummaryInfo.fromJson(j));
        },
        onStderr: logs.add,
      );
      expect(code, 0, reason: logs.join('\n'));
      final files = summary.single.splitFiles;
      expect(files, hasLength(7));
      expect(files.map((f) => f.file), contains('app-TLS.pcap'));
      expect(files.map((f) => f.file), contains('app-other.pcap'));
      expect(files.fold<int>(0, (n, f) => n + f.packets), 25);
      for (final f in files) {
        expect(File('$dir${Platform.pathSeparator}${f.file}').existsSync(), isTrue,
            reason: '${f.file} should exist');
      }
      expect(File('$dir${Platform.pathSeparator}index.json').existsSync(), isTrue);
    });

    test('--split-by without a directory fails with the usage exit code', () async {
      final logs = <String>[];
      final code = await runner.run(
        NetcapRequest(mode: SourceMode.file, path: sample, splitBy: 'app'),
        onStderr: logs.add,
      );
      expect(code, 2);
      expect(logs.join('\n'), contains('--split-by needs -w'));
    });
  });
}
