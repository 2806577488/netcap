/// Data models for the JSON Lines stream emitted by `netcap --jsonl`.
///
/// The C++ side owns the protocol; this file only mirrors it. Every field is
/// parsed defensively so a future netcap that adds or renames fields can never
/// crash the UI, it just shows less.
library;

int _asInt(dynamic v, [int fallback = 0]) {
  if (v is int) return v;
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v) ?? fallback;
  if (v is bool) return v ? 1 : 0;
  return fallback;
}

int? _asIntOrNull(dynamic v) {
  if (v == null) return null;
  if (v is int) return v;
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v);
  return null;
}

String _asStr(dynamic v) {
  if (v == null) return '';
  if (v is String) return v;
  return v.toString();
}

String? _asStrOrNull(dynamic v) {
  if (v == null) return null;
  final s = _asStr(v);
  return s.isEmpty ? null : s;
}

bool _asBool(dynamic v) {
  if (v is bool) return v;
  if (v is num) return v != 0;
  if (v is String) return v == 'true' || v == '1';
  return false;
}

/// One row of the application-protocol breakdown in the final summary.
class AppCount {
  AppCount({
    required this.kind,
    required this.name,
    required this.packets,
    required this.bytes,
  });

  final String kind;
  final String name;
  final int packets;
  final int bytes;

  factory AppCount.fromJson(Map<String, dynamic> j) => AppCount(
        kind: _asStr(j['kind']),
        name: _asStr(j['name']),
        packets: _asInt(j['packets']),
        bytes: _asInt(j['bytes']),
      );

  /// netcap reports the catch-all bucket with an empty tag; the UI wants a word.
  String get label => kind.isEmpty ? 'other' : kind;
}

/// The first line of a run: what we opened and how to interpret the packets.
class HelloInfo {
  HelloInfo({
    required this.tool,
    required this.live,
    required this.source,
    required this.described,
    required this.linktype,
    required this.linktypeName,
    required this.filter,
    required this.snaplen,
    required this.nanosecond,
    this.reassembly = false,
    this.keylog = '',
    this.keylogLoaded = false,
    this.keylogEntries = 0,
  });

  final String tool;
  final bool live;
  final String source;
  final String described;
  final int linktype;
  final String linktypeName;
  final String filter;
  final int snaplen;
  final bool nanosecond;

  /// Whether TCP reassembly is on for this run (older netcap has no field).
  final bool reassembly;

  /// The path given to --keylog, empty when none was passed.
  final String keylog;

  /// True when netcap parsed the key log; [keylogEntries] is how many secrets.
  final bool keylogLoaded;
  final int keylogEntries;

  factory HelloInfo.fromJson(Map<String, dynamic> j) => HelloInfo(
        tool: _asStr(j['tool']),
        live: _asBool(j['live']),
        source: _asStr(j['source']),
        described: _asStr(j['described']),
        linktype: _asInt(j['linktype']),
        linktypeName: _asStr(j['linktype_name']),
        filter: _asStr(j['filter']),
        snaplen: _asInt(j['snaplen']),
        nanosecond: _asBool(j['nanosecond']),
        reassembly: _asBool(j['reassembly']),
        keylog: _asStr(j['keylog']),
        keylogLoaded: _asBool(j['keylog_loaded']),
        keylogEntries: _asInt(j['keylog_entries']),
      );
}

/// The last line of a run: counters, reassembly statistics and the app mix.
/// One process as counted by the C++ side (`--attrib`, summary `procs`).
class ProcCount {
  ProcCount({
    required this.pid,
    required this.name,
    required this.label,
    required this.packets,
    required this.bytes,
    this.flows = 0,
    this.transactions = 0,
  });

  final int pid;
  final String name;
  final String label;
  final int packets;
  final int bytes;
  final int flows;
  final int transactions;

  /// What to show when the image name could not be resolved.
  String get display => label.isNotEmpty ? label : (name.isNotEmpty ? name : 'pid $pid');

  factory ProcCount.fromJson(Map<String, dynamic> j) => ProcCount(
        pid: _asInt(j['pid']),
        name: _asStr(j['name']),
        label: _asStr(j['label']),
        packets: _asInt(j['packets']),
        bytes: _asInt(j['bytes']),
        flows: _asInt(j['flows']),
        transactions: _asInt(j['transactions']),
      );
}

/// One file produced by `--split-by`, from the summary `split_files` list.
class SplitFile {
  SplitFile({
    required this.key,
    required this.file,
    required this.packets,
    required this.bytes,
  });

  final String key;
  final String file;
  final int packets;
  final int bytes;

  factory SplitFile.fromJson(Map<String, dynamic> j) => SplitFile(
        key: _asStr(j['key']),
        file: _asStr(j['file']),
        packets: _asInt(j['packets']),
        bytes: _asInt(j['bytes']),
      );
}

/// One interception decision, from the summary `block` object.
class BlockAction {
  BlockAction({
    required this.target,
    required this.process,
    required this.pid,
    required this.mode,
    required this.performed,
    required this.skipped,
    required this.reason,
    required this.error,
  });

  final String target;
  final String process;
  final int pid;
  final String mode;
  final bool performed;
  final bool skipped;
  final String reason;
  final String error;

  /// done / dry / skip / fail, mirroring the text report.
  String get state => performed
      ? 'done'
      : (skipped ? 'skip' : (error.isEmpty ? 'dry' : 'fail'));

  String get detail => error.isNotEmpty ? error : reason;

  factory BlockAction.fromJson(Map<String, dynamic> j) => BlockAction(
        target: _asStr(j['target']),
        process: _asStr(j['process']),
        pid: _asInt(j['pid']),
        mode: _asStr(j['mode']),
        performed: _asBool(j['performed']),
        skipped: _asBool(j['skipped']),
        reason: _asStr(j['reason']),
        error: _asStr(j['error']),
      );
}

/// One decision of the local interception proxy (`--serve`): the `intercept`
/// event of `--jsonl`.
class InterceptRecord {
  InterceptRecord({
    required this.tsUs,
    required this.action,
    required this.method,
    required this.url,
    required this.host,
    required this.client,
    required this.rule,
    required this.detail,
    required this.status,
    required this.requestBytes,
    required this.responseBytes,
    this.clientProc = '',
    this.mitm = '',
  });

  final int tsUs;
  final String action; // block / modify / redirect / pass / tunnel / error
  final String method;
  final String url;
  final String host;
  final String client;
  final String rule;
  final String detail;
  final int status;
  final int requestBytes;
  final int responseBytes;

  /// The application that opened the connection, when the proxy could name it
  /// (from the OS endpoint tables). Empty when it could not.
  final String clientProc;

  /// `on` / `skip` / `off`: this connection was decrypted, left alone by the
  /// per-application policy, or never eligible because HTTPS decryption is off.
  final String mitm;

  /// How the HTTPS column reads: 解密 / 跳过 / 未解密.
  String get mitmLabel {
    switch (mitm) {
      case 'on':
        return '解密';
      case 'skip':
        return '跳过';
      case 'off':
        return '未解密';
      default:
        return mitm.isEmpty ? '—' : mitm;
    }
  }

  /// The action as the UI shows it: Chinese, because the rest of the interface is.
  String get actionLabel {
    switch (action) {
      case 'block':
        return '拦截';
      case 'modify':
        return '改写';
      case 'redirect':
        return '重定向';
      case 'tunnel':
        return '隧道';
      case 'pass':
        return '放行';
      // Not a failure: the browser hung up first (a redirect chain superseding
      // the request that started it, a closed tab, a dropped prefetch).  netcap
      // writes its own action for that so a healthy log stops reading as if
      // everything broke.
      case 'cancelled':
        return '中断';
      case 'error':
        return '出错';
      default:
        return action.isEmpty ? '—' : action;
    }
  }

  /// `10:35:40.535303` — the same shape as the packet table's clock.
  String get time {
    if (tsUs <= 0) return '—';
    final d = DateTime.fromMillisecondsSinceEpoch(tsUs ~/ 1000, isUtc: true);
    String two(int v) => v < 10 ? '0$v' : '$v';
    final micros = (tsUs % 1000000).toString().padLeft(6, '0');
    return '${two(d.hour)}:${two(d.minute)}:${two(d.second)}.$micros';
  }

  /// What the row is actually about: the URL, or the host for a CONNECT.
  String get target => url.isNotEmpty ? url : host;

  bool matchesSearch(String needle) {
    if (needle.isEmpty) return true;
    final q = needle.toLowerCase();
    for (final f in <String>[
      action,
      actionLabel,
      method,
      url,
      host,
      client,
      rule,
      detail,
      clientProc,
      mitmLabel,
    ]) {
      if (f.toLowerCase().contains(q)) return true;
    }
    return false;
  }

  factory InterceptRecord.fromJson(Map<String, dynamic> j) => InterceptRecord(
        tsUs: _asInt(j['ts_us']),
        action: _asStr(j['action']),
        method: _asStr(j['method']),
        url: _asStr(j['url']),
        host: _asStr(j['host']),
        client: _asStr(j['client']),
        rule: _asStr(j['rule']),
        detail: _asStr(j['detail']),
        status: _asInt(j['status']),
        requestBytes: _asInt(j['request_bytes']),
        responseBytes: _asInt(j['response_bytes']),
        clientProc: _asStr(j['client_proc']),
        mitm: _asStr(j['mitm']),
      );
}

/// The `intercept_summary` event: what the proxy did over its lifetime.
class InterceptSummary {
  const InterceptSummary({
    required this.connections,
    required this.requests,
    required this.blocked,
    required this.modified,
    required this.redirected,
    required this.passed,
    required this.tunnels,
    required this.errors,
    required this.cancelled,
    required this.bytesIn,
    required this.bytesOut,
  });

  final int connections;
  final int requests;
  final int blocked;
  final int modified;
  final int redirected;
  final int passed;
  final int tunnels;
  final int errors;
  final int cancelled;
  final int bytesIn;
  final int bytesOut;

  static const empty = InterceptSummary(
    connections: 0,
    requests: 0,
    blocked: 0,
    modified: 0,
    redirected: 0,
    passed: 0,
    tunnels: 0,
    errors: 0,
    cancelled: 0,
    bytesIn: 0,
    bytesOut: 0,
  );

  factory InterceptSummary.fromJson(Map<String, dynamic> j) => InterceptSummary(
        connections: _asInt(j['connections']),
        requests: _asInt(j['requests']),
        blocked: _asInt(j['blocked']),
        modified: _asInt(j['modified']),
        redirected: _asInt(j['redirected']),
        passed: _asInt(j['passed']),
        tunnels: _asInt(j['tunnels']),
        errors: _asInt(j['errors']),
        cancelled: _asInt(j['cancelled']),
        bytesIn: _asInt(j['bytes_in']),
        bytesOut: _asInt(j['bytes_out']),
      );
}

/// The interception report (`--block`); `enabled` is false when it was not used.
class BlockReport {
  const BlockReport({
    required this.enabled,
    required this.mode,
    required this.matched,
    required this.attempted,
    required this.performed,
    required this.failed,
    required this.skipped,
    required this.lastError,
    required this.actions,
  });

  final bool enabled;
  final String mode;
  final int matched;
  final int attempted;
  final int performed;
  final int failed;
  final int skipped;
  final String lastError;
  final List<BlockAction> actions;

  static const empty = BlockReport(
    enabled: false,
    mode: '',
    matched: 0,
    attempted: 0,
    performed: 0,
    failed: 0,
    skipped: 0,
    lastError: '',
    actions: [],
  );

  factory BlockReport.fromJson(Map<String, dynamic> j) {
    final actions = <BlockAction>[];
    final raw = j['actions'];
    if (raw is List) {
      for (final e in raw) {
        if (e is Map) actions.add(BlockAction.fromJson(e.cast<String, dynamic>()));
      }
    }
    return BlockReport(
      enabled: _asBool(j['enabled']),
      mode: _asStr(j['mode']),
      matched: _asInt(j['matched']),
      attempted: _asInt(j['attempted']),
      performed: _asInt(j['performed']),
      failed: _asInt(j['failed']),
      skipped: _asInt(j['skipped']),
      lastError: _asStr(j['last_error']),
      actions: actions,
    );
  }
}

class SummaryInfo {
  SummaryInfo({
    required this.seen,
    required this.matched,
    required this.bytes,
    required this.malformed,
    required this.sourcePackets,
    required this.kernelStats,
    required this.kernelDrops,
    required this.fragSeen,
    required this.fragCompleted,
    required this.fragDropped,
    required this.fragPending,
    required this.written,
    required this.writePath,
    required this.interrupted,
    required this.apps,
    this.streams = 0,
    this.tlsStreams = 0,
    this.decryptedStreams = 0,
    this.http1Streams = 0,
    this.http2Streams = 0,
    this.httpTransactions = 0,
    this.httpDecryptedTransactions = 0,
    this.http2Transactions = 0,
    this.reassembledBytes = 0,
    this.reassembly = false,
    this.keysLoaded = false,
    this.keylogEntries = 0,
    this.attribution = false,
    this.procs = const [],
    this.splitBy = '',
    this.splitFiles = const [],
    this.block = BlockReport.empty,
  });

  final int seen;
  final int matched;
  final int bytes;
  final int malformed;
  final int sourcePackets;
  final bool kernelStats;
  final int kernelDrops;
  final int fragSeen;
  final int fragCompleted;
  final int fragDropped;
  final int fragPending;
  final int written;
  final String writePath;
  final bool interrupted;
  final List<AppCount> apps;

  /// Reassembly / TLS decryption counters, absent from older netcap builds.
  final int streams;
  final int tlsStreams;
  final int decryptedStreams;
  final int http1Streams;
  final int http2Streams;
  final int httpTransactions;
  final int httpDecryptedTransactions;
  final int http2Transactions;
  final int reassembledBytes;
  final bool reassembly;
  final bool keysLoaded;
  final int keylogEntries;

  /// Process attribution and interception, absent unless those options were on.
  final bool attribution;
  final List<ProcCount> procs;
  final String splitBy;
  final List<SplitFile> splitFiles;
  final BlockReport block;

  factory SummaryInfo.fromJson(Map<String, dynamic> j) {
    final apps = <AppCount>[];
    final raw = j['apps'];
    if (raw is List) {
      for (final e in raw) {
        if (e is Map) apps.add(AppCount.fromJson(e.cast<String, dynamic>()));
      }
    }
    final procs = <ProcCount>[];
    final rawProcs = j['procs'];
    if (rawProcs is List) {
      for (final e in rawProcs) {
        if (e is Map) procs.add(ProcCount.fromJson(e.cast<String, dynamic>()));
      }
    }
    final splitFiles = <SplitFile>[];
    final rawSplit = j['split_files'];
    if (rawSplit is List) {
      for (final e in rawSplit) {
        if (e is Map) splitFiles.add(SplitFile.fromJson(e.cast<String, dynamic>()));
      }
    }
    var block = BlockReport.empty;
    final rawBlock = j['block'];
    if (rawBlock is Map) block = BlockReport.fromJson(rawBlock.cast<String, dynamic>());
    return SummaryInfo(
      seen: _asInt(j['seen']),
      matched: _asInt(j['matched']),
      bytes: _asInt(j['bytes']),
      malformed: _asInt(j['malformed']),
      sourcePackets: _asInt(j['source_packets']),
      kernelStats: _asBool(j['kernel_stats']),
      kernelDrops: _asInt(j['kernel_drops']),
      fragSeen: _asInt(j['frag_seen']),
      fragCompleted: _asInt(j['frag_completed']),
      fragDropped: _asInt(j['frag_dropped']),
      fragPending: _asInt(j['frag_pending']),
      written: _asInt(j['written']),
      writePath: _asStr(j['write_path']),
      interrupted: _asBool(j['interrupted']),
      apps: apps,
      streams: _asInt(j['streams']),
      tlsStreams: _asInt(j['tls_streams']),
      decryptedStreams: _asInt(j['decrypted_streams']),
      http1Streams: _asInt(j['http1_streams']),
      http2Streams: _asInt(j['http2_streams']),
      httpTransactions: _asInt(j['http_transactions']),
      httpDecryptedTransactions: _asInt(j['http_decrypted_transactions']),
      http2Transactions: _asInt(j['http2_transactions']),
      reassembledBytes: _asInt(j['reassembled_bytes']),
      reassembly: _asBool(j['reassembly']),
      keysLoaded: _asBool(j['keys_loaded']),
      keylogEntries: _asInt(j['keylog_entries']),
      attribution: _asBool(j['attribution']),
      procs: procs,
      splitBy: _asStr(j['split_by']),
      splitFiles: splitFiles,
      block: block,
    );
  }

  /// One line for the status bar / statistics pane.
  String get keylogLabel => keysLoaded
      ? '已加载 $keylogEntries 条密钥'
      : (keylogEntries > 0 ? '$keylogEntries 条密钥未生效' : '未加载');
}

/// One reassembled TCP stream, from the `stream` event (`netcap --streams`).
class StreamInfo {
  StreamInfo({
    required this.index,
    this.client = '',
    this.server = '',
    this.protocol = '',
    this.app = '',
    this.sni = '',
    this.alpn = '',
    this.tls = false,
    this.decrypted = false,
    this.http = false,
    this.http2 = false,
    this.websocket = false,
    this.keysAvailable = false,
    this.truncated = false,
    this.tlsVersionId = 0,
    this.tlsVersion = '',
    this.cipherId = 0,
    this.cipher = '',
    this.packets = 0,
    this.clientBytes = 0,
    this.serverBytes = 0,
    this.plaintextBytes = 0,
    this.records = 0,
    this.retransmits = 0,
    this.outOfOrder = 0,
    this.overlaps = 0,
    this.gaps = 0,
    this.transactions = 0,
    this.firstUs = 0,
    this.lastUs = 0,
    this.note = '',
  });

  /// netcap's stream number; not unique across runs, only within one.
  final int index;
  final String client;
  final String server;

  /// `TCP` / `TLS` / `HTTPS/1.1` / `HTTPS/2` / `HTTP/1.1` / `HTTP/2`.
  final String protocol;

  /// The application tag, e.g. `tls` / `http` / `dns` / `unknown`.
  final String app;
  final String sni;
  final String alpn;
  final bool tls;
  final bool decrypted;
  final bool http;
  final bool http2;
  final bool websocket;
  final bool keysAvailable;
  final bool truncated;
  final int tlsVersionId;
  final String tlsVersion;
  final int cipherId;
  final String cipher;
  final int packets;
  final int clientBytes;
  final int serverBytes;
  final int plaintextBytes;
  final int records;
  final int retransmits;
  final int outOfOrder;
  final int overlaps;
  final int gaps;
  final int transactions;
  final int firstUs;
  final int lastUs;
  final String note;

  factory StreamInfo.fromJson(Map<String, dynamic> j) => StreamInfo(
        index: _asInt(j['index']),
        client: _asStr(j['client']),
        server: _asStr(j['server']),
        protocol: _asStr(j['protocol']),
        app: _asStr(j['app']),
        sni: _asStr(j['sni']),
        alpn: _asStr(j['alpn']),
        tls: _asBool(j['tls']),
        decrypted: _asBool(j['decrypted']),
        http: _asBool(j['http']),
        http2: _asBool(j['http2']),
        websocket: _asBool(j['websocket']),
        keysAvailable: _asBool(j['keys_available']),
        truncated: _asBool(j['truncated']),
        tlsVersionId: _asInt(j['tls_version_id']),
        tlsVersion: _asStr(j['tls_version']),
        cipherId: _asInt(j['cipher_id']),
        cipher: _asStr(j['cipher']),
        packets: _asInt(j['packets']),
        clientBytes: _asInt(j['client_bytes']),
        serverBytes: _asInt(j['server_bytes']),
        plaintextBytes: _asInt(j['plaintext_bytes']),
        records: _asInt(j['records']),
        retransmits: _asInt(j['retransmits']),
        outOfOrder: _asInt(j['out_of_order']),
        overlaps: _asInt(j['overlaps']),
        gaps: _asInt(j['gaps']),
        transactions: _asInt(j['transactions']),
        firstUs: _asInt(j['first_us']),
        lastUs: _asInt(j['last_us']),
        note: _asStr(j['note']),
      );

  /// `10.0.0.5:52000 → 93.184.216.34:443`.
  String get endpoints {
    if (client.isEmpty && server.isEmpty) return '—';
    return '$client → $server';
  }

  /// netcap's own protocol tag, with a fallback for a missing field.
  String get protocolLabel {
    if (protocol.isNotEmpty) return protocol;
    if (http) return http2 ? 'HTTP/2' : 'HTTP/1.1';
    if (tls) return 'TLS';
    return 'TCP';
  }

  int get durationMs => lastUs > firstUs ? (lastUs - firstUs) ~/ 1000 : 0;
}

/// One HTTP transaction, from the `http` event (`--http` or `--follow`).
class HttpTransactionInfo {
  HttpTransactionInfo({
    this.streamId,
    this.http2 = false,
    this.decrypted = false,
    this.client = '',
    this.server = '',
    this.transport = '',
    this.host = '',
    this.method = '',
    this.target = '',
    this.url = '',
    this.version = '',
    this.status = 0,
    this.statusLine = '',
    this.contentType = '',
    this.requestBytes = 0,
    this.responseBytes = 0,
    this.requestComplete = false,
    this.responseComplete = false,
    this.websocket = false,
    this.truncated = false,
    this.startUs = 0,
    this.endUs = 0,
    this.durationMs = 0,
    this.note = '',
    this.summary = '',
  });

  /// Only HTTP/2 records carry a `stream_id`; H1 leaves it null.
  final int? streamId;
  final bool http2;
  final bool decrypted;
  final String client;
  final String server;

  /// e.g. `HTTPS/1.1 (decrypted)`, `HTTP/1.1`.
  final String transport;
  final String host;
  final String method;
  final String target;
  final String url;
  final String version;
  final int status;

  /// `HTTP/1.1 200 OK`.
  final String statusLine;
  final String contentType;
  final int requestBytes;
  final int responseBytes;
  final bool requestComplete;
  final bool responseComplete;
  final bool websocket;
  final bool truncated;
  final int startUs;
  final int endUs;
  final int durationMs;
  final String note;

  /// netcap's one-line rendering, kept verbatim for the detail pane.
  final String summary;

  factory HttpTransactionInfo.fromJson(Map<String, dynamic> j) =>
      HttpTransactionInfo(
        streamId: _asIntOrNull(j['stream_id']),
        http2: _asBool(j['http2']),
        decrypted: _asBool(j['decrypted']),
        client: _asStr(j['client']),
        server: _asStr(j['server']),
        transport: _asStr(j['transport']),
        host: _asStr(j['host']),
        method: _asStr(j['method']),
        target: _asStr(j['target']),
        url: _asStr(j['url']),
        version: _asStr(j['version']),
        status: _asInt(j['status']),
        statusLine: _asStr(j['status_line']),
        contentType: _asStr(j['content_type']),
        requestBytes: _asInt(j['request_bytes']),
        responseBytes: _asInt(j['response_bytes']),
        requestComplete: _asBool(j['request_complete']),
        responseComplete: _asBool(j['response_complete']),
        websocket: _asBool(j['websocket']),
        truncated: _asBool(j['truncated']),
        startUs: _asInt(j['start_us']),
        endUs: _asInt(j['end_us']),
        durationMs: _asInt(j['duration_ms']),
        note: _asStr(j['note']),
        summary: _asStr(j['summary']),
      );

  /// `GET /secure`; falls back to the URL when only that is known.
  String get label {
    final m = method.isEmpty ? '?' : method;
    final t = target.isNotEmpty ? target : url;
    return '$m $t'.trim();
  }

  /// `200 OK`; the em dash keeps the column aligned when there is no response.
  String get statusLabel {
    if (status <= 0) return '—';
    final line = statusLine.trim();
    if (line.isEmpty) return '$status';
    // netcap writes the whole status line; the list column wants the tail.
    if (line.startsWith('HTTP/')) {
      final sp = line.indexOf(' ');
      if (sp > 0) return line.substring(sp + 1).trim();
    }
    return line;
  }

  /// True only when both halves of the exchange were seen in full.
  bool get complete => requestComplete && responseComplete;

  String get bytesLabel => '${requestBytes}B/${responseBytes}B';
}

/// A capture interface as reported by `netcap -d --jsonl`.
class DeviceInfo {
  DeviceInfo({
    required this.index,
    required this.name,
    required this.description,
    required this.address,
    required this.mac,
    required this.family,
    required this.up,
    required this.loopback,
    required this.isDefault,
  });

  final int index;
  final String name;
  final String description;
  final String address;
  final String mac;
  final int family;
  final bool up;
  final bool loopback;
  final bool isDefault;

  factory DeviceInfo.fromJson(Map<String, dynamic> j) => DeviceInfo(
        index: _asInt(j['index']),
        name: _asStr(j['name']),
        description: _asStr(j['description']),
        address: _asStr(j['address']),
        mac: _asStr(j['mac']),
        family: _asInt(j['family']),
        up: _asBool(j['up']),
        loopback: _asBool(j['loopback']),
        isDefault: _asBool(j['default']),
      );

  /// Text shown inside the device dropdown.
  String get label {
    final b = StringBuffer();
    if (isDefault) b.write('★ ');
    b.write(name);
    if (address.isNotEmpty) b.write('  ($address)');
    if (!up) b.write('  · 已断开');
    return b.toString();
  }
}

/// Interface enumeration result plus the platform's live-capture mechanism.
class DeviceListing {
  const DeviceListing({
    required this.devices,
    required this.count,
    required this.mechanismAvailable,
    required this.mechanism,
    required this.requirement,
  });

  final List<DeviceInfo> devices;
  final int count;
  final bool mechanismAvailable;
  final String mechanism;
  final String requirement;

  static const empty = DeviceListing(
    devices: <DeviceInfo>[],
    count: 0,
    mechanismAvailable: false,
    mechanism: '',
    requirement: '',
  );

  factory DeviceListing.fromJson(
    Map<String, dynamic> j,
    List<DeviceInfo> devices,
  ) =>
      DeviceListing(
        devices: devices,
        count: _asInt(j['count'], devices.length),
        mechanismAvailable: _asBool(j['mechanism_available']),
        mechanism: _asStr(j['mechanism']),
        requirement: _asStr(j['requirement']),
      );
}

/// One captured packet. [tree] is the ordered detail view the C++ side built
/// (field name -> already-formatted string), which is what the detail pane
/// renders verbatim so the UI and the CLI can never disagree.
class PacketRecord {
  PacketRecord({
    required this.n,
    required this.tsUs,
    required this.time,
    required this.len,
    required this.origlen,
    required this.truncated,
    required this.malformed,
    required this.reason,
    required this.ipVersion,
    required this.src,
    required this.dst,
    required this.proto,
    required this.sport,
    required this.dport,
    required this.sportName,
    required this.dportName,
    required this.flags,
    required this.app,
    required this.appName,
    required this.appSummary,
    required this.hostname,
    required this.httpMethod,
    required this.httpUri,
    required this.httpStatus,
    required this.tlsSni,
    required this.dnsQname,
    required this.payloadLen,
    required this.payloadHead,
    required this.payloadHex,
    required this.frameHex,
    required this.tree,
    required this.raw,
    this.proc = '',
    this.procPath = '',
    this.procPid = 0,
    this.procDir = '',
  });

  final int n;
  final int tsUs;
  final String time;
  final int len;
  final int origlen;
  final bool truncated;
  final bool malformed;
  final String reason;
  final int ipVersion;
  final String src;
  final String dst;
  final String proto;
  final int sport;
  final int dport;
  final String sportName;
  final String dportName;
  final String flags;
  final String app;
  final String appName;
  final String appSummary;
  final String hostname;
  final String? httpMethod;
  final String? httpUri;
  final int? httpStatus;
  final String? tlsSni;
  final String? dnsQname;
  final int payloadLen;
  final String payloadHead;
  final String? payloadHex;
  final String? frameHex;
  final Map<String, String> tree;
  final Map<String, dynamic> raw;

  /// Process attribution (`--attrib`). Empty when netcap did not resolve one;
  /// a replayed pcap is attributed from the *local* endpoint table, so names
  /// are only as good as the port overlap.
  final String proc;
  final String procPath;
  final int procPid;

  /// `out` when this host sent the packet, `in` when it received it.
  final String procDir;

  /// The process column text: the image name, and the PID next to it so the row
  /// can be matched against Task Manager.  Only the name is known for processes
  /// that refuse to be opened, and only the PID for processes that have already
  /// exited (their name can never be read again).
  String get procLabel {
    if (proc.isEmpty && procPid == 0) return '—';
    if (proc.isEmpty) return 'pid $procPid';
    if (procPid == 0) return proc;
    return '$proc ($procPid)';
  }

  /// True when this packet was attributed to a process.
  bool get hasProc => proc.isNotEmpty || procPid != 0;

  factory PacketRecord.fromJson(Map<String, dynamic> j) {
    final tree = <String, String>{};
    final t = j['tree'];
    if (t is Map) {
      t.forEach((k, v) => tree[_asStr(k)] = _asStr(v));
    }
    return PacketRecord(
      n: _asInt(j['n']),
      tsUs: _asInt(j['ts_us']),
      time: _asStr(j['time']),
      len: _asInt(j['len']),
      origlen: _asInt(j['origlen']),
      truncated: _asBool(j['truncated']),
      malformed: _asBool(j['malformed']),
      reason: _asStr(j['reason']),
      ipVersion: _asInt(j['ip_version']),
      src: _asStr(j['src']),
      dst: _asStr(j['dst']),
      proto: _asStr(j['proto']),
      sport: _asInt(j['sport']),
      dport: _asInt(j['dport']),
      sportName: _asStr(j['sport_name']),
      dportName: _asStr(j['dport_name']),
      flags: _asStr(j['flags']),
      app: _asStr(j['app']),
      appName: _asStr(j['app_name']),
      appSummary: _asStr(j['app_summary']),
      hostname: _asStr(j['hostname']),
      httpMethod: _asStrOrNull(j['http_method']),
      httpUri: _asStrOrNull(j['http_uri']),
      httpStatus: _asIntOrNull(j['http_status']),
      tlsSni: _asStrOrNull(j['tls_sni']),
      dnsQname: _asStrOrNull(j['dns_qname']),
      payloadLen: _asInt(j['payload_len']),
      payloadHead: _asStr(j['payload_head']),
      payloadHex: _asStrOrNull(j['payload_hex']),
      frameHex: _asStrOrNull(j['frame_hex']),
      tree: tree,
      raw: j,
      proc: _asStr(j['proc']),
      procPath: _asStr(j['proc_path']),
      procPid: _asInt(j['proc_pid']),
      procDir: _asStr(j['proc_dir']),
    );
  }

  /// `app` is empty for unknown traffic; the table wants a readable bucket.
  String get appTag => app.isEmpty ? 'other' : app;

  /// The address column text, e.g. `10.0.0.5:51000 -> 93.184.216.34:443`.
  String get sourceEndpoint => _endpoint(src, sport, sportName);
  String get destEndpoint => _endpoint(dst, dport, dportName);

  static String _endpoint(String host, int port, String service) {
    if (host.isEmpty) return '—';
    if (port == 0) return host;
    final svc = service.isEmpty ? '' : ' $service';
    return '$host:$port$svc';
  }

  /// Best one-line description available for the packet list.
  String get summary {
    if (malformed) return '畸变帧: $reason';
    if (appSummary.isNotEmpty) return appSummary;
    if (hostname.isNotEmpty) return hostname;
    if (proto == 'ARP') {
      return tree['arp.op'] ?? 'ARP';
    }
    final tr = tree;
    if (tr.containsKey('icmp.type')) {
      return '${tr['icmp.type']} ${tr['icmp.code'] ?? ''}'.trim();
    }
    if (tr.containsKey('icmpv6.type')) {
      return '${tr['icmpv6.type']} ${tr['icmpv6.code'] ?? ''}'.trim();
    }
    if (tr.containsKey('ip.fragment')) return tr['ip.fragment']!;
    return flags.isEmpty ? proto : '$proto $flags';
  }

  /// Case-insensitive substring search used by the local (client-side) filter.
  bool matchesSearch(String needle) {
    if (needle.isEmpty) return true;
    final n = needle.toLowerCase();
    for (final f in <String>[
      src,
      dst,
      proto,
      appName,
      appSummary,
      proc,
      procPath,
      if (procPid != 0) '$procPid',
      hostname,
      summary,
      flags,
      ?httpUri,
      ?tlsSni,
      ?dnsQname,
    ]) {
      if (f.toLowerCase().contains(n)) return true;
    }
    return false;
  }
}
