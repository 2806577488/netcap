// The 「过滤日志」 window: every decision the interception proxy made, newest
// first, with a plain-language filter row, a search box and three buttons.
//
// Design brief: somebody who is not a computer person has to be able to answer
// "why did this page not load?" — so each decision is a word (拦截 / 改写 /
// 隧道 / 放行 / 中断 / 出错 / 重定向), tapping a row opens the long
// explanation, and the file-related buttons (keep it in a file, export it,
// throw it away) call back into the main window instead of touching the disk
// here.  `中断` is separate from `出错` because a browser that hangs up is not a
// broken proxy, and a log full of red rows that mean nothing trains a reader to
// ignore the one row that matters.
//
// That last part is not just tidiness: the page is handed the records and the
// callbacks, and a widget test runs inside the fake-async zone where a real
// `File.writeAsString` future never completes.
import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'models.dart';
import 'log_merge.dart';
import 'widgets.dart';

/// Writes [contents] under [suggestedName] and returns the path it landed in,
/// or null when the user cancelled the save dialog.  The page never does this
/// itself, so the caller keeps owning the file.
typedef LogExport = Future<String?> Function(
  String suggestedName,
  String contents,
);

/// Opens the page.  Returns when it is closed.
Future<void> showLogPage(
  BuildContext context, {
  required List<InterceptRecord> records,
  String logPath = '',
  bool writing = false,
  ValueChanged<bool>? onWritingChanged,
  Future<void> Function()? onClear,
  LogExport? export,
  Set<String>? sessionKeys,
}) {
  return showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (_) => LogPage(
      records: records,
      logPath: logPath,
      writing: writing,
      onWritingChanged: onWritingChanged,
      onClear: onClear,
      export: export,
      sessionKeys: sessionKeys,
    ),
  );
}

/// The chip row in reading order.  The action strings are exactly the ones
/// netcap writes into the `intercept` event (`InterceptRecord.action`).
const List<(String, String?)> _filters = <(String, String?)>[
  ('全部', null),
  ('拦截', 'block'),
  ('改写', 'modify'),
  ('隧道', 'tunnel'),
  ('放行', 'pass'),
  ('中断', 'cancelled'),
  ('出错', 'error'),
  ('重定向', 'redirect'),
];

/// The same colours the main window's interception table uses, so a row means
/// the same thing in both places.
Color _actionColor(String action) {
  switch (action) {
    case 'block':
      return const Color(0xFFF85149);
    case 'modify':
    case 'redirect':
      return const Color(0xFFD29922);
    case 'tunnel':
      return const Color(0xFF8B949E);
    case 'error':
      return const Color(0xFFFF7B72);
    case 'cancelled':
      // Grey on purpose: the client hung up, nothing is broken.
      return const Color(0xFF8B949E);
    default:
      return const Color(0xFF3FB950);
  }
}

class LogPage extends StatefulWidget {
  const LogPage({
    super.key,
    required this.records,
    this.logPath = '',
    this.writing = false,
    this.onWritingChanged,
    this.onClear,
    this.export,
    this.sessionKeys,
  });

  /// The decisions, oldest first — the order the caller appends them in.  The
  /// page keeps this list for its whole life; it never sorts or edits it.
  final List<InterceptRecord> records;

  /// Where the proxy appends them; empty when it is not writing a file.
  final String logPath;

  /// Is the file-writing switch on?
  final bool writing;

  final ValueChanged<bool>? onWritingChanged;
  final Future<void> Function()? onClear;
  final LogExport? export;

  /// Keys (see `filterLogKey`) of the rows this session produced.  The page is
  /// handed the file's rows merged in as well — they are shown, and the export
  /// marks them `[上次]` so a 17:43 export cannot be mistaken for "this just
  /// happened".  Null means "everything here is from this session".
  final Set<String>? sessionKeys;

  @override
  State<LogPage> createState() => _LogPageState();
}

class _LogPageState extends State<LogPage> {
  final TextEditingController _search = TextEditingController();
  final ScrollController _scroll = ScrollController();

  /// The selected chip's action string, null for 全部.
  String? _action;
  String _query = '';

  /// The row the reader opened, by identity: InterceptRecord has no `==`.
  InterceptRecord? _expanded;

  late bool _writing = widget.writing;

  /// The last thing that happened to the file buttons ("已导出到 …").
  String _note = '';

  @override
  void dispose() {
    _search.dispose();
    _scroll.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------- the data

  /// Newest first.  `tsUs` is the clock; two events that share it (which really
  /// happens, the clock is microsecond and the proxy is fast) keep their
  /// arrival order, reversed — the later line is the newer decision.
  List<InterceptRecord> _ordered() {
    final order = List<int>.generate(widget.records.length, (i) => i);
    order.sort((a, b) {
      final ta = widget.records[a].tsUs;
      final tb = widget.records[b].tsUs;
      if (ta != tb) return tb.compareTo(ta);
      return b.compareTo(a);
    });
    return <InterceptRecord>[for (final i in order) widget.records[i]];
  }

  List<InterceptRecord> _visible(List<InterceptRecord> all) {
    final q = _query.trim();
    return all
        .where((r) => (_action == null || r.action == _action) && r.matchesSearch(q))
        .toList();
  }

  /// `拦截 12 · 改写 8 · 放行 40`, over the whole log, zeros left out.
  String _summary() {
    final parts = <String>[];
    for (final f in _filters) {
      final action = f.$2;
      if (action == null) continue;
      final n = widget.records.where((r) => r.action == action).length;
      if (n > 0) parts.add('${f.$1} $n');
    }
    final known = _filters.where((f) => f.$2 != null).map((f) => f.$2).toSet();
    final other = widget.records.where((r) => !known.contains(r.action)).length;
    if (other > 0) parts.add('其他 $other');
    return parts.isEmpty ? '还没有记录' : parts.join(' · ');
  }

  String get _pathText =>
      widget.logPath.trim().isEmpty ? '还没有选文件' : widget.logPath;

  // -------------------------------------------------------------- the report

  String _two(int v) => v < 10 ? '0$v' : '$v';

  String _stamp(DateTime d) =>
      '${d.year}-${_two(d.month)}-${_two(d.day)} '
      '${_two(d.hour)}:${_two(d.minute)}:${_two(d.second)}';

  String _suggestedName(DateTime now) =>
      'netcap-filter-log-${now.year}${_two(now.month)}${_two(now.day)}'
      '-${_two(now.hour)}${_two(now.minute)}.txt';

  /// Plain UTF-8 text, one line per record, `\n` separated.  The whole log is
  /// exported even when the view is filtered — the header says how many rows
  /// the reader was looking at, so a filtered export is never mistaken for
  /// everything.
  String _report(
    List<InterceptRecord> all,
    List<InterceptRecord> shown,
    DateTime now,
  ) {
    final b = StringBuffer()
      ..writeln('# netcap 过滤日志')
      ..writeln('# 导出时间：${_stamp(now)}')
      ..writeln('# 共 ${all.length} 条 · ${_summary()}');
    if (shown.length != all.length) {
      b.writeln('# 界面当前只显示 ${shown.length} 条，本文件包含全部记录。');
    }
    final fromFile = _previousSessionCount(all);
    if (fromFile > 0) {
      b.writeln('# 其中 $fromFile 条来自上次会话（filter-log.jsonl），行首标了 [上次]。');
    }
    b.writeln('# 列：时间  动作  方法  URL  状态  命中规则  说明');
    for (final r in all) {
      final stale = _isPreviousSession(r);
      b.writeln(<String>[
        stale ? '[上次] ${r.time}' : r.time,
        r.actionLabel,
        r.method,
        _clip(r.target, _logUrlLimit),
        r.status > 0 ? '${r.status}' : '-',
        _clip(r.rule, _logRuleLimit),
        r.detail,
      ].join('  '));
    }
    return b.toString();
  }

  /// A log line is meant to be read, and a tracking URL carrying three kilobytes
  /// of query string is not: the screen and the export get a budget, while the
  /// JSONL file on disk keeps every byte.  (Half of a 1.25 MB export was one
  /// page's telemetry URLs, and the other half was the whole generic rule list.)
  static const int _logUrlLimit = 200;
  static const int _logRuleLimit = 160;

  static String _clip(String text, int limit) {
    if (text.length <= limit) return text;
    return '${text.substring(0, limit)}… (+${text.length - limit} chars)';
  }

  /// Was this row written by an earlier session?  Only answerable when the
  /// caller told us which keys the live session produced; a caller that passes
  /// an empty set is saying "this session has produced nothing yet", which makes
  /// every row on screen a leftover from the file.
  bool _isPreviousSession(InterceptRecord r) {
    final keys = widget.sessionKeys;
    if (keys == null) return false;
    return !keys.contains(filterLogKey(r));
  }

  int _previousSessionCount(List<InterceptRecord> all) {
    if (widget.sessionKeys == null) return 0;
    return all.where(_isPreviousSession).length;
  }

  // ------------------------------------------------------------ the buttons

  void _setWriting(bool value) {
    setState(() => _writing = value);
    (widget.onWritingChanged ?? (bool _) {})(value);
  }

  Future<void> _export() async {
    final all = _ordered();
    final now = DateTime.now();
    final save =
        widget.export ?? (String name, String contents) async => null;
    String? path;
    try {
      path = await save(_suggestedName(now), _report(all, _visible(all), now));
    } catch (e) {
      if (mounted) setState(() => _note = '导出失败：$e');
      return;
    }
    if (!mounted) return;
    setState(() {
      _note = (path == null || path.trim().isEmpty)
          ? '没有保存导出内容。'
          : '已导出到 $path';
    });
  }

  Future<void> _confirmClear() async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('清空日志？'),
        content: const Text(
          '这会把列表里的记录全部删掉。已经导出到文件的记录不受影响，但删掉之后就找不回来了。',
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('清空'),
          ),
        ],
      ),
    );
    if (yes != true) return;
    await (widget.onClear ?? () async {})();
    if (!mounted) return;
    setState(() => _note = '已清空列表。');
  }

  // ---------------------------------------------------------------- the view

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final width = math.min(1240.0, math.max(360.0, size.width - 80));
    final height = math.min(700.0, math.max(320.0, size.height - 60));
    final all = _ordered();
    final rows = _visible(all);
    return Dialog(
      insetPadding: const EdgeInsets.all(16),
      backgroundColor: const Color(0xFF0E1218),
      child: SizedBox(
        width: width,
        height: height,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            _header(context),
            const Divider(height: 1),
            _bar(context, rows.length),
            const Divider(height: 1),
            Expanded(child: _list(context, rows)),
            const Divider(height: 1),
            _footer(context),
          ],
        ),
      ),
    );
  }

  Widget _header(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 14, 12, 12),
      child: Row(
        children: <Widget>[
          const Icon(Icons.receipt_long_outlined, size: 20),
          const SizedBox(width: 10),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text('过滤日志',
                    style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
                SizedBox(height: 2),
                Text(
                  '这里是 netcap 每一次判断的记录：拦了什么、改了什么、放行了什么。',
                  style: TextStyle(fontSize: 11.5, color: Color(0xFF9AA4B2)),
                ),
              ],
            ),
          ),
          IconButton(
            tooltip: '关闭',
            onPressed: () => Navigator.of(context).pop(),
            icon: const Icon(Icons.close, size: 18),
          ),
        ],
      ),
    );
  }

  Widget _bar(BuildContext context, int shown) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          TextField(
            controller: _search,
            onChanged: (value) => setState(() => _query = value),
            style: const TextStyle(fontSize: 13),
            decoration: const InputDecoration(
              isDense: true,
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.search, size: 18),
              hintText: '搜域名、URL、规则或进程…',
              hintStyle: TextStyle(fontSize: 12.5),
            ),
          ),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 6,
            children: <Widget>[
              for (final f in _filters)
                ChoiceChip(
                  label: Text(f.$1, style: const TextStyle(fontSize: 12.5)),
                  selected: _action == f.$2,
                  visualDensity: VisualDensity.compact,
                  materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  onSelected: (_) => setState(() => _action = f.$2),
                ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: <Widget>[
              Text(
                '显示 $shown / 共 ${widget.records.length} 条',
                style: TextStyle(fontSize: 12, color: cs.primary),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Text(
                  _summary(),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant),
                ),
              ),
            ],
          ),
          // Rows that came out of filter-log.jsonl are marked here as well as in
          // the export: a list that silently mixes last night's rows with this
          // session's makes the reader distrust the whole page.
          if (_previousSessionCount(widget.records) > 0) ...<Widget>[
            const SizedBox(height: 6),
            Text(
              '其中 ${_previousSessionCount(widget.records)} 条来自上次会话'
              '（filter-log.jsonl），行首标了 [上次]。',
              style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant),
            ),
          ],
        ],
      ),
    );
  }

  Widget _list(BuildContext context, List<InterceptRecord> rows) {
    if (widget.records.isEmpty) {
      return const EmptyState(
        icon: Icons.receipt_long_outlined,
        title: '还没有记录',
        detail: 'netcap 一开始做判断，每一笔都会出现在这里。',
      );
    }
    if (rows.isEmpty) {
      return const EmptyState(
        icon: Icons.search_off,
        title: '没有匹配的记录',
        detail: '换个词试试，或者点「全部」看所有记录。',
      );
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        _columnHeads(),
        Expanded(
          child: Scrollbar(
            controller: _scroll,
            child: ListView.builder(
              controller: _scroll,
              padding: const EdgeInsets.fromLTRB(12, 2, 12, 12),
              itemCount: rows.length,
              itemBuilder: (context, i) => _row(context, rows[i], i),
            ),
          ),
        ),
      ],
    );
  }

  /// The column names, over the same flexes as the rows, so the list is
  /// readable without the reader knowing what a coloured badge means.
  Widget _columnHeads() {
    const style =
        TextStyle(fontSize: 10.5, letterSpacing: 0.4, color: Color(0xFF7C8798));
    return const Padding(
      padding: EdgeInsets.fromLTRB(22, 8, 22, 4),
      child: Row(
        children: <Widget>[
          Expanded(flex: 11, child: Text('时间', style: style)),
          Expanded(flex: 7, child: Text('动作', style: style)),
          Expanded(flex: 6, child: Text('方法', style: style)),
          Expanded(flex: 17, child: Text('域名', style: style)),
          Expanded(flex: 30, child: Text('网址', style: style)),
          Expanded(flex: 6, child: Text('状态', style: style)),
          Expanded(flex: 15, child: Text('命中规则', style: style)),
          Expanded(flex: 12, child: Text('进程', style: style)),
        ],
      ),
    );
  }

  Widget _row(BuildContext context, InterceptRecord r, int index) {
    final open = identical(_expanded, r);
    final color = _actionColor(r.action);
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Material(
        // Material, not a decorated Container: the InkWell inside it needs a
        // Material ancestor or Flutter asserts that the splash is invisible.
        color: open ? const Color(0xFF1C2634) : const Color(0xFF141A22),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        child: InkWell(
          key: ValueKey<String>('log-row-$index'),
          borderRadius: BorderRadius.circular(8),
          onTap: () => setState(() => _expanded = open ? null : r),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: <Widget>[
                _cells(r, color),
                if (open) _detail(r, index),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _cells(InterceptRecord r, Color color) {
    const mono = TextStyle(
      fontFamily: 'Consolas',
      fontSize: 11.5,
      height: 1.2,
      color: Color(0xFFD6DEE8),
    );
    const dim = TextStyle(
      fontFamily: 'Consolas',
      fontSize: 11.5,
      height: 1.2,
      color: Color(0xFF8A94A6),
    );
    final status = r.status > 0 ? '${r.status}' : '—';
    final statusColor = r.status >= 400
        ? const Color(0xFFF85149)
        : (r.status >= 300 ? const Color(0xFFD29922) : dim.color);
    Widget cell(int flex, String text, TextStyle style) => Expanded(
          flex: flex,
          child: Text(
            text.isEmpty ? '—' : text,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: style,
          ),
        );
    return Row(
      children: <Widget>[
        cell(11, _isPreviousSession(r) ? '[上次] ${r.time}' : r.time, mono),
        Expanded(
          flex: 7,
          child: Align(
            alignment: Alignment.centerLeft,
            child: Pill(text: r.actionLabel, color: color),
          ),
        ),
        cell(6, r.method, mono),
        cell(17, r.host, mono),
        cell(30, _clip(r.target, _logUrlLimit), mono),
        cell(6, status, mono.copyWith(color: statusColor)),
        cell(15, _clip(r.rule, _logRuleLimit), dim),
        cell(12, r.clientProc, dim),
      ],
    );
  }

  Widget _detail(InterceptRecord r, int index) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(2, 8, 2, 2),
      child: Column(
        key: ValueKey<String>('log-detail-$index'),
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          _kv('说明', r.detail.isEmpty ? '—' : r.detail),
          _kv('网址', r.target.isEmpty ? '—' : r.target),
          _kv('命中规则', r.rule.isEmpty ? '（没有命中规则）' : _clip(r.rule, _logRuleLimit)),
          _kv('客户端', r.client.isEmpty ? '—' : r.client),
          _kv('进程', r.clientProc.isEmpty ? '（没能认出是哪个程序）' : r.clientProc),
          _kv('HTTPS', r.mitmLabel),
          _kv(
            '流量',
            '请求 ${formatBytes(r.requestBytes)}'
                ' · 响应 ${formatBytes(r.responseBytes)}',
          ),
        ],
      ),
    );
  }

  Widget _kv(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 1),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          SizedBox(
            width: 78,
            child: Text(
              label,
              style: const TextStyle(fontSize: 11, color: Color(0xFF8A94A6)),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(
                fontFamily: 'Consolas',
                fontSize: 11.5,
                height: 1.35,
                color: Color(0xFFD6DEE8),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _footer(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 12, 10),
      child: Row(
        children: <Widget>[
          SizedBox(
            width: 300,
            child: Material(
              color: const Color(0xFF141A22),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(10),
              ),
              child: SwitchListTile(
                dense: true,
                contentPadding: const EdgeInsets.symmetric(horizontal: 12),
                value: _writing,
                title: const Text(
                  '记到文件',
                  style: TextStyle(fontSize: 13.5, fontWeight: FontWeight.w600),
                ),
                subtitle: Text(
                  _pathText,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontFamily: 'Consolas',
                    fontSize: 11,
                    color: Color(0xFF8A94A6),
                  ),
                ),
                onChanged: _setWriting,
              ),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              _note,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant),
            ),
          ),
          TextButton.icon(
            onPressed: _export,
            icon: const Icon(Icons.save_alt, size: 16),
            label: const Text('导出…'),
          ),
          const SizedBox(width: 6),
          OutlinedButton(onPressed: _confirmClear, child: const Text('清空')),
          const SizedBox(width: 6),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('关闭'),
          ),
        ],
      ),
    );
  }
}
