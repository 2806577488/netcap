// The rules page: look at the list, and own your own rules.
//
// Design brief (from the user): "用户需要能在界面查看规则和修改 写 删除 规则" —
// somebody who is not a computer person has to be able to see what is being
// filtered, add a rule, change one and delete one, without ever opening the
// 138k line built-in list in a text editor.  So:
//   * the bundled list is read-only here and can be searched, and a hit can be
//     disabled with one press (that writes an `@@` / `#@#` exception into the
//     user's own file, which is how Adblock lists express "not this one"),
//   * the user's own rules are a short list with a delete button per line and
//     an add box that asks the engine itself whether the line is valid,
//   * every change is written straight to disk, and the page says out loud that
//     the proxy reads its rules at startup.
import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import 'netcap.dart';
import 'rule_lists.dart';

/// Validates one rule line (the page passes the real engine, the tests pass a
/// fake so they do not need a netcap.exe).
typedef RuleCheckRunner = Future<RuleCheck> Function(String line);

/// Opens the page.  Returns when it is closed.
Future<void> showRulesPage(
  BuildContext context, {
  required RuleLists lists,
  required String settingsPath,
  required RuleCheckRunner check,
  bool running = false,
  bool picking = false,
  Future<void> Function()? onRestart,
  Future<void> Function(bool)? onPickingChanged,
  Future<String?> Function()? pickList,
  ValueChanged<RuleLists>? onListsChanged,
  Future<String> Function(String path)? readFile,
  Future<void> Function(String path, String text)? writeFile,
}) {
  return showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (_) => RulesPage(
      lists: lists,
      settingsPath: settingsPath,
      check: check,
      running: running,
      picking: picking,
      onRestart: onRestart,
      onPickingChanged: onPickingChanged,
      pickList: pickList,
      onListsChanged: onListsChanged,
      readFile: readFile,
      writeFile: writeFile,
    ),
  );
}

/// The exception that switches [rule] off inside a filter list: `@@` for a
/// network rule, `#@#` for an element hiding rule.  Handing back the opposite
/// marker is how "enable" is implemented (it deletes that line again).
String ruleExceptionFor(String rule) {
  final line = rule.trim();
  final hash = line.indexOf('#');
  if (hash >= 0) {
    final tail = line.substring(hash);
    if (tail.startsWith('##') || tail.startsWith('#@#')) {
      final host = line.substring(0, hash);
      // `##` is two characters, `#@#` is three: the selector starts after the
      // marker, and forgetting that difference eats its first character.
      final int skip = tail.startsWith('##') ? 2 : 3;
      final selector = line.substring(hash + skip);
      return '$host${tail.startsWith('##') ? '#@#' : '##'}$selector';
    }
  }
  return line.startsWith('@@') ? line.substring(2) : '@@$line';
}

/// True for a line that switches something off rather than filtering it.
bool ruleIsException(String rule) {
  final line = rule.trim();
  return line.startsWith('@@') || line.contains('#@#');
}

class RulesPage extends StatefulWidget {
  const RulesPage({
    super.key,
    required this.lists,
    required this.settingsPath,
    required this.check,
    this.running = false,
    this.picking = false,
    this.onRestart,
    this.onPickingChanged,
    this.pickList,
    this.onListsChanged,
    this.readFile,
    this.writeFile,
  });

  /// Which lists the proxy loads.  The page edits this object in place and then
  /// calls [onListsChanged], so the window and the page never disagree.
  final RuleLists lists;

  /// Where that choice is remembered (`rule-lists.json`).
  final String settingsPath;

  final RuleCheckRunner check;
  final bool running;
  final Future<void> Function()? onRestart;

  /// The element picker: [picking] is whether it is on right now, and
  /// [onPickingChanged] writes or deletes the flag file a running proxy polls.
  /// No callback means the picker is not offered at all.
  final bool picking;
  final Future<void> Function(bool)? onPickingChanged;

  /// Asks the window for another list file (the tests hand in a fake).
  final Future<String?> Function()? pickList;

  /// Called after every switch/removal so the caller can save and refresh.
  final ValueChanged<RuleLists>? onListsChanged;

  /// The two file seams.  Widget tests hand in in-memory functions, because real
  /// IO inside the fake-async zone of a widget test never completes.
  final Future<String> Function(String path)? readFile;
  final Future<void> Function(String path, String text)? writeFile;

  @override
  State<RulesPage> createState() => _RulesPageState();
}

class _RulesPageState extends State<RulesPage> {
  final TextEditingController _add = TextEditingController();
  final TextEditingController _search = TextEditingController();
  final TextEditingController _raw = TextEditingController();

  List<String> _mine = <String>[];
  bool _loading = true;
  bool _busy = false;
  String _note = '';
  bool _noteOk = false;

  /// Rule counts per list file, filled in lazily (the bundled list is 3.5 MB, so
  /// the page counts it in the background instead of blocking on open).
  final Map<String, int> _counts = <String, int>{};
  bool _counting = false;

  RuleLists get _lists => widget.lists;

  // The built-in list is loaded the first time it is searched, never up front:
  // opening the page has to stay instant even though the file is 3.5 MB.
  List<String> _base = <String>[];
  bool _baseLoaded = false;
  bool _baseLoading = false;
  String _query = '';
  List<int> _hits = <int>[];

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _add.dispose();
    _search.dispose();
    _raw.dispose();
    super.dispose();
  }

  // ---- the file seams ------------------------------------------------------
  // Everything goes through these two, so a widget test can hand in an
  // in-memory map: real IO inside the fake-async zone of a widget test never
  // completes and would hang the whole run.
  Future<String> _read(String path) =>
      (widget.readFile ?? (String p) => File(p).readAsString())(path);

  Future<void> _write(String path, String text) =>
      (widget.writeFile ?? (String p, String t) => File(p).writeAsString(t))(
        path,
        text,
      );

  /// Only the real filesystem needs the directory made first.
  Future<void> _ensureDir() async {
    if (widget.writeFile != null) return;
    final dir = File(widget.lists.userRulesPath).parent;
    if (!await dir.exists()) await dir.create(recursive: true);
  }

  Future<void> _load() async {
    try {
      String text;
      try {
        text = await _read(widget.lists.userRulesPath);
      } catch (_) {
        await _ensureDir();
        await _write(widget.lists.userRulesPath, '');
        text = '';
      }
      _mine = text
          .split(RegExp(r'\r?\n'))
          .map((line) => line.trim())
          .where((line) => line.isNotEmpty)
          .toList();
    } catch (e) {
      _note = '读不到我的规则文件：$e';
      _noteOk = false;
    }
    if (mounted) setState(() => _loading = false);
    unawaited(_countLists());
  }

  Future<void> _save() async {
    try {
      await _ensureDir();
      await _write(widget.lists.userRulesPath, '${_mine.join('\n')}\n');
    } catch (e) {
      if (mounted) {
        setState(() {
          _note = '写不进我的规则文件：$e';
          _noteOk = false;
        });
      }
    }
  }

  Future<void> _ensureBase() async {
    if (_baseLoaded || _baseLoading) return;
    _baseLoading = true;
    if (mounted) setState(() {});
    try {
      if (widget.lists.builtinPath.trim().isNotEmpty) {
        final text = await _read(widget.lists.builtinPath);
        _base = text.split(RegExp(r'\r?\n'));
      }
    } catch (_) {
      _base = <String>[];
    }
    _baseLoaded = true;
    _baseLoading = false;
    if (mounted) setState(() => _searchInto(_query));
  }

  /// A bounded scan: the user sees the first 200 hits, which is plenty to pick
  /// the rule they mean, and the page stays responsive on a 138k line list.
  void _searchInto(String query) {
    final q = query.trim().toLowerCase();
    _query = query;
    if (q.length < 2) {
      _hits = <int>[];
      return;
    }
    final found = <int>[];
    for (var i = 0; i < _base.length && found.length < 200; i++) {
      final line = _base[i].trim();
      if (line.isEmpty || line.startsWith('!') || line.startsWith('[')) continue;
      if (line.toLowerCase().contains(q)) found.add(i);
    }
    _hits = found;
  }

  Future<void> _addRule() async {
    final line = _add.text.trim();
    if (line.isEmpty) return;
    if (_mine.contains(line)) {
      setState(() {
        _note = '这条已经在你的规则里了。';
        _noteOk = false;
      });
      return;
    }
    setState(() => _busy = true);
    final verdict = await widget.check(line);
    if (!mounted) return;
    setState(() => _busy = false);
    if (!verdict.ok) {
      setState(() {
        _note = '这条规则 netcap 用不了：${verdict.reason}';
        _noteOk = false;
      });
      return;
    }
    setState(() {
      _mine = <String>[..._mine, line];
      _add.clear();
      _note = verdict.isComment
          ? '加上了，但这一行只是注释，不会拦任何东西。'
          : '加上了：${verdict.note}（重启代理后生效）';
      _noteOk = true;
    });
    await _save();
  }

  Future<void> _removeRule(String rule) async {
    setState(() {
      _mine = _mine.where((line) => line != rule).toList();
      _note = '删掉了：$rule（重启代理后生效）';
      _noteOk = true;
    });
    await _save();
  }

  Future<void> _toggleDisabled(String rule) async {
    final exception = ruleExceptionFor(rule);
    final already = _mine.contains(exception);
    setState(() {
      if (already) {
        _mine = _mine.where((line) => line != exception).toList();
        _note = '又启用了：$rule（重启代理后生效）';
      } else {
        _mine = <String>[..._mine, exception];
        _note = '禁用了：$rule（重启代理后生效）';
      }
      _noteOk = true;
    });
    await _save();
  }

  Future<void> _editRaw() async {
    _raw.text = _mine.join('\n');
    final saved = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('编辑我的规则'),
        content: SizedBox(
          width: 620,
          height: 380,
          child: TextField(
            controller: _raw,
            maxLines: null,
            expands: true,
            textAlignVertical: TextAlignVertical.top,
            style: const TextStyle(fontFamily: 'Consolas', fontSize: 12.5),
            decoration: const InputDecoration(
              border: OutlineInputBorder(),
              hintText: '一行一条规则，空行会被忽略',
            ),
          ),
        ),
        actions: <Widget>[
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('取消')),
          FilledButton(onPressed: () => Navigator.of(ctx).pop(true), child: const Text('保存')),
        ],
      ),
    );
    if (saved != true) return;
    setState(() {
      _mine = _raw.text
          .split(RegExp(r'\r?\n'))
          .map((line) => line.trim())
          .where((line) => line.isNotEmpty)
          .toList();
      _note = '文本已保存（重启代理后生效）';
      _noteOk = true;
    });
    await _save();
  }

  Future<void> _restart() async {
    final again = widget.onRestart;
    if (again == null) return;
    setState(() {
      _busy = true;
      _note = '正在按新规则重启代理…';
      _noteOk = true;
    });
    await again();
    if (!mounted) return;
    setState(() {
      _busy = false;
      _note = '代理已按新规则启动。';
      _noteOk = true;
    });
  }

  // ---- the filter lists ----------------------------------------------------

  /// Counts every list once, in the background: the bundled one is 3.5 MB, and
  /// opening the page must stay instant.
  Future<void> _countLists() async {
    if (_counting) return;
    _counting = true;
    final paths = <String>[
      if (_lists.builtinPath.trim().isNotEmpty) _lists.builtinPath,
      if (_lists.userRulesPath.trim().isNotEmpty) _lists.userRulesPath,
      ..._lists.extra.map((list) => list.path),
    ];
    for (final path in paths) {
      if (_counts.containsKey(path)) continue;
      try {
        _counts[path] = RuleLists.countRules(await _read(path));
      } catch (_) {
        _counts[path] = -1; // -1 means "this file is not there"
      }
      if (mounted) setState(() {});
    }
    _counting = false;
  }

  String _countText(String path) {
    final n = _counts[path];
    if (n == null) return '统计中…';
    if (n < 0) return '读不到这个文件';
    // Lines, not parsed rules: the engine skips a few forms (procedural
    // cosmetics, regex patterns it does not run), so its own count is lower
    // than the number of lines in the file.
    return '$n 行';
  }

  void _changed() {
    widget.onListsChanged?.call(_lists);
    if (mounted) setState(() {});
  }

  Future<void> _addList() async {
    final picked = await widget.pickList?.call();
    if (picked == null || picked.trim().isEmpty) return;
    if (_lists.extra.any((list) => list.path == picked) || picked == _lists.builtinPath) {
      setState(() {
        _note = '这个列表已经在了。';
        _noteOk = false;
      });
      return;
    }
    _lists.extra.add(RuleList(path: picked));
    _changed();
    unawaited(_countLists());
    setState(() {
      _note = '加上了 ${_shortName(picked)}；重启代理后生效。';
      _noteOk = true;
    });
  }

  void _removeList(RuleList list) {
    _lists.extra.remove(list);
    _changed();
    setState(() {
      _note = '移除了 ${_shortName(list.path)}，清单里不再加载它。';
      _noteOk = true;
    });
  }

  Widget _listsCard() {
    return _card(
      title: '过滤列表',
      trailing: TextButton.icon(
        onPressed: (widget.pickList == null || _busy) ? null : _addList,
        icon: const Icon(Icons.add, size: 18),
        label: const Text('添加列表文件…'),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          _listRow(
            title: '内置广告列表',
            subtitle: 'EasyList + EasyPrivacy，随 netcap 一起发布'
                '（${_shortName(_lists.builtinPath)}）',
            count: _countText(_lists.builtinPath),
            enabled: _lists.builtinEnabled,
            onChanged: (on) {
              _lists.builtinEnabled = on;
              _changed();
            },
          ),
          _listRow(
            title: '我的规则',
            subtitle: '你自己写的那一小份（${_lists.userRulesPath}）',
            count: '${_mine.length} 行',
            enabled: _lists.userRulesEnabled,
            onChanged: (on) {
              _lists.userRulesEnabled = on;
              _changed();
            },
          ),
          for (final list in _lists.extra)
            _listRow(
              title: _shortName(list.path),
              subtitle: list.path,
              count: _countText(list.path),
              enabled: list.enabled,
              onChanged: (on) {
                list.enabled = on;
                _changed();
              },
              onRemove: () => _removeList(list),
            ),
          // The element picker: click an element on a page and it is hidden from
          // then on.  What it writes is a rule in the user's own list, so the
          // switch is only offered when there is a list to write to.
          if (widget.onPickingChanged != null) ...<Widget>[
            const Divider(height: 18),
            Row(
              children: <Widget>[
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text('在页面上点选元素',
                          style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                      SizedBox(height: 2),
                      Text(
                        '打开后页面底部会有一行提示：点哪个元素就把它藏起来，'
                        '规则写进「我的规则」（按 Esc 或关掉这个开关就退出）。'
                        '这个开关随时拨，不用重启代理——但页面得是在代理运行时加载的：'
                        '如果那一页在启动代理之前就开着，先 Ctrl+F5 刷一次，'
                        '脚本是随页面一起下来的。',
                        style: TextStyle(fontSize: 11.5, color: Color(0xFF8A94A4)),
                      ),
                    ],
                  ),
                ),
                Switch(
                  value: widget.picking,
                  onChanged: (bool on) => widget.onPickingChanged!(on),
                ),
              ],
            ),
          ],
          const SizedBox(height: 8),
          const Text(
            '打开着的列表会一起加载（第一个走 --rules，其余走 --rules-extra）；'
            '列表就是 Adblock Plus 那种语法，改动在重启代理后生效。',
            style: TextStyle(fontSize: 11.5, color: Color(0xFF8A94A4)),
          ),
        ],
      ),
    );
  }

  Widget _listRow({
    required String title,
    required String subtitle,
    required String count,
    required bool enabled,
    required ValueChanged<bool> onChanged,
    VoidCallback? onRemove,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: <Widget>[
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 13.5,
                    fontWeight: FontWeight.w600,
                    color: enabled ? const Color(0xFFE6EAF2) : const Color(0xFF8A94A4),
                  ),
                ),
                const SizedBox(height: 1),
                Text(subtitle, style: const TextStyle(fontSize: 11, color: Color(0xFF7C8798))),
                Text(count, style: const TextStyle(fontSize: 11, color: Color(0xFF7C8798))),
              ],
            ),
          ),
          if (onRemove != null)
            IconButton(
              tooltip: '移除这个列表',
              onPressed: _busy ? null : onRemove,
              icon: const Icon(Icons.delete_outline, size: 18),
            ),
          Switch(value: enabled, onChanged: _busy ? null : onChanged),
        ],
      ),
    );
  }

  String _shortName(String path) {
    final at = path.lastIndexOf(RegExp(r'[\\/]'));
    return at < 0 ? path : path.substring(at + 1);
  }

  @override
  Widget build(BuildContext context) {
    final exceptions = _mine.where(ruleIsException).toList();
    final own = _mine.where((line) => !ruleIsException(line)).toList();
    return Dialog(
      insetPadding: const EdgeInsets.all(16),
      backgroundColor: const Color(0xFF0E1218),
      child: SizedBox(
        width: 900,
        height: 680,
        child: _loading
            ? const Center(child: CircularProgressIndicator())
            : Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: <Widget>[
                  _header(context),
                  const Divider(height: 1),
                  Expanded(
                    child: ListView(
                      padding: const EdgeInsets.fromLTRB(18, 14, 18, 14),
                      children: <Widget>[
                        // The status line lives at the top: the list below is
                        // long, and a note parked under it would scroll out of
                        // sight exactly when the user needs to read it.
                        if (_note.isNotEmpty) ...<Widget>[
                          Row(
                            children: <Widget>[
                              Icon(
                                _noteOk ? Icons.check_circle_outline : Icons.error_outline,
                                size: 16,
                                color: _noteOk ? const Color(0xFF7FD1A0) : const Color(0xFFE08A8A),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  _note,
                                  style: TextStyle(
                                    fontSize: 12.5,
                                    color: _noteOk ? const Color(0xFF7FD1A0) : const Color(0xFFE08A8A),
                                  ),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 12),
                        ],
                        _listsCard(),
                        const SizedBox(height: 14),
                        _myRulesCard(own, exceptions),
                        const SizedBox(height: 14),
                        _builtinCard(),
                      ],
                    ),
                  ),
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
          const Icon(Icons.rule, size: 20),
          const SizedBox(width: 10),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text('规则', style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
                SizedBox(height: 2),
                Text(
                  '上面是过滤列表清单：每条都能单独开关，也能加一个新的列表文件；'
                  '下面「我的规则」是你自己写的那一小份。',
                  style: TextStyle(fontSize: 12, color: Color(0xFF9AA4B2)),
                ),
              ],
            ),
          ),
          IconButton(
            tooltip: '关闭',
            onPressed: _busy ? null : () => Navigator.of(context).pop(),
            icon: const Icon(Icons.close),
          ),
        ],
      ),
    );
  }

  Widget _myRulesCard(List<String> own, List<String> exceptions) {
    return _card(
      title: '我的规则',
      trailing: TextButton.icon(
        onPressed: _busy ? null : _editRaw,
        icon: const Icon(Icons.edit_note, size: 18),
        label: const Text('编辑原始文本'),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          if (own.isEmpty)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 6),
              child: Text('还没有自己的规则。下面写一条，或者从内置列表里挑一条禁用。',
                  style: TextStyle(fontSize: 12.5, color: Color(0xFF9AA4B2))),
            )
          else
            ...own.map(
              (rule) => _row(
                rule,
                trailing: IconButton(
                  tooltip: '删除这条',
                  onPressed: _busy ? null : () => _removeRule(rule),
                  icon: const Icon(Icons.delete_outline, size: 18),
                ),
              ),
            ),
          if (exceptions.isNotEmpty) ...<Widget>[
            const SizedBox(height: 8),
            const Text('禁用的规则（来自内置列表）',
                style: TextStyle(fontSize: 12, color: Color(0xFF9AA4B2))),
            ...exceptions.map(
              (rule) => _row(
                rule,
                dim: true,
                trailing: TextButton(
                  onPressed: _busy ? null : () => _removeRule(rule),
                  child: const Text('启用'),
                ),
              ),
            ),
          ],
          const SizedBox(height: 10),
          Row(
            children: <Widget>[
              Expanded(
                child: TextField(
                  controller: _add,
                  onSubmitted: (_) => _addRule(),
                  style: const TextStyle(fontSize: 13, fontFamily: 'Consolas'),
                  decoration: const InputDecoration(
                    isDense: true,
                    border: OutlineInputBorder(),
                    hintText: '例如 ||ads.example.com^   或   example.com##.ad-box',
                    hintStyle: TextStyle(fontSize: 12.5, fontFamily: 'inherit'),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              FilledButton(
                onPressed: _busy ? null : _addRule,
                child: const Text('添加'),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _builtinCard() {
    return _card(
      title: '内置列表',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          TextField(
            controller: _search,
            onChanged: (value) {
              _searchInto(value);
              setState(() {});
              _ensureBase();
            },
            style: const TextStyle(fontSize: 13),
            decoration: const InputDecoration(
              isDense: true,
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.search, size: 18),
              hintText: '在这条列表里搜域名或类名（至少两个字）',
              hintStyle: TextStyle(fontSize: 12.5),
            ),
          ),
          if (_baseLoading)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text('正在读内置列表…', style: TextStyle(fontSize: 12, color: Color(0xFF9AA4B2))),
            )
          else if (_query.trim().length >= 2 && _hits.isEmpty)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text('没找到。', style: TextStyle(fontSize: 12.5, color: Color(0xFF9AA4B2))),
            )
          else if (_hits.isNotEmpty)
            ..._hits.map((index) {
              final rule = _base[index].trim();
              final disabled = _mine.contains(ruleExceptionFor(rule));
              return _row(
                rule,
                dim: disabled,
                trailing: disabled
                    ? TextButton(
                        onPressed: _busy ? null : () => _toggleDisabled(rule),
                        child: const Text('启用'),
                      )
                    : TextButton(
                        onPressed: _busy ? null : () => _toggleDisabled(rule),
                        child: const Text('禁用'),
                      ),
              );
            }),
        ],
      ),
    );
  }

  Widget _row(String text, {Widget? trailing, bool dim = false}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 1),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: <Widget>[
          Expanded(
            child: Text(
              text,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: 12.5,
                fontFamily: 'Consolas',
                color: dim ? const Color(0xFF6E7889) : const Color(0xFFD6DEE8),
                decoration: dim ? TextDecoration.lineThrough : null,
              ),
            ),
          ),
          ?trailing,
        ],
      ),
    );
  }

  Widget _card({required String title, required Widget child, Widget? trailing}) {
    // Material, not a DecoratedBox: a ListTile-ish child on a plain
    // decoration trips the "ink splashes may be invisible" assertion.
    return Material(
      color: const Color(0xFF141A22),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 10, 14, 14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Row(
              children: <Widget>[
                Expanded(
                  child: Text(title,
                      style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w600)),
                ),
                ?trailing,
              ],
            ),
            const SizedBox(height: 6),
            child,
          ],
        ),
      ),
    );
  }

  Widget _footer(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 10, 12, 10),
      child: Row(
        children: <Widget>[
          const Expanded(
            child: Text(
              '代理在启动时读一次规则：改完点右边那颗按钮，或者自己停止再启动。',
              style: TextStyle(fontSize: 11.5, color: Color(0xFF9AA4B2)),
            ),
          ),
          if (widget.running && widget.onRestart != null)
            FilledButton.icon(
              onPressed: _busy ? null : _restart,
              icon: const Icon(Icons.restart_alt, size: 18),
              label: const Text('按新规则重启代理'),
            ),
          const SizedBox(width: 8),
          OutlinedButton(
            onPressed: _busy ? null : () => Navigator.of(context).pop(),
            child: const Text('关闭'),
          ),
        ],
      ),
    );
  }
}
