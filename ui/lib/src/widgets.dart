/// Small presentation widgets shared by the capture screen: hex dump, the
/// ordered detail tree, colored protocol pills and an in-app file browser.
///
/// The file browser is hand written on purpose: it keeps the project free of
/// third-party packages, so `flutter pub get` never has to reach the network
/// for anything but the SDK itself.
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';

/// Decodes the hex strings netcap emits (`payload_head`, `-x`, `-X`).
Uint8List hexToBytes(String hex) {
  final out = <int>[];
  var hi = -1;
  for (final code in hex.codeUnits) {
    final v = _hexValue(code);
    if (v < 0) continue;
    if (hi < 0) {
      hi = v;
    } else {
      out.add((hi << 4) | v);
      hi = -1;
    }
  }
  return Uint8List.fromList(out);
}

int _hexValue(int c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  return -1;
}

String formatBytes(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KiB';
  if (bytes < 1024 * 1024 * 1024) {
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MiB';
  }
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GiB';
}

String formatCount(int n) {
  final s = n.toString();
  final b = StringBuffer();
  for (var i = 0; i < s.length; i++) {
    if (i > 0 && (s.length - i) % 3 == 0) b.write(',');
    b.write(s[i]);
  }
  return b.toString();
}

/// Colour used for the protocol column, so the list is scannable at a glance.
Color protoColor(String proto) {
  switch (proto) {
    case 'TCP':
      return const Color(0xFF4FA3FF);
    case 'UDP':
      return const Color(0xFFB07CFF);
    case 'ICMP':
      return const Color(0xFFFFA657);
    case 'ICMPv6':
      return const Color(0xFFFFC857);
    case 'ARP':
      return const Color(0xFF9AA7B4);
    case 'IPv6':
      return const Color(0xFF57D9A3);
    default:
      return const Color(0xFF8A94A6);
  }
}

/// Colour used for the application column.
Color appColor(String app) {
  switch (app) {
    case 'HTTP':
      return const Color(0xFF39D0D8);
    case 'TLS':
      return const Color(0xFF6EE787);
    case 'DNS':
    case 'mDNS':
      return const Color(0xFFE3B341);
    case 'QUIC':
      return const Color(0xFFC678DD);
    case 'SSH':
      return const Color(0xFF7FB3FF);
    case 'DHCP':
      return const Color(0xFFFF9F6E);
    default:
      return const Color(0xFF6C7686);
  }
}

class Pill extends StatelessWidget {
  const Pill({
    super.key,
    required this.text,
    required this.color,
    this.dense = true,
  });

  final String text;
  final Color color;
  final bool dense;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: EdgeInsets.symmetric(horizontal: dense ? 5 : 8, vertical: 1),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.16),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.45)),
      ),
      child: Text(
        text,
        style: TextStyle(
          color: color,
          fontSize: dense ? 10.5 : 12,
          fontWeight: FontWeight.w600,
          letterSpacing: 0.2,
        ),
      ),
    );
  }
}

class SectionTitle extends StatelessWidget {
  const SectionTitle({super.key, required this.text, this.trailing});

  final String text;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(10, 12, 10, 4),
      child: Row(
        children: [
          Expanded(
            child: Text(
              text,
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w700,
                letterSpacing: 0.6,
                color: Theme.of(context).colorScheme.primary,
              ),
            ),
          ),
          ?trailing,
        ],
      ),
    );
  }
}

class InfoRow extends StatelessWidget {
  const InfoRow({
    super.key,
    required this.label,
    required this.value,
    this.mono = true,
    this.valueColor,
    this.selectable = true,
  });

  final String label;
  final String value;
  final bool mono;
  final Color? valueColor;
  final bool selectable;

  @override
  Widget build(BuildContext context) {
    final style = TextStyle(
      fontFamily: mono ? 'Consolas' : null,
      fontSize: 12,
      height: 1.35,
      color: valueColor,
    );
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 1.5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 132,
            child: Text(
              label,
              style: TextStyle(
                fontFamily: 'Consolas',
                fontSize: 11.5,
                height: 1.35,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          Expanded(
            child: selectable
                ? SelectableText(value, style: style)
                : Text(value, style: style),
          ),
        ],
      ),
    );
  }
}

/// Renders a byte buffer as the classic offset / hex / ASCII dump.
class HexDumpView extends StatelessWidget {
  const HexDumpView({super.key, required this.hex, this.maxBytes = 1 << 16});

  final String hex;
  final int maxBytes;

  @override
  Widget build(BuildContext context) {
    final bytes = hexToBytes(hex);
    if (bytes.isEmpty) {
      return const EmptyState(
        icon: Icons.data_object,
        title: '没有字节内容',
        detail: '这一帧没有捕获到载荷，或者未启用原始字节记录。',
      );
    }
    final shown = bytes.length > maxBytes ? maxBytes : bytes.length;
    final rows = (shown + 15) ~/ 16;
    final mono = TextStyle(
      fontFamily: 'Consolas',
      fontSize: 12,
      height: 1.45,
      color: Theme.of(context).colorScheme.onSurface,
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(10, 8, 10, 4),
          child: Text(
            '${bytes.length} 字节'
            '${shown < bytes.length ? '（仅显示前 $shown 字节）' : ''}',
            style: mono.copyWith(
              fontSize: 11,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
        ),
        Expanded(
          child: Scrollbar(
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(10, 0, 10, 10),
              itemCount: rows,
              itemBuilder: (context, row) {
                final off = row * 16;
                final end = (off + 16 > shown) ? shown : off + 16;
                final hexPart = StringBuffer();
                for (var i = off; i < off + 16; i++) {
                  if (i < end) {
                    hexPart.write(bytes[i].toRadixString(16).padLeft(2, '0'));
                  } else {
                    hexPart.write('  ');
                  }
                  hexPart.write(i % 8 == 7 ? '  ' : ' ');
                }
                final ascii = StringBuffer();
                for (var i = off; i < end; i++) {
                  final b = bytes[i];
                  ascii.write(b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.');
                }
                return SelectableText(
                  '${off.toRadixString(16).padLeft(8, '0')}  '
                  '$hexPart |$ascii|',
                  style: mono,
                );
              },
            ),
          ),
        ),
      ],
    );
  }
}

const Map<String, String> _treeGroups = {
  'frame': '帧 Frame',
  'eth': '以太网 Ethernet',
  'vlan': 'VLAN 802.1Q',
  'ip': 'IPv4',
  'ipv6': 'IPv6',
  'arp': 'ARP',
  'tcp': 'TCP',
  'udp': 'UDP',
  'icmp': 'ICMP',
  'icmpv6': 'ICMPv6',
  'app': '应用层 Application',
  'http': 'HTTP',
  'tls': 'TLS',
  'dns': 'DNS',
  'payload': '载荷 Payload',
};

/// Renders the ordered `tree` object from a packet JSON line, grouped by the
/// protocol prefix so it reads like the CLI's `-v` output.
class DetailTreeView extends StatelessWidget {
  const DetailTreeView({super.key, required this.tree});

  final Map<String, String> tree;

  @override
  Widget build(BuildContext context) {
    if (tree.isEmpty) {
      return const EmptyState(
        icon: Icons.account_tree_outlined,
        title: '没有解析细节',
        detail: 'netcap 未能解析这一帧，或该帧没有可展示的字段。',
      );
    }
    final groups = <String, List<MapEntry<String, String>>>{};
    for (final e in tree.entries) {
      final dot = e.key.indexOf('.');
      final g = dot < 0 ? '' : e.key.substring(0, dot);
      groups.putIfAbsent(g, () => <MapEntry<String, String>>[]).add(e);
    }
    final children = <Widget>[];
    for (final g in groups.keys) {
      final title = _treeGroups[g] ?? (g.isEmpty ? '其他 Other' : g);
      children.add(SectionTitle(text: title));
      for (final e in groups[g]!) {
        children.add(InfoRow(label: e.key, value: e.value));
      }
    }
    return SelectionArea(
      child: ListView(
        padding: const EdgeInsets.only(bottom: 16),
        children: children,
      ),
    );
  }
}

class EmptyState extends StatelessWidget {
  const EmptyState({
    super.key,
    required this.icon,
    required this.title,
    this.detail,
    this.action,
  });

  final IconData icon;
  final String title;
  final String? detail;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 40, color: cs.onSurfaceVariant.withValues(alpha: 0.6)),
            const SizedBox(height: 10),
            Text(title, style: TextStyle(color: cs.onSurfaceVariant, fontSize: 14)),
            if (detail != null) ...[
              const SizedBox(height: 6),
              Text(
                detail!,
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: cs.onSurfaceVariant.withValues(alpha: 0.75),
                  fontSize: 12,
                ),
              ),
            ],
            if (action != null) ...[const SizedBox(height: 14), action!],
          ],
        ),
      ),
    );
  }
}

/// A dependency-free replacement for a native open/save-file dialog.
///
/// `save: true` switches it to "write a new file": it grows a *file name* box
/// (pre-filled with `suggestedName`), and if that name already exists in the
/// folder it says so in red and turns the button into 「覆盖保存」 — picking an
/// existing file must never overwrite it by accident (the user hit exactly
/// that: the export dialog offered a path box only and clobbered a real file).
class FileBrowserDialog extends StatefulWidget {
  const FileBrowserDialog({
    super.key,
    this.initialDirectory,
    this.title = '选择文件',
    this.extensions = const ['.pcap', '.pcapng', '.cap', '.netcap'],
    this.save = false,
    this.suggestedName = '',
  });

  final String? initialDirectory;
  final String title;
  final List<String> extensions;
  final bool save;
  final String suggestedName;

  static Future<String?> show(
    BuildContext context, {
    String? initialDirectory,
    String title = '选择文件',
    List<String> extensions = const ['.pcap', '.pcapng', '.cap', '.netcap'],
    bool save = false,
    String suggestedName = '',
  }) {
    return showDialog<String>(
      context: context,
      builder: (_) => FileBrowserDialog(
        initialDirectory: initialDirectory,
        title: title,
        extensions: extensions,
        save: save,
        suggestedName: suggestedName,
      ),
    );
  }

  @override
  State<FileBrowserDialog> createState() => _FileBrowserDialogState();
}

class _FileBrowserDialogState extends State<FileBrowserDialog> {
  String _dir = Directory.current.path;
  final _pathCtrl = TextEditingController();
  final _nameCtrl = TextEditingController();
  String? _error;
  List<FileSystemEntity> _dirs = const [];
  List<FileSystemEntity> _files = const [];
  String? _selected;

  /// Where a save would land right now (a name with a separator is taken as a
  /// full path, so pasting one still works).
  String get _target {
    final name = _nameCtrl.text.trim();
    if (name.isEmpty) return _dir;
    if (name.contains(Platform.pathSeparator) || name.contains('/')) return name;
    return '$_dir${Platform.pathSeparator}$name';
  }

  bool get _targetExists {
    if (!widget.save) return false;
    final t = _target;
    if (t.isEmpty || t == _dir) return false;
    return File(t).existsSync();
  }

  @override
  void initState() {
    super.initState();
    var start = widget.initialDirectory;
    if (start == null || start.isEmpty || !Directory(start).existsSync()) {
      start = Directory.current.path;
    }
    _nameCtrl.text = widget.suggestedName;
    _scan(start);
    _pathCtrl.text = _dir;
  }

  @override
  void dispose() {
    _pathCtrl.dispose();
    _nameCtrl.dispose();
    super.dispose();
  }

  /// Fills the listing state without touching setState, so it is safe to call
  /// from initState as well as from event handlers.
  void _scan(String path) {
    final dir = Directory(path);
    try {
      final entries = dir.listSync(followLinks: false);
      final dirs = <FileSystemEntity>[];
      final files = <FileSystemEntity>[];
      for (final e in entries) {
        if (e is Directory) {
          dirs.add(e);
        } else if (e is File && _wanted(e.path)) {
          files.add(e);
        }
      }
      dirs.sort((a, b) => a.path.toLowerCase().compareTo(b.path.toLowerCase()));
      files.sort((a, b) => a.path.toLowerCase().compareTo(b.path.toLowerCase()));
      _dir = dir.path;
      _dirs = dirs;
      _files = files;
      _selected = null;
      _error = null;
    } on FileSystemException catch (e) {
      _error = '无法打开 ${dir.path}: ${e.osError?.message ?? e.message}';
    }
  }

  void _enter(String path, {bool keepField = true}) {
    _scan(path);
    if (keepField) _pathCtrl.text = _dir;
    if (mounted) setState(() {});
  }

  bool _wanted(String path) {
    // An empty filter means "show everything": the key log picker needs that,
    // because an SSLKEYLOGFILE can be named anything at all.
    if (widget.extensions.isEmpty) return true;
    final lower = path.toLowerCase();
    return widget.extensions.any(lower.endsWith);
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return AlertDialog(
      title: Text(widget.title),
      content: SizedBox(
        width: 720,
        height: 480,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                IconButton(
                  tooltip: '上一级',
                  onPressed: () {
                    final parent = Directory(_dir).parent.path;
                    if (parent != _dir) _enter(parent);
                  },
                  icon: const Icon(Icons.arrow_upward, size: 18),
                ),
                Expanded(
                  child: TextField(
                    controller: _pathCtrl,
                    style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
                    decoration: const InputDecoration(
                      isDense: true,
                      border: OutlineInputBorder(),
                      contentPadding:
                          EdgeInsets.symmetric(horizontal: 8, vertical: 10),
                      hintText: r'输入路径后回车，例如 D:\Demo\FilterTheWeb',
                    ),
                    onSubmitted: (v) {
                      final t = v.trim();
                      if (t.isEmpty) return;
                      if (File(t).existsSync()) {
                        setState(() => _selected = t);
                      } else {
                        _enter(t);
                      }
                    },
                  ),
                ),
              ],
            ),
            if (widget.save) ...[
              const SizedBox(height: 10),
              TextField(
                controller: _nameCtrl,
                autofocus: true,
                style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
                decoration: const InputDecoration(
                  isDense: true,
                  border: OutlineInputBorder(),
                  labelText: '文件名',
                  contentPadding:
                      EdgeInsets.symmetric(horizontal: 8, vertical: 10),
                ),
                onChanged: (_) => setState(() {}),
                onSubmitted: (_) => setState(() {}),
              ),
              const SizedBox(height: 6),
              Row(
                children: [
                  Icon(
                    _targetExists ? Icons.warning_amber_rounded : Icons.save_alt,
                    size: 15,
                    color: _targetExists ? cs.error : cs.onSurfaceVariant,
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                      _targetExists
                          ? '这个文件夹里已经有同名文件：保存会覆盖它 —— $_target'
                          : '保存到：$_target',
                      style: TextStyle(
                        fontSize: 12,
                        color: _targetExists ? cs.error : cs.onSurfaceVariant,
                      ),
                    ),
                  ),
                ],
              ),
            ],
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(_error!, style: TextStyle(color: cs.error, fontSize: 12)),
              ),
            const SizedBox(height: 8),
            Expanded(
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Expanded(
                    child: Card(
                      margin: EdgeInsets.zero,
                      child: ListView.builder(
                        itemCount: _dirs.length,
                        itemBuilder: (context, i) {
                          final d = _dirs[i];
                          final name = d.path.split(Platform.pathSeparator).last;
                          return ListTile(
                            dense: true,
                            leading: const Icon(Icons.folder, size: 18, color: Color(0xFFE3B341)),
                            title: Text(name, style: const TextStyle(fontSize: 13)),
                            onTap: () => _enter(d.path),
                          );
                        },
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Card(
                      margin: EdgeInsets.zero,
                      child: _files.isEmpty
                          ? const EmptyState(
                              icon: Icons.search_off,
                              title: '此目录没有匹配的文件',
                            )
                          : ListView.builder(
                              itemCount: _files.length,
                              itemBuilder: (context, i) {
                                final f = _files[i];
                                final name = f.path.split(Platform.pathSeparator).last;
                                final sel = _selected == f.path;
                                return ListTile(
                                  dense: true,
                                  selected: sel,
                                  selectedTileColor: cs.primary.withValues(alpha: 0.14),
                                  leading: const Icon(Icons.insert_drive_file,
                                      size: 18, color: Color(0xFF7FB3FF)),
                                  title: Text(name, style: const TextStyle(fontSize: 13)),
                                  subtitle: Text(
                                    formatBytes(File(f.path).lengthSync()),
                                    style: const TextStyle(fontSize: 11),
                                  ),
                                  onTap: () => setState(() {
                                    // In save mode a click means "use this
                                    // name" (and the button then says 覆盖).
                                    if (widget.save) {
                                      _nameCtrl.text = name;
                                    } else {
                                      _selected = f.path;
                                    }
                                  }),
                                  onLongPress: widget.save
                                      ? null
                                      : () => Navigator.of(context).pop(f.path),
                                );
                              },
                            ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('取消'),
        ),
        FilledButton.icon(
          onPressed: widget.save
              ? (_nameCtrl.text.trim().isEmpty
                  ? null
                  : () => Navigator.of(context).pop(_target))
              : (_selected == null
                  ? null
                  : () => Navigator.of(context).pop(_selected)),
          icon: Icon(widget.save ? Icons.save_alt : Icons.check, size: 18),
          label: Text(widget.save
              ? (_targetExists ? '覆盖保存' : '保存')
              : (_selected == null
                  ? '选择文件'
                  : '使用 ${_selected!.split(Platform.pathSeparator).last}')),
        ),
      ],
    );
  }
}

/// The 「日志」 window: a plain, selectable dump of everything netcap printed.
///
/// It deliberately lives in its own dialog instead of the main window's
/// right-hand column — that column reports state (connection, certificate,
/// takeover, counters), and the raw `netcap:` output used to bury it. The list
/// is shared with the caller, so the window keeps filling while it is open: a
/// slow tick rebuilds it and follows the tail unless the reader scrolled up.
class LogWindow extends StatefulWidget {
  const LogWindow({
    super.key,
    required this.lines,
    required this.onCopy,
    required this.onClear,
  });

  final List<String> lines;
  final VoidCallback onCopy;
  final VoidCallback onClear;

  @override
  State<LogWindow> createState() => _LogWindowState();
}

class _LogWindowState extends State<LogWindow> {
  final ScrollController _scroll = ScrollController();
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    _ticker = Timer.periodic(const Duration(milliseconds: 500), (_) {
      if (!mounted) return;
      final atEnd = !_scroll.hasClients ||
          _scroll.position.pixels >= _scroll.position.maxScrollExtent - 40;
      setState(() {});
      if (atEnd) _jumpToEnd();
    });
    WidgetsBinding.instance.addPostFrameCallback((_) => _jumpToEnd());
  }

  void _jumpToEnd() {
    if (!_scroll.hasClients) return;
    _scroll.jumpTo(_scroll.position.maxScrollExtent);
  }

  @override
  void dispose() {
    _ticker?.cancel();
    _scroll.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = widget.lines.isEmpty ? '（还没有输出）' : widget.lines.join('\n');
    return AlertDialog(
      title: Row(
        children: [
          const Icon(Icons.receipt_long_outlined, size: 18),
          const SizedBox(width: 8),
          Text('运行日志（${widget.lines.length} 行）',
              style: const TextStyle(fontSize: 15)),
        ],
      ),
      content: SizedBox(
        width: 900,
        height: 520,
        child: Container(
          decoration: BoxDecoration(
            color: cs.surface,
            border: Border.all(color: cs.outlineVariant),
            borderRadius: BorderRadius.circular(8),
          ),
          padding: const EdgeInsets.all(10),
          child: Scrollbar(
            controller: _scroll,
            child: SingleChildScrollView(
              controller: _scroll,
              child: SelectableText(
                text,
                style: TextStyle(
                  fontFamily: 'Consolas',
                  fontSize: 11.5,
                  height: 1.35,
                  color: cs.onSurfaceVariant,
                ),
              ),
            ),
          ),
        ),
      ),
      actions: [
        TextButton.icon(
          onPressed: widget.onCopy,
          icon: const Icon(Icons.copy_all_outlined, size: 16),
          label: const Text('复制全部'),
        ),
        TextButton.icon(
          onPressed: widget.onClear,
          icon: const Icon(Icons.delete_outline, size: 16),
          label: const Text('清空'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('关闭'),
        ),
      ],
    );
  }
}
