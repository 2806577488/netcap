// The graphical HTTPS page.
//
// Design brief (from the user): this has to be usable by someone who is not a
// computer person.  So: one big switch, one certificate card that says what to
// do, a short list of programs with plain names, and the raw netcap arguments
// tucked away under 高级.  Nothing here asks the user to type a comma separated
// image-name list unless they open that fold on purpose.
import 'package:flutter/material.dart';

import 'mitm_apps.dart';
import 'widgets.dart';

/// Opens the page and returns the settings the user saved, or null on cancel.
Future<MitmSettings?> showMitmPage(
  BuildContext context, {
  required MitmSettings settings,
  required bool caExists,
  required bool caTrusted,
  required String caDetail,
  required Future<String> Function() onDetect,
  required Future<String> Function() onCreate,
  required Future<String> Function() onInstall,
  required Future<String> Function() onUninstall,
  required Future<List<MitmApp>> Function() onListRunning,
}) {
  return showDialog<MitmSettings>(
    context: context,
    builder: (_) => MitmPage(
      settings: settings,
      caExists: caExists,
      caTrusted: caTrusted,
      caDetail: caDetail,
      onDetect: onDetect,
      onCreate: onCreate,
      onInstall: onInstall,
      onUninstall: onUninstall,
      onListRunning: onListRunning,
    ),
  );
}

class MitmPage extends StatefulWidget {
  const MitmPage({
    super.key,
    required this.settings,
    required this.caExists,
    required this.caTrusted,
    required this.caDetail,
    required this.onDetect,
    required this.onCreate,
    required this.onInstall,
    required this.onUninstall,
    required this.onListRunning,
  });

  final MitmSettings settings;
  final bool caExists;
  final bool caTrusted;
  final String caDetail;
  final Future<String> Function() onDetect;
  final Future<String> Function() onCreate;
  final Future<String> Function() onInstall;
  final Future<String> Function() onUninstall;
  final Future<List<MitmApp>> Function() onListRunning;

  @override
  State<MitmPage> createState() => _MitmPageState();
}

class _MitmPageState extends State<MitmPage> {
  late MitmSettings _s = widget.settings;
  late bool _exists = widget.caExists;
  late bool _trusted = widget.caTrusted;
  late String _detail = widget.caDetail;
  final _manualCtrl = TextEditingController();
  bool _busy = false;

  @override
  void dispose() {
    _manualCtrl.dispose();
    super.dispose();
  }

  Future<void> _ca(Future<String> Function() action) async {
    setState(() {
      _busy = true;
    });
    String text;
    try {
      text = await action();
    } catch (e) {
      text = '操作失败：$e';
    }
    if (!mounted) return;
    setState(() {
      _busy = false;
      // The three buttons all end up asking the same question afterwards.
      // Installing implies the certificate exists from now on, even if this page
      // was opened when there was none yet.
      if (text.contains('已安装')) {
        _trusted = true;
        _exists = true;
      }
      if (text.contains('已移除')) _trusted = false;
      if (text.contains('已创建')) _exists = true;
      _detail = text;
    });
  }

  Future<void> _addPrograms() async {
    final path = await FileBrowserDialog.show(
      context,
      title: '选择要过滤的程序',
      extensions: const ['.exe'],
    );
    if (path == null || path.trim().isEmpty || !mounted) return;
    final exe = path.split(RegExp(r'[\\/]')).last;
    setState(() => _s = _s.withApp(exe));
  }

  Future<void> _pickRunning() async {
    List<MitmApp> running;
    try {
      running = await widget.onListRunning();
    } catch (e) {
      if (mounted) setState(() => _detail = '读不到正在运行的程序：$e');
      return;
    }
    if (!mounted) return;
    final picked = await showDialog<List<MitmApp>>(
      context: context,
      builder: (_) => _PickRunningDialog(running: running, known: _s.apps.map((a) => a.exe).toList()),
    );
    if (picked == null || picked.isEmpty || !mounted) return;
    setState(() {
      var next = _s;
      for (final app in picked) {
        next = next.withApp(app.exe, label: app.label);
      }
      _s = next;
    });
  }

  void _addManual() {
    final text = _manualCtrl.text.trim();
    if (text.isEmpty) return;
    setState(() {
      var next = _s;
      for (final part in text.split(RegExp(r'[,;，、\s]+'))) {
        final name = part.trim();
        if (name.isEmpty) continue;
        next = next.withApp(name.toLowerCase().endsWith('.exe') ? name : '$name.exe');
      }
      _s = next;
      _manualCtrl.clear();
    });
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final size = MediaQuery.of(context).size;
    final width = size.width < 860 ? size.width - 40 : 820.0;
    final height = size.height < 700 ? size.height - 40 : 660.0;
    return Dialog(
      insetPadding: const EdgeInsets.all(18),
      child: SizedBox(
        width: width,
        height: height,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _header(cs),
            const Divider(height: 1),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.fromLTRB(18, 14, 18, 14),
                children: [
                  _switchCard(cs),
                  const SizedBox(height: 12),
                  _certCard(cs),
                  const SizedBox(height: 12),
                  _scopeCard(cs),
                  const SizedBox(height: 12),
                  _programCard(cs),
                  const SizedBox(height: 12),
                  _advancedCard(cs),
                ],
              ),
            ),
            const Divider(height: 1),
            _footer(cs),
          ],
        ),
      ),
    );
  }

  Widget _header(ColorScheme cs) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 14, 10, 12),
      child: Row(
        children: [
          Icon(Icons.lock_outline, size: 20, color: cs.primary),
          const SizedBox(width: 8),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('HTTPS 过滤', style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
                SizedBox(height: 2),
                Text(
                  '加密网站的内容默认是看不见的，所以里面的广告拦不住。这里决定让 netcap 看懂哪些程序的上网内容——只在这台电脑上生效，随时可以关掉。',
                  style: TextStyle(fontSize: 11.5),
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

  Widget _switchCard(ColorScheme cs) {
    final on = _s.enabled;
    return _card(
      cs,
      children: [
        // The card itself is a DecoratedBox, so the tile needs its own Material
        // for the ink splash: without it Flutter asserts that the splash is
        // invisible (and the switch would feel dead).
        Material(
          type: MaterialType.transparency,
          child: SwitchListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            value: on,
            title: const Text('看懂 HTTPS（解密加密流量）', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
            subtitle: Text(
              on ? '开着：能按网址、路径拦广告，也能改写网页内容' : '关着：只做普通转发，看不到加密内容，规则只能按域名拦',
              style: const TextStyle(fontSize: 11.5),
            ),
            onChanged: (v) => setState(() => _s = _s.copyWith(enabled: v)),
          ),
        ),
      ],
    );
  }

  Widget _certCard(ColorScheme cs) {
    final installed = _exists && _trusted;
    final badge = installed
        ? ('已安装', cs.primary)
        : (_exists ? ('还没安装', const Color(0xFFD29922)) : ('还没有证书', const Color(0xFFD29922)));
    return _card(
      cs,
      children: [
        Row(
          children: [
            const Expanded(
              child: Text('1. 证书（浏览器凭什么相信我们）',
                  style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: badge.$2.withValues(alpha: 0.16),
                borderRadius: BorderRadius.circular(20),
              ),
              child: Text(badge.$1, style: TextStyle(fontSize: 11.5, color: badge.$2)),
            ),
          ],
        ),
        const SizedBox(height: 6),
        Text(
          installed
              ? '证书已装进当前用户的根证书库。要撤销：点下面的「移除证书」，或者随时重装/卸载都不会影响其它软件。'
              : '要解密 HTTPS，必须先装上 netcap 自己的证书（只装给当前用户，不碰系统级设置，也不会发给任何人）。装完重启代理生效。',
          style: const TextStyle(fontSize: 11.5),
        ),
        if (_detail.trim().isNotEmpty) ...[
          const SizedBox(height: 6),
          Text(_detail.trim(), style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant)),
        ],
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 6,
          children: [
            FilledButton.icon(
              onPressed: _busy || installed ? null : () => _ca(widget.onInstall),
              icon: const Icon(Icons.download_for_offline_outlined, size: 16),
              label: const Text('一键安装证书', style: TextStyle(fontSize: 12.5)),
            ),
            OutlinedButton.icon(
              onPressed: _busy || _exists ? null : () => _ca(widget.onCreate),
              icon: const Icon(Icons.add_moderator_outlined, size: 16),
              label: const Text('先生成证书', style: TextStyle(fontSize: 12.5)),
            ),
            OutlinedButton.icon(
              onPressed: _busy ? null : () => _ca(widget.onDetect),
              icon: const Icon(Icons.refresh, size: 16),
              label: const Text('重新检测', style: TextStyle(fontSize: 12.5)),
            ),
            OutlinedButton.icon(
              onPressed: _busy || !_trusted ? null : () => _ca(widget.onUninstall),
              icon: const Icon(Icons.delete_outline, size: 16),
              label: const Text('移除证书', style: TextStyle(fontSize: 12.5)),
            ),
          ],
        ),
      ],
    );
  }

  Widget _scopeCard(ColorScheme cs) {
    return _card(
      cs,
      children: [
        const Text('2. 过滤哪些程序', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
        const SizedBox(height: 4),
        _option(
          cs,
          selected: _s.scope == MitmScope.selected,
          title: '常见程序（推荐）',
          subtitle: '只看浏览器、微信、QQ 这些最可能被广告打扰的程序；银行、网银客户端之类默认不动。',
          onTap: () => setState(() => _s = _s.copyWith(scope: MitmScope.selected)),
        ),
        _option(
          cs,
          selected: _s.scope == MitmScope.all,
          title: '这台电脑上的所有程序',
          subtitle: '全都看得懂，但在下面把不想动的程序关掉（比如网银、公司 VPN）。',
          onTap: () => setState(() => _s = _s.copyWith(scope: MitmScope.all)),
        ),
        if (!_s.active)
          Padding(
            padding: const EdgeInsets.only(top: 6),
            child: Text(
              _s.enabled ? '目前没有选中任何程序，等于关闭——打开下面任意一个程序即可。' : '总开关关着，这里的选择先存起来，打开总开关后生效。',
              style: const TextStyle(fontSize: 11.5, color: Color(0xFFD29922)),
            ),
          ),
      ],
    );
  }

  Widget _option(ColorScheme cs, {
    required bool selected,
    required String title,
    required String subtitle,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 7),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(selected ? Icons.radio_button_checked : Icons.radio_button_off,
                size: 17, color: selected ? cs.primary : cs.onSurfaceVariant),
            const SizedBox(width: 8),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                  const SizedBox(height: 2),
                  Text(subtitle, style: const TextStyle(fontSize: 11.5)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _programCard(ColorScheme cs) {
    final rows = _s.apps;
    return _card(
      cs,
      children: [
        Row(
          children: [
            const Expanded(
              child: Text('3. 程序清单', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
            ),
            Text('${_s.decryptList.length} / ${rows.length}',
                style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant)),
          ],
        ),
        const SizedBox(height: 2),
        Text(
          _s.scope == MitmScope.selected ? '打开的程序会被解密过滤，关掉的直接放行。' : '所有程序默认解密，关掉的这几个不碰。',
          style: const TextStyle(fontSize: 11.5),
        ),
        const SizedBox(height: 6),
        ConstrainedBox(
          constraints: const BoxConstraints(maxHeight: 232),
          child: rows.isEmpty
              ? const Padding(
                  padding: EdgeInsets.symmetric(vertical: 14),
                  child: Text('清单是空的，用下面的按钮添加程序。', style: TextStyle(fontSize: 12)),
                )
              : ListView.builder(
                  shrinkWrap: true,
                  itemCount: rows.length,
                  itemBuilder: (_, i) => _programRow(cs, rows[i]),
                ),
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 6,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            OutlinedButton.icon(
              onPressed: _addPrograms,
              icon: const Icon(Icons.add, size: 16),
              label: const Text('添加程序…', style: TextStyle(fontSize: 12.5)),
            ),
            OutlinedButton.icon(
              onPressed: _pickRunning,
              icon: const Icon(Icons.list_alt, size: 16),
              label: const Text('从正在运行的程序里挑…', style: TextStyle(fontSize: 12.5)),
            ),
            SizedBox(
              width: 230,
              child: TextField(
                controller: _manualCtrl,
                style: const TextStyle(fontSize: 12),
                decoration: const InputDecoration(
                  isDense: true,
                  hintText: '或直接输入，如 bank.exe',
                  hintStyle: TextStyle(fontSize: 11.5),
                  border: OutlineInputBorder(),
                  contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 10),
                ),
                onSubmitted: (_) => _addManual(),
              ),
            ),
            TextButton(
              onPressed: _addManual,
              child: const Text('添加', style: TextStyle(fontSize: 12.5)),
            ),
          ],
        ),
      ],
    );
  }

  Widget _programRow(ColorScheme cs, MitmApp app) {
    final on = _s.decrypts(app.exe);
    final first = app.title.isNotEmpty ? app.title.characters.first.toUpperCase() : '?';
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          CircleAvatar(
            radius: 13,
            backgroundColor: cs.primary.withValues(alpha: 0.18),
            child: Text(first, style: const TextStyle(fontSize: 12)),
          ),
          const SizedBox(width: 9),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(app.title, style: const TextStyle(fontSize: 12.5)),
                if (app.label.trim().isNotEmpty)
                  Text(app.exe, style: TextStyle(fontSize: 10.5, color: cs.onSurfaceVariant)),
              ],
            ),
          ),
          if (_s.scope == MitmScope.selected && !_s.knows(app.exe))
            TextButton(
              onPressed: () => setState(() => _s = _s.setDecrypt(app.exe, true)),
              child: const Text('加入', style: TextStyle(fontSize: 11.5)),
            ),
          Switch(
            value: on,
            onChanged: (v) => setState(() => _s = _s.setDecrypt(app.exe, v)),
          ),
          IconButton(
            tooltip: '从清单里删掉',
            iconSize: 15,
            visualDensity: VisualDensity.compact,
            onPressed: () => setState(() {
              _s = _s.copyWith(apps: _s.apps.where((a) => a.exe != app.exe).toList());
            }),
            icon: const Icon(Icons.close),
          ),
        ],
      ),
    );
  }

  Widget _advancedCard(ColorScheme cs) {
    final args = _s.toArgs();
    return _card(
      cs,
      children: [
        Theme(
          data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
          // The card is a DecoratedBox, so the tile inside needs its own
          // Material or Flutter asserts that the ink splash is invisible.
          child: Material(
            type: MaterialType.transparency,
            child: ExpansionTile(
            tilePadding: EdgeInsets.zero,
            childrenPadding: const EdgeInsets.only(top: 4),
            title: const Text('高级（给懂命令行的人）', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
            subtitle: const Text('页面上的选择会变成下面这串参数，跟着代理一起启动',
                style: TextStyle(fontSize: 11.5)),
            children: [
              SelectableText(
                args.isEmpty ? '（不带解密参数：只做纯隧道）' : 'netcap --serve 127.0.0.1:8080 ${args.join(' ')}',
                style: const TextStyle(fontFamily: 'Consolas', fontSize: 11.5),
              ),
              const SizedBox(height: 6),
              const Text(
                '--mitm-only 是只解密名单里的程序，--mitm-skip 是全部解密但跳过名单里的程序。两者都由上面的清单自动生成，不用手写。',
                style: TextStyle(fontSize: 11),
              ),
            ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _footer(ColorScheme cs) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 10, 18, 10),
      child: Row(
        children: [
          Expanded(
            child: Text(
              _s.summary,
              style: TextStyle(fontSize: 12, color: _s.active ? cs.primary : cs.onSurfaceVariant),
            ),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('取消'),
          ),
          const SizedBox(width: 8),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(_s),
            child: const Text('保存'),
          ),
        ],
      ),
    );
  }

  Widget _card(ColorScheme cs, {required List<Widget> children}) {
    return Container(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest.withValues(alpha: 0.35),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: cs.outlineVariant.withValues(alpha: 0.5)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: children),
    );
  }
}

/// The "pick from the running programs" sheet: search, multi-select, add.
class _PickRunningDialog extends StatefulWidget {
  const _PickRunningDialog({required this.running, required this.known});

  final List<MitmApp> running;
  final List<String> known;

  @override
  State<_PickRunningDialog> createState() => _PickRunningDialogState();
}

class _PickRunningDialogState extends State<_PickRunningDialog> {
  final _search = TextEditingController();
  final _picked = <String>{};

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final needle = _search.text.trim().toLowerCase();
    final known = widget.known.map((e) => e.toLowerCase()).toSet();
    final list = widget.running
        .where((a) => needle.isEmpty || a.exe.toLowerCase().contains(needle))
        .toList();
    return Dialog(
      insetPadding: const EdgeInsets.all(40),
      child: SizedBox(
        width: 520,
        height: 520,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 14, 8, 8),
              child: Row(
                children: [
                  const Expanded(
                    child: Text('正在运行的程序', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
                  ),
                  IconButton(
                    iconSize: 18,
                    onPressed: () => Navigator.of(context).pop(),
                    icon: const Icon(Icons.close),
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: TextField(
                controller: _search,
                autofocus: true,
                style: const TextStyle(fontSize: 12.5),
                decoration: const InputDecoration(
                  isDense: true,
                  prefixIcon: Icon(Icons.search, size: 16),
                  hintText: '搜程序名，例如 chrome',
                  hintStyle: TextStyle(fontSize: 12),
                  border: OutlineInputBorder(),
                  contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 10),
                ),
                onChanged: (_) => setState(() {}),
              ),
            ),
            const SizedBox(height: 8),
            Expanded(
              child: list.isEmpty
                  ? const Center(child: Text('没有匹配的程序', style: TextStyle(fontSize: 12)))
                  : ListView.builder(
                      itemCount: list.length,
                      itemBuilder: (_, i) {
                        final app = list[i];
                        final on = _picked.contains(app.exe);
                        return CheckboxListTile(
                          dense: true,
                          value: on,
                          title: Text(app.exe, style: const TextStyle(fontSize: 12.5)),
                          subtitle: known.contains(app.exe.toLowerCase())
                              ? const Text('已经在清单里', style: TextStyle(fontSize: 11))
                              : null,
                          onChanged: (v) => setState(() {
                            if (v == true) {
                              _picked.add(app.exe);
                            } else {
                              _picked.remove(app.exe);
                            }
                          }),
                        );
                      },
                    ),
            ),
            const Divider(height: 1),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
              child: Row(
                children: [
                  Expanded(
                    child: Text('已选 ${_picked.length} 个', style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant)),
                  ),
                  TextButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('取消'),
                  ),
                  const SizedBox(width: 8),
                  FilledButton(
                    onPressed: _picked.isEmpty
                        ? null
                        : () => Navigator.of(context).pop(
                              _picked.map((e) => MitmApp(exe: e)).toList(),
                            ),
                    child: const Text('添加'),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
