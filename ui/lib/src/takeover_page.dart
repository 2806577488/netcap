import 'package:flutter/material.dart';

/// Everything the "让所有程序走过滤" page edits, in one value object, so the
/// capture screen keeps owning the live state and the page stays a pure editor.
class TakeoverDraft {
  const TakeoverDraft({
    this.systemProxy = false,
    this.systemProxyForce = false,
    this.bypass = '<local>',
    this.tun = false,
    this.tunAdapter = '',
    this.upstream = '',
    this.tunAddress = '',
    this.tunSeconds = 12,
  });

  final bool systemProxy;
  final bool systemProxyForce;
  final bool tun;
  final String bypass;
  final String tunAdapter;
  final String upstream;
  final String tunAddress;
  final int tunSeconds;

  TakeoverDraft copyWith({
    bool? systemProxy,
    bool? systemProxyForce,
    String? bypass,
    bool? tun,
    String? tunAdapter,
    String? upstream,
    String? tunAddress,
    int? tunSeconds,
  }) {
    return TakeoverDraft(
      systemProxy: systemProxy ?? this.systemProxy,
      systemProxyForce: systemProxyForce ?? this.systemProxyForce,
      bypass: bypass ?? this.bypass,
      tun: tun ?? this.tun,
      tunAdapter: tunAdapter ?? this.tunAdapter,
      upstream: upstream ?? this.upstream,
      tunAddress: tunAddress ?? this.tunAddress,
      tunSeconds: tunSeconds ?? this.tunSeconds,
    );
  }

  /// One plain sentence for the capture screen's summary.
  String get summary {
    if (tun) return '所有程序自动走过滤（备用方式：虚拟网卡）';
    if (systemProxy) return '所有程序自动走过滤（自动设置系统代理）';
    return '只有自己设了代理的程序会走过滤';
  }

  /// The flags this draft would add to the command line, for the "advanced" fold.
  List<String> get args {
    final out = <String>[];
    if (tun) {
      out.add('--tun');
      out.add('--tun-takeover');
      if (tunAdapter.trim().isNotEmpty) out.addAll(['--tun-adapter', tunAdapter.trim()]);
      if (tunAddress.trim().isNotEmpty) out.addAll(['--tun-address', tunAddress.trim()]);
      out.addAll(['--tun-seconds', '$tunSeconds']);
    } else if (systemProxy) {
      out.add('--system-proxy');
      out.add('on');
      if (bypass.trim().isNotEmpty) out.addAll(['--system-proxy-bypass', bypass.trim()]);
      if (systemProxyForce) out.add('--system-proxy-force');
    }
    if (upstream.trim().isNotEmpty) out.addAll(['--upstream', upstream.trim()]);
    return out;
  }
}

/// Opens the page and returns the edited draft, or null when the user cancels.
Future<TakeoverDraft?> showTakeoverPage(
  BuildContext context, {
  required TakeoverDraft draft,
  required bool rescueScript,
  required String proxyStatusLabel,
  required String proxyStatusDetail,
  required Future<String> Function() onReadCurrent,
  required Future<String> Function() onCheckChain,
  required Future<String> Function() onRestoreProxy,
  required Future<String> Function() onTunCheck,
  required Future<String> Function(int seconds) onTunDrill,
}) {
  return showDialog<TakeoverDraft>(
    context: context,
    barrierDismissible: false,
    builder: (_) => TakeoverPage(
      draft: draft,
      rescueScript: rescueScript,
      proxyStatusLabel: proxyStatusLabel,
      proxyStatusDetail: proxyStatusDetail,
      onReadCurrent: onReadCurrent,
      onCheckChain: onCheckChain,
      onRestoreProxy: onRestoreProxy,
      onTunCheck: onTunCheck,
      onTunDrill: onTunDrill,
    ),
  );
}

/// A deliberately short page: one switch most people need, everything else
/// folded away under "高级".  The previous version put a dozen command-line
/// flags on screen at once and a non-technical user rightly called it a mess.
class TakeoverPage extends StatefulWidget {
  const TakeoverPage({
    super.key,
    required this.draft,
    required this.rescueScript,
    required this.proxyStatusLabel,
    required this.proxyStatusDetail,
    required this.onReadCurrent,
    required this.onCheckChain,
    required this.onRestoreProxy,
    required this.onTunCheck,
    required this.onTunDrill,
  });

  final TakeoverDraft draft;
  final bool rescueScript;
  final String proxyStatusLabel;
  final String proxyStatusDetail;
  final Future<String> Function() onReadCurrent;
  final Future<String> Function() onCheckChain;
  final Future<String> Function() onRestoreProxy;
  final Future<String> Function() onTunCheck;
  final Future<String> Function(int seconds) onTunDrill;

  @override
  State<TakeoverPage> createState() => _TakeoverPageState();
}

class _TakeoverPageState extends State<TakeoverPage> {
  late TakeoverDraft _d = widget.draft;
  late final TextEditingController _bypassCtrl =
      TextEditingController(text: widget.draft.bypass);
  late final TextEditingController _upstreamCtrl =
      TextEditingController(text: widget.draft.upstream);
  late final TextEditingController _adapterCtrl =
      TextEditingController(text: widget.draft.tunAdapter);
  late final TextEditingController _addressCtrl =
      TextEditingController(text: widget.draft.tunAddress);
  String _report = '';
  bool _busy = false;

  @override
  void dispose() {
    _bypassCtrl.dispose();
    _upstreamCtrl.dispose();
    _adapterCtrl.dispose();
    _addressCtrl.dispose();
    super.dispose();
  }

  Future<void> _run(Future<String> Function() action) async {
    setState(() => _busy = true);
    String text;
    try {
      text = await action();
    } catch (e) {
      text = '操作失败：$e';
    }
    if (!mounted) return;
    setState(() {
      _busy = false;
      _report = text;
    });
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final size = MediaQuery.of(context).size;
    final width = size.width < 760 ? size.width - 40 : 700.0;
    final height = size.height < 700 ? size.height - 40 : 640.0;
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
                  _mainCard(cs),
                  const SizedBox(height: 12),
                  _advancedFold(cs),
                  if (_report.trim().isNotEmpty) ...[
                    const SizedBox(height: 12),
                    _reportCard(cs),
                  ],
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
          Icon(Icons.shield_outlined, size: 20, color: cs.primary),
          const SizedBox(width: 8),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('让所有程序都走过滤',
                    style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
                SizedBox(height: 2),
                Text('浏览器、微信、其它软件里的广告，靠这一步才能全拦下来。',
                    style: TextStyle(fontSize: 12)),
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

  Widget _mainCard(ColorScheme cs) {
    final on = _d.systemProxy || _d.tun;
    return _card(
      cs,
      children: [
        SwitchListTile(
          dense: true,
          contentPadding: EdgeInsets.zero,
          value: on,
          title: const Text('自动让所有程序走 netcap',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
          subtitle: Text(
            on
                ? '保存后，回主界面点「启动代理」就生效；点「停止」或关掉程序时会自动把设置还原。'
                : '不用管代理设置。打开这个开关，netcap 自己把系统的代理指过来，关闭时自动恢复原样。',
            style: const TextStyle(fontSize: 11.5),
          ),
          onChanged: widget.rescueScript
              ? (v) => setState(() => _d = v
                  ? _d.copyWith(systemProxy: true, tun: false)
                  : _d.copyWith(systemProxy: false, tun: false))
              : null,
        ),
        const SizedBox(height: 6),
        Row(
          children: [
            Text('现在：', style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant)),
            Expanded(
              child: Text(
                widget.proxyStatusLabel.trim().isEmpty ? '读不到' : widget.proxyStatusLabel,
                style: const TextStyle(fontSize: 11.5),
              ),
            ),
            TextButton.icon(
              onPressed: _busy ? null : () => _run(widget.onReadCurrent),
              icon: const Icon(Icons.refresh, size: 15),
              label: const Text('刷新', style: TextStyle(fontSize: 12)),
            ),
          ],
        ),
        if (!widget.rescueScript)
          Text('桌面上找不到 netcap-restore.cmd（出事后的离线还原脚本），所以这个开关被禁用了。',
              style: TextStyle(fontSize: 11.5, color: cs.error)),
        const SizedBox(height: 6),
        Container(
          padding: const EdgeInsets.fromLTRB(10, 8, 10, 8),
          decoration: BoxDecoration(
            color: const Color(0xFFD29922).withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Row(
            children: [
              const Icon(Icons.health_and_safety_outlined, size: 16, color: Color(0xFFD29922)),
              const SizedBox(width: 8),
              const Expanded(
                child: Text(
                  '万一程序崩了、或者网络不对：双击桌面上的 netcap-restore.cmd 一键恢复。',
                  style: TextStyle(fontSize: 11.5),
                ),
              ),
              TextButton(
                onPressed: _busy ? null : () => _run(widget.onRestoreProxy),
                child: const Text('现在还原', style: TextStyle(fontSize: 12)),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _advancedFold(ColorScheme cs) {
    // A real Material paints this panel: ListTile (inside ExpansionTile) refuses
    // to sit under a plain DecoratedBox, it wants a Material as the background.
    return Material(
      color: cs.surfaceContainerHighest.withValues(alpha: 0.35),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(10),
        side: BorderSide(color: cs.outlineVariant.withValues(alpha: 0.5)),
      ),
      child: Theme(
        data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          tilePadding: const EdgeInsets.symmetric(horizontal: 14),
          childrenPadding: const EdgeInsets.fromLTRB(14, 0, 14, 14),
          title: const Text('高级（一般不用改）',
              style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
          subtitle: const Text('虚拟网卡方式、链式上游、接管演练、查看当前设置',
              style: TextStyle(fontSize: 11)),
          children: [
            _field('跳过这些地址（--system-proxy-bypass）', _bypassCtrl, '默认 <local>',
                (v) => _d = _d.copyWith(bypass: v)),
            SwitchListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              value: _d.systemProxyForce,
              title: const Text('上游连不上也照样接管（--system-proxy-force）',
                  style: TextStyle(fontSize: 12.5)),
              subtitle: const Text('默认会先确认能连上；上游不通时强行接管等于断开网络',
                  style: TextStyle(fontSize: 11)),
              onChanged: widget.rescueScript
                  ? (v) => setState(() => _d = _d.copyWith(systemProxyForce: v))
                  : null,
            ),
            const Divider(height: 18),
            const Text('备用方式：虚拟网卡（不用改任何程序的设置）',
                style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600)),
            const SizedBox(height: 2),
            const Text('它接管整台机器的流量，但只看得到域名；必须有可用的链式上游，否则会断开网络。',
                style: TextStyle(fontSize: 11)),
            SwitchListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              value: _d.tun,
              title: const Text('用虚拟网卡接管全部流量（--tun --tun-takeover）',
                  style: TextStyle(fontSize: 12.5)),
              onChanged: widget.rescueScript
                  ? (v) => setState(() => _d = v
                      ? _d.copyWith(tun: true, systemProxy: false)
                      : _d.copyWith(tun: false))
                  : null,
            ),
            _field('链式上游（--upstream）：接管时必须填', _upstreamCtrl, '例如 127.0.0.1:7890',
                (v) => _d = _d.copyWith(upstream: v)),
            const SizedBox(height: 6),
            _field('网卡名字（--tun-adapter）', _adapterCtrl, '留空就用 netcap',
                (v) => _d = _d.copyWith(tunAdapter: v)),
            const SizedBox(height: 6),
            _field('隧道地址（--tun-address）', _addressCtrl, '留空自动选',
                (v) => _d = _d.copyWith(tunAddress: v)),
            const SizedBox(height: 8),
            Row(
              children: [
                const Text('演练时长', style: TextStyle(fontSize: 12)),
                const SizedBox(width: 8),
                for (final secs in const [5, 12, 30])
                  Padding(
                    padding: const EdgeInsets.only(right: 6),
                    child: ChoiceChip(
                      label: Text('$secs 秒', style: const TextStyle(fontSize: 11)),
                      selected: _d.tunSeconds == secs,
                      onSelected: (_) => setState(() => _d = _d.copyWith(tunSeconds: secs)),
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 6),
            Wrap(
              spacing: 6,
              runSpacing: 4,
              children: [
                OutlinedButton.icon(
                  onPressed: _busy ? null : () => _run(widget.onTunCheck),
                  icon: const Icon(Icons.fact_check_outlined, size: 15),
                  label: const Text('只读预检（--tun-check）', style: TextStyle(fontSize: 12)),
                ),
                FilledButton.tonalIcon(
                  onPressed: !widget.rescueScript || _busy
                      ? null
                      : () => _run(() => widget.onTunDrill(_d.tunSeconds)),
                  icon: const Icon(Icons.play_arrow_outlined, size: 15),
                  label: Text('演练 ${_d.tunSeconds} 秒后自动还原',
                      style: const TextStyle(fontSize: 12)),
                ),
              ],
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              onPressed: _busy ? null : () => _run(widget.onCheckChain),
              icon: const Icon(Icons.route_outlined, size: 15),
              label: const Text('检查会连到哪里（只读）', style: TextStyle(fontSize: 12)),
            ),
            if (widget.proxyStatusDetail.trim().isNotEmpty) ...[
              const SizedBox(height: 10),
              const Text('当前系统代理设置',
                  style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600)),
              for (final line in widget.proxyStatusDetail.split('\n'))
                if (line.trim().isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: 2),
                    child: Text(line, style: const TextStyle(fontFamily: 'Consolas', fontSize: 11)),
                  ),
            ],
            const SizedBox(height: 10),
            SelectableText(
              _d.args.isEmpty
                  ? 'netcap --serve 127.0.0.1:8080        # 没有打开任何接管'
                  : 'netcap ${_d.args.join(' ')} --serve 127.0.0.1:8080',
              style: const TextStyle(fontFamily: 'Consolas', fontSize: 11.5),
            ),
          ],
        ),
      ),
    );
  }

  Widget _reportCard(ColorScheme cs) {
    return _card(
      cs,
      children: [
        const Text('结果', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
        const SizedBox(height: 6),
        SelectableText(_report.trim(),
            style: const TextStyle(fontFamily: 'Consolas', fontSize: 11)),
      ],
    );
  }

  Widget _footer(ColorScheme cs) {
    final on = _d.systemProxy || _d.tun;
    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 10, 18, 10),
      child: Row(
        children: [
          Expanded(
            child: Text(
              on ? _d.summary : '取消不会改动任何设置',
              style: TextStyle(fontSize: 12, color: on ? cs.primary : cs.onSurfaceVariant),
            ),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('取消'),
          ),
          const SizedBox(width: 8),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(_d),
            child: const Text('保存'),
          ),
        ],
      ),
    );
  }

  Widget _field(String label, TextEditingController controller, String hint,
      ValueChanged<String> onChanged) {
    return TextField(
      controller: controller,
      style: const TextStyle(fontFamily: 'Consolas', fontSize: 12),
      decoration: InputDecoration(
        isDense: true,
        labelText: label,
        hintText: hint,
        border: const OutlineInputBorder(),
        contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 12),
      ),
      onChanged: (v) => setState(() => onChanged(v)),
    );
  }

  /// Cards are Materials, not decorated boxes: anything with a ListTile inside
  /// needs a real Material ancestor for its background and ink.
  Widget _card(ColorScheme cs, {required List<Widget> children}) {
    return Material(
      color: cs.surfaceContainerHighest.withValues(alpha: 0.35),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(10),
        side: BorderSide(color: cs.outlineVariant.withValues(alpha: 0.5)),
      ),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: children),
      ),
    );
  }
}
