// The filter-list list itself: how the remembered choice turns into the
// `--rules` / `--rules-extra` arguments the proxy is started with.
import 'package:flutter_test/flutter_test.dart';
import 'package:netcap_ui/src/rule_lists.dart';

void main() {
  const builtin = r'C:\app\rules\adblock.txt';
  const userPath = r'C:\Users\Czr\AppData\Roaming\netcap-ui\my-rules.txt';

  test('the remembered choice survives a round trip', () {
    final lists = RuleLists(
      builtinPath: builtin,
      userRulesPath: userPath,
      builtinEnabled: false,
      userRulesEnabled: true,
      extra: <RuleList>[
        RuleList(path: r'C:\lists\easylist-cn.txt'),
        RuleList(path: r'C:\lists\annoyances.txt', enabled: false),
      ],
    );
    final back = RuleLists.fromJson(
      lists.toJson(),
      builtinPath: builtin,
      userRulesPath: userPath,
    );
    expect(back.builtinEnabled, isFalse);
    expect(back.userRulesEnabled, isTrue);
    expect(back.extra.length, 2);
    expect(back.extra.first.path, r'C:\lists\easylist-cn.txt');
    expect(back.extra.last.enabled, isFalse);
  });

  test('a second entry for the built-in file folds back into its switch', () {
    // This is what the user saw: `--rules <the bundled file>` used to leave
    // two rows for one file.
    final back = RuleLists.fromJson(
      <String, Object?>{
        'builtin': false,
        'extra': <Object?>[
          <String, Object?>{'path': r'C:\app\rules\adblock.txt', 'enabled': true},
          <String, Object?>{'path': r'C:\lists\other.txt'},
        ],
      },
      builtinPath: builtin,
      userRulesPath: userPath,
    );
    expect(back.builtinEnabled, isTrue, reason: 'the file still has to load');
    expect(back.extra.length, 1);
    expect(back.extra.single.path, r'C:\lists\other.txt');
  });

  test('two spellings of one path are the same file', () {
    expect(RuleLists.samePath(r'C:\A\b.TXT', r'c:/a/B.txt'), isTrue);
    expect(RuleLists.samePath(r'C:\a\b.txt', r'C:\a\c.txt'), isFalse);
    expect(RuleLists.samePath('', ''), isFalse);
  });

  test('the base list is the built-in one, otherwise the first enabled extra', () {
    final off = RuleLists(
      builtinPath: builtin,
      userRulesPath: userPath,
      builtinEnabled: false,
      extra: <RuleList>[
        RuleList(path: r'C:\lists\a.txt'),
        RuleList(path: r'C:\lists\b.txt'),
      ],
    );
    expect(off.rulesPath, r'C:\lists\a.txt');
    expect(off.extraPaths, <String>[r'C:\lists\b.txt', userPath]);
    expect(off.anyEnabled, isTrue);

    final on = RuleLists(
      builtinPath: builtin,
      userRulesPath: userPath,
      extra: <RuleList>[RuleList(path: r'C:\lists\a.txt')],
    );
    expect(on.rulesPath, builtin);
    expect(on.extraPaths, <String>[r'C:\lists\a.txt', userPath]);
    expect(on.summary, contains('内置'));
  });

  test('nothing switched on means the proxy may not start', () {
    final none = RuleLists(
      builtinPath: builtin,
      userRulesPath: userPath,
      builtinEnabled: false,
      userRulesEnabled: false,
    );
    expect(none.anyEnabled, isFalse);
    expect(none.extraPaths, isEmpty);
  });

  test('counting a list skips comments, section headers and blank lines', () {
    const text = '! a comment\n[Adblock Plus 2.0]\n\n||ads.example^\n'
        'example.com##.ad-box\n   \n';
    expect(RuleLists.countRules(text), 2);
  });
}
