# 第三方组件与数据声明

本项目**自己写的代码**（`src/`、`include/`、`ui/`、`tools/`）以 [MIT](LICENSE) 授权：
随便用、随便改、随便分发、商用、闭源再发布都行，只要求保留版权声明与许可原文。

下面这些内容**不是**本项目原创，各自适用上游许可，**不受 MIT 条款覆盖**。

---

## 规则表（`rules/`）

| 文件 | 来源 | 许可 |
| --- | --- | --- |
| `rules/easylist.txt`、`rules/easyprivacy.txt`，以及二者合并后的 `rules/adblock.txt` | [EasyList](https://easylist.to/)、[EasyPrivacy](https://easylist.to/) | CC BY-SA 3.0 / GPLv3（双许可） |
| `rules/optional/adguard-cn.txt` | [AdGuard Filters](https://github.com/AdguardTeam/AdGuardFilters) | GPLv3 |
| `rules/optional/easylistchina.txt` | [EasyList China](https://easylist.to/) | CC BY-SA 3.0 / GPLv3 |
| `rules/optional/cjx-annoyance.txt` | [CJX's Annoyance List](https://github.com/cjx82630/cjxlist) | 见上游仓库声明 |

`rules/adblock.txt` 是 EasyList 与 EasyPrivacy 机械合并的结果（外加少量本项目特有的规则），
合并时保留了上游的许可声明。如果你要把这个文件单独再分发，请遵守上游的 CC BY-SA 3.0 / GPLv3；
程序读取规则文件不构成对规则内容的再许可，二者是分开的。

---

## Wintun（`third_party/wintun/wintun.dll`）

- 来源：[wintun.net](https://www.wintun.net/)，作者 WireGuard LLC
- 许可：**Prebuilt Binaries License**（专有许可，**不是** GPL），全文见
  [`third_party/wintun/LICENSE.txt`](third_party/wintun/LICENSE.txt)
- 关键条款：不得逆向工程、反编译、修改或移除版权声明；再分发仅允许在“随附于仅通过许可 API
  使用该库的软件”这一情形下进行，且必须保留许可文本。本仓库正是按此方式随附 `wintun.dll`
  及其许可证。

**注意**：`netcap-win64.zip` 里也带了一份 `wintun.dll` 与 `wintun-LICENSE.txt`，同样受该许可约束。

---

## Brotli 静态字典（`src/brotli_dictionary.cpp`）

- 来源：RFC 7932 定义的 Brotli 静态字典
- 许可：MIT（Brotli 项目，Google）

---

## Flutter / Dart（仅发布包）

`netcap-win64.zip` 内含 Flutter Windows 运行时（`flutter_windows.dll`、`data/`）。

- 来源：[Flutter](https://flutter.dev/)
- 许可：BSD-3-Clause（Flutter 引擎与 Dart SDK）

---

## 免责声明

本项目包含 TLS 中间人解密、原始套接字抓包、WFP 内核级阻断等能力。
**只在你拥有或已获得明确授权的网络与设备上使用。**
按 MIT 条款，作者不对使用本软件造成的任何后果承担担保或责任。
