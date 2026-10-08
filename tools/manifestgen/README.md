# manifestgen

`manifestgen` 生成、签名并校验 W1nCray 的内核签名清单（`kernel/manifest`）。它只在发布机
与 CI 上运行，agent 从不执行它。命令与用法见 `main.go` 顶部注释：

```
manifestgen keygen -out keys/manifest-1.key
manifestgen build  -config kernels.yaml -out unsigned.json [-cache dir] [-sequence N] [-kernels a,b]
manifestgen sign   -key keys/manifest-1.key -in unsigned.json -out manifest.json
manifestgen verify -in manifest.json -default-keys [-min-sequence N] [-agent X.Y.Z]
```

`build` 与 `sign` 都带 `[-no-legacy-gate]`，见下文「0.5.x 兼容闸门」。

完整的 v11 构建描述是 `examples/v11.yaml`（agent 与 Xray 内核来自本机 `dist/`，gost / realm /
frp 来自各自 GitHub Release）。`-kernels xray` 只重建选定的条目，不必重新下载全部上游资产。

## 目标键：`targets` 与 `openwrt_targets`

清单里每个内核条目有两个目标表：

| 清单字段 | 键 | 谁可以选择 |
|---|---|---|
| `targets` | 纯 `os/arch`（`linux/amd64`）；历史清单里还可能是 `os/arch+openwrt` | 所有系统；`+openwrt` 只在 OpenWrt 上 |
| `openwrt_targets` | **只能**是纯 `os/arch` | 只在 OpenWrt 上；其它系统**永不**读取 |

生成器（`manifestgen build`）写入的规则：

- `targets` 的**每一个**键都必须满足 v0.5.2 的旧正则
  `^[a-z0-9]{2,16}/[a-z0-9]{2,16}$`（见 `git show v0.5.2:kernel/manifest/manifest.go`）。
- OpenWrt 专用（lite）构建写进 `openwrt_targets`，键是不带后缀的 `os/arch`，
  与同一个键在 `targets` 里的通用构建并存。
- 配置里**不允许**再出现任何 `+后缀` 键：`targets:`、`openwrt_targets:` 与 `local:` 的
  `target` 都必须是纯 `os/arch`（`config.check` 直接拒绝）。远程 `openwrt_targets:` 与
  `local:` 条目的 `openwrt: true` 都可用。

`examples/v11.yaml` 的 Xray 内核即：

```yaml
    local:
      - {file: dist/W1nCray-xray-linux-amd64.gz,      target: linux/amd64, to: W1nCray-xray}
      - {file: dist/W1nCray-xray-linux-amd64-lite.gz, target: linux/amd64, to: W1nCray-xray, variant: fallbackroots, openwrt: true}
```

## 为什么不是 `linux/<arch>+openwrt`

`+openwrt` 后缀是 v11 引入的，但 **v0.5.2 的 `kernel/manifest/manifest.go` 不认识它**：

- v0.5.2 的 `reTarget = ^[a-z0-9]{2,16}/[a-z0-9]{2,16}$`；
- v0.5.2 的 `Kernel.validate()` 对**任何一个**不匹配的目标键返回 `ErrManifestInvalid`，
  **整份清单被拒**，不是跳过该条目。

于是面板清单里只要有一个 `linux/<arch>+openwrt` 键，生产落地机上跑着的 0.5.x agent 就
一份清单都拿不到：`kernel_install`、`self_update` 全部 `no_manifest`，转发规则也因没有
签名清单被拒（REG3-1，上线阻断项）。

改成 `openwrt_targets` 后，v0.5.2 的解码路径（`sign.go` 的 `json.NewDecoder`，**没有**
`DisallowUnknownFields`）把不认识的字段直接忽略，签名覆盖整棵 JSON 树（`canonical.go`），
所以：

- 新清单在 v0.5.2 上通过校验，内核目录可用；
- 新 agent 仍能拿到 OpenWrt lite 构建；
- 旧清单（`targets` 里的 `+openwrt` 键）继续被识别，已签发的测试清单不必重签。

同一原因也让 v11 的校验**向前兼容**：形如 `os/arch+<未知后缀>`（后缀 `[a-z0-9]{1,16}`）的键
不再导致整份清单被拒，而是被忽略、永不可选，并由 `Manifest.ValidateReport` 报告
（`manifestgen verify` 会打印一行 `note: ignoring target ...`）。其它不合规的键仍按原规则拒绝。
这样将来新增平台后缀时，不会重演「新后缀把旧 agent 全部挡在门外」。

## 0.5.x 兼容闸门（默认开启）

`build` 在写 `unsigned.json` 之前、`sign` 在读入 `unsigned.json` 之后，都会对**最终清单**
跑一次 `checkLegacyV052`（`legacy.go`）。它复刻 v0.5.2 的 `Kernel.validate()`
（`git show v0.5.2:kernel/manifest/manifest.go`；`kernel/manifest` 测试里的
`legacyV052Validate` 是同一份逻辑）：

- 清单至少有一个内核；
- **每个**内核的 `targets` 至少有一个键——空 `targets` 被 v0.5.2 判为 `no targets`；
- **每个** `targets` 键匹配 `^[a-z0-9]{2,16}/[a-z0-9]{2,16}$`，因此不允许任何 `+后缀` 键。

v0.5.2 遇到上述任一情况返回 `ErrManifestInvalid` 并**拒绝整份清单**（不是跳过该条目）。
所以只要配置里有一个只写 `openwrt_targets` 的内核，生成的清单就会让 0.5.x agent 的
`kernel_install`、`self_update` 全部 `no_manifest`——这正是 REG3-1 的另一种形式。
闸门不通过时 `build`/`sign` 直接报错退出，错误信息写明内核名与版本、违规的键，以及
「v0.5.2 会因此拒绝整份清单、旧 agent 将拿不到任何内核」。

闸门**默认开启，不是可关的开关**。只有明确不再需要支持 0.5.x（例如 0.5.x 已下线）时，
才可以用显式命令行参数 `--no-legacy-gate` 跳过它；`build` 与 `sign` 各自都要显式传入：

- 后果：生成的清单会被所有仍在运行的 0.5.x agent **整份拒绝**，它们的 `kernel_install`、
  `self_update` 以及一切依赖签名清单的命令都返回 `no_manifest`，内核目录为空；
  v11 agent 不受影响。
- `verify` 不跑闸门：它校验签名、序列号与时效，不决定发布内容。

## 选择顺序（agent 侧）

`kernel/platform.Info.Candidates()` 给出候选顺序，`kernel/install.selectTarget` 取第一个可用
（存在、非 null、variant 与机器兼容）的构建：

| 系统 | 顺序 |
|---|---|
| OpenWrt | `openwrt_targets["os/arch"]` → `targets["os/arch+openwrt"]`（旧格式）→ `targets["os/arch"]` |
| 其它 | `targets["os/arch"]` |

ARM 还会逐级回退（armv7 → armv6 → armv5），每一级都按上表展开。选中的构建以**纯 `os/arch`
键**记录进安装标记（`<kernels>/<name>/<version>/.installed.json` 的 `target`）。
