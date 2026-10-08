# PLAN v11 — Xray 内核化：agent 单独安装，Xray 由 agent 按需安装/卸载

日期：2026-10-07　状态：执行中
用户原话：「xray 和 agent 还是不够独立，我希望 xray 像其它内核一样默认也不安装，初次安装默认就只安装 agent，当需要安装或者卸载时由 agent 控制」

## 1. 现状（证据）

- 单一程序：`cmd/root.go:64-110` `run()` → `panel.New` 同时构建 Xray-core、Xboard 节点控制器、agent。v10 已把两者的**生命周期**解耦（xray 重建不影响 agent），但仍是同一个二进制、同一个进程：装 agent 必然带上 Xray（约 78 MiB），agent 自升级必然重启 Xray。
- 「Xray 部分」不只是 Xray-core：`app/dispatcher`（包装 Xray 内部 DefaultDispatcher）+ `common/limiter` 实现 Xboard 用户的**限速、设备数限制、在线 IP 统计、断开连接**，必须与 Xray-core 同进程【已验证：`app/dispatcher/dispatcher.go:1-8`、`common/limiter/limiter.go:1-3`、`core/core.go:123-128`】。官方 Xray 二进制做不到这些（只能经 gRPC API 加删用户、读流量）。
- 现有内核（gost/realm/frp）：签名清单 + `agent/kernelx` 下载校验安装，`agent/supervisor` 作为 agent 子进程运行；agent 重启时子进程随之结束（`agent/supervisor/supervisor.go:14-22`：孤儿进程无法接管，只能终止）。
- 期望状态已有 `kernels: [{name, version}]`（`agent/spec/spec.go` Desired.Kernels），已有命令 kernel_install / kernel_remove / kernel_rollback / component_restart（`agent/opscmd/kernel.go`）。
- 生产现状：只有 landing-01 一台机器；转发实例 0 个（`v2_agent_instance` 为空，2026-10-07 只读查询）。用户其它服务器仍运行 W1nCray v0.3 单机模式（无 agent）。

## 2. 方案

### 2.1 拆成两个程序（同一仓库）

| 程序 | 内容 | 安装方式 |
|---|---|---|
| `W1nCray`（agent） | 面板连接（HTTP+WS）、终端、文件、内核管理、转发（gost/realm/frp）、自升级、遥测 | install.sh 一键安装；**不链接 Xray-core** |
| `W1nCray-xray`（Xray 内核） | Xray-core + 限速/设备数 dispatcher + Xboard 节点控制器（用户同步、流量/在线上报、机器模式节点发现）+ 配置文件监听重载 | 由 agent 按签名清单下载安装（清单内核名 `xray`），**默认不安装** |

选择「自建 Xray 内核」而不是官方 Xray 二进制的理由：限速、设备数限制、在线 IP、踢连接依赖进程内 dispatcher，官方二进制无法实现（证据见 §1）。否决官方二进制 + gRPC API 方案。

### 2.2 Xray 内核作为独立 systemd 服务

- agent 安装 xray 内核后写入 `/etc/systemd/system/W1nCray-xray.service`（`ExecStart=<内核目录>/xray/<版本>/W1nCray-xray run -c <config.yml>`，`Restart=always`），`systemctl enable --now`。
- 与 gost/realm 作为 agent 子进程不同：**Xray 是用户流量的核心，不能随 agent 重启/自升级而中断**，所以用独立服务；agent 重启、升级、崩溃都不影响 Xray。
- 卸载：`systemctl disable --now`，删除服务文件和内核文件；**保留配置**（config.yml 与受管文件），重新安装即恢复。
- 升级/回滚：kernelx 保留上一版本；切换后检查健康（状态接口 30 s 内报告 running），失败自动回滚到上一版本并重启。
- 无 systemd 的系统：退回由 agent supervisor 作为子进程运行（与 gost 相同），面板提示「此系统 Xray 会随 agent 重启」。

### 2.3 agent ↔ Xray 内核的交互

| 需求 | 方式 |
|---|---|
| 配置 | 内核读 config.yml（Xray 部分）与受管文件；机器模式所需的面板地址/机器 ID/令牌/节点控制器设置只读取自 agent.yml（与现在相同的字段） |
| 应用受管文件前的校验 | agent 执行已安装的 `W1nCray-xray check-staged --dir <暂存目录>`，输出 JSON 错误（原进程内 CoreValidator 移到内核） |
| 重载 | 内核自身监听配置文件变化（沿用 v10 指纹去重）；files_apply 写入后等待内核状态报告新指纹已加载 |
| 状态/遥测 | 内核提供本地 Unix 套接字 `/run/W1nCray/xray.sock`（D1：原先在配置目录，SELinux enforcing 下 `init_t` 不能在 `etc_t` 里创建它）的 `GET /status`（版本、运行时长、节点数、在线用户、最近错误、已加载配置指纹），agent 汇入 components 与概览 |
| Xboard 节点通信 | 仍由内核直接与面板通信（用户、流量、在线 IP、WS），与现在一致 |

### 2.4 安装/卸载由谁触发

- 面板「维护 → 内核」页：Xray 与 gost/realm 并列，可安装、卸载、升级、回滚、重启；卸载前若机器绑定了节点，提示「卸载后这 N 个节点将停止服务」。
- 给机器绑定节点时：若 Xray 未安装，面板把 `xray` 加入该机器期望状态的 kernels，agent 自动安装并启动（Xray 标签显示「正在安装 Xray…」）。
- 全新安装（install.sh）：只装 agent，不装 Xray。

### 2.5 转发引擎去掉 xray

agent 不再链接 Xray-core，转发规则/实例只用 gost、realm（frp 用于反向代理）。`engine: xray` 的实例由面板和 agent 校验拒绝并给出原因；`auto` 不再选择 xray。生产中没有任何实例（§1），无迁移负担。`vless_enc` 隧道安全模式随之移除。

### 2.6 迁移（已有机器）

- **landing-01（agent 模式，v0.5.x 单一程序）**：不需要改旧版本代码——
  1. 面板先对 0.5.x agent 下发 `kernel_install {name:xray}`：0.5.x 的 kernelx 是通用的，只下载、校验、解压到内核目录，不运行；
  2. 再下发 self_update 到 0.6.0：新 agent 启动后**先完成自升级确认**（面板应答），确认之后才写入并启动 `W1nCray-xray.service`。自动回滚只可能发生在确认之前，此时 Xray 服务尚未启动，回滚到 0.5.x（进程内 Xray）不会与 Xray 服务争端口；
  3. Xray 中断 = 旧进程退出到新服务启动（秒级），不含下载时间。面板「升级到 0.6」按钮自动按 1→2 编排。
- **用户其它 v0.3 单机服务器（无 agent）**：`install.sh update` 检测到已有 Nodes 配置时，安装 agent + Xray 内核服务两者（Xray 内核由 install.sh 直接按发布地址下载并校验 SHA256SUMS），行为与现在一致；之后可按需绑定面板。
- 新 agent 首次启动若发现 config.yml 有节点但 Xray 内核未安装（例如手工替换二进制），自动安装 Xray 内核并启动，日志明确说明。

## 2.7 Alpine（OpenRC）/ OpenWrt（procd）

现状（2026-10-07 核查）：
- 【已验证，v0.3】install.sh 的 OpenRC / procd 服务后端、架构与 MIPS 浮点检测、busybox 下载与校验，在测试机上以真实 rootfs（Alpine 3.20.3、OpenWrt 23.05.5 x86-64）chroot + unshare 验证过（PLAN-v5 V6）。当时程序只有 Xray 节点功能。
- 【代码有、未实测】agent 自升级在无 systemd 时以 setsid 脱离进程（`agent/selfupdate/respawn_unix.go:35-48`），回滚后依赖 OpenRC/procd 自身重拉（`ready_linux.go:87-111`）；内核下载不使用 /tmp（OpenWrt 的 /tmp 占内存）；平台探测区分 musl/glibc（`kernel/platform/platform.go:33-85`）。
- 【未验证】v0.4 起的 agent 功能（面板链接、终端、文件管理、内核下载、转发、自升级）只在 Debian（systemd）上实测过。
- 内核覆盖：gost 全架构（Go 静态）；realm 只发 musl 版（Alpine/OpenWrt 可用，但缺 386/armv5/loong64/riscv64）；frp 缺 386/armv6。

本期要求：
- X2：Xray 内核服务除 systemd 外，同样提供 OpenRC（`/etc/init.d/W1nCray-xray`，supervise-daemon 守护）与 procd（`/etc/init.d/W1nCray-xray`，procd respawn）两种后端，写法与 install.sh 现有后端一致；三者都没有时才退回 agent 子进程。
- X3：Xray 内核在清单中为 OpenWrt 提供 lite 变体（与现在 W1nCray lite 相同的构建标签），agent 在 OpenWrt 上选择 lite；OpenWrt 上把内核目录与服务脚本追加进 `/etc/sysupgrade.conf`（固件升级后保留）。lite 构建写在内核的 `openwrt_targets` 字段（纯 `os/arch` 键），**不写** `linux/<arch>+openwrt` 键，理由见 §2.8。
- 验收增加：在测试机上用 Alpine 3.20 与 OpenWrt 23.05 真实 rootfs（chroot + unshare，与 v0.3 同法）跑通「安装 agent → 面板连上 → 安装 Xray 内核 → 服务运行 → agent 重启不影响 Xray → 卸载」，以及 gost 转发与终端。

### 2.8 清单目标键：`openwrt_targets` 与 0.5.x 兼容（F10，上线阻断项）

v11 最初把 OpenWrt lite 构建放在 `targets` 的 `linux/<arch>+openwrt` 键上。生产落地机跑的是
**v0.5.2**，它的 `kernel/manifest/manifest.go` 只认 `^[a-z0-9]{2,16}/[a-z0-9]{2,16}$`，并且对
**任一**不合规目标键**整份清单拒绝**（`git show v0.5.2:kernel/manifest/manifest.go`）。于是
面板清单（sequence 8/9/10）里的 `+openwrt` 键让老机器一份清单都拿不到：`kernel_install` 与
`self_update` 全部 `no_manifest`，gost/realm/frp 转发规则也因没有签名清单被拒 —— PLAN §2.6 的
两步迁移第 1 步就走不通（REG3-1）。

定稿：

| 清单字段 | 键 | 选择者 |
|---|---|---|
| `targets` | 纯 `os/arch`；历史清单的 `os/arch+openwrt` 继续被识别 | 所有系统；`+openwrt` 只在 OpenWrt |
| `openwrt_targets` | 纯 `os/arch`（无后缀） | 只在 OpenWrt；其它系统永不读取 |

- 选择顺序（`kernel/platform.Info.Candidates` → `kernel/install.selectTarget`）：OpenWrt 上
  `openwrt_targets["os/arch"]` → `targets["os/arch+openwrt"]`（旧格式）→ `targets["os/arch"]`；
  非 OpenWrt 只有 `targets["os/arch"]`。ARM 仍逐级回退。
- 0.5.x 用 Go 默认 `json.Decoder`（`sign.go`，无 `DisallowUnknownFields`）解码进结构体，未知字段
  `openwrt_targets` 被忽略；签名覆盖整棵 JSON 树（`canonical.go`），新增字段同样被签名。所以新清单
  在 v0.5.2 上通过校验、内核目录可用。
- v11 的 `Validate` 同时向前兼容：`os/arch+<未知后缀>`（后缀 `[a-z0-9]{1,16}`）不再整份拒绝，而是
  忽略该目标（不可被选中）并由 `Manifest.ValidateReport` 报告；其它不合规键仍按原规则拒绝。
- `tools/manifestgen` 不再生成任何 `+后缀` 键（配置里出现即拒绝），OpenWrt 构建走
  `openwrt_targets:` 或 `local` 条目的 `openwrt: true`；`examples/v11.yaml`、`tools/manifestgen/README.md`
  与 `docs/AGENT.md` §13.8.2 同步。
- 验收（F10）：单元测试内置 v0.5.2 规则复刻，断言新格式通过、旧格式被拒；真实 v0.5.2 在 debian13
  上接受新清单（无 `manifest invalid`、`kernel_list` catalog 非空）；v11 在 openwrt2410 上从
  `openwrt_targets` 选中 lite 构建（核对下载资产名与 sha256）。

## 3. 工作包

| WP | 内容 | 仓库 |
|---|---|---|
| X1 | 拆程序：`cmd/w1ncray-xray`（内核：run / check-staged / status / version）；agent 主程序不再导入 core、node、app/dispatcher、corehost、driver/xray；panel 包拆为 agent 守护与 xray 节点服务两部分 | W1nCray |
| X2 | agent 侧 Xray 服务管理：安装/卸载/升级/回滚/重启（systemd 单元与子进程两种模式）、期望状态 kernels 含 xray 时自动确保、状态套接字采集、files 校验改为调用内核 CLI、首启迁移 | W1nCray |
| X3 | 自升级到 v0.6 的迁移步骤（先装 Xray 内核再切换）；install.sh（全新只装 agent；update 识别单机节点配置）；release/build.sh 产出两个程序；manifestgen 清单加入 xray 内核条目 | W1nCray |
| X4 | 面板：内核页加入 Xray（卸载提示绑定节点）、绑定节点自动把 xray 加入期望 kernels、Xray 标签「未安装/安装中」状态、转发引擎去掉 xray、概览显示 Xray 服务状态 | W1nCBoard |

## 4. 验收

1. 全新测试机：install.sh 只装 agent（无 Xray 进程、无 W1nCray-xray 服务）；面板内核页一键安装 Xray → 服务运行；绑定节点后用户可连；卸载 → 服务与文件消失、配置保留；再安装恢复。
2. agent 重启 / 自升级期间，经 Xray 节点的长连接不中断。
3. Xray 内核升级失败（故障注入的坏版本）自动回滚。
4. 测试机 machine 3（v0.5.3-dev 单一程序）经面板自升级到 v0.6.0：Xray 中断仅为秒级，节点、受管文件、转发全部恢复；回滚路径可用。
5. 受管文件「保存并生效」仍经内核校验，错误配置被拒绝并显示原因。
6. 转发（gost/realm）全部回归；engine=xray 被拒绝并说明原因。
7. Go 全量测试（含 Linux -race）、phpunit、前端自测、真实浏览器桌面 + 375px。

## 4.1 内核测试矩阵（gost / realm / frp / xray × 三种系统）

现状（2026-10-07 核查）：三个外部内核都有「真实二进制」端到端测试（`driver/gost/e2e_*`、`driver/realm/e2e_test.go`、`driver/frp/e2e_*`，构建标签 `e2e`），但需要环境变量指定二进制，**此前所有回归都跳过了它们**；面板级实测只覆盖了 gost（直连 + TLS/WSS/gRPC 隧道）。realm、frp 从未用真实二进制跑过。

| 层 | 内容 | Debian (systemd) | Alpine 3.20 (OpenRC) | OpenWrt 23.05 (procd) |
|---|---|---|---|---|
| L1 驱动 | `go test -tags e2e` 真实二进制（各内核自己的全部 E2E 用例） | gost / realm / frp | 同左（musl 环境，二进制取清单中该平台的资产） | 同左 |
| L2 agent | 经面板下发：gost 直连 + tls/wss/grpc 隧道；realm 直连（TCP/UDP）+ realm 隧道（ws）；frp 反向代理（portal/bridge，经原始实例）；崩溃自动重启；agent 重启后恢复 | ✅ 必测 | ✅ 必测 | ✅ 必测 |
| L2b 内核生命周期 | **gost / realm / frp / xray 四个内核逐一**：经面板安装 → 版本与文件就位 → 运行 → 升级到另一版本 → 回滚 → 卸载（文件与服务清除、配置保留、正在使用时的拒绝/提示）→ 再安装恢复；断网/校验失败时安装被拒且不留残留 | ✅ 必测 | ✅ 必测 | ✅ 必测 |
| L3 Xray 内核 | 安装 → 节点用户可连 → agent 重启不断流 → 升级/坏版本回滚 → 卸载 | ✅ | ✅ | ✅（lite） |

每格记录：命令、原始输出摘要、结论；失败项先修再进下一层。L1 Debian 先行（不依赖 v11 代码）。

## 4.2 系统兼容矩阵（用户要求：多系统实测；有把握的同类可不测）

### 哪些差异真正影响我们（代码证据）
- **C 库无关**：W1nCray、W1nCray-xray、gost、frp 均为 Go 静态编译（`release/build.sh` `CGO_ENABLED=0`），realm 用 musl 静态版（清单 variant `musl-full`）——glibc 版本、musl 与否都不影响运行。
- **R1 init 及版本**：install.sh 三套后端（systemd / OpenRC supervise-daemon / procd，`install.sh:405-565`）；自升级 watchdog 用 `systemd-run --no-block`（`agent/selfupdate/restart.go:173-207`），`--no-block` 需 systemd ≥ 220，**CentOS 7 是 219** → 走 setsid 回退路径，必须实测；v11 新增 Xray 内核服务同样涉及三套后端。
- **R2 SELinux**（CentOS Stream 9/10 默认 enforcing）：内核二进制放在 state 目录（/etc/W1nCray 下），被 init_t 执行可能被拒；agent 写 systemd 单元的标签。必须在开启 enforcing 的真机/虚拟机实测。**D1 已实测并修复**：`etc_t` 的内核二进制被 systemd 以 `init_t` 启动，`init_t` 不能在 `etc_t` 目录里创建状态套接字（AVC `sock_file create`）；修复 = 状态套接字移到 `/run/W1nCray`（`RuntimeDirectory=`）+ 内核树标为 `bin_t`（`agent/selinux`，semanage 持久规则、chcon 回退）。CentOS 7 / Stream 9 / Stream 10 三台 enforcing 虚拟机实测通过，无新 AVC（docs/AGENT.md §13.7）。
- **R3 CA 证书与 TLS**：Go 使用系统根证书；CentOS 7、Debian 9 的证书包较旧 → 访问 GitHub / 面板 HTTPS；lite 版内置备用根证书（构建标签 fallbackroots）。
- **R4 内核版本**：CentOS 7 为 3.10；Go 运行时、PTY、realm 的特性需在真内核上跑（chroot 用的是宿主内核，测不出来）。
- **R5 下载与工具**：curl/wget（busybox/uclient-fetch）、sha256sum、gunzip、mktemp（`install.sh:241-377`）。
- **R6 OpenWrt 系**：procd 版本、busybox 配置、包管理（opkg → 25.x 的 apk，install.sh 不装包，影响小）、防火墙 fw3(iptables)/fw4(nftables)——**转发端口在 WAN 侧默认被防火墙拦截**（新发现，见 4.3）、/tmp 为 tmpfs、sysupgrade 保留目录。

### 选型（每个风险点取最旧 + 最新 + 有特殊改动的；其余标注「同类推断」）
| 系统 | 方式 | 理由 |
|---|---|---|
| CentOS 7 (systemd 219, 内核 3.10) | KVM 虚拟机 | R1 最旧、R3、R4 |
| CentOS Stream 9 / 10 (SELinux enforcing) | KVM 虚拟机 | R2 |
| Debian 9 (systemd 232) | KVM 虚拟机 | R1、R3 旧 |
| Debian 13 | KVM 虚拟机 | 最新 |
| Ubuntu 18.04 (systemd 237) | KVM 虚拟机 | Ubuntu 最旧 |
| Ubuntu 26.04 | KVM 虚拟机 | 最新 |
| Debian 10/11/12、Ubuntu 20.04/22.04/24.04 | 同类推断 + chroot 冒烟 | systemd 241–255 之间无我们用到的行为差异；Debian 12 已在测试机实测 |
| Alpine 3.21 / 3.24 (OpenRC) | KVM 虚拟机 | 最旧 + 最新；3.20 已 chroot 实测 |
| Alpine 3.22 / 3.23 | chroot 冒烟 | 同类推断 |
| OpenWrt 21.02 (fw3) / 23.05 (fw4) / 24.10 / 最新 | KVM 虚拟机 (x86-64 官方镜像) | R6 |
| ImmortalWrt 24.10、iStoreOS、KWRT | KVM 虚拟机 (x86-64 官方镜像) | 魔改系：默认软件包、防火墙、密码、存储布局不同 |
| Lean's LEDE | 无官方二进制，仅源码 | 若时间允许自行编译 x86-64 实测；否则按代码推断（procd + fw4/fw3，同 OpenWrt） |
| MIPS / ARM 路由器 | qemu 模拟 OpenWrt malta(mipsel) / armvirt | 只验证功能，不测性能 |

### 每个系统测什么
L1 内核驱动测试（chroot，快）；L2：install.sh 全新安装 agent → 服务运行 → 连上测试面板 → 安装 gost/realm/frp → 直连与隧道流量 → 终端 → 文件 → agent 重启/自升级；L3（v11 完成后）：Xray 内核安装/运行/卸载、agent 重启不断流。

## 4.3 已发现的新问题
- OpenWrt 系默认防火墙拒绝 WAN 入站：转发规则在路由器上监听的端口，用户从外网连不上。方案：agent 在 OpenWrt 上为实例监听端口维护一个专用的 fw4/fw3 规则组（`W1nCray_<实例>`），实例删除即移除；面板转发规则显示「已在路由器防火墙放行」。实测后定稿。

**定稿（D2）**：实现见 `agent/fwopen`，规则为**每个实例一条** UCI `config rule`，section 名 `w1ncray_<实例id>`（UCI section 名只允许 `[A-Za-z0-9_]`，故 `-`→`_d`、`_`→`__`），字段 `name 'W1nCray <实例名>'`、`src wan`、`proto`（按 `network`，可为 `tcp udp`）、`dest_port`（支持范围）、`target ACCEPT`；只放行对外监听的实例（forward/tunnel_entry/reverse_portal 的 `listen`，tunnel_exit 的 `tunnel.listen`；回环地址、`enabled:false`、reverse_bridge 不放行）。本地开关 `agent.yml` `Firewall.AutoOpen`（OpenWrt 缺省 true，其它系统恒 false，本期只实现 OpenWrt），经 `hello.policy.firewall.auto_open` 与实例状态 `firewall_open` 上报；防火墙失败只告警、不回滚实例。实测（D2 实验室）：OpenWrt 21.02.7（fw3/iptables，`/etc/init.d/firewall reload`）、OpenWrt 24.10.8（fw4/nftables，`fw4 reload`）、iStoreOS 三台，规则分别出现在 `uci show firewall` 与 `iptables -S`/`nft list ruleset`；宿主经 QEMU 端口转发访问成功，删除实例后规则与可达性同时消失。**加固（R1-14 / R1-15，F5）**：`uci commit` 成功后重载失败会有限次重试（最多 3 次，退避 1s/2s，重载循环总时长上限 20s）；仍失败则返回 `*fwopen.ReloadError`，reconciler 在实例状态（`firewall_open=false`）与报告消息里写明「规则已保存、尚未生效」，下一次成功重载即生效——不新增面板协议字段。端口声明解析失败的实例不再静默跳过：记一条含实例 id 的 warn，并把被跳过的条目（id + 原因）随 Sync 结果返回，reconciler 写进报告消息。

## 5. 风险与回滚

- 拆分涉及 panel 包大规模重构：逐 WP 合并，每步全量测试；保留 v0.5.3 作为可回滚版本。
- systemd 单元由 agent 写入：只写固定名称的单元文件，内容由 agent 生成，不接受面板传入的路径或命令。
- 迁移中断：只在 landing 用户低峰期执行，并先在测试机演练两次（含回滚）。生产操作需用户逐项同意。
