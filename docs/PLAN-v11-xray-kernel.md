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
| 状态/遥测 | 内核提供本地 Unix 套接字 `<state>/xray.sock` 的 `GET /status`（版本、运行时长、节点数、在线用户、最近错误、已加载配置指纹），agent 汇入 components 与概览 |
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
- X3：Xray 内核在清单中为 OpenWrt 提供 lite 变体（与现在 W1nCray lite 相同的构建标签），agent 在 OpenWrt 上选择 lite；OpenWrt 上把内核目录与服务脚本追加进 `/etc/sysupgrade.conf`（固件升级后保留）。
- 验收增加：在测试机上用 Alpine 3.20 与 OpenWrt 23.05 真实 rootfs（chroot + unshare，与 v0.3 同法）跑通「安装 agent → 面板连上 → 安装 Xray 内核 → 服务运行 → agent 重启不影响 Xray → 卸载」，以及 gost 转发与终端。

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
| L3 Xray 内核 | 安装 → 节点用户可连 → agent 重启不断流 → 升级/坏版本回滚 → 卸载 | ✅ | ✅ | ✅（lite） |

每格记录：命令、原始输出摘要、结论；失败项先修再进下一层。L1 Debian 先行（不依赖 v11 代码）。

## 5. 风险与回滚

- 拆分涉及 panel 包大规模重构：逐 WP 合并，每步全量测试；保留 v0.5.3 作为可回滚版本。
- systemd 单元由 agent 写入：只写固定名称的单元文件，内容由 agent 生成，不接受面板传入的路径或命令。
- 迁移中断：只在 landing 用户低峰期执行，并先在测试机演练两次（含回滚）。生产操作需用户逐项同意。
