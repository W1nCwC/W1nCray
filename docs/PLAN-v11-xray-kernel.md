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

- **landing-01（agent 模式，v0.5.x 单一程序）**：面板先发布 xray 内核到清单；agent 升级到 v0.6.0 的流程改为：旧进程仍在服务时，新 agent 的升级步骤先下载并安装 xray 内核（不启动），提交升级时依次「停止旧进程 → 启动 Xray 服务 → 启动新 agent」，Xray 中断时间 = 一次重启（秒级），不含下载时间。自动回滚仍有效（回到 v0.5.x 单一程序，Xray 服务被停用）。
- **用户其它 v0.3 单机服务器（无 agent）**：`install.sh update` 检测到已有 Nodes 配置时，安装 agent + Xray 内核服务两者（Xray 内核由 install.sh 直接按发布地址下载并校验 SHA256SUMS），行为与现在一致；之后可按需绑定面板。
- 新 agent 首次启动若发现 config.yml 有节点但 Xray 内核未安装（例如手工替换二进制），自动安装 Xray 内核并启动，日志明确说明。

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

## 5. 风险与回滚

- 拆分涉及 panel 包大规模重构：逐 WP 合并，每步全量测试；保留 v0.5.3 作为可回滚版本。
- systemd 单元由 agent 写入：只写固定名称的单元文件，内容由 agent 生成，不接受面板传入的路径或命令。
- 迁移中断：只在 landing 用户低峰期执行，并先在测试机演练两次（含回滚）。生产操作需用户逐项同意。
