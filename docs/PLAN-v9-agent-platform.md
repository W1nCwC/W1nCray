# PLAN v9 — agent 作为服务器管理平台

起草 2026-10-06。输入：用户新需求 + `.dsh/out/ANALYSIS-go.md` / `ANALYSIS-php.md`（现状缺口分析）。传输契约：`docs/WS-PROTOCOL.md`。

## 0 用户要求（原话要点）
1. agent **凌驾于内核之上**：拥有服务器管理功能；xray/realm/gost/frp **按 agent 下发按需部署**。
2. `config.yml` 是 **xray 内核**的配置，不是 agent 的；面板能直接设置 config.yml、出站(out)、入站(in)、路由(router)、DNS，以及 geoip/geosite，agent 同步到服务器。
3. agent 与面板保持 **WebSocket 实时连接**，上报负载、设备信息（CPU、内存、带宽、磁盘、各组件运行情况）。
4. **xray 部分启用后**才单独上报节点信息、拉取用户；realm/gost/frp 由 agent 采集后回传面板。
5. 面板可通过 agent：**远程终端、下发命令、修改文件、下发升级**；远程**安装/卸载/查看内核**。

## 1 架构决定
| 决定 | 内容 | 理由（证据） |
|---|---|---|
| D1 分离配置 | 新增 `agent.yml`（agent 自己：面板链接、token、本地策略、终端/文件开关、模块开关）。`config.yml` 归 xray。旧单文件（含 `Agent:` 块）继续兼容；若同目录存在 `agent.yml` 则以它为准。面板的文件同步**只会写 xray 受管文件，永远不碰 `agent.yml`** | Go 分析 §4.6：`Agent:` 写坏会静默降级；分离后面板编辑不可能让 agent 失联 |
| D2 一条常驻 WS | agent 主动 `wss://…/w1ncray-ws`，请求头认证；承载遥测、命令、终端、文件操作、升级；HTTP 轮询保留为兜底并继续承载 desired/ack/blob | 契约见 WS-PROTOCOL；PHP 分析 §4：现有 `/ws` 进程被改成拒绝一切，且生产老节点仍在用，**不碰它**，新开独立进程与路径（纯新增） |
| D3 xray 模块化 | 面板按机器下发 `modules.xray_nodes`；启用后 agent 才启动节点控制器（拉用户、上报节点）。其余内核由 agent 的驱动统计采集后随 `components` 回传 | 需求 4；现有 `driver.Stats` 可用 |
| D4 受管文件同步 | desired 增加 `files` 段：`[{name, sha256, size, kernel}]`，**内容不进 desired**，agent 用机器 token 从面板 HTTPS 拉取 blob；落盘流程 = 暂存 → 校验（复用 `core.CheckFiles`）→ 原子替换 → 重载 xray → 健康窗口 → 确认或回滚到 last_good | PHP 分析 §3：大文件不能进加密的 revision snapshot；Go 分析 §7.1 |
| D5 白名单文件名 | 受管 xray 文件只有固定名字：`config.yml, route.json, custom_inbound.json, custom_outbound.json, dns.json, geoip.dat, geosite.dat`，目录固定为 xray 配置目录；其他路径只能走"文件操作"并受 roots 限制 | 缩小爆炸半径 |
| D6 内核管理 | 把已存在但无人调用的 `kernel/install` 的 `List/Remove/Rollback` 暴露为命令 `kernel_*`；report 里的内核清单改结构化；不删除正在使用的版本 | Go 分析 §3、§7.2 |
| D7 升级 | `self_update`：目标版本必须出现在**已签名清单**的 `agent` 条目（沿用同一信任根）；下载校验 → 原子替换 → 重启 → 新进程在 N 分钟内未能重连面板则自动回滚到旧二进制 | 不引入新信任根；回滚防变砖 |
| D8 终端 | `creack/pty`（纯 Go）；独立包 `agent/terminal`；**本地开关 `Terminal.Enabled`，默认开**（用户决定）；要关闭在机器本地设 `Terminal.Enabled: false`，安装命令/`link` 带 `--noterminal`；面板侧签发终端 ticket 仍须管理员重输密码；每机 ≤ 2 会话、空闲 15 min 超时、最长 4 h；审计只记元数据（谁/何时/时长/字节数），**不记录终端内容**；浏览器侧用一次性 ticket | Go 分析 §5/§7.3：`noshell_test.go` 与 AGENT.md 的安全模型明确否定终端——这是**有意识的模型变更**，必须在文档与测试里显式记录，并把允许 shell 的代码限定在 `agent/terminal` 包 |
| D9 文件操作 | `file_*` 命令限定在本地策略 `Files.Roots`（默认：xray 配置目录、agent 状态目录）；`Files.Unrestricted` 需本地显式开启；拒绝路径穿越/符号链接逃逸/非普通文件 | 同上 |
| D10 监控 | HostInfo + Telemetry（契约 §3）；带宽按网卡两次采样求差；面板存最新值 + 30 s 降采样历史 7 天 | Go 分析 §1：CPU/内存/磁盘已有，设备信息与带宽缺 |

## 2 分期与工作包（前后端并行，全部派给 dsh，我验收）
**阶段 1 — 通道 + 监控**（本期先做）
- G1 (Go) `agent/ws`：WS 客户端、重连、`hello/ping`、命令分发（复用既有命令处理）、HTTP 兜底；`agent.yml` 分离与加载。
- G2 (Go) `agent/telemetry`：HostInfo / Telemetry / Components 采集（Linux 优先，其他平台降级）。
- P1 (PHP) `w1ncray:ws-server`：独立 Workerman 进程；agent/browser 两种角色；注册表；hello/telemetry/components 落库；`hint`/`cmd` 推送；浏览器 ticket 与订阅转发；迁移（样本表、state 列）。
- P2 (PHP+JS) 管理 API（遥测最新值/历史、ticket）与页面「概览」标签（设备信息 + 实时仪表 + 曲线；无外部库，canvas 折线图）。
**阶段 2 — 内核/升级/文件**
- G3 内核命令与结构化清单；G4 自升级（清单 `agent` 条目、manifestgen 扩展、回滚）；G5 受管文件同步与重载/回滚；
- P3 内核/升级 API+页面；P4 受管文件存储、desired 集成、编辑器页面（JSON 校验、geo 上传）。
**阶段 3 — 终端与文件管理**
- G6 `agent/terminal` + `file_*` 命令 + 本地策略；P5 终端中继、ticket、审计；页面终端（vendor xterm.js）+ 文件管理。

## 3 验收原则（沿用本项目的教训）
- 每个 WP：dsh 自己跑测试并贴原始输出，**我独立复跑**，并在真实栈上做一次端到端（真实登录、真实 agent，不手写登录态、不依赖 mock）。
- 安全相关（终端、文件、升级）的威胁用例必须有测试：未授权、越权路径、重放 ticket、超限、断线清理。
- 生产变更：先备份 → 纯新增优先 → 验证 → 记录回滚；新独立进程部署前征得用户同意（涉及面板 compose 与反代）。

## 4 风险
- PTY 库在 mips/loong64 等的纯 Go 编译性（Go 分析 §8-9）→ 构建矩阵验证，不可用的架构自动禁用终端并在 `hello.capabilities` 里不声明。
- WS 单进程注册表（PHP 分析 §4.3）→ 先 `count=1`，注册表键放 Redis 以便将来扩展。
- 终端是高权限通道：默认关、可审计、可单机关闭；面板被攻破 ≈ 开了终端的机器被攻破（与 nezha/komari 同级）——需要用户知情。
