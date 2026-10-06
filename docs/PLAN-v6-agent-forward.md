# 方案 v6（修订版）：W1nCray Agent —— 面板控制、多内核编排

> 日期：2026-10-05 · 状态：**待用户确认，未动工** · 基线：HEAD `b1a104f`（v0.3.0 之后），Xray-core v1.260327.0
> 修订原因：用户提出新的总体架构——**Xboard 只当 dashboard，W1nCray 作为 agent，由 agent 按面板设置决定部署哪些内核、用哪个内核做什么**（类 ForwardX / Zelay / Relay Panel 的形态）。本版整体取代同名文件的首版（首版是"全部塞进 Xray 进程"的路线）。
> 依据：五份并行调研——面板侧、Xray 内核侧、gost/frp/realm 对标、同类项目实现、内核可落地性矩阵。**子智能体的 Write 工具被限制，五份原报告未落盘，其结论以证据表形式留存于本文**；标【主智能体已复核】的条目由我在仓库/源码中亲自核对，其余为子智能体的源码或实验结论，对应阶段动工前会抽查。

## 1. 需求

1. **Agent**：面板远程管理后端，前端能直接修改后端配置并看到应用结果（含离线、回滚、审计）。
2. **多内核编排**：agent 根据面板下发的"期望状态"，决定安装/升级哪些内核、各内核运行哪些实例；Xray（节点）只是其中一个内核。
3. **转发能力（对标 gost / frp / realm）**：直接转发、ws/wss/TLS 隧道、反向代理（NAT 后设备回连）、发送/接收 PROXY protocol。
4. **Xboard 当 dashboard**：Xboard 现有"服务器管理"一般，由 W1nCray agent 配合面板插件重构。
5. 背景：OpenWRT 等无公网设备也要能被用户连上（本会话前文）。

## 2. 证据

### 2.1 同类项目怎么做（调研 5 个：ForwardX、Zelay、Relay Panel、flux-panel、RelayDeck）

| # | 结论 | 档位 |
|---|---|---|
| S1 | 接入方式一致：**agent 主动外连面板**（轮询或 WebSocket/SSE 唤醒），NAT 后可用 | 已验证（子智能体读源码） |
| S2 | 分水岭在"面板下发什么"：ForwardX 下发 **shell 命令串**，agent `sh -c` 执行（`agent/main.go:2320-2356,13896`）；flux-panel 的 agent 有 **root PTY 终端**（`terminal_manager.go:80-100`）、**任意 Docker 部署**（`docker_app.go:91-135`），且 ws:// 明文、secret 在 URL、**接受明文命令**、加密失败降级明文（`websocket_reporter.go:457,520-612,1832`）；Relay Panel 只下发**结构化期望状态**，agent 本地渲染 nft/tc/realm 配置，外部命令全部 `exec.Command` 数组，无 `sh -c`（`internal/agent/render.go`、`executor.go`），RelayDeck 用强类型 plan + 特权分离 | 已验证 |
| S3 | 内核二进制普遍"安装时从 GitHub 下载"，realm/gost 多数**无 sha256**（ForwardX、Relay Panel 用 `latest`）；有校验的（flux xray、Relay Panel agent）校验文件与二进制**同源/同镜像**，只防传输损坏；唯一做对一半的：RelayDeck 取 GitHub API `digest`、flux agent 自升级写死下载源 + 自检版本 + 重连确认超时回滚 | 已验证 |
| S4 | 统计：**nftables 命名 counter 最可靠**；realm/socat 无统计，其他项目靠按端口挂 nft/iptables counter + conntrack 补；解析 `iptables -nvxL`/`nft list` 文本脆弱，应用 `nft -j` | 已验证 |
| S5 | 热重载普遍缺失：Relay Panel 把全部 realm 规则合并成一个进程，任一变更杀进程重启，**断全部连接**；ForwardX gost 合并重启同样；ForwardX realm"一端口一进程"变更影响面小 | 已验证 |
| S6 | 值得借鉴：desired-state 带 revision/hash/IssuedAt 且迟到结果丢弃；`Healthy()` 核对真实状态（进程存活、端口监听、nft 表存在）而非 revision 号；`nft -c` 预检 + 事务 + 回滚；累计值上报由面板算增量；Preflight（端口冲突、ip_forward、firewalld/ufw/Docker FORWARD）；目标地址策略（RelayDeck `policy.rs`：拒绝本机/私网/回环）；systemd 加固 | 已验证 |
| S7 | 只有 RelayDeck 做了开放中继/SSRF 防护；其余只验格式，**不拒绝内网/回环目标** | 已验证 |

### 2.2 内核可落地性（最新稳定版 2026-10-05 查询）

| 内核 | 版本 | 许可证 | 覆盖 W1nCray 12 个目标 | 解压后体积 | 热重载 | 统计 | PROXY 收/发 | 结论 |
|---|---|---|---|---|---|---|---|---|
| **xray** | v26.3.27（后续 26.7–26.9 均 prerelease） | MPL-2.0 | 全部（mips64 系硬浮点；mips/mipsle 另带 softfloat 二进制）；**W1nCray 已内嵌** | 34–40MB（+geo≈30MB） | 无 SIGHUP；**gRPC 动态增删入站** | StatsService（按入站/出站/用户） | 收发（仅 TCP 可用于发送） | **纳入，内嵌为默认**（外部进程模式不做） |
| **gost** | v3.3.0 | MIT | 全部（mips64/le 仅硬浮点；386 未设 GO386=softfloat） | **43–54MB** | SIGHUP / `POST /config/reload` / REST CRUD；重载会先关闭所有 service 再重绑，失败可能半更新（issue #754），存量连接是否保留**待验证** | Prometheus（每 service 字节/连接；`client` 标签基数高） | 收发 | **纳入（首个外部内核）** |
| **realm** | v2.9.6 | MIT | **缺 386/armv5/loong64/riscv64**；mips64 硬浮点；须选**非 slim + musl** 资产（slim 无 PROXY/LB/ws） | **4.4–6.9MB** | **无**（改配置即重启，断连） | **无** | 收发（仅 TCP） | **纳入（次选）：小设备、纯中继、无需计量** |
| frp | v0.71.0 | Apache-2.0 | 缺 386；mips64 硬浮点 | 33–39MB（frpc+frps 合计，OpenWrt 只需 frpc） | frpc 可 reload；frps 无 | 有 | **只发**不收 | **暂缓**（仅需 xtcp 打洞时再议） |
| sing-box | v1.14.2 | **GPL-3.0 + 名称条款** | 全部 | **73–93MB** | SIGHUP=整实例重建 | clash API（官方包无 v2ray API） | **已移除** | **暂缓**，且不随发行物分发、不托管；用户自选时仅从上游下载 |
| nftables DNAT | – | – | 取决于内核模块 | 0 | 事务 | 命名 counter | – | **暂缓**：OpenWrt fw4 每次 reload `flush table inet fw4`，且多 base chain 的 accept 不能绕过 fw4 的 drop，正确做法是走 UCI/`fw4 reload`；缺模块的固件不可用 |
| iptables / socat | – | socat GPL-2.0+例外 | – | – | – | 无 | – | **不纳入**（nft 与 realm/gost 已覆盖；socat 每连接 fork、无统计） |

校验能力：五家都有 GitHub `asset.digest`；gost/frp 有 checksums 文件；xray 有 `.dgst`（与 zip 同源）；**没有任何一家有 cosign/GPG**，仅 sing-box 有 release attestation；`api.github.com` 未认证 60 次/小时且国内不可达。**结论：不能把上游当信任根。**
内存：**无可靠实测数据**（仅 issue 碎片：gost 在 128MB 设备上有 OOM 报告，mws 每 stream 默认 1MB 缓冲；sing-box 128MB 吃紧），数字必须在目标设备上实测。

### 2.3 Xray 原语（来自首版分析，对"xray 驱动"仍然有效）

| 需求 | 实现 | 实测结论（Windows/amd64 回环） |
|---|---|---|
| TCP/UDP 直连、portMap、端口范围 | `dokodemo-door` → 路由 → `freedom{redirect}` | 通过 |
| ws/wss/tls/grpc/xhttp 隧道 | 入口 dokodemo → VLESS 出站 → 出口 VLESS 入站 → freedom | 27 组通过；**不要用 trojan 作载体**（突发 512KiB 写 200/200 失败）；`allowInsecure` 已移除，自签证书需 `pinnedPeerCertSha256`；推荐 VLESS+VLESS-Encryption(raw) |
| 反向代理 | 老式 `app/reverse` bridge/portal + 自管 BridgeWorker | TCP+UDP 通，断线恢复 0.6–3 s；官方 `Bridge.Close` 不彻底 |
| 发送 PROXY | `freedom.proxyProtocol` 1/2 | **仅 TCP 可用**；UDP 会写成独立垃圾数据报 |
| 接收 PROXY | `sockopt.acceptProxyProtocol`（策略固定 REQUIRE） | 无头即断；**无可信源名单，可被伪造** → 仅回环/内网监听；真实 IP 可进入限速器/在线 IP |
| 正向隧道保真客户端 IP | 入口 `freedom{proxyProtocol:2}`+`dialerProxy`（PROXY 头搭载） | 已验证 |
| 体积 | 所需包已在二进制内 | lite 增量 ≈ +12 KB |

### 2.4 既有缺陷（编排前必须先修）

| # | 缺陷 | 证据 | 档位 |
|---|---|---|---|
| D-A | `core.RemoveOutbound` 不 Close handler → reverse 桥端移除后仍重连成僵尸 | `core/handlers.go:32-37` | **主智能体已复核** |
| D-B | `RuleManager.apply` 失败时 router 规则表已被先清空，`SetNode` 失败只回滚自身 map、不重放 → 所有节点的内网屏蔽头规则一并失效 | `core/rules.go:45-62,145`；Xray `router.go:124-137` | **主智能体已复核** |
| D-C | 删除入站/规则/出站、实例重建都不断存量连接；portal 重建后 reverse 隧道 45 s 不恢复，dispatcher 登记并 Kill 后 1.8 s 恢复 | 子智能体实验 E7/E8/E24 | 已验证（子智能体），Linux splice 下【待确认】 |
| D-D | `BlockPrivateIP` 只匹配字面 IP，route.json 默认 `AsIs` 时域名目标可绕过 | E15 | 已验证（子智能体） |
| D-E | 默认 level-0 `ConnIdle=30/UplinkOnly=2/DownlinkOnly=4` 会掐掉空闲转发连接；未配置 level 走 `SessionDefault`（amd64 缓冲 512KiB/连接） | `panel/config.go:62-65` **主智能体已复核** | 已验证 |
| D-F | 配置要求 `Nodes` 非空 → 纯转发机/纯 agent 无法启动 | `panel/config.go:87` **主智能体已复核** | 已验证 |
| D-G | 安装器 `verify_sha256` 在缺 `sha256sum` 或缺 `SHA256SUMS` 时只警告并放行，且校验文件与二进制同源 | `install.sh:255-275` **主智能体已复核** | 已验证（agent 下载内核**不得沿用此 fail-open 行为**） |
| D-H | ws 节点入站默认信任 `X-Forwarded-For`，可伪造源 IP 绕过设备限制（既有问题，不在本期范围，仅记录） | `websocket/hub.go:68-80`；`node/build.go:477-479` | 已验证（代码），未单测 |

### 2.5 面板侧（Xboard）

| # | 事实 | 档位 |
|---|---|---|
| X1 | Xboard 上游已有"机器"：`v2_server_machine`（token/last_seen_at/load_status）、`v2_server.machine_id`；`POST /api/v2/server/machine/{nodes,status}`；WS 用 `machine_id+token`；**只做归属+监控，无配置/规则下发** | 已验证（上游 `4f48e61`） |
| X2 | 面板可经 `NodeSyncService::pushMachine` 向机器推**任意事件名**；但 fire-and-forget、离线即丢；WS 只在握手校验 token，`resetToken`/禁用不踢已连 agent → **WS 下行只发 hint，不带密钥/完整配置** | 已验证（子智能体） |
| X3 | 管理端前端是**闭源预编译子模块**（`xboard-admin-dist`），无菜单扩展点；`admin_menus/admin_crud` 是否被前端消费**无法确定** | 已验证 / 待确认 |
| X4 | 插件可注册带 `admin` 鉴权的 API、独立页面、迁移、定时任务；插件目录不受 `update.sh` 的 `git reset --hard` 影响；路由无自动前缀；插件路由在 Octane 下的运行时表现**待烟测** | 代码路径已验证，运行时待确认 |
| X5 | agent→面板的自定义 **WS 上行事件会被 `NodeWorker` 白名单丢弃**，0 节点机器 WS 半残 → 需改核心 `NodeWorker.php`（单文件）；故阶段 2 上行全走 HTTP | 已验证（子智能体） |
| X6 | `log` 中间件只对顶层键脱敏，嵌套密钥会明文进审计表 → 写接口不挂 `log`，用插件自有审计表 | 已验证（子智能体） |
| X7 | 用户面板（魔改，约 commit `60ba571`）**是否具备机器模式无法确定**；W1nCray 当前未实现机器模式 | 待确认 |

## 3. 总体架构

```
 ┌──────────────── Xboard（dashboard）────────────────┐
 │ 插件 w1nc_agent：DB(期望状态/revision/审计) + 管理 API + 独立管理页  │
 │ agent API: /api/v2/server/machine/agent/{config,ack,report}        │
 │ WS 下行：pushMachine('sync.agent', hint)                          │
 └──────────────▲──────────────────────────┬──────────┘
        HTTPS 上行(拉 config/ack/report)     WS 仅 hint（NAT 后也可用，agent 外连）
 ┌──────────────┴──────────────────────────▼──────────┐
 │ W1nCray = Agent                                      │
 │  Reconciler  期望状态 → 各 Driver 的 Validate/Render/Apply │
 │  Manifest    内置公钥 + 签名内核清单 + 校验安装/回滚          │
 │  Supervisor  子进程（退避重启/日志/PID/last-good）           │
 │  PortLedger  端口账本（bind 探测 + 冲突检测）                │
 │  Drivers:  xray(内嵌) │ gost(外部) │ realm(外部) │ …后续      │
 └─────────────────────────────────────────────────────┘
```

### 3.1 原则（每条都有 §2 的证据支撑）

1. **只下发期望状态，不下发命令**（S2）。agent 本地渲染；**不存在**终端、Docker 部署、脚本推送、`sh -c` 执行面板内容的路径；外部命令一律 `exec.Command(name, args...)` 数组；进入配置文本的字段必须是强类型（`netip.Addr`、`uint16`、枚举）或严格正则，渲染器逐字段单测。
2. **信任根是 agent 内置的 ed25519 公钥签名的"内核清单"，不是 GitHub，也不是面板**（S3、D-G）。面板只能从清单里选 `name+version`，**不能给 URL 或 hash**；sha256 在我方 CI 里写入清单，agent 不依赖 GitHub API；下载源只是传输通道（我方镜像 → 第三方镜像 → 上游 GitHub），哈希对不上就拒绝；**校验失败一律拒绝（fail-closed）**。清单带单调 `sequence` 与 `expires_at`（防回滚/冻结）、`revoked` 列表。
3. **通道必须 TLS，不允许降级**；token 可吊销/轮换，不放 argv 与 URL（S2）；密钥只走 HTTPS，不进 WS、不进通用审计。
4. **DB 为真相源，WS 只做提示**（X2）：agent 在每次 WS `auth.success` 后及每个 pull 周期都 `POST /config`（`have_revision/hash`，相同 304）。
5. **事务式应用 + 自动回滚**（S6）：渲染 → 内核自带校验（`xray -test` 等价、`gost`/`realm` 配置 schema 校验）→ 原子切换 → 健康检查 → 失败恢复 last-good 并 `ack: rolled_back`；对同一 hash 失败后面板不再重复推送（`blocked_hash`）。
6. **以真实状态对账**（S6）：每个周期核对"期望 vs 实际"（进程存活、端口监听、配置哈希），上报差异，而不只是 revision 号。
7. **变更粒度隔离**（S5）：xray 用其运行时 API 增删入站（不重启内核）；realm 一规则一进程；gost 利用其 API/SIGHUP；做不到热更的内核必须在能力里声明"变更会断连"，面板据此提示。
8. **本地策略为根信任**：`Agent.Policy`（规则数、端口范围、监听地址、DenyCIDRs、AllowPrivate、是否允许公网监听接收 PROXY、允许的内核集合）在本地配置，**远程不可放宽**。
9. **目标地址策略**（S7）：默认拒绝本机/私网/回环/链路本地/元数据地址；`AllowPrivate` 只能本地放开；域名目标在校验期解析检查（存在重绑 TOCTOU，文档注明）。
10. **无万能通道**：agent 的命令只有白名单（`probe`、`restart_instance`、`dump_state`），参数为强类型；自升级若实现，下载源写死在 agent 内、校验签名与哈希、新版本自检、重连确认超时回滚（借鉴 flux 的流程）。

### 3.2 Driver 接口

```go
type Driver interface {
    Name() string
    Caps() Caps   // 协议(tcp/udp)、隧道类型、反向代理、PROXY 收/发、LB/健康检查、统计类型、
                  // 热更方式、变更是否断连、所需权限、支持的 GOOS/GOARCH/浮点/libc、安装体积
    // 内核二进制（内嵌内核返回 nil）
    Detect(ctx) (Installed, error)             // 不联网
    Install(ctx, Pin) error                    // 清单 Pin{Version,Asset,SHA256}：流式下载→校验→解压到目标目录→版本自检→原子切换；保留上一版
    Rollback(ctx) error
    // 实例
    Validate(ctx, Instance) error              // 纯校验 + 内核自带检查
    Render(Instance) (Artifact, error)         // 纯函数、确定性；Artifact{Files, Hash, PortClaims}
    Apply(ctx, Artifact) (ApplyResult, error)  // 内部决定 Start/热更/Reload/重启；写 last-good；失败回滚
    Stop(ctx, ids ...string) error
    Stats(ctx) ([]Counter, error)              // 累计值（不做差分，面板按 revision 处理回绕）
    Health(ctx) Health                         // 进程/监听/配置哈希是否与期望一致
}
```
公共组件：`Supervisor`、`Manifest`、`PortLedger`、`Reconciler`，避免各 Driver 重复实现。

### 3.3 期望状态与"转发规则"模型

期望状态 = `{kernels:[{name,version}], instances:[{id, engine, spec}], policy_ref, revision}`。规则模型与内核无关（snake_case，借鉴 gost service/chain、frp proxy、realm endpoint）：`kind`（`forward` / `tunnel_entry` / `tunnel_exit` / `reverse_portal` / `reverse_bridge`）、`listen{addr,ports,port_map}`、`network[]`、`targets[{host,port,weight}]`、`balance{strategy,health}`、`proxy_protocol_out`、`accept_proxy_protocol`、`idle_profile`、`limits`、`acl`、`via/reverse{...}`、**`engine`（`auto` | `xray` | `gost` | `realm`）**。

**Validate 必须按所选引擎的 `Caps()` 拒绝不支持的特性**（面板上对应置灰），例如：
| 特性 | xray | gost | realm |
|---|---|---|---|
| TCP / UDP | ✔ / ✔ | ✔ / ✔ | ✔ / ✔ |
| 隧道 | VLESS(raw/ws/grpc/xhttp，tls/pin/Encryption) | ws/wss/mws/tls/kcp/quic/h2/grpc… | ws/tls/wss |
| 反向代理 | ✔（自管 BridgeWorker） | ✔（rtcp/rudp/tunnel） | ✘ |
| PROXY 发送 / 接收 | TCP / TCP（接收无可信源） | TCP / TCP（接收头可选；UDP 发送为独立首包） | TCP / TCP |
| LB | rr/random + failover(observatory)；权重/iphash 待补 | round/random/fifo/hash + 被动摘除 | roundrobin(权重)/iphash，**无健康检查** |
| 精确统计（计量） | ✔ 入站/出站/用户计数 | ✔ Prometheus（限制 `client` 标签） | ✘（须在面板提示"该引擎不支持计量"） |
| 变更是否断连 | 否（增删入站；规则整表替换，见 D-B） | 取决于 SIGHUP 重载语义（待验证） | **是**（一规则一进程以缩小影响面） |
| 安装体积 | 内嵌 +0 | 43–54MB | 4–7MB |

`engine: auto` 的选择由 agent 按 Caps、设备架构（清单有无该目标）、剩余空间决定，并把选择结果回传面板；**无法满足时拒绝应用并说明原因，不静默降级**。

其余校验（Validate，纯函数 + 端口试绑）：`id/name` 唯一；`listen` 不重复（含范围展开）；端口范围与目标范围等长；`network∋udp` 与 `proxy_protocol_out>0` 互斥；`entry` 与 `exit` 不可同时 `send`；`tunnel_exit` 必须固定 `targets` 或本地策略允许的 `allow_any_target`；隧道出口每规则独立 client + `user+ip+port` 白名单 + 兜底 block；reverse 域名随机 ≥128 bit；接收 PROXY 的入站默认仅回环/内网监听。

### 3.4 gost 渲染的已知陷阱（驱动实现必须规避）

- gost JSON 元数据中的整数经 JSON 解码为 float64，`GetInt` 只认 bool/int/string，**`"proxyProtocol":2` 静默无效、`"2"` 才生效**（子智能体实测）→ 渲染器统一用字符串。
- `mtls/mws/mwss` 是 smux 多路复用的 TLS/WS，**不是双向 TLS**（双向 TLS 靠 caFile）。
- SIGHUP 重载可能 `EADDRINUSE`/半更新（issue #754）→ 优先走 REST API 增删单个 service，而不是整体重载（待验证）。
- 小内存设备慎用 `mws`（每 stream 默认 1MB 缓冲，维护者口头说明，未在源码复核）。

## 4. 分阶段实施

> 每阶段独立可发布、独立验收；先 0 后 1。阶段 2/3/4 的先后可由用户调整（见 §6）。

### 阶段 0：修既有缺陷（本身就是 bugfix，建议 v0.3.1）

| 文件 | 改动 | 理由 |
|---|---|---|
| `core/handlers.go` | `RemoveOutbound` 先 `common.Close(handler)` 再 `RemoveHandler` | D-A |
| `core/rules.go` | apply 失败后重放上一份规则；compose 前 ruleTag 去重；`NodeRules` 增加 `Balancers` 并与全局合并 | D-B |
| `app/dispatcher` | `ConnTracker`：按 `in.Tag` 登记 `in.Conn`，提供 Active/Total/Kill/KillAll | D-C |
| `panel/panel.go` | shutdown/reload 前 KillAll | D-C |
| `install.sh` | `verify_sha256` 改为校验失败/缺失即拒绝（提供显式 `--insecure-skip-verify`） | D-G；**会改变现网安装行为，需用户确认** |
| 文档 | 记录 D-D（域名绕过内网屏蔽）、D-H；是否修改 `AsIs` 默认值另行征求意见 | 修改默认值会改变现网行为 |

验收：新增单测复现 E14/E21/E24 并通过；全量回归（含 `node` 约 60 s 的 e2e）通过。

### 阶段 1：Agent 内核 + xray 驱动（本地期望状态文件，无需面板）

- 新包：`agent/`（`Reconciler`、`Supervisor`、`PortLedger`、期望状态类型与校验）、`kernel/`（`Manifest` 签名校验、下载安装、回滚、`kernel import` 离线导入）、`driver/xray`（内嵌节点驱动 + 转发驱动：`forward/compile` 纯函数把规则编译成 dokodemo/freedom/vless/reverse/routing）。
- 现有节点逻辑不改行为：重构为 `driver/xray` 的"节点"实例；允许 **0 节点**运行（D-F）；本地 `Agent:`/`Forward:` 配置段，fsnotify 热载沿用。
- `core/core.go buildConfig`：policy 加 `system.stats*`；预置固定转发 level（TCP 长连接 `connIdle=3600`、UDP `connIdle=60~120`，显式 `bufferSize`，D-E）。
- 清单：先定数据结构与签名验证 + 一份测试清单；**生产清单与签名私钥由你持有**（见 §6）。
- 状态上报结构：每实例 state/conns/bytes/tunnel 连接/目标存活；每内核 installed/version/health。

MVP 的 LB 范围：roundRobin/random + failover。权重、iphash、规则级限速/并发放第二批（子智能体判定可行但未实测）。

### 阶段 2：面板控制（W1nCray 机器模式 + Xboard 插件）

- W1nCray：`api/xboard` 增加机器模式（`machine_id+token`、`/machine/nodes`、`/machine/status`、WS 机器级连接与 `sync.nodes`）；参照官方 Xboard-Node 的 `internal/machine`、`internal/panel/ws.go`，规避其 query 传 token 被日志记录（沿用现有 `redact`）、WS 重连不重拉节点（我们**连上即拉**）、`writeCh` 潜在数据竞争（高度可能，未跑 -race）。agent：`POST /config`（`have_revision/hash`，304）→ Validate → 应用 → `POST /ack`；`POST /report`（10–30 s，`seq` 幂等）；收到 `sync.agent` hint 立即拉取；命令白名单；本地 `last_good` 回滚。
- 插件 `plugins/W1ncAgent/`（code=`w1nc_agent`）：迁移、管理 API（`/api/v2/{secure_path}/agent/*`，`admin` 中间件，**不挂 `log`**）、agent API（`/api/v2/server/machine/agent/*`，`X-Machine-Id`+Bearer，`hash_equals`，不走 query）、独立管理页（`/{secure_path}/agent`，自带登录表单取 Sanctum token，JS/CSS **内联进 blade**）、`schedule()` 做离线检测与 revision 清理。**第一阶段对 Xboard 核心零改动**；3b（可选）补 `NodeWorker.php` 小补丁启用 WS 上行与 0 节点机器 WS 清理。
- 表（前缀 `v2_`）：`agent_machine_config`、`agent_instance`（spec json 不含密钥、secret 加密）、`agent_revision`（不可变快照）、`agent_machine_state`（applied/last_good/apply_status/blocked_hash/caps/kernels）、`agent_instance_status`、`agent_traffic_hourly`、`agent_command`、`agent_audit`。管理端 API：machine/fetch、policy、instance CRUD、`config/validate`（服务端 dry-run）、`config/apply`（`base_revision` 乐观锁，409）、`config/rollback`（新建 N+1，不改写历史）、revision/{list,diff}、kernel/{list,pin}（只能选清单内版本）、command/send、status、audit。
- WS（面板→agent，经 `pushMachine`）：`sync.agent{machine_id,revision,hash,mode:"hint"}`、`agent.command{cmd_id,hint:true}`；W1nCray `dispatch` 对未知事件静默忽略（已核对 `api/xboard/ws.go` 无 default 分支），向前兼容。在线判定用插件自己的 `last_report_at`。
- 动工前需在用户面板做**只读检查**并在测试面板做空插件烟测（见 §6，均需你同意）。

### 阶段 3：gost 驱动（首个外部内核）

`Install`（清单、流式解压、只解 `gost`）、`Render`（§3.4 陷阱）、`Apply`（REST 增删 service 优先，SIGHUP 兜底）、`Stats`（Prometheus，限制标签基数）、`Health`。**在真实 Linux 机器上用真实 gost v3.3.0 做 e2e**，并实测 §3.4 里标注"待验证"的重载语义与存量连接行为。OpenWrt 上因 43–54MB 的体积必须检查空间并引导 `--prefix`/extroot，放不下就在面板置灰。

### 阶段 4：realm 驱动（小设备、纯中继）

一规则一进程；**必须选非 slim + musl 资产**；缺失目标（386/armv5/loong64/riscv64）在清单中为 `null`，面板置灰；`Stats` 返回"不支持"，面板提示不可计量；二进制哈希来自清单。

### 阶段 5（可选，暂缓）

frp（xtcp 需求出现时）、nftables（在 OpenWrt 上走 UCI/`fw4 reload`，另行评估）、sing-box（仅"用户自选、从上游下载"，不托管）。

## 5. 验收（节选，各阶段开工时定稿）

| # | 标准 |
|---|---|
| A1 | 清单：签名错误/过期/`sequence` 回退/被吊销/哈希不符 → 一律拒绝并保持原版本运行；下载源任意一个被篡改都无法安装 |
| A2 | 校验失败、网络中断、空间不足时，现有内核与规则不受影响；升级失败自动回滚到上一版 |
| A3 | 期望状态应用失败整体回滚，**不影响现有节点的内网屏蔽规则**（回归 D-B）；删除实例后存量连接被断（回归 D-C） |
| A4 | agent 代码中不存在 `sh -c` 执行面板内容的路径（静态检查 + 测试）；未知字段、越界端口、违反本地策略的下发全部被拒并给出明确错误 |
| A5 | 规则能力校验：对 realm 请求计量/健康检查/反向代理 → 被拒；`engine:auto` 选择可解释，无法满足时拒绝而非降级 |
| F1–F7 | TCP/UDP 直连、端口范围、portMap；VLESS 隧道（raw+Encryption、raw+TLS(pin)、ws）TCP/UDP 通且出口只放行声明目标；反向代理 TCP+UDP 通、杀任一端后 ≤5 s 恢复、`Remove` 后桥端不再重连；PROXY 发送/接收/透传正确且 `udp+proxy_out` 被拒、公网监听接收 PROXY 被本地策略拒；规则热增删不重启内核、不影响节点入站与在线用户 |
| P1–P4 | 面板：离线机器改配置后上线自动收敛；`base_revision` 冲突返回 409；回滚新建 N+1；token 重置后 agent 下一次 HTTP 即被拒；审计表无明文密钥 |
| G1–G3 | gost：真实内核 e2e（直连/隧道/反代/PROXY）；重载时存量连接行为有实测结论；Prometheus 统计与连接数口径与实测一致 |
| R1 | realm：变更一条规则只影响该规则的连接；musl/非 slim 资产选择正确；不支持项被面板置灰 |
| B1 | 体积与资源：lite 构建体积增量 < 1 MiB（外部内核按需下载，不进发行物）；mips softfloat/arm 交叉编译与 `version` 自检通过；**目标设备（OpenWrt、小内存）上的内存/吞吐实测**（现无数据） |
| L1 | Linux 实测：splice 下空闲超时、Close 打断连接、PortLedger 与真实监听对账 |

## 6. 动工前需要你的决策与配合

**决策（我的推荐）：**
1. **采纳你提出的架构**：Xboard=dashboard，W1nCray=agent+内核编排；转发能力由多内核驱动提供。与首版的差别：不再把 gost/frp/realm 排除在外，而是作为**独立进程**由 agent 管理，因此首版"体积/Rust 无法链接/绕开统计"的否决理由对这条路线**不再成立**；仍否决"链接进同一进程"。
2. **内核范围**：xray（内嵌）+ gost + realm 先做；frp、nftables、sing-box 暂缓；iptables、socat 不做。
3. **前端落点**：Xboard 插件 + 独立管理页（管理端菜单无扩展点，见 X3）。否决改魔改面板核心（`update.sh` 的 `git reset --hard` 会覆盖、前端无源码）与 W1nCray 自带 Web UI 作主入口（NAT 后不可达）。
4. **顺序**：阶段 0 → 1 → 2 → 3 → 4。若你更想先看到"面板直接管理 gost"，可把 3 提前到 2 之前，代价是先没有面板。

**需要你提供或同意：**
- **清单签名密钥与托管**：你生成并离线保管 ed25519 私钥（公钥内置进 agent，保留 2 把以便轮换）；清单与内核镜像放哪里（GitHub release + 国内可达镜像？）；这涉及你的发布流程，请定。
- 对用户面板（<panel-host>）做**只读**检查：是否具备机器模式迁移、版本与魔改范围、管理端 dist 是否含 `admin_menus/admin_crud`、nginx 能否反代新路径；以及在**测试面板**放空插件烟测（涉及写入，单独征求同意）。
- 一台可用于测试的 Linux 机器（阶段 3/4 的真实内核 e2e、splice/内存实测）；OpenWrt 实机或 chroot；生产机器不会在未授权时使用。
- 阶段 0 里对 `install.sh` 校验行为的收紧（fail-closed）会改变现网安装行为，请确认。

## 7. 风险与回滚

| 风险 | 缓解 / 回滚 |
|---|---|
| 面板被攻破 → 全舰队被控 | 无命令通道；面板只能选清单内版本；本地策略为根信任；agent 只执行强类型期望状态 |
| 内核供应链投毒 | 签名清单 + 哈希在我方 CI 写入 + fail-closed；下载源仅为通道；`revoked` 列表 |
| 开放中继 / SSRF | 默认拒绝本机/私网/回环/元数据目标；`allow_any_target`、`AllowPrivate` 仅本地放开 |
| PROXY 头伪造 | 默认仅回环/内网监听；公网需本地策略显式放开 |
| 失败应用破坏现有节点 | 阶段 0 修 D-B；应用失败整体回滚并重放上一份 |
| 外部内核变更断连 | 能力声明 + 面板提示；realm 一规则一进程；xray 增删入站不重启 |
| 小设备放不下/OOM | 清单带 `installed_size`，空间检查；放不下置灰；内存数据未知，实机前不承诺 |
| 许可证 | 外部内核按需下载则 W1nCray 不分发其二进制；若托管镜像需随附各自 LICENSE 与 `source_url`；**sing-box 不托管**；以上为技术性判断，非法律意见 |
| 回滚 | 每阶段独立提交；`Agent.Enabled:false` 退回当前行为；内核目录 `kernels/<name>/<ver>` + `current` 链接，升级失败切回；插件"停用"≠"卸载"（卸载会删表） |

## 8. 被否决的备选

1. **全部塞进 Xray 进程（首版）**：与用户架构不符，且无法利用 realm 的小体积与 gost 的隧道/热更能力。保留其中 Xray 驱动部分。
2. **把 gost/frp 作为 Go 库链接进 W1nCray**：+7.3~26.3MB（full 集因 tun2socks×gvisor 编译失败）、升级 21 个依赖、绕开 Xray 路由/统计/限速；改为独立进程由 agent 管理。realm 是 Rust，本就无法链接。
3. **面板下发命令/脚本（ForwardX 式）**、**终端/Docker 万能通道（flux 式）**：见 S2，任何字段校验遗漏即 RCE，面板被攻破即全舰队 root。
4. **校验文件取自下载源/镜像**：见 S3、D-G。
5. **WS 下行携带完整配置**：吊销缺口 + 离线丢失（X2）。
6. **合并全部规则成一个进程重启**（Relay Panel 式）：变更断全部连接（S5）。
7. **nftables 作首批驱动**：fw4 冲突与内核模块依赖（§2.2），暂缓。
8. **面板修改核心 + 前端补丁**、**W1nCray 自带 Web UI 作主入口**：见 §6。

## 9. 无法确定 / 待确认

1. 用户面板是否有机器模式及与上游差异（X7）；管理端 SPA 是否消费 `admin_menus`、token 存储键（X3）；插件路由在 Octane 下的表现（X4，需烟测）。
2. gost 重载时存量连接是否保留、API 增删 service 的行为（只读源码，未运行）。
3. 各内核 RSS 内存、mips/OpenWrt 实机吞吐（无可靠数据；子智能体实验均在 Windows/amd64 回环，数字不可外推）。
4. Linux 下 splice 对 ConnIdle 的影响、Close 能否打断 splice；半开连接下 portal 发现死 bridge 的时间；Xray 对 UDP 会话数/并发的内置上限。
5. realm musl 资产是否静态链接、sing-box 的 `libcronet.so` 是否被加载（未解包验证）；frp/sing-box 的反向隧道细节（本期暂缓，未深查）。
6. 上游 386 构建（gost/xray）未设 `GO386=softfloat`，无 SSE2 的老 x86 上很可能 SIGILL（高度可能，未实机验证）。
7. 规则级流量如何映射到 Xboard"按用户"计费上报（产品决策）；PROXY protocol 在 UDP 上的规范与接收端支持（未查原文）。
8. 清单 `archive_sha256` 等具体值由我方 CI 在发布时实测填写，文档中的样例哈希仅为格式示意。
