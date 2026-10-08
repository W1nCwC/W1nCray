# PLAN v10 — 可用性重构：终端与文件、Xray 配置可查看、一键转发、Xray 与 agent 解耦

日期：2026-10-07　状态：执行中
仓库：W1nCray（`C:\W1nC-XrayR`，feat/agent）、W1nCBoard（`C:\W1nCBoard`，master）

## 0. 用户诉求（原话归纳）

1. xray 部分和 agent 还不独立。
2. 面板交互反人类。
3. 终端去掉密码验证，加上文件访问。
4. xray 配置文件只能下发，需要能查看。
5. realm/gost/frp 的「实例」看不懂；学习转发面板：两台服务器一键组装入口/出口，选协议和功能即可。

## 1. 现状与根因（证据）

### 1.1 Xray 与 agent 不独立【已验证】

- 单进程：`cmd/root.go:99` `panel.New` 同时构建 xray core、Xboard 节点控制器和 agent（`panel/panel.go:233` `bootstrap.Boot(..., cr)`，core 在启动时注入）。
- **任何 xray 配置变更都会整体重建**：`panel/panel.go:641-660` 监听 config.yml / route / dns / custom_inbound / custom_outbound，触发 `requestReload` → `shutdown()`（`panel/panel.go:525-555`）→ `p.agent.Shutdown`。
- `agent/bootstrap/bootstrap.go:399-413` `Runtime.Shutdown`：关闭全部终端会话、`Reconciler.Stop` 停掉**所有实例（含 gost/realm/frp 转发）**、`Sup.Shutdown`、断开面板 WS。
- 结论：在面板上改一次 route.json → 终端断开、所有转发中断、WS 断线重连。xray 只是 4 个引擎之一，却绑架了整个 agent。
- `agent/bootstrap/ops.go:23-25`：进程内 xray 不受 supervisor 管理，`component_restart` 无法单独重启它。

### 1.2 终端密码与文件访问【已验证】

- `WsTicketController::ticket` purpose=terminal 必须 `confirm_password`（`app/Http/Controllers/V2/Admin/W1nCray/WsTicketController.php:42-44`）。
- 文件操作 `FileController::op` 对 file_write/file_delete 要密码（同文件 `:383-388`）。
- 远程文件只能在 agent 本地 `Files.Roots` 内（测试机为 `/root/e2e-v10/files`），根 `/` 被 `checkRootIsSane` 拒绝；`Files.Unrestricted` 默认 false。终端开启时 root shell 已可做任何事，文件限制没有安全意义，只剩不便。
- `file_write` 一次最多 128 KiB、无追加（`agent/fileops/fileops.go:48-49`），无法上传大文件；无 mkdir。
- 文件管理在「文件」标签下半部，终端标签里没有。

### 1.3 Xray 配置「只能下发」【已验证】

- 文件页以面板为中心：面板没有工作副本时状态显示「未上传」（测试机 config.yml 即如此），列表不显示机器上的真实文件（大小、修改时间、内容）。
- 查看只能点「编辑」进入（`public/w1ncray/managed-editor.js:50-56` 实际用 file_read 读机器文件），没有只读查看。
- 保存→发布→应用 三步分离，界面充满「工作副本 / 已发布 / revision / roots / hello.policy / files/op」术语。

### 1.4 转发实例看不懂【已验证】

- 「新建实例」表单是原始 schema：id、engine、kind（forward / tunnel_entry / tunnel_exit / reverse_portal / reverse_bridge）、listen.addr、listen.ports、targets，隧道参数只能写原始 JSON。
- 隧道需要在两台机器上分别建 tunnel_entry 与 tunnel_exit，手工对齐 tunnel.server/listen/secret/证书指纹。
- 后端能力其实齐全：`agent/spec/spec.go` Tunnel{type,server,listen,security,pin_sha256,...}；realm 支持 forward/tunnel_entry/tunnel_exit（`driver/realm/realm.go:170`），gost、xray 驱动也支持隧道。**缺的是面板层的编排。**

### 1.5 同类面板做法（调研）

ForwardX（github.com/poouo/Forwardx）、极光面板等：
- 一键脚本装 agent，面板不存 SSH 凭据；
- 「转发规则」= 入口服务器 + 监听端口 + 协议（TCP/UDP/TCP+UDP）+ 目标；
- 「隧道」= 入口 → 出口，选择传输（TLS/WSS/TCP/MTLS…），可多跳、入口组/出口组；
- 列表直接显示规则流量、延迟、自测结果。

## 2. 方案

### WP-A　Xray 与 agent 解耦（Go，W1nCray v0.5.3）

目标：xray 配置变更只重建 xray core 与 Xboard 节点控制器；agent（WS、终端、supervisor、gost/realm/frp 实例）不中断。

- `panel.Panel`：agent 在 `Start` 中只启动一次，`shutdown()`（xray 重建路径）不再调用 `agent.Shutdown`；只有 `Close()`（进程退出）才关 agent。
- agent 对 xray core 的依赖改为可替换：`corehost` 增加 `Swap(newCore)`（或 bootstrap 暴露 `Runtime.AttachCore(cr)`）；xray 重建后对 **engine=xray 的实例**重新 reconcile，其它引擎不动。
- agent.yml 变更：只重启 agent（不动 xray）；config.yml 等 xray 文件变更：只重建 xray。两类文件分开监听。
- `ReloadForAgent`（files_apply 触发）语义不变，但不再拆掉 agent，因此应用 xray 配置后 files_apply 结果能在同一连接上回报。
- 上游：panel.go reload 路径、bootstrap.Boot、corehost、driver/xray；下游：reconcile、terminal、ws；横向：docs/AGENT.md「重载语义」一节。
- 不做（本期否决）：把 xray 拆成独立子进程。理由：节点控制器（用户同步、流量/在线上报）与 xray core 进程内紧耦合，拆进程需要新 IPC 与双进程自升级/systemd KillMode 改造，风险大；解耦生命周期已解决「改 xray 断转发/断终端」的实际问题。self_update 仍会重启整个进程（含 xray），列为后续项。
- 验收：测试机上 gost 转发持续 iperf/nc 连接 + 打开终端，面板修改 route.json 并应用 → 终端不断、转发连接不断、WS 不重连（日志无 hello 重发），xray 新路由生效；Linux `go test ./panel/... ./agent/... ./corehost/...` 与 `-race` 通过。
- 回滚：landing VPS 保留 v0.5.2 二进制备份，`mv` 回去并重启。

### WP-B　终端免密 + 文件访问

后端（PHP）：
- `WsTicketController`：purpose=terminal 不再要求 `confirm_password`（字段保留为可选并忽略，向后兼容旧前端）。
- `FileController::op`：file_write/file_delete/新增的 file_mkdir 不再要求密码。
- 审计不变：每次终端会话、每次文件写删仍写审计记录。
- 其它高风险操作（内核安装、自升级、回滚）本期保留密码，界面改为一次输入后本页 10 分钟内免再输（前端内存，不落盘）。

agent（Go，随 v0.5.3）：
- `Files.Unrestricted` 改为三态：未写时**跟随 Terminal.Enabled**（终端开启 = root shell 已可达，文件不再限制根目录）；显式写 false 仍受 roots 限制。
- `file_write` 增加 `offset`/`append`，支持分片上传（单片仍 ≤128 KiB）；新增 `file_mkdir`、`file_rename`。
- hello.policy 上报有效的 unrestricted，面板据此决定是否显示「/」根。

前端：
- 终端标签改为「终端 | 文件」双栏（桌面左右分栏、手机上下切换）：路径面包屑、目录列表（名称/大小/修改时间/权限）、进入目录、查看、编辑（文本 ≤1 MiB 分片读写）、下载（分片读）、上传（分片写）、新建文件夹、重命名、删除（确认框，不要密码）、「在终端中打开此目录」（向 PTY 输入 `cd <path>`）。
- 「文件」标签里的「远程文件」下半部移除（并入终端标签）。

验收：无密码打开终端；在 `/etc`、`/root` 浏览、查看、编辑保存、上传 5 MiB 文件后 sha256 一致、下载一致、删除；Terminal.Enabled=false 的机器仍只能在 roots 内。

### WP-C　Xray 配置：以机器为准、可查看

- 「Xray」标签（见 WP-E）中的配置文件列表以**机器上的真实文件**为准：进入页面时对 xray 目录做一次 file_list，显示 文件 / 大小 / 修改时间 / 状态。
- 状态改为人话：`与面板一致` / `有未生效的修改`（面板有保存但未应用） / `机器上被手动改过`（机器 sha 与面板最后应用 sha 不同） / `仅机器上有`（面板从未保存过，即原「未上传」）。
- 操作：`查看`（只读、等宽、行号、复制、下载）、`编辑`、`历史`、geo 文件 `从 URL 更新`。
- 编辑保存按钮为 `保存并生效`：前端顺序调用 put → publish → apply，并在同一对话框显示校验/应用进度与失败原因（失败自动回滚由 agent 现有逻辑保证）；`仅保存`作为次要按钮。
- 术语（revision、roots、hello.policy、files/op、working copy）全部移入「高级信息」折叠。
- 后端：`FileController::fetch` 增加机器侧清单（来自最近一次 file_list 结果缓存）或前端直接发 file_list，二选一，**选前端直发**（无需新表，结果实时）。

验收：测试机 config.yml「仅机器上有」可直接查看内容；编辑 route.json 保存并生效，状态回到「与面板一致」，xray 新规则生效；手动在机器上改 dns.json → 显示「机器上被手动改过」。

### WP-D　一键转发（面板编排，PHP + 前端）

新对象「转发规则」（表 `v2_w1ncray_forward_rules`），面板把一条规则编译成一或两个实例下发：

| 字段 | 说明 |
|---|---|
| 名称 | 可读名 |
| 入口服务器 | 选择机器 |
| 监听端口 | 手填或「自动分配」（在入口机 policy 端口范围内找空闲） |
| 协议 | TCP / UDP / TCP+UDP |
| 方式 | `直连`（入口直接转发到目标）/ `隧道`（入口 → 出口 → 目标） |
| 出口服务器 | 方式=隧道时选择机器 |
| 隧道协议 | `TLS`（推荐，默认）/ `WSS` / `WS` / `TCP（不加密）` |
| 目标 | 一行一个 `host:port`，多于一个时出现「负载均衡」选项 |
| 高级（折叠） | 引擎（自动/realm/gost/xray）、PROXY 协议、限速、连接数上限、来源 IP 白名单、出口隧道端口（默认自动） |

编译规则：
- 直连 → 入口机一个 `forward` 实例。
- 隧道 → 入口机 `tunnel_entry`（listen=用户端口，tunnel.server=出口机公网地址:隧道端口）+ 出口机 `tunnel_exit`（tunnel.listen=0.0.0.0:隧道端口，targets=目标），面板生成 secret（32 字节随机）；加密传输用新的 `security: tls_self`（WP-G）：两端由 secret 在本地派生同一张自签证书，入口只信任这一张，无需两段式发布、无需公共 CA。
- 默认引擎 gost（独立进程，不受 xray 重载影响；relay 用 secret 认证）。证据：realm 只认公共 CA 证书（`driver/realm/realm.go:39-43`），gost 目前不支持指纹（`driver/gost/plan.go:566`），xray 的自签证书派生在 Go 里（`driver/xray/derive.go:76-118`），PHP 无法复刻 x509 DER，故证书只能在 agent 端派生。
- 实例 id 由规则派生（`r<id>-entry` / `r<id>-exit`），在实例列表中标记「由转发规则管理」，原始编辑入口只读。
- 机器新增「公网地址」字段（默认取 agent 上报的公网 IP，可改成域名），隧道连接用它。
- 删除规则 = 同时删除两端实例；修改规则 = 重新编译两端并各自发布。

界面：
- 侧栏新增全局页面「转发」：规则列表（名称、入口 机器:端口、→ 出口、→ 目标、协议/隧道、状态[两端都运行=正常]、流量）；`新建转发` 弹出上表的简洁表单，默认只显示必填项。
- 机器详情「转发」标签：只列与本机相关的规则，`新建转发` 预填入口=本机。
- 原「实例」标签降级为「转发 → 高级：原始实例」。

验收（测试机双 agent：machine 3 + 新建 machine 4，同机不同 state 目录）：
- 直连 TCP：nc 通；
- 隧道 TLS（realm）与 WSS（gost）：入口端口 → 出口 → 目标 nc/HTTP 通，出口隧道端口抓包为 TLS；
- 修改目标、删除规则两端实例同步消失；
- UDP 直连通（dig 经转发）。

### WP-G　`tls_self` 隧道安全模式（Go，v0.5.3）

- `spec.Tunnel.Security` 新值 `tls_self`：要求 `Instance.Secret`；服务端（tunnel_exit / reverse_portal）使用 `SelfCert(secret, sni)`；客户端（tunnel_entry / reverse_bridge）只信任该证书（等价于 pin = SelfCertPin(secret, sni)，本地计算）。
- `SelfCert` 从 driver/xray 提到共享包（如 `agent/tlsself`），xray 与 gost 驱动共用；gost：出口写 cert/key 文件（0600，state 目录），入口 `secure: true` + `serverName` + `caFile` 指向同一证书；xray：复用现有 tls_pin 路径；realm：拒绝并给出原因。
- validate：`tls_self` 需要 secret、仅 tls/ws(→wss)/grpc 等加密传输组合；面板 InstanceSpec/DesiredValidator 同步接受该值。
- 验收：gost 隧道 tls/wss/mtls 三种传输 + tls_self 端到端通；改动出口 secret 后入口握手失败（证明在校验证书）。

### WP-E　机器页信息架构

10 个标签（概览/实例/节点/内核/文件/终端/升级/修订历史/审计/命令）收敛为 5 个：

| 新标签 | 内容 |
|---|---|
| 概览 | 设备卡、仪表、组件状态 |
| Xray | Xboard 节点绑定 + Xray 配置文件（WP-C） |
| 转发 | 本机转发规则（WP-D）+ 高级：原始实例 |
| 终端 | 终端 + 文件管理（WP-B） |
| 维护 | 内核、Agent 升级、操作记录（修订历史/审计/命令合并为一个时间线，按类型筛选） |

全部文案去术语：在线状态、版本、apply_status 等用中文短语；英文枚举只在「高级信息」里出现。

## 3. 改动清单

| 仓库 | 位置 | 改动 | WP |
|---|---|---|---|
| W1nCray | panel/panel.go | agent 生命周期与 xray 重建分离；分开监听 agent.yml 与 xray 文件 | A |
| W1nCray | corehost/、driver/xray | core 可替换，重建后重挂 xray 实例 | A |
| W1nCray | agent/bootstrap | `AttachCore`；Shutdown 只在进程退出调用 | A |
| W1nCray | agent/agentcfg、agent/fileops、agent/opscmd | Unrestricted 三态跟随终端；file_write offset/append；file_mkdir/file_rename | B |
| W1nCray | docs/AGENT.md | 重载语义、文件权限说明 | A/B |
| W1nCBoard | WsTicketController、FileController | 去密码；op 新类型 | B |
| W1nCBoard | AgentCommand 合同（sanitizeArgs/validateArgs） | file_mkdir/file_rename/file_write offset | B |
| W1nCBoard | 新 migration + Model + Service + Controller + Route | 转发规则与编译器、机器公网地址 | D |
| W1nCBoard | public/w1ncray/* | 机器页 5 标签、终端+文件、Xray 配置、转发页 | B/C/D/E |
| W1nCBoard | tests/ | 上述 PHP 改动的 phpunit；前端 selftest | 全部 |

## 4. 风险与回滚

- 去掉终端密码：拿到管理员登录态即可得到 root shell。缓解：保留审计；agent 本地 `Terminal.Enabled: false` 仍是最终开关。用户已明确要求。
- 文件无限制：同上，仅在终端开启的机器生效。
- WP-A 改动 reload 核心路径：先在测试机完整回归（节点用户同步、流量上报、在线 IP、files_apply 回滚、self_update），再上 landing；保留 v0.5.2 二进制备份。
- tls_self 依赖两端 agent ≥ v0.5.3；面板对旧版本 agent 置灰「加密隧道」并提示升级。
- 生产部署前逐项备份（面板文件、数据库 dump、landing 二进制与配置），每一步需要用户同意。

## 5. 执行顺序

1. 并行：WP-A（Go）、WP-B agent 部分 + WP-G（Go）、WP-B 后端（PHP）、WP-D 后端（PHP）。
2. 前端：WP-E 骨架 → WP-B 终端+文件 → WP-C → WP-D（避免同文件冲突，顺序合并）。
3. 测试机端到端（双 agent），真实浏览器桌面 + 375px 双尺寸验收。
4. 发布 W1nCray v0.5.3 预发布 → 生产（征得同意后）。

## 6. 执行记录（2026-10-07，测试机 双 agent：machine 3 入口 / machine 4 出口）

| 项 | 结果 | 证据 |
|---|---|---|
| WP-A 解耦 | ✅ | 改 config.yml 触发 xray 重建（日志 reloading → xray reattached → Xray started），同期 gost 隧道长连接 60/60、179/179 往返成功，WS 未重连 |
| WP-B 终端免密 + 文件管理 | ✅ | 浏览器直接连终端；文件管理器浏览 `/`；「在终端中打开」→ `cd '/etc'`；3 MiB 分片上传后服务器 sha256 与浏览器一致 |
| WP-C Xray 配置查看 | ✅ | 列表显示机器真实大小/时间；查看 route.json；编辑 config.yml「保存并生效」→ revision 9 落盘并重建 |
| WP-D 一键转发 | ✅ | 直连、TLS、WSS、gRPC 隧道四种实测通（HTTP 301 / echo）；出口证书 CN=w1n-fwd，非 TLS/无 relay 认证的连接被关闭 |
| WP-E 5 标签 | ✅ | 桌面 + 375px 逐页检查无溢出 |
| WP-G tls_self | ✅ | gost tls/wss/grpc；grpc 需 authority=证书名（已修） |

验收中发现并修复的问题（均有回归测试）：
- 卡片模式在真实浏览器空白（NodeList）、桌面表格被掏空（单元格移入 details）、自动刷新收起详情。
- 命名根 xray 只在 Roots 恰好含配置目录时存在；不受限模式忽略命名根；token 文件未排除。
- files_apply 先于期望状态到达 → 用旧文件清单「already current」，编辑未落盘（加 revision 参数，agent 先拉取再应用）。
- 文件监听在 agent 写入后二次重建 xray（内容指纹去重）。
- WS hello 记录新运行实例却不清零 last_seq → 新一轮上报全部被当重复丢弃，实例状态不写入、规则一直「生效中」（v9 起的缺陷）。
- hello.policy 不含端口范围 → 面板分配到 agent 拒绝的端口；拒绝原因未显示；只允许回环监听的机器未提前拦截。
- 面板接受 agent 不认识的 mtls/mwss → 整份 revision 被拒、两台机器冻结（改为 gRPC，面板白名单与 agent 一致）。
- frp 不能承载转发规则；PHP ConvertEmptyStringsToNull 把空 root 变 null；ForwardController 时间戳、测试助手方法名冲突。

遗留 / 后续：
- self_update 仍会重启整个进程（含 xray）；xray 拆为独立子进程未做（见 WP-A 否决理由）。
- engine=xray 的转发实例在 xray 配置变更时会随重建短暂中断（gost/realm 不受影响；面板文案已注明）。
- 生产部署需：面板文件 + 1 个迁移 + WS 网关重启（telemetry 修复在网关进程内）+ agent v0.5.3 发布与清单 seq 3，待用户同意。
