# W1nCray Agent 使用手册

> 面向运维。本手册描述 `feat/agent` 分支（v0.3.0 之后）的 Agent：用一个本地 JSON 文件声明「这台机器要跑哪些转发」，由 W1nCray 落到外部内核（gost / frp / realm）上。
> 面板远程下发（Xboard / W1nCBoard 控制）属后续阶段，见 [PLAN-v7-panel-control.md](PLAN-v7-panel-control.md)；本手册只讲本地文件这条路径。
> 手册里的样例、拒绝信息、策略对照表全部由 `agent/examples` 的测试守护：代码一变、样例或信息不再成立，`go test ./agent/examples/` 就会失败。

目录：[1 概念](#1-概念) · [2 引擎能力](#2-引擎能力与限制) · [3 Agent 配置块](#3-agent-配置块) · [4 本地策略](#4-本地策略-policy) · [5 期望状态字段](#5-期望状态字段速查) · [6 样例索引](#6-样例索引) · [7 命令](#7-命令) · [8 排错](#8-常见拒绝原因与排错) · [9 安全须知](#9-安全须知) · [10 已知限制](#10-已知限制与未决事项)

## 1 概念

- **Agent 是进程内的内核编排器**，不是另一个守护进程。它跑在 `W1nCray` 主进程里，与 Xboard 的 `Nodes` 相互独立：可以只配 Agent、不配 Nodes。
- **只接受「期望状态」，不接受命令**。你给它一份完整的 `spec.Desired`（JSON），它负责：校验 → 按本地策略过滤 → 为每个实例选引擎 → 渲染该引擎的配置 → 端口预检 → 启动/热更 → 健康检查 → 失败则回滚到上一份可用状态。文件里没有的实例会被移除（整体应用，不是增量）。
- **引擎**：`gost`、`frp`、`realm` 都是外部内核，从**已签名的内核清单**安装（见 §3 `ManifestPath`），期望状态只能指定版本号，下载地址与哈希永远来自清单。（v11 起不再有内嵌转发引擎。）
- **本地策略是根信任**（§4）：期望状态无论从哪来，都不能放宽它。
- **应用是事务式的**：校验或渲染失败 → `rejected`，现场不动；应用中途失败 → 恢复上一份可用状态并把失败的这份内容「冻结」（`rolled_back`），内容不变就不再重试。

一次应用的结果是一个 `Report`（`agent-apply` 会把它以 JSON 打印出来，报告里不含任何 `secret`）：

```json
{
  "revision": 1,
  "hash": "1477e8e9…",
  "status": "applied",
  "message": "applied 2 instance(s)",
  "instances": [
    { "id": "auto-simple", "state": "running", "engine": "realm", "requested_engine": "auto",
      "config_hash": "a7758ab0…", "ports": ["tcp 0.0.0.0:21300"], "firewall_open": true },
    { "id": "auto-iphash", "state": "running", "engine": "realm", "requested_engine": "auto",
      "config_hash": "c9d4789f…", "ports": ["tcp 0.0.0.0:21301"], "firewall_open": true }
  ],
  "kernels": { "realm": "<已安装版本>" },
  "at": "…"
}
```

| `status` | 含义 | 现场 |
|---|---|---|
| `applied` | 全部运行且通过健康检查 | 已是新状态 |
| `rejected` | 期望状态不合法：违反 schema / 本地策略 / 没有引擎能跑 / 端口冲突 / 渲染失败 | **没有改动** |
| `failed` | 环境原因（如内核装不上、状态目录不可写） | 没有改动，可重试 |
| `rolled_back` | 应用中途失败，已恢复上一份可用状态；这份内容被冻结（`blocked`），改内容才会再试 | 恢复为旧状态 |
| `partial` | 回滚也只恢复了一部分 | **需要人工处理** |

`instances[].state`：`running`、`disabled`（`enabled:false`）、`rejected`、`failed`、`rolled_back`、`not_applied`。`validation_errors[]` 给出 `instance`、`index`、`field`、`message`，是排错的主要依据。

## 2 引擎能力与限制

> **v11 变更（WP-X1 / D5）**：agent 的**内嵌 xray 转发引擎已彻底删除**（PLAN v11 §2.5）：`driver/xray` 与 `corehost` 两个包已从仓库移除。`engine: xray` 的实例会被校验拒绝（`xray 转发引擎已移除，请使用 gost 或 realm`），`auto` 只在 gost / frp / realm 里选；`tunnel.security: vless_enc` 一并移除。Xray 本身改为独立的 `W1nCray-xray` 程序（见 §13），转发只用 gost / realm（frp 用于反向代理）。

下表**以各驱动 `Caps()` 为准**（`driver/gost/driver.go`、`driver/frp/frp.go`、`driver/realm/realm.go`），不要凭印象。Reconciler 在选引擎时用同一份数据拒绝不支持的特性，不会静默降级。

| 能力 | gost（外部） | frp（外部） | realm（外部） |
|---|---|---|---|
| 实例类型 `kind` | forward、tunnel_entry、tunnel_exit、reverse_portal、reverse_bridge | **仅** reverse_portal、reverse_bridge | forward、tunnel_entry、tunnel_exit（**无反向代理**） |
| 网络 | tcp、udp | tcp、udp | tcp、udp |
| 隧道载体 `tunnel.type` | tcp、tls、ws、wss、grpc | tcp、tls、ws、kcp、quic（**不支持 wss**） | tcp、tls、ws、wss |
| 反向代理 | 是（bridge 决定目的地；portal 不带 `targets`） | 是 | 否 |
| 接收 PROXY（`accept_proxy_protocol`） | 是 | **否** | 是 |
| 发送 PROXY（`proxy_protocol_out`，仅 TCP） | 是 | 是（仅 bridge） | 是 |
| 负载均衡策略 | round_robin、random、iphash、failover | 仅 failover（bridge 每端口一个目标；portal 不接受 `balance`） | round_robin、iphash |
| 健康检查（`Caps`） | passive | active（仅 bridge） | none |
| 统计 | api | api（仅 portal） | **none（不可计量）** |
| 重载方式 | api（REST 增删 service，不用整体重载） | api（frpc 仅改代理时）；**frps 改动即重启该 portal** | none（**改一个实例即重启该实例的进程，断开它的连接**） |
| 改动一个实例是否牵连其他实例 | 否 | 否（一实例一进程） | 否（一实例一进程） |
| 外部内核 / 安装体积 | 是 / ≈50 MB | 是 / ≈36 MB | 是 / ≈6.9 MB |

**`engine: auto`** 在能胜任的引擎里选：按安装体积从小到大，再按名字，即 **realm → frp → gost**（v11 起没有内嵌引擎可优先）。选择结果和被淘汰引擎的原因写在报告的 `engine` / `considered` 里；没有任何引擎能跑时**拒绝**并列出每个引擎的原因，不会降级。写了 `balance.health` 时，`auto` 优先选主动探测（active）的引擎；只有被动摘除（passive，gost）的引擎能跑时才选它，并在 `considered` 里注明「selected with passive health checks only」；没有故障检测能力（none，realm）的引擎会被拒绝，原因为 `health checks are not supported`。

各引擎还有这些「表里装不下」的约束（来自驱动的校验代码与文档，`engine` 写错时会收到对应拒绝信息，见 §8）：

- **gost**：不支持 `tls_pin`、`vless_enc`、`tunnel.alpn`；`tls_self` 可用（出口把 `secret` 派生的证书/私钥写进 state 目录，入口以同一张证书作 CA 并 `secure: true` 校验 `sni`），但只限 TLS 类传输（`tls` / `wss` / `grpc`），与 `tcp` / `ws` 组合会被拒；权重只对 `random` 策略生效（其他策略写了非 1 的权重会被拒）；`tunnel_exit` / `reverse_portal` 不支持 `proxy_protocol_out` 与 `limits`，portal 不支持 `acl`；`accept_proxy_protocol` 仅限 forward / tunnel_entry；`tunnel_exit` 的目标不能用端口范围；入口方（entry / bridge）不带 `cert` 时用系统根证书严格校验出口，所以出口应使用公共 CA 签发的证书；出口用私有 CA / 自签证书时，入口方写 `tunnel.cert: {mode: "file", cert_file: "<CA 绝对路径>"}` 把它作为信任锚（不能带 `key_file`）。`balance.health` 只支持 `type: tcp`，不接受 `timeout_s` / `probe_url`；这是被动摘除：`max_fails` 次失败后该目标暂时退出轮转，`interval_s` 是它被摘除的时长。
- **frp**：每个 portal 一个 `frps`、每个 bridge 一个 `frpc` 进程；不支持 `acl`、`limits`、`idle_profile`、`allow_any_target`；bridge 只能有一个 target（端口范围须与 `listen.ports` 等长）或用 `port_map`；公共端口不能等于控制端口。**bridge 默认不校验 portal 的证书**（frp 的默认行为），TLS 只防窃听、不防中间人；要校验就在 bridge 写 `tunnel.cert: {mode: "file", cert_file: "<CA 或 portal 证书的绝对路径>"}` 作信任锚（不能带 `key_file`，不支持客户端证书）；`balance` 只能用在 bridge 上，且只接受 `failover`（单目标），`health` 可用 `tcp` / `http`，不能与 `network` 含 udp 同用；`secret` 即 frp token（还要避开 `: @`，见 §5）。
- **realm**：无 ACL、无 limits、无健康检查（挂掉的目标仍会分到流量）；UDP 只能单目标；**隧道只支持 TCP，且只能 realm ↔ realm**；`tcp` / `tls` 隧道没有任何应用层认证（配 `secret` 会被拒），`ws` / `wss` 靠由 `secret` 派生的 path 令牌认证；只信任公共 CA 证书，不能固定指纹，**也不能用 `tls_self`**（自签证书无法校验，会被拒并提示改用 gost）；entry 只能一个监听端口、不能 `port_map`；**出口不是守门员**——任何能连到出口端口的主机都能让它向目标建连，务必用防火墙把来源限制为入口机。

`idle_profile`（空闲超时预设）在各引擎的实际取值：

| 预设 | gost | realm | frp |
|---|---|---|---|
| `tcp_long` | 3600 s | 无 TCP 空闲超时（预设为空操作） | 不支持 |
| `tcp_default`（TCP 的缺省） | 300 s | 同上 | 不支持 |
| `udp_short`（UDP 的缺省） | 30 s | 30 s | 不支持 |
| `udp_long` | 120 s | 120 s | 不支持 |

> 用 gost 转发 SSH / 数据库这类长连接时，请显式写 `"idle_profile": "tcp_long"`，否则会按 300 s 的缺省空闲断开。gost 在未指定 UDP 预设时用 60 s。

## 3 `Agent:` 配置块

agent 自己的配置可以放在两个地方：与 `config.yml` 同目录的 **`agent.yml`**（推荐），或 `config.yml` 里的 `Agent:` 块（旧布局，仍然兼容）。

### `agent.yml`（独立文件，推荐）

`agent.yml` 是 agent 配置的**根**（没有 `Agent:` 外层），字段名与 `config.yml` 的 `Agent:` 块完全相同。示例见 [`release/config/agent.yml.example`](../release/config/agent.yml.example)。

**优先级**：同目录只要存在 `agent.yml`，就**整体以它为准**——`config.yml` 里遗留的 `Agent:` 块被完全忽略（不合并、也不报错），`W1nCray check` 会打印一行 `! … 的 Agent 段被 agent.yml 覆盖（已忽略）`。没有 `agent.yml` 时行为不变：`config.yml` 的 `Agent:` 块生效。`agent.yml` 存在但解析失败会让配置加载失败（启动失败 / 热重载放弃），所以它握有**服务能否启动的否决权**：改动前先备份，`W1nCray check` 会把它的问题放在第一屏。

路径（`StateDir`、`KernelsDir`、`Panel.TokenFile`）相对**生效文件所在目录**解析；两个文件同目录时与以前完全一致。

```yaml
# /etc/W1nCray/agent.yml
Enabled: true
StateDir: /etc/W1nCray/state
Policy:
  AllowListen: ["0.0.0.0"]
  PortRange: [20000, 40000]
Panel:
  Enabled: true
  URL: https://panel.example.com
  MachineID: 12
  TokenFile: /etc/W1nCray/agent.token
  MachineNodes: true
Terminal:
  Enabled: false # 只在本机关闭交互终端（缺省开启）
Files:
  Roots: []
Modules:
  XrayNodes: true
Firewall:
  AutoOpen: true # 仅 OpenWrt：为对外监听的实例自动放行 WAN 端口（缺省即开启）
Kernels:
  AllowHTTP: false # 允许清单资产走明文 http:// 镜像（缺省 false = 只允许 https；仅本机可配）
Drivers:
  Frp:
    ReadyTimeoutSec: 0 # 0 = 按架构与 OpenWrt 缺省（见「驱动就绪等待」）
  Gost:
    ReadyTimeoutSec: 0 # 同上；两个驱动各自独立
```

| 段 | 字段 |
|---|---|
| 根 | `Enabled`、`StateDir`、`ManifestPath`、`ManifestKeysPath`、`KernelsDir`、`DesiredPath`（含义同下表） |
| `Policy` | 见 §4（本地根信任，远端无法放宽） |
| `Panel` | 见「机器模式节点」一节 |
| `Terminal` | `Enabled`（缺省 **true**）、`MaxSessions`（≤2）、`IdleTimeoutS`、`MaxDurationS` |
| `Files` | `Roots`、`Unrestricted`（**三态**，见下）、`AllowExec`、`MaxBytes`（单个受管文件 blob 上限，缺省 64 MiB；**负值 = 本机禁用 geo 下发**）、`MaxGeoBytes`（只覆盖 `geoip.dat`/`geosite.dat`，0 = 用 `MaxBytes`） |
| `Modules` | `XrayNodes`（缺省 true；false 时本机永不启动节点控制器） |
| `Firewall` | `AutoOpen`（**三态**，见「路由器防火墙自动放行」：OpenWrt 上缺省 true，其它系统恒为 false） |
| `Kernels` | `AllowHTTP`（缺省 **false**：内核清单的资产只允许 `https://`；见「内网 http 镜像」） |
| `Drivers` | `Frp.ReadyTimeoutSec`、`Gost.ReadyTimeoutSec`（frp / gost 实例就绪等待上限；**0 = 按架构与 OpenWrt 缺省**：amd64/arm64 且非 OpenWrt 15s，其它一律 60s；见「驱动就绪等待」） |

**迁移（旧布局 → `agent.yml`）**：`W1nCray link` 现在把连接信息写进 `agent.yml`，不再写 `config.yml`：

- 目标目录没有 `agent.yml`：写出一份新的 `agent.yml`（**原子写**：同目录临时文件 + rename，权限 0600），`config.yml` 只保留 xray 内核的配置。
- `config.yml` 里还有旧的 `Agent:` 块：该块被**迁移**进 `agent.yml`——本机设置（`Policy`、`DesiredPath`、`Terminal`、`Files`、`Modules` 等）原样保留（所以已经本地关闭终端的机器迁移后仍然是关闭的）；`Panel` 段按本次 `link` 的参数重写，但 link 不负责的 Panel 键（`ManifestSync`、`PullIntervalSec`、`NodeController` 模板等）同样保留，不会被悄悄改回默认值；`config.yml` 原处留一行 `# Agent: 段已迁移到 agent.yml …` 注释。迁移后的配置能通过 `W1nCray check`。
- **节点早已转成机器模式、只剩 `Agent:` 块的机器**（例如由 v0.4 的 `link` 转换过的落地机）：普通 `link` 会因"Nodes: 段里没有节点条目"拒绝。改用纯布局拆分 `W1nCray link --split [--noterminal] [--dry-run] [--force]`：把现有 `Agent:` 块**原样**搬进 `agent.yml`（不需要也不接受 `--panel/--machine/--token`，令牌与连接信息都在块里），`config.yml` 原处留一行注释。写入前校验"拆出的 `agent.yml` 与原块解析结果完全一致"且能独立加载；写入后若完整离线检查出现原配置没有的问题，自动恢复原文件。两份原文件都会先备份；完成后 `W1nCray check` 再 `W1nCray restart`。
- `agent.yml` 已经存在：**拒绝覆盖**并给出明确错误（不会动任何文件）；只有 `link --force` 才覆盖，且**先备份**为 `agent.yml.bak-<时间戳>`。
- `--dry-run` 依然不写任何文件（`config.yml`、`agent.yml`、令牌、备份都不写）。
- 写入前仍做「只比较本次转换**新增**的失败项」的基线校验；`--skip-check` 跳过它。

**终端（D8 / RULINGS v9 第 17 条）**：交互终端**默认开启**——不写 `Terminal` 段即为开启。机器只能在**本地**关闭它：写 `Terminal: {Enabled: false}`，或在安装/关联时用 `--noterminal`（`install.sh --noterminal`、`W1nCray link --noterminal`）。面板无法远程打开或关闭它：本机状态只通过 `hello.policy` 上报，面板据此显示「该机器已在本地关闭终端」。

> ⚠️ **升级提醒**：已经部署的机器升级到带终端的版本后，由于缺省是开启，会**自动获得终端能力**（面板可以申请交互会话）。不需要的机器请显式写 `Terminal: {Enabled: false}`，或用 `--noterminal` 重新关联。

**文件管理（D9 / PLAN v10）**：`Files.Roots` 是 `file_*` 命令能到达的目录（缺省 = xray 配置目录 + agent 状态目录）。`Files.Unrestricted` 是**三态**开关：

- **不写**（缺省）：跟随终端。终端有效开启（见上，缺省开启）→ 文件管理**不受限**。理由：终端就是一个 root shell，根目录限制只剩不便，没有安全意义。
- **显式 `true`**：不受限，与终端开关无关。
- **显式 `false`**：永远受 `Roots` 限制，即使终端开着。

`W1nCray check` 会报出**有效值**（`hello.policy.files.unrestricted`），面板据此显示与组装命令。**不受限模式**下路径必须是绝对路径（`Resolve` 忽略 `root` 参数），因此面板应传 `root: ""` + 绝对 `path`；`Roots` 仍照常上报，只是不再参与路径解析（它们是给面板的快捷入口）。**受限模式**的约定不变：`root` 是本机命名的 root 名（`xray`/`state`/…），`path` 是相对路径。不受限模式下即使 `Roots` 为空，`file_*` 命令与 `files` 能力照样提供。

### 路由器防火墙自动放行（OpenWrt，D2）

OpenWrt 系（OpenWrt / ImmortalWrt / iStoreOS / KWRT）默认拒绝 WAN 入站，所以在路由器上监听的转发端口，从外网连不上。agent 在 **OpenWrt** 上会为每个对外监听的实例维护一条 UCI 防火墙规则。这个开关是**本机**的，面板无法打开或关闭：

```yaml
Firewall:
  AutoOpen: true # OpenWrt 上缺省即 true；false = 本机完全不碰防火墙
```

| 情况 | `hello.policy.firewall.auto_open` | 行为 |
|---|---|---|
| OpenWrt，未写 `Firewall` 段 | `true` | 自动放行（缺省） |
| OpenWrt，`AutoOpen: false` | `false` | 完全不动防火墙 |
| 其它系统 | `false` | 本期不实现（agent 从不碰防火墙） |

每个实例一条规则，section 名固定、可识别：

```
config rule 'w1ncray_<实例id>'
	option name 'W1nCray <实例名>'
	option src 'wan'
	option proto 'tcp'          # 或 'tcp udp'，按实例的 network
	option dest_port '8443'     # 端口范围写成 '20000-20009'
	option target 'ACCEPT'
```

- **只动自己的规则**：agent 只读、建、改、删 section 名以 `w1ncray_` 开头的规则；用户自己的规则、zone、defaults 一律不碰。
- **UCI section 名**只允许 `[A-Za-z0-9_]`（`-` 会被 uci 以 `Invalid argument` 拒绝），所以实例 id 里的 `-` 写成 `_d`、`_` 写成 `__`（可逆、不冲突）：id `d2-fwd2` 的 section 是 `w1ncray_d2_dfwd2`，id `d2fwd1` 是 `w1ncray_d2fwd1`。
- **只放行对外监听的实例**：`forward` / `tunnel_entry` / `reverse_portal` 用 `listen.addr`，`tunnel_exit` 用 `tunnel.listen`；`listen.addr` 是回环（`127.0.0.1` / `::1`）的实例、`enabled: false` 的实例、以及 `reverse_bridge`（它只主动连出，公网端口属于 portal 实例）都不放行。
- **同步**：每次应用成功后按当前实例集合对账——新增，端口或 proto 变化即更新，实例删除即删除；agent 启动时再对账一次，删除遗留的 `w1ncray_*` 规则。有改动时先 `uci commit firewall` 再重载：OpenWrt ≥ 22.03 用 `fw4 reload`，21.02（fw3/iptables）用 `/etc/init.d/firewall reload`。没有改动就不 commit、不重载。重载失败会重试（最多 3 次，退避 1s/2s，整个重载循环总时长上限 20s）。
- **失败不拆实例**：防火墙命令失败只记一条 warn，实例继续运行（本机转发仍然可用），对应实例的 `firewall_open` 为 `false`；不会因为防火墙失败回滚正在运行的实例。若失败发生在 `uci commit` 之后（规则已保存、重载失败），重试都失败时报告消息写明「规则已保存、尚未生效」，下一次成功重载（下一次 apply 或重启）即生效。
- **端口解析失败不静默跳过**：实例的端口声明解析失败时它拿不到规则，agent 记一条含实例 id 的 warn，并把「哪些实例没有规则、为什么」一并返回给 reconciler 写进报告消息；`firewall_open` 为 `false`。这不需要新的面板协议字段。
- **状态上报**：实例状态里新增 `firewall_open`（`/ack` 的 `report.instances[]` 与 `/report` 的 `instances[]`）。它只在 agent 确实放行了该实例的公网端口时为 `true`；机器不由 agent 管理防火墙时恒为 `false`，面板要结合 `hello.policy.firewall.auto_open` 解读。

### 内网 http 镜像（`Kernels.AllowHTTP`，D-M1）

内核（gost / frp / realm / xray）只从**已签名清单**安装：清单签名、`archive_sha256` 与每个成员文件的 `sha256` 都由 agent 在本机校验，**下载走什么协议不影响完整性**。所以清单里写了明文 `http://` 镜像（自建/内网、没有 TLS）时，agent 默认仍然拒绝，报：

```
…: download failed: all 1 sources failed: http://mirror.example/dist/W1nCray-xray-linux-amd64.gz: scheme not allowed
```

本机想用 http 镜像时，在 `agent.yml`（或 `config.yml` 的 `Agent:` 块）打开这个开关：

```yaml
Kernels:
  AllowHTTP: true # 缺省 false = 只允许 https
```

- **只能本地配置**：面板下发的是期望状态与受管文件，不是 agent 配置，无法打开或关闭它；本机状态通过 `hello.policy.kernels.allow_http` 上报，面板据此显示「该机器允许 http 镜像」。
- **只影响 scheme**：签名、有效期、吊销、序号防回滚、`min_agent`、平台 target、archive/成员哈希校验一律照旧（fail-closed 不变）。https 与 http 源可以混在同一个清单里，按清单顺序尝试。
- `W1nCray check` 会打印该开关；`W1nCray xray install` 与常驻服务读同一份配置、同一个值。

### 驱动就绪等待（`Drivers.Frp.ReadyTimeoutSec` / `Drivers.Gost.ReadyTimeoutSec`，D4/F6）

frp 驱动每启动一个实例（portal 的 `frps`、bridge 的 `frpc`）都要等它就绪：管理 API 能应答，portal 还要控制链路建立。gost 驱动同样要等 gost 进程起来、REST API 能应答（旧上限是写死的 10 s）。两个驱动的等待上限现在共用同一张表：

| 架构 | 非 OpenWrt | OpenWrt |
|---|---|---|
| `amd64`、`arm64` | **15 s** | **60 s** |
| 其它（`mips`/`mipsle`、`arm`、`386`、`riscv64` …） | **60 s** | **60 s** |

也就是说只有「64 位 x86/ARM 且不是 OpenWrt」才走 15 s 快档。路由器 CPU 比它的 GOARCH 看起来弱得多（arm64 的 MT7981 / Cortex-A53 不是 arm64 服务器）：v11 D4 的模拟机测试里 frps 在 15 s 内没起来就被判失败、重启，进而拖垮一批用例；T2 复测显示模拟 arm64 上仍有 3 次就绪超时，gost 也仍受它自己写死的 10 s 影响。按架构 + 是否 OpenWrt 放宽后，这些设备无需改配置即可工作。

比缺省还慢的机器可以本机覆盖（单位秒，**只能本地配置**，两个驱动各自独立）：

```yaml
Drivers:
  Frp:
    ReadyTimeoutSec: 90 # 0（或不写）= 按上表缺省；负值会被配置校验拒绝
  Gost:
    ReadyTimeoutSec: 120
```

超时的报错形如 `frp: frps-rp did not become ready in time (see the log of instance rp)` 或 `gost: process did not become ready: api not ready: …`；看到它说明该实例在对应上限内没起来，先看实例日志（端口占用、证书、token），确实只是启动慢再调大这个值。

### `config.yml` 的 `Agent:` 块（旧布局）

写在 `config.yml` 里（与 `Nodes` 同级，YAML）。未启用（`Enabled: false` 或整块缺省）时 Agent 完全不工作。同目录一旦出现 `agent.yml`，本块即被整体忽略（见上）。

```yaml
Agent:
  Enabled: true
  DesiredPath: /etc/W1nCray/desired.json
  ManifestPath: /etc/W1nCray/manifest.json
  ManifestKeysPath: /etc/W1nCray/keys.txt
  StateDir: /etc/W1nCray/state
  KernelsDir: /etc/W1nCray/state/kernels
  Policy:
    AllowListen: ["0.0.0.0"]
    PortRange: [20000, 40000]
```

| 字段 | 默认 | 含义 |
|---|---|---|
| `Enabled` | `false` | 总开关。只有它为 `true` 时才校验与启用本块；没有 `Nodes` 时必须启用 Agent，否则配置被判无效（`no Nodes configured and Agent.Enabled is not set`） |
| `DesiredPath` | 空 | 期望状态 JSON 文件。设置后：启动时应用一次；之后文件被写入/创建/重命名时**去抖 500 ms 自动重新应用**，无需重载整个进程。应用失败只记日志（`agent: apply <path>: …`）并保留旧状态。未设置时 Agent 不会自己读任何文件（可用 `agent-apply` 手动应用） |
| `ManifestPath` | 空 | 已签名的内核清单。**不设置时没有任何转发内核可用**（v11 起没有内嵌引擎），gost / frp / realm 都无法安装（报「no signed kernel manifest loaded (set Agent.ManifestPath)」）。设置后不再读取面板同步的持久化副本（见 §3「内核清单自动同步」） |
| `ManifestKeysPath` | 空 | 额外信任的 ed25519 公钥文件（hex，每行一个），叠加在二进制内嵌公钥之上，供本地/自托管使用；生产信任根是编译时内嵌的公钥。没有任何公钥时任何清单都会被拒（fail-closed，预期行为） |
| `StateDir` | 配置文件所在目录下的 `state` | Agent 状态目录：已应用/上次可用的期望状态、冻结记录、各驱动的私有目录、PID 目录。文件权限 0600（含 `secret`） |
| `KernelsDir` | `StateDir/kernels` | 外部内核安装目录 |
| `Kernels.AllowHTTP` | `false` | 允许内核清单的资产走明文 `http://` 镜像（本机开关，见「内网 http 镜像」；签名与 sha256 校验不受影响） |
| `Drivers.Frp.ReadyTimeoutSec` | `0`（按架构与 OpenWrt） | frp 实例就绪等待上限（秒）；0 = amd64/arm64 且非 OpenWrt 15s，其它一律 60s（见「驱动就绪等待」） |
| `Drivers.Gost.ReadyTimeoutSec` | `0`（按架构与 OpenWrt） | gost 实例就绪等待上限（秒）；0 = 与 frp 同一张表（见「驱动就绪等待」）；负值被配置校验拒绝 |
| `Policy` | 见 §4 | 本地根信任策略 |

校验：`PortRange` 必须恰好两个元素 `[lo, hi]`；`Policy.AllowEngines` 只能出现 `auto` / `xray` / `gost` / `frp` / `realm`（`xray` 只是保留的名字，写了也会在校验阶段被拒）。**建议留空**：留空表示不限制引擎，面板下发的实例可选任一引擎，实际可用性由已签名清单决定（gost / frp / realm 由 agent 按需下载安装，见 §3 与 §4）。

### 机器模式节点（`MachineNodes`）

在面板上把节点绑定到一台「机器」后，本机不必再逐个写 `Nodes`，只配一个机器令牌即可：W1nCray 用 `Agent.Panel` 的 `URL` / `MachineID` / `Token`（或 `TokenFile`）向面板查询这台机器名下的节点，并为每个节点自动起一个控制器。节点增删由面板决定，本机不改配置、不重启。

> 下面的例子按 `config.yml` 的旧布局写；放进 `agent.yml` 时去掉 `Agent:` 这一层（`Panel:` 顶格），其余完全不变。

```yaml
Nodes: []          # 机器模式下允许为空；静态 Nodes 与机器节点可以共存
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: https://panel.example.com
    MachineID: 12
    TokenFile: /etc/W1nCray/machine.token
    MachineNodes: true
    NodeController:            # 机器节点共用的 ControllerConfig 模板
      ListenIP: 0.0.0.0
      CertConfig:
        CertMode: dns
        Provider: cloudflare
        DNSEnv:
          CF_DNS_API_TOKEN: "..."
```

| 字段 | 默认 | 含义 |
|---|---|---|
| `MachineNodes` | `false` | 打开机器模式。要求 `Agent.Enabled` 与 `Agent.Panel.Enabled`，否则配置被判无效（`MachineNodes requires Agent.Panel.Enabled` / `Agent.Panel.Enabled requires Agent.Enabled`） |
| `NodeController` | 节点默认值（`ListenIP: 0.0.0.0`、`SendIP: 0.0.0.0`、`DNSType: AsIs`） | 机器节点共用的 `ControllerConfig`（`ListenIP`、`CertConfig`、`DisableWebSocket` …）。只写想覆盖的字段，其余回落到 `node.DefaultConfig()` |
| `NodeControllers` | 空 | 按**面板节点 ID** 的本地覆盖（见下节），键是面板分配的节点 ID，值是一份完整的 `ControllerConfig` |

行为与边界：

- **认证**：请求头 `X-Machine-Id: <MachineID>` + `Authorization: Bearer <令牌>`；令牌**绝不**出现在 URL、日志或报错里。面板返回 401 `bad_credentials` / 403 `machine_disabled` / 404 `unknown_node` 时，分别映射为凭据错误、机器被禁用、未知节点（错误里保留 HTTP 状态码）。
- **发现失败不影响静态节点**：面板不可达或令牌错误时，静态 `Nodes` 照常启动，只记一条 warn（`machine nodes: … (static nodes keep running; retrying)`），并在后台延时 30 s 通过重载机制重试。
- **节点变化自动生效**：启动后每 60 s 查询一次节点列表的 `version`，变化即触发一次整体重载（`reloading: machine nodes changed`）：新增的节点被拉起，移除的节点被关闭。
- **面板可以要求立即刷新**：`hint{what:"nodes"}` 到达 agent 后，agent 通过内核本地接口（§13.4 的 `GET /nodes/sync`）让**内核立刻重跑一次**上面的「取 version → 变了才重载」。绑定/解绑节点不再需要等最长 60 s 的轮询；列表没变时空转的 hint 不触发重载。内核未安装、内核太旧（没有该路由，返回 404）或调用失败（面板不可达、超时）时，agent 只记一条 warn（`bootstrap: xray nodes hint: …; falling back to the kernel's 60s machine-node poll`）并退回 60 s 轮询，**不会**让命令失败或崩溃。`policy.modules.xray_nodes` 仍是本机闸门：为假时 hint 直接拒绝（§3 的 `Modules`）。
- **机器节点不启用 WebSocket**：面板 WS 握手会把令牌放进 URL，违反「令牌不进 URL」，所以机器节点只走 HTTP 轮询（debug 日志 `machine mode: websocket disabled, using HTTP polling`）。
- **`W1nCray check`**：离线时打印机器 ID 与「节点由面板下发」；加 `--online` 才联网，列出节点数与列表版本。有本地覆盖时还会列出被覆盖的节点 ID（只有 ID，没有任何内容）。
- 机器节点的 tag 形如 `node<节点ID>@machine<机器ID>`，与静态节点的 `node<节点ID>@<主机>` 不会重名。

#### 按节点本地覆盖（`NodeControllers`）

同一台机器上的三个节点，本地配置往往并不相同：有的要 PROXY protocol，有的要自己的证书，有的要 DNS/REALITY。`NodeControllers` 按**面板节点 ID** 覆盖 `NodeController`：键是面板分配给节点的 ID，值是一份完整的 `ControllerConfig`（字段与 `Nodes[].ControllerConfig` 完全相同）。选择规则是「要么整份覆盖，要么回落」，绝不逐字段合并，避免隐式继承出意外：

| 情况 | 使用的配置 |
|---|---|
| `NodeControllers[id]` 存在 | **整体**使用它（不与 `NodeController` 逐字段合并） |
| 没有该 id | `NodeController` 模板 |
| 两者都没有 | `node.DefaultConfig()`（`ListenIP`/`SendIP: 0.0.0.0`、`DNSType: AsIs`） |

被使用的配置都会先补全节点默认值（与 `NodeController` 走同一套逻辑），所以只写想改的字段即可。校验：键必须是正整数（`node id <id> must be a positive number`），值不能为 nil（`NodeControllers[<id>] must not be empty`）。

```yaml
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: https://panel.example.com
    MachineID: 12
    TokenFile: /etc/W1nCray/machine.token
    MachineNodes: true
    NodeControllers:
      # 119：不写。没有 NodeController 模板时，它就是纯 node.DefaultConfig()
      173:                      # PROXY protocol + DNS 申请证书（Cloudflare 凭据只留本机）
        EnableProxyProtocol: true
        CertConfig:
          CertMode: dns
          CertDomain: node173.example.com
          Provider: cloudflare
          DNSEnv:
            CF_DNS_API_TOKEN: "<只在 173 上填写；不要提交到仓库，也不要发给面板>"
      138:                      # DNS 解析 + 本机 REALITY 参数
        EnableDNS: true
        DNSType: UseIPv4
        EnableREALITY: true
        REALITYConfigs:
          Show: false
          Dest: www.microsoft.com:443
          ServerNames: [www.microsoft.com]
          PrivateKey: "<只在 138 上填写>"
          ShortIds: [""]
```

- **凭据留在本机**：`NodeControllers` 只在本机读取。面板只下发「这台机器有哪些节点」和每个节点的用户定义，从不接收本机的证书、DNS 凭据或 REALITY 私钥；`W1nCray check` 也只列被覆盖的节点 ID，不打印其中任何内容。
- **覆盖是整份替换**：模板里的设置不会自动带进来。例如模板设了 `DisableWebSocket: true`，某节点想改回默认行为，就在它的覆盖里显式写 `DisableWebSocket: false`。
- **面板没分配的覆盖不是错误**：`NodeControllers` 里写了、但面板当前没有分配给这台机器的节点 ID，只记一条 info 日志（`NodeControllers[<id>] is configured but the panel did not assign that node`）；节点以后可能再分配回来。
- **空值不会变成覆盖**：YAML 里的 `173:`（没有内容）与 `173: {}` 都会被解析器直接丢掉，不会生成一份「空覆盖」；所以想让某个节点不继承模板，必须至少显式写一个字段（例如 `DisableWebSocket: false`）。

#### 一键接入（`install.sh --panel`）

面板管理页给管理员生成的一键命令形如：

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/W1nCwC/W1nCray/main/install.sh) install \
  --panel https://panel.example.com --machine 3 --token <TOKEN>
```

安装脚本在装好二进制与服务的同时，写出机器模式配置：`config.yml` 只写 xray 侧（`Log: {Level: info}`），agent 侧写进 `<配置目录>/agent.yml`。

| 参数 | 说明 |
|---|---|
| `--panel URL` | 面板地址。必须 `https://`；仅本机回环（`localhost` / `127.x` / `::1`）可用明文 `http://`。末尾斜杠会被去掉 |
| `--machine ID` | 面板上的机器 ID，必须是正整数 |
| `--token TOKEN` / `--token-file FILE` | 二选一提供机器令牌；`--token-file` 读文件（首尾空白与换行会被去掉） |
| `--allow-http` | 面板地址是**非回环**的 `http://` 时必须显式给出，否则拒绝安装并说明原因 |
| `--port-range LO-HI` | `Policy.PortRange`，默认 `20000-40000` |
| `--noterminal` | 在本机关闭交互终端（终端默认开启），并透传给提示里的 `W1nCray link` 命令 |

- `--panel` / `--machine` / 令牌三者必须同时提供，缺任何一个都会以中文报错并非 0 退出；`--port-range`、`--allow-http` 与 `--noterminal` 只在 `--panel` 下有效。
- 令牌写入 `<配置目录>/agent.token`（先 `umask 077` 再写，再 `chmod 600`，内容不带换行），生成的 `agent.yml` 用 `Panel.TokenFile` 引用它；令牌**不会**进入 `config.yml`、`agent.yml`、日志或传给子进程的参数。`uninstall` 会一并删除 `agent.token`。
- 加 `--allow-http` 时 `agent.yml` 里会写 `AllowInsecureHTTP: true`（否则 `Agent.Panel` 会拒绝明文 http 的非回环地址）。
- `agent.yml` 是**原子写**（同目录临时文件 + `mv`，权限 0600）；覆盖已有的 `agent.yml` 前会先备份为 `agent.yml.bak-<时间戳>`。
- **幂等**：若 `agent.yml` 已存在且已关联面板（`Panel.Enabled: true`），安装**不覆盖**它，只以黄色提示说明；`config.yml` 已存在时同样不覆盖（只提示）。
- 若 `config.yml` 已存在且还有静态 `Nodes`：安装不覆盖它，也不写 `agent.yml`，而是提示先在面板绑定这些节点，再手动执行 `W1nCray link …`（`link` 把静态节点与旧的 `Agent:` 段迁移到 `agent.yml`）；提示里的 `link` 命令会带上你给的 `--noterminal`。
- 机器模式安装时的配置检查是离线的（`check` 不带 `--online`）：面板暂时不可达不会阻止服务启动，agent 会在后台重试领取节点。
- 安装结束会提示「已关联面板，agent 将自动领取节点与转发规则」并给出查看日志的命令；提示里不回显令牌。

### 内核清单自动同步（`ManifestSync`）

外部内核（gost / frp / realm）的可执行文件由一份**已签名清单**约束。清单可以由面板托管：agent 用机器令牌定时拉取，但**真伪只由 agent 本机验签决定**（内置 ed25519 公钥）。面板即使被攻破，没有私钥也下发不了恶意内核；任何验签失败的内容一律丢弃，不写盘，也不影响正在运行的实例。

```yaml
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: https://panel.example.com
    MachineID: 12
    TokenFile: /etc/W1nCray/machine.token
    ManifestSync: true          # 缺省即 true；设 false 关闭
    ManifestIntervalSec: 3600   # 缺省 3600；范围 [300, 86400]
```

| 字段 | 默认 | 含义 |
|---|---|---|
| `ManifestSync` | `true` | 是否从面板同步内核清单。仅在 `Agent.Enabled` 且 `Agent.Panel.Enabled` 时生效；设为 `false` 时面板不会提供清单，只能靠本机 `Agent.ManifestPath` |
| `ManifestIntervalSec` | `3600` | 同步间隔（秒），被限制在 `[300, 86400]`。成功一轮后按 ±10% 抖动等待；失败按 30 s 起指数退避（上限 5 min） |

端点与协议：`GET {URL}/api/v2/server/machine/agent/manifest`，请求头 `X-Machine-Id` + `Authorization: Bearer <令牌>`（**令牌不进 URL、日志与报错**）。`200` 返回清单 JSON（带 `ETag`）；带 `If-None-Match` 且未变化返回 `304`；面板还没有清单返回 `404 {"error":"no_manifest"}`；`401` / `403` 与其它 agent 端点一致。

行为：

- **启动后立即拉一次**，之后按间隔轮询；循环随服务退出而结束，不会留下后台 goroutine。
- `200`：响应体上限 **1 MiB**；交给本机验签（`install.LoadManifest`：签名、有效期、吊销、序号防回滚），**通过**才原子写入 `<StateDir>/manifest.json`（权限 0600，临时文件 + rename）并记住 `ETag`；**不通过**只记一条 warn（不含清单内容）、不写盘、不更新 `ETag`，已在用的清单继续生效。
- `304`：清单未变，什么都不做；`404`：面板尚未发布，只记 debug；网络错误或 `5xx`：记 warn 并退避重试，不会 panic，也不影响运行中的实例。
- **启动时**：若没有配置 `Agent.ManifestPath` 而 `<StateDir>/manifest.json` 存在，就用它作为初始清单——同样要过本机验签；验签失败（被篡改、过期、序号回退）只记 warn，agent 继续运行并等待面板同步。
- `W1nCray check` 会打印清单同步的开关与间隔；加 `--online` 时还会实际拉取一次并报告 `sequence`（**不打印清单内容**，签名仍由 agent 在本机校验）。

> 与 `Agent.ManifestPath` 的关系：`ManifestPath` 是操作者手工放置的清单，优先级更高——只要设置了它，就不再读取 `<StateDir>/manifest.json`。面板同步写入的持久化副本只在 `ManifestPath` 为空时用于下次启动。

## 4 本地策略 `Policy`

策略只能写在本机配置里，**远端或文件里的期望状态无法放宽它**。字段与默认值取自 `panel/config.go`（`AgentPolicy`）和 `agent/validate`（`NormalizePolicy`）。**默认就是拒绝**：不写 `Policy` 时，只允许监听 `127.0.0.1`、不允许 1024 以下端口、不允许私网目标、不允许任意目标、不允许公网监听接收 PROXY。

| 字段 | 默认 | 含义 |
|---|---|---|
| `MaxInstances` | 64（≤0 取默认） | 期望状态最多多少个实例，超出报错。0 **不是**无限 |
| `MaxPortsPerInstance` | 256（≤0 取默认） | 单个实例监听（端口范围）或映射的端口数上限 |
| `AllowListen` | `["127.0.0.1"]` | 允许监听的地址列表：IP 或 CIDR。`0.0.0.0` 表示任意 IPv4、`::` 表示任意 IPv6。同时约束 `listen.addr` 与 `tunnel.listen` |
| `PrivilegedPorts` | `false` | 是否允许监听 1024 以下端口 |
| `PortRange` | 不限（`[0,0]`） | 允许监听的端口区间 `[lo, hi]`；只写下界时上界取 65535 |
| `DenyPorts` | 空 | 额外禁止监听的端口 |
| `DenyCIDRs` | 空 | **额外**禁止的目标网段（IP 或 CIDR），叠加在下面「始终拒绝」之上 |
| `AllowPrivate` | `false` | 是否允许目标为私网（RFC1918、CGNAT `100.64.0.0/10`、`fec0::/10`、ULA）。**开启后环回、链路本地、云元数据等仍被拒** |
| `AllowAnyTarget` | `false` | 是否允许 `tunnel_exit` 使用 `allow_any_target`（出口替入口去连任意地址，等于开放中继） |
| `AllowAcceptProxyOnPublic` | `false` | 是否允许在非环回、非私网的地址上 `accept_proxy_protocol`（PROXY 头可伪造） |
| `AllowEngines` | 空（=不限制） | 允许使用的引擎白名单。**默认不限制**：留空表示面板下发的实例可选任一引擎，gost / frp / realm 由 agent 按需从已签名清单下载安装（可用性由清单决定，不由本字段决定）。写了名单时，不在名单里的引擎显式指定会被拒，`auto` 只在名单内选。`xray` 不在可选项里（内嵌引擎已删除） |

**目标地址「始终拒绝」**（与 `AllowPrivate` 无关，来自 `agent/validate/hosts.go`）：未指定地址、环回、链路本地、多播、`0.0.0.0/8`、`240.0.0.0/4`、云元数据地址（`169.254.169.254`、`169.254.170.2`、`100.100.100.200`、`168.63.129.16`、`192.0.0.192`、`fd00:ec2::254`），以及内嵌了以上 IPv4 的 IPv6 形式。主机名必须是 ASCII 的 LDH 名称（IDN 用 punycode），`localhost` / `*.localhost` 被拒；域名在**校验期**解析一次，解析失败或任何一个解析结果违规都拒绝（fail-closed）。内核之后还会再解析，所以存在 DNS 重绑定的时间窗，敏感场景请用字面 IP。注意 `tunnel.server`（隧道对端）也按目标规则检查：入口/桥端要连的出口/portal 若在私网，同样需要 `AllowPrivate`。

**样例需要的最小本地策略**（`TestLocalPolicyNeeds` 守护）见 §6 表中「本地策略」列：除两个仅回环监听的 PROXY 接收样例外，其余样例监听 `0.0.0.0`，需要 `AllowListen` 包含它；两个 bridge 样例的目标是内网地址，需要 `AllowPrivate: true`。样例端口都在 20000–40000，可直接配合 README 里的 `PortRange: [20000, 40000]`。

## 5 期望状态字段速查

`spec.Desired`（`agent/spec/spec.go`）。解码是**严格**的：未知字段（拼错的字段名）和文件尾部多余内容都会报错；JSON 不支持注释，说明请写在实例的 `name` 里。

顶层：

| 字段 | 说明 |
|---|---|
| `version` | 必须为 `1` |
| `revision` | 整数，记录用。内容哈希**不含** revision，只改 revision 不会重新应用（返回 `unchanged`） |
| `kernels` | 可选，`[{name, version}]` 固定内核版本；`name` 取 xray/gost/frp/realm，同一内核不能重复；版本必须在清单里。省略则用清单中该内核可安装的最高版本 |
| `instances` | 实例数组，受 `MaxInstances` 限制；整体应用，缺失的实例会被移除 |

实例 `Instance`：

| 字段 | 说明 |
|---|---|
| `id` | 必填，`[a-z0-9_-]{1,40}`，文件内唯一且稳定（改 id = 删旧建新） |
| `name` | 可选，≤64 字符，不得含空格、引号、`` ` \ # ; $ < > { } | & `` 和控制字符。本手册样例用它写一句中文说明 |
| `enabled` | `false` 的实例不运行、不占端口、不做 DNS 检查 |
| `engine` | `auto` / `gost` / `frp` / `realm`；`xray` 是已删除的内嵌引擎，写了会被拒（`xray 转发引擎已移除`） |
| `kind` | `forward` / `tunnel_entry` / `tunnel_exit` / `reverse_portal` / `reverse_bridge` |
| `listen` | `{addr, ports, port_map}`。`addr` 必须是字面 IP；`ports` 为单端口 `"8443"` 或范围 `"20000-20009"`（单端口不要写成 `"x-x"`）；`port_map`：`{"监听端口":"host:port"}`，键必须是 `ports` 内的单个端口，**覆盖** `targets` 对该端口的映射，仅限 forward / tunnel_entry |
| `network` | `["tcp"]`（缺省）、`["udp"]` 或 `["tcp","udp"]`；不可重复 |
| `targets` | `[{host, ports, weight}]`，≤64。`ports` 是单端口或与 `listen.ports` **等长**的范围（一一映射）；`weight` 0 表示 1 |
| `balance` | `{strategy, health}`；`strategy` ∈ round_robin / random / iphash / failover / least_ping（引擎支持的子集见 §2）；`health` = `{type: tcp\|http, interval_s 0–3600, timeout_s 0–300, max_fails 0–100, probe_url}`，`probe_url` 只能是以 `/` 开头的路径且仅 `type: http` 可用 |
| `proxy_protocol_out` | 0 / 1 / 2，向目标发送 PROXY 头；**仅 TCP**，不能与 `network` 含 udp 组合 |
| `accept_proxy_protocol` | 监听口要求 PROXY 头；**仅 TCP**，仅 forward / tunnel_entry / reverse_portal；公网监听需要策略放开 |
| `tunnel` | `{type, server, listen, host, path, sni, alpn, security, pin_sha256, cert}`，见下 |
| `reverse` | `{link, domain, bridge_allow}`，仅 reverse_*；`link` 只是配对标记；`domain` 是已删除的 xray 反向代理的会合名，**没有引擎再读取它**，但为兼容旧面板仍须通过随机性校验（十六进制 ≥32 字符或 base64url ≥22 字符，且字符种类 ≥8）；`bridge_allow` 只被 frp 用作目的地白名单（gost 忽略），新样例不要使用，目的地一律写在 bridge 的 `targets` 里 |
| `idle_profile` | `tcp_long` / `tcp_default` / `udp_short` / `udp_long`；`tcp_*` 需要 network 含 tcp，`udp_*` 需要含 udp |
| `limits` | `{max_conns, rate_up_bps, rate_down_bps}`，0 不限；速率单位为 **bit/s**（`8000000` = 8 Mbit/s）；realm / frp 不支持 |
| `acl` | `{allow, deny}`，来源 IP 或 CIDR；`allow` 非空时只放行列表内来源（gost 中 `deny` 先判）。对 `tunnel_exit` 来说「来源」是入口机的地址，可用它把出口限制为只有入口机能连（realm / frp 不支持 ACL） |
| `allow_any_target` | 仅 `tunnel_exit`，与 `targets` 互斥，且需要策略 `AllowAnyTarget` |
| `secret` | 隧道/反向链路的共享密钥，两端必须相同。16–256 字符，只允许 `[A-Za-z0-9_.+/=-]`——这是三个引擎都接受的交集（frp 不收 `: @`，gost 只收可打印 ASCII）；含其他字符在校验阶段就被拒绝 |

各 `kind` 要填什么：

| kind | `listen` | `tunnel` | `secret` | `targets` |
|---|---|---|---|---|
| `forward` | 必填 | 不允许 | 不允许 | 必填（或 `port_map` 覆盖每个监听端口） |
| `tunnel_entry` | 必填（用户连入的口） | 必填，写 `server`（出口的 `host:port`） | 必填 | 可选；写它表示入口要求出口连这个目的地，留空则由出口用自己的 `targets` 决定 |
| `tunnel_exit` | **不允许**（监听在 `tunnel.listen`） | 必填，写 `listen`（`ip:port`） | 必填 | 固定目标，或 `allow_any_target` 二选一 |
| `reverse_portal` | 必填（公网侧用户口） | 必填，写 `listen`（控制链路） | 必填 | 不允许（目的地由 bridge 的 targets 决定） |
| `reverse_bridge` | 只写 `ports` = portal 侧公网端口（`addr` 不用） | 必填，写 `server`（portal 的 `host:port`） | 必填 | 必填（内网目标，端口一一对应 `listen.ports`） |

`tunnel` 字段：`type` ∈ tcp / tls / ws / wss / grpc / xhttp / kcp / quic（引擎支持子集见 §2）；`security` ∈ `none` / `tls` / `tls_pin` / `tls_self`（`vless_enc` **已随 xray 转发引擎移除**，写了会被拒；`tls_pin` 需要 `pin_sha256` = 出口叶子证书 DER 的 SHA-256，64 位十六进制，但**当前没有引擎实现证书固定**——gost 与 realm 都不行——所以会被驱动拒绝，请改用 `tls_self` 或 `tunnel.cert` 信任锚；`tls`/`wss` 类型再写 `none` 自相矛盾会被拒）；`host`（Host 头）、`path`、`sni`（须为域名）、`alpn`（≤8 项）；`cert`：出口/portal 侧是要出示的证书 `{mode: self|file|panel, cert_file, key_file}`（`file` 模式两个文件都要）；入口/bridge 侧只能是信任锚 `{mode: "file", cert_file}`（用来校验对端，不能带 `key_file`，`self` / `panel` 被拒；哪个引擎真正采用它由驱动决定：gost、frp 采用，realm 以 `a certificate belongs to the tunnel exit` 拒绝）。路径须为绝对路径（只含字母数字和 `. _ / -`，不含 `..`）。

**`security: tls_self`（两端自己派生证书）**：面板无法复刻 x509 生成，所以 `tls_self` 让**两端各自**用共享 `secret`（和 `sni`）派生出**同一张**确定性自签证书（`agent/tlsself`，HKDF-SHA256 + Ed25519；`sni` 为空时证书名是 `w1n-fwd.invalid`）：

- 必须有 `Instance.Secret`（16–256 字符，与其他隧道同规则）；`pin_sha256` 与 `cert` 都**必须为空**（指纹由 secret 派生、证书由 secret 派生，写了就是矛盾，会被拒）。
- **gost**：出口把派生证书与私钥写进该实例在 state 目录下的文件（`tls_self_<id>.crt` / `.key`，0600，`file` 名为相对路径，gost 的工作目录就是 state 目录），listener 的 `tls.certFile/keyFile` 指向它们；入口把派生证书当 CA（自签证书即自身 CA），渲染成 `tls: {secure: true, serverName: <sni 或 w1n-fwd.invalid>, caFile: tls_self_<id>.crt}`。只支持 TLS 类传输（`tls` / `wss` / `grpc`）；与 `tcp` / `ws` 组合会被拒。
- **realm**：拒绝（只信任内置公共 CA 根，无法校验自签证书），提示改用 gost；`engine: auto` 也不会选它。
- 与 `tls_pin` 的区别：`tls_pin` 的指纹要面板/人工填进两份 desired，换 secret 就得重算，而且没有引擎实现固定；`tls_self` 只需要两端共享 secret，面板不需要碰证书。

## 6 样例索引

样例位于 [`agent/examples/testdata/`](../agent/examples/testdata/)，每个文件都是一份**完整可用**的 `spec.Desired`。用法：复制到目标机器 → 改 `secret`、IP、域名、端口 → 用 `agent-apply -f` 或 `Agent.DesiredPath` 应用。所有 `secret` 都是占位值 `CHANGE-ME-32-chars-minimum-secret`，**必须替换**；样例中的 `203.0.113.x` / `198.51.100.x` 是文档保留地址，`192.168.x.x` 是内网示例。

- 成对的样例（`*-entry` / `*-exit`、`*-bridge` / `*-portal`）分别放到**两台机器**上，`id`、`secret`、隧道类型必须一致，入口/桥端的 `tunnel.server` 指向对端的 `tunnel.listen`。
- 「agent-apply」列：所有样例都只用外部引擎（gost / frp / realm），`agent-apply` 与常驻的 `W1nCray` 服务两种方式都行（都需要 `ManifestPath` 提供内核）。
- 「本地策略」：`默认` = 不写 Policy 也能通过；`listen` = `AllowListen` 需包含 `0.0.0.0`；`private` = 需 `AllowPrivate: true`。

| 样例 | 引擎 | 场景 | 本地策略 | 注意点 |
|---|---|---|---|---|
| [forward-tcp](../agent/examples/testdata/forward-tcp.json) | gost | TCP 直连转发 | listen | 写了 `tcp_long`（空闲 1 小时）；不写则 300 s（`tcp_default`） |
| [forward-udp](../agent/examples/testdata/forward-udp.json) | gost | UDP 直连转发（DNS） | listen | `udp_short`；UDP 不能与 PROXY 头组合 |
| [forward-tcp-udp](../agent/examples/testdata/forward-tcp-udp.json) | gost | TCP + UDP 同端口 | listen | 两个协议各占一个端口声明，同端口不冲突 |
| [forward-port-range](../agent/examples/testdata/forward-port-range.json) | gost | 端口范围一一映射 | listen | 监听与目标范围必须等长，否则报 `ranges must be the same length` |
| [forward-port-map](../agent/examples/testdata/forward-port-map.json) | gost | `port_map`：①逐端口指定、不写 targets；②覆盖范围里的一个端口 | listen | ① 的 `port_map` 必须覆盖每个监听端口；② 的 20301 去 `port_map` 指定处，其余按 targets |
| [forward-balance](../agent/examples/testdata/forward-balance.json) | gost | 负载均衡：round_robin、random（权重 3:1）、failover | listen | gost 只在 `random` 策略下采用权重，其他策略写非 1 权重会被拒；failover 的 `health` 只支持 `type: tcp`，不接受 `timeout_s` / `probe_url` |
| [forward-acl](../agent/examples/testdata/forward-acl.json) | gost | 来源 ACL（allow 网段 + deny 单个地址） | listen | `deny` 先判；`allow` 非空即白名单；realm / frp 不支持 ACL |
| [forward-gost-limits](../agent/examples/testdata/forward-gost-limits.json) | gost | 连接数 / 带宽限制 + 被动摘除的主备 | listen | 速率单位 bit/s。`health` 是 gost 的**被动摘除**（只支持 `type: tcp`，`max_fails` 次失败后摘除 `interval_s` 秒），不是主动探测；主动探测目前只有 frp 的反向 bridge 支持 |
| [proxy-send](../agent/examples/testdata/proxy-send.json) | gost | 向目标发送 PROXY v2 | listen | 目标服务必须开启接收 PROXY，否则会把头当作数据；仅 TCP |
| [proxy-accept](../agent/examples/testdata/proxy-accept.json) | gost | 接收 PROXY（前置 nginx / haproxy 送入） | **默认** | 只监听 `127.0.0.1`。PROXY 头可伪造，改成公网监听会被拒（需 `AllowAcceptProxyOnPublic`，不建议） |
| [proxy-passthrough](../agent/examples/testdata/proxy-passthrough.json) | gost | PROXY 透传：收头再发头，保留真实来源 | **默认** | 同上；上游必须真的发 PROXY 头，否则连接被断 |
| [tunnel-tls-self-entry](../agent/examples/testdata/tunnel-tls-self-entry.json) / [exit](../agent/examples/testdata/tunnel-tls-self-exit.json) | gost | 隧道：wss + `tls_self`，两端由 `secret` 派生同一张自签证书 | listen | 入口/出口都不写 `pin_sha256` / `cert`；两端 `secret` 与 `sni` 必须一致；只支持 TLS 类传输（`tls` / `wss` / `grpc`） |
| [reverse-frp-portal](../agent/examples/testdata/reverse-frp-portal.json) / [bridge](../agent/examples/testdata/reverse-frp-bridge.json) | frp | 反向代理：bridge 在内网主动连出，portal 在公网开口 | portal：listen；bridge：private | bridge 的 `listen.ports` 要与 portal 的公网端口一致；bridge 默认不校验 portal 证书（可用 `tunnel.cert.cert_file` 指定信任锚）；样例带 `failover` + TCP 主动健康检查，目标挂掉时 frpc 撤下该公网端口；`secret` 就是 frp token |
| [reverse-gost-portal](../agent/examples/testdata/reverse-gost-portal.json) / [bridge](../agent/examples/testdata/reverse-gost-bridge.json) | gost | 反向代理：wss 控制链路 | portal：listen；bridge：private | portal 需公共 CA 证书文件（`cert.mode: file`）；bridge 严格校验域名，`sni` 必须对得上 |
| [realm-relay](../agent/examples/testdata/realm-relay.json) | realm | 小设备纯中继：①TCP+UDP 单目标 ②TCP 轮询（权重 2:1）+ 发送 PROXY v1 | listen | 无统计、无健康检查、无 ACL；改配置会重启该实例并断连；UDP 只能单目标 |
| [realm-wss-entry](../agent/examples/testdata/realm-wss-entry.json) / [exit](../agent/examples/testdata/realm-wss-exit.json) | realm | realm ↔ realm 的 wss 隧道 | listen | 隧道只支持 TCP；出口需**公共 CA** 签发的证书文件；认证靠 `secret` 派生的 path 令牌；务必用防火墙限制只有入口机能连出口 |
| [gost-wss-entry](../agent/examples/testdata/gost-wss-entry.json) / [exit](../agent/examples/testdata/gost-wss-exit.json) | gost | gost ↔ gost 的 wss 隧道 | listen | 入口不写 targets，目标由出口决定（出口只放行声明的目标）；出口需公共 CA 证书 |
| [engine-auto](../agent/examples/testdata/engine-auto.json) | auto | `engine: auto`：自动选引擎 | listen | 所有外部引擎都在时两者都落到 realm（体积最小，且支持 forward 与 iphash） |

（历史说明：v11 之前还有 xray 引擎的样例 `reverse-xray-portal/bridge` 与 `tunnel-tls-pin-entry/exit`；转发引擎删除后，前者与已有的 `reverse-gost-*` 重复而删除，后者改为上面的 gost `tls_self` 样例——`tls_pin` 已无引擎支持。）

## 7 命令

### `W1nCray agent-apply -f desired.json`

按配置里的 `Agent` 段（`-c` 指定配置文件，缺省找 `./config.yml`、`/etc/W1nCray/config.yml`）启动一次 Agent 引导，**严格解码**并应用 `desired.json` 一次，把 `Report` 以 JSON 打印到标准输出（即使失败也打印）；退出码非 0 表示未成功。注意：

- 需要配置里 `Agent.Enabled: true`，否则报 `config … has no enabled Agent section`。
- **没有内嵌引擎**：`engine: xray` 会在校验阶段被拒（`xray 转发引擎已移除，请使用 gost 或 realm`）；`engine: auto` 只在已注册的外部引擎里选。
- 已被启动的外部内核在命令退出后继续运行（命令自身的说明如此）。
- 它不获取实例锁，也**不是 dry-run**：会真实启动内核、占用端口。不要在常驻服务正在使用同一 `StateDir` 时并行执行【高度可能：二者共用状态目录，代码中 agent-apply 无锁】。
- 想只检查而不落地：目前没有 dry-run 命令，建议先在测试机上应用同一份文件。

### `W1nCray check`

`W1nCray check [-c config.yml] [--online]` 校验配置而不提供服务。对 Agent 它只检查：`ManifestPath`、`ManifestKeysPath` 指向的文件存在（不存在算失败）；`DesiredPath` 文件存在（不存在只是警告：启动时不会应用）。**它不校验 `desired.json` 的内容**——内容是否合法只有应用时才知道（常驻服务的日志里会有 `agent: apply <path>: …`，或用 `agent-apply` 看完整报告）。启用面板时还会打印内核清单同步的开关与间隔（§3「内核清单自动同步」）；`--online` 会顺带拉取一次清单并报告 `sequence`，但不打印内容，也不代替 agent 的本地验签。

### `W1nCray link`

`W1nCray link --panel <URL> --machine <ID> (--token <T> | --token-file <F>) [-c config.yml] [--port-range LO-HI] [--allow-http] [--noterminal] [--force] [--dry-run] [--ignore-api-overrides] [--skip-check]` 把 v0.3 的静态节点转成机器模式，**不重启服务**。它按文本行级改写 `config.yml`（注释与无关的键原样保留），并把 agent 配置写进同目录的 `agent.yml`：

- 只转换 `ApiConfig.ApiHost` 的 scheme+host（含端口）与 `--panel` 一致的节点；其余节点保持静态并在报告里说明原因。
- `ApiConfig` 里有机器模式无法表达的本地覆盖（`SpeedLimit > 0`、`DeviceLimit > 0`、`RuleListPath` 非空）时该节点不转换，除非加 `--ignore-api-overrides`。
- 被转换的条目整块注释掉（块首是 `#LINKED-<日期> …` 回滚标记），它的 `ControllerConfig` 原样放进 `agent.yml` 的 `Panel.NodeControllers[<节点ID>]`（凭据仍只在本机）。
- `agent.yml`（原子写、0600）包含 `Enabled`、`StateDir`、`Policy`（`AllowListen` / `PortRange`，不写 `AllowEngines`）、`Panel`（`Enabled` / `URL` / `MachineID` / `TokenFile` / `MachineNodes` / `NodeControllers`）；`config.yml` 里不再写 `Agent:` 段。旧的 `Agent:` 块会被**迁移**进 `agent.yml`（本机设置与 link 不负责的 `Panel` 键保留，`Panel` 的连接字段按本次参数重写），原处留一行注释说明已迁出。详见 §3「`agent.yml`」。
- `agent.yml` 已存在时**拒绝覆盖**（零改动）；`--force` 才覆盖，且先备份为 `agent.yml.bak-<时间戳>`。
- `--noterminal` 在 `agent.yml` 里写 `Terminal: {Enabled: false}`；不加时**不写**该键，即终端保持默认开启。
- 令牌写入 `<配置目录>/agent.token`（先 `umask 077`、权限 0600、不带换行）；已存在且内容相同则跳过，内容不同则报错且不覆盖。令牌不会出现在 `config.yml`、`agent.yml`、stdout、stderr 或错误里。
- 写入前做**基线对比**：先把**原配置**（同目录临时拷贝）跑一遍完整校验，收集失败项集合 B；再把生成的新配置（把将要写入的 `agent.yml` 内联成 `Agent:` 块）跑一遍，收集集合 N。只有 `N` 中**新增**的失败项（`N \ B`）才中止并**不改动任何文件**（打印新增失败项的完整文本）。若 `N ⊆ B` 且 `B` 非空则继续转换，并打印显眼的警告列出原配置**转换前就有**的问题（最多 10 条，与本次转换无关）。`B`、`N` 都为空时静默通过。失败项用 `W1nCray check` 打印的 `✗` 文本做稳定标识（剔除临时文件名/时间戳等易变部分）；除离线 `check` 外还会检查机器模式下才生效的 `NodeControllers[].CertConfig.CertMode`。已有 `agent.yml` 时（`--force`）会额外单独校验将要写入的新文件。
- `--skip-check` 跳过上述写入前校验（会打印警告），生成结果直接写入。
- 成功后 `config.yml` 备份为 `config.yml.bak-link-<时间戳>`（0600）再原子替换；`agent.yml` 由原子写覆盖，原文件备份为 `agent.yml.bak-<时间戳>`。
- `--dry-run` 只打印计划（不写任何文件，包括令牌与 `agent.yml`）。
- 对已转换过的配置（有 `#LINKED-` 标记，或 `agent.yml` 已存在）再次运行会以清晰错误退出且零改动；需要重做时先恢复备份，或用 `--force`。

### 常驻服务

`Agent.DesiredPath` 设置后，修改该文件即自动应用（§3）。看结果：日志里的 `agent: <path>: <status> (<n> instance(s))`，失败时有具体错误。

### 面板命令（`kernel_*`、`file_*`、`files_*` 与 `component_restart`）

面板可以在两条通道上下发命令，两条通道**共用同一个命令注册表与同一个按 id 去重的空间**（`agent/opscmd`）：

- HTTP：`POST /config` 或 `POST /report` 的响应里带 `commands`，结果回 `POST /command-result`；
- WebSocket：`cmd {type,args,ttl_s}`，结果回 `cmd.result`（同一 `id`）。

同一个命令 id 在两条通道上只会执行一次、只回一次结果。命令注册表里的类型就是白名单，**未注册的类型一律回 `failed` 且 `result.error="unsupported command"`，不执行**。`refresh` 与 `dump_state` 是内建类型（需要拉取循环与最近一次报告，仍由 `agent/panelclient` 实现），其余由 `agent/opscmd` 提供。

**长命令**（`kernel_install`、`files_apply` 与 `self_update`）先回 `{"status":"accepted"}`（在 `ttl_s` 内），完成后再回同一个 id 的最终 `done`/`failed`；在最终结果投出前该 id 一直算"处理中"，面板重投同一 id 不会再次执行（契约 §7-7）。

| type | args | 行为与结果 |
|---|---|---|
| `kernel_list` | `{}` | 回 `{kernels:[KernelEntry], catalog:[{name,versions:[…]}]}`。`kernels` 是**已安装**的版本（事实，读内核目录）；`catalog` 只列已签名清单里**本机可用**的版本。没有加载清单时 `catalog: []`，`kernels` 照常返回。 |
| `kernel_install` | `{name, version?}` | 长命令。`version` 省略/空 = 清单里该内核的最新版本。只从**已签名清单**安装（哈希、平台、revoked、`min_agent` 全部照旧校验）。结果 `{name, version, path}`。**管理员明确下发时绕过并清除自动重试退避**（D-M3）：回滚掉的版本可以立刻重装，退避只约束自动重试。 |
| `kernel_remove` | `{name, version}` | 删除**指定**的已安装版本，其它版本保留。**正在使用的版本被拒**：`failed` + `result.code="in_use"`（当前指针指向它，或有存活进程正在执行它）。成功时回 `{freed_bytes}`；**幂等**：目标本来就没装（或已经删掉）时同样 `done`，结果里带 `already_absent: true`（D-M2）。**唯一例外是 `name=xray`**：Xray 是服务，`version` 指向**当前**版本时即卸载内核（停用并删除服务文件、删除全部 xray 版本，保留 `config.yml` 与受管文件），结果里带 `uninstalled: true`；`version` 是旧版本时只删该版本、不停也不改 Xray 服务。面板在机器仍绑定节点时以 HTTP 409 `xray_in_use` 直接拦下该命令，因此卸载路径只在没有节点绑定后可达；`version` 为空（协议不允许，仅为兼容旧面板保留）按卸载处理并记一条 warning（本机没有配置 Xray 配置路径、因而没有服务管理器时，xray 与其它内核一样按普通版本处理）。 |
| `kernel_rollback` | `{name}` | 把 `previous` 变成 `current`，两者互换；结果 `{name, version, path}`。 |
| `component_restart` | `{name}` | 只重启**受管内核进程**（gost/realm/frp 由 supervisor 拉起）。结果 `{name, restarted:<n>}`。`agent` 一律拒绝（见下）；`xray` 走 Xray 内核服务（§13.5.1），服务未托管时回 `not_supported`。 |
| `file_list` | `{root, path}` | 列出一个 root 下相对路径的目录项：`{entries:[{name,type,size,mode,mtime}], roots:[…]}`；`path` 省略 = root 本身。`mode` 是八进制权限串，`mtime` 是 Unix 秒。 |
| `file_read` | `{root, path, offset?, limit?}` | 回 `{data:"<base64>", size, eof}`。`limit` 不得超过本机上限（默认 128 KiB，契约 §7-8），超限回 `failed` + `result.code="too_large"`。 |
| `file_write` | `{root, path, data:"<base64>", mode?, sha256?, append?}` | `append` 缺省/false：原子整体替换（同目录临时文件 + `rename`）。`append: true`：追加到**已存在**的普通文件末尾（文件不存在回 `failed` + `result.code="not_found"`；直接 `O_APPEND` 写，不再走临时文件），`mode` 不适用（文件已存在）。单片仍 ≤ 128 KiB（`MaxWrite`）。`mode` 是八进制字符串（缺省 0644）：可执行位需 `Files.AllowExec`，setuid/setgid/sticky 一律拒绝；给了 `sha256` 就先核对（**该 sha256 始终是本次载荷**的）。结果 `{path, sha256, size, created, append?}` 里的 `sha256`/`size` 是**写完后整个文件**的（分片上传据此校验）。 |
| `file_delete` | `{root, path}` | 删一个**普通文件**（目录一律拒绝），回 `{path, deleted:true}`。 |
| `file_mkdir` | `{root, path, mode?}` | 等价 `mkdir -p`：逐级创建缺失的父目录（中间目录 0755），`mode` 只作用于最后一级，缺省 0755。目录 mode 只允许 `0700`/`0750`/`0755`（目录的可执行位是"可进入"，因此不需要 `Files.AllowExec`；world-writable 目录在 root 内是符号链接替换漏洞，一律拒绝），setuid/setgid/sticky 拒绝。回 `{path, created}`（已存在时 `created:false`，不是错误）。 |
| `file_rename` | `{root, path, to}` | 在**同一个 root 内**把 `path` 移到 `to`（不受限模式两者都是绝对路径）。**目标已存在则拒绝**（不覆盖，回 `failed` + `result.code="already_exists"`），`to` 的父目录必须已存在。回 `{path, to, renamed:true}`。 |
| `files_apply` | `{}` | 长命令。对**最近一次 desired 的 `files` 段**执行：下载 blob（按 sha256，命中缓存不重复下载）→ 暂存 → 校验 → 原子替换（先留 `last_good`）→ 重载。结果 `{status, files[], reload, applied_pending?, errors?, reason?, rolled_back?}`。 |
| `files_validate` | `{}` | 只暂存 + 校验，**不写任何受管文件、不重载**。结果同 `files_apply`（`reload:"not_needed"`）。 |
| `files_rollback` | `{}` | 用 `last_good` 快照恢复受管文件并重载。结果 `{status:"rolled_back", rolled_back:true, files[], reload}`。 |

细节与边界：

- **长命令的结果顺序是保证的**（D-M3）：面板把 `accepted` 的 `result` **覆盖**在命令行已有的结果上，所以 agent 保证 `accepted` 先于最终 `done`/`failed` 到达（否则最终结果先到会被清成 `null`，失败就没有错误信息了）。若 `accepted` 没能投出（面板不可达等），最终结果立即发出，不会被这条顺序规则拖住。
- **保留名 `agent`**：签名清单里名为 `agent` 的条目属于 `self_update`（契约 §7-11）。`kernel_install`/`kernel_remove`/`kernel_rollback` 与 `component_restart` 一律拒绝它（`failed` + `result.code="reserved_name"`）；`kernel_list` 仍会如实列出已安装的版本。
- **`component_restart` 不能重启 agent**：agent 不由 supervisor 管理（重启它会断掉面板连接），回 `failed` + `result.code="reserved_name"`。`name=xray` 由 Xray 内核服务处理（§13.5.1）：服务已托管则重启它，未托管回 `not_supported`。名字对应的内核进程没在跑时回 `failed`（`component "x" is not running`）。
- **`in_use` 的判定**：优先用 supervisor 的 pid 记录（`<StateDir>/pid/*.pid`）+ 存活与 `/proc/<pid>/exe` 身份复核，把正在执行的二进制映射回 `<KernelsDir>/kernels/<name>/<version>/`；平台无法核实身份（Windows 等）或没配 pid 目录时，退化为"当前指针 = 在用"，不假装精确。回滚后进程仍执行旧版本的情况也能如实反映。
- **`KernelEntry` 字段**：`{name, version, current, previous, path, size_bytes, installed_at, in_use}`（契约 §3）。`size_bytes` 是**清单声明**的安装体积（各文件声明大小之和），不是磁盘实测。`kernel_list` 不额外发明 `size_on_disk`/`in_use_exact` 等字段（契约里没有）。
- **`freed_bytes`** 同样是该版本清单声明的体积（删除前读取），不是 `du` 的实测值。`kernel_remove xray <旧版本>` 只算该版本；删除 xray 的**当前**版本（卸载内核）时一次删掉整棵内核目录，所以它是所有已装版本声明体积之和（REG2 观察 1 的修复）。
- **能力声明**：`hello.capabilities`（以及 HTTP `/config` 的 `features`）里出现 `kernel` 的条件是**内核安装器可用且已加载一份已签名清单**——没有清单时 `kernel_install` 无法解析版本，所以不做这个承诺（契约 §7-1）。
- **能力集合是动态的，靠重连发布**：`hello.capabilities` 只在建连时发送一次，同一连接上第二个 `hello` 是协议错误（面板回 `unexpected_type`），而能力可能在握手之后才就绪（签名清单到达、`self_update` 注册完成）。agent 在每个 telemetry/components 周期把运行时的能力集合与上次 `hello` 实际发出的集合按**集合**比较（排序、去重）：不同就干净地断开当前连接并重连一次，让新的 `hello` 携带新集合。两次这样的重连至少间隔 30 s（集合来回抖动不会变成重连风暴），且本机有活动终端会话时推迟到会话结束（重连会打断用户的 shell）。这条路径**不发送任何新帧类型**（契约 §1/§3）。
- **`file_*` 的根与错误码**：受限模式下 `root` 是**本机命名的 root**（默认 `xray` = xray 配置目录、`state` = agent 状态目录，其余按目录名），`path` 是相对路径；不受限模式下 `root` 传空、`path` 传绝对路径（PLAN v10，见 §3 的 `Files`）。`agent.yml`、`desired.json`、`last_good.json` 永不在任何 root 内（`mkdir`/`rename` 同样拒绝）。越界、符号链接逃逸、非常规文件等拒绝都带稳定的 `result.code`：`outside_roots`、`symlink`、`not_regular`、`not_a_directory`、`is_a_directory`、`too_large`、`exec_bit`、`special_mode`、`sha256_mismatch`、`unknown_root`、`already_exists`、`not_found`、`invalid_args`。
- **结构化清单**：`hello.kernels` 与 HTTP `/report`、`/ack` 的 `kernel_entries` 是同一份 `KernelEntry[]`；旧的 `kernels` map（"本次应用选的版本"）保持不变，仍一起发送。
- **事件**：内核安装成功发 `event{kind:"kernel.installed"}`，卸载成功发 `event{kind:"kernel.removed"}`（契约 §7-10）。事件只走 WebSocket（HTTP 契约没有事件通道）。**断线期间的 event 会缓存补发**（契约 §7-14）：sender 保留一个有上限的待发队列（最多 **64** 条，超出丢**最旧**并计数、记一条 warning），会话建立（`hello.ok`）后**按原序**补发；发送失败也回到队列，同一帧最多重试 **3** 次后丢弃并计数。补发不改线格式：`event` 载荷没有时间戳字段，补发的帧与入队时逐字节相同，面板端无需改动。
- **参数是严格解码的**：多一个字段、少一个必填字段、类型不对都会回 `failed` + `result.code="invalid_args"`，命令不执行。

### 7.1 `self_update`（agent 自升级）

签名清单里名为 `agent` 的条目描述 agent 自己的版本（契约 §7-11）；`self_update {version}` 用它升级：

- **长命令**：先回 `{"status":"accepted"}`，完成后再回同一 id 的 `done`/`failed`。目标版本必须出现在清单的 `agent` 条目里，并通过全部既有校验（签名、`revoked`、`min_agent`、平台 target、`archive_sha256`、成员 `sha256`/`size`）与清单声明的版本自检（`run.version_cmd`，argv 数组、不经 shell）。raw `.gz` 产物（`release/build.sh` 的 `dist/W1nCray-linux-<arch>.gz`，清单 `archive:"gz"`、恰好一个 extract 成员）与 `.tar.gz`/`.zip` 走同一条校验路径。**任何一步失败都不会写运行中的可执行文件**。
- **原子替换**：`exe → exe.old`、已验证的暂存副本 → `exe`，然后写 `<StateDir>/update/pending.json`。任何一步失败都会把原二进制放回；`.old` 从不删除，最坏情况（看门狗也死了）用一条 `mv exe.old exe` 即可手工恢复，这是"不变砖"的最后一道兜底。
- **看门狗（回滚）**：提交后 agent 启动一个隐藏助手 `__watchdog`，再按原 argv 正常退出（走既有的优雅关停：停内核、关 Xray）。助手**只做看门狗，绝不自己拉起 agent**——重启是服务管理器的职责（systemd `Restart=always`、OpenRC `supervise-daemon`、procd `respawn`）。
  - **由旧二进制的副本运行**：Commit 会把旧二进制复制到 `<StateDir>/update/watchdog/W1nCray-<旧版本>`（0755，逐字节校验 sha256 与 `exe.old` 一致），助手用这个**已知良好**的副本执行 `__watchdog`。绝不能用新二进制当自己的看门狗：新二进制正是"可能起不来"的那一个。确认或回滚后副本被清理。
  - **判定规则**（`pending.json` 存在期间，轮询间隔默认 2 s，总预算 `Deadline`）：判活以**新进程自己写的就绪标记** `<StateDir>/update/ready.json`（`{version,pid,exe_path,at}`）为权威信号——看门狗要求标记里的 `version` 等于 `pending.json` 的版本、且该 pid 存活；单实例锁 `config.yml.lock` 只作为回退（新进程还没写标记、或标记不可用时）。这样「服务管理器还没把新进程拉起来」与「新进程起不来」不再混淆，也排除了锁里残留的已退出进程 pid（D-M7）。
    - **pid 身份核实**（F3b）：存活还不够，该 pid 还必须**确实在运行 agent 的可执行文件**。看门狗读 `/proc/<pid>/exe`（剥掉内核在镜像被 unlink 后追加的 ` (deleted)` 后缀），与已知集合比对：安装路径 `ExePath`、`ExePath.old`（提交后仍在跑、尚未退出的旧进程）、当前 pending 版本的暂存目录 `<StateDir>/update/staged/<版本>`、看门狗副本目录 `<StateDir>/update/watchdog/`（`W1nCray-<版本>`；看门狗自己的 Updater 不知道自己被复制时的版本，所以按目录认）（路径都做符号链接解析后比较）。`/proc/<pid>/exe` 不可读时（权限或竞态）退而比对 `/proc/<pid>/cmdline` 的 argv[0]，且必须是绝对路径；**仅凭进程名（comm）不足以认定**——任何程序都能叫 `W1nCray`。身份不符（例如锁文件/就绪标记里的 pid 已被内核复用给 sshd、dropbear 或别的服务）→ 记 warning（含 pid 与解析到的 exe）并按「**没有 agent**」处理，绝不当作新版本存活。无法核实身份的平台（非 Linux）同样保守地视为「不是 agent」。
    - `pending.json` 消失（新进程已 `Confirm()`）→ 成功，退出并清理副本与就绪标记。
    - 观测期内 agent pid 变化（重启）≥ `Attempts`（默认 3），或连续 `AliveWindow` 没有任何存活 agent → **回滚**：先按 pid **停止正在运行的新版本进程**（SIGTERM，`stopGrace` 5 s 后 SIGKILL；**发 SIGTERM 前与发 SIGKILL 前各核实一次身份**，因为等待期间进程可能已经退出、pid 可能已被复用，身份不符就不发信号并记录），再 best-effort 停掉 `W1nCray-xray` 服务（R1-16），然后 `Updater.Rollback` 把 `.old` 原子换回 `exe`、写 `<StateDir>/update/rollback.json`、清 pending；随后按后端重启 agent（systemd `systemctl reset-failed/restart`、OpenRC `rc-service W1nCray restart`、procd `/etc/init.d/W1nCray restart`；无服务管理器时只告警）。回滚是幂等的。**任何情况下都不会出现「运行中的可执行文件 ≠ 安装路径上的文件」**：回滚前会再探一次，若新进程在决策与动作之间起来了就不回滚，继续观察；**也不会因为锁文件/就绪标记里的陈旧 pid 杀掉无关进程**（F3b）。
    - `Deadline` 到了 agent 仍存活且稳定但没 `Confirm`（例如连不上面板）→ **不回滚**，助手退出并保留 pending/.old 供人工处理；`self_update.stalled` 仍由新进程按既有逻辑上报（面板故障不是二进制坏，契约 §7-11）。此时启动迁移不再被无限期推迟（R1-7，见 §13.5.2）。
  - **窗口与架构**：`AliveWindow` 默认 **60 s**（amd64/arm64）、**180 s**（更慢的目标：mips/arm/386 等），`Deadline` 默认 3 min / 8 min；它必须覆盖「服务管理器的重启间隔（systemd `RestartSec`、procd respawn、OpenRC supervise-daemon）+ 新进程自身启动」。本机可用 `agent.yml` 的 `Agent.SelfUpdate.AliveWindowSec` / `DeadlineSec` 覆盖（本地配置，面板不可改；`DeadlineSec` 若不大于窗口会被抬到窗口之上）。旧的固定 10 s 在 2 vCPU OpenWrt 25.12 上会误判健康的新进程（D-M7）。
- **助手如何在 systemd 下活下来**：systemd 默认 `KillMode=control-group`，服务停止/重启时同一 cgroup 的所有进程都会被杀死，`Setsid` 也逃不掉——而"主进程退出 → 服务管理器重启"正是自升级的关键时刻，看门狗必须活过它。因此在 systemd 下助手用 `systemd-run --quiet --collect --no-block --unit=w1ncray-selfupdate-<unix时间> -- <旧二进制副本> __watchdog <args>` 启动，落在**独立的 transient unit/cgroup**，服务重启不会连坐。检测条件：环境变量 `INVOCATION_ID` 非空或 `/run/systemd/system` 存在，且 `systemd-run` 可执行；不满足（OpenRC/procd/无服务管理器）或 `systemd-run` 启动失败 → 记日志并回退到 `Setsid` 方式，**升级不会因为看门狗启动方式而失败**。命令一律是 argv 数组、不经 shell。
- **确认**：新进程在第一次成功得到面板 `/config` 应答后调用 `Confirm()`，删除 `.old`、`pending.json` 与 `ready.json`。
- **连不上面板不回滚**：新进程起来了但 10 分钟内没连上面板，只发 `event{kind:"self_update.stalled"}`（与其他 event 一样进入有上限的待发队列，重连后按原序补发，见 §7 的「事件」与契约 §7-14），**绝不自动回滚**——面板故障不是二进制坏。同时（R1-7）该进程会**自行执行 Xray 启动迁移**并发 `event{kind:"self_update.xray_started"}`：此时看门狗已退出（Deadline 到点不回滚），不会再发生回滚，而 0.5.x 在面板不可达时照常服务 Xray，0.6 不能因为面板故障就停服。
- **事件**：`self_update.started`（开始）、`self_update.rolled_back`（看门狗回滚后由下一次启动上报一次）、`self_update.stalled`、`self_update.xray_started`（未确认但已启动 Xray 内核服务）。`self_update.rolled_back` 是在 WS 会话建立**之前**产生的（新进程刚 `Boot`，尚未 `hello.ok`），它正是靠 §7 的待发队列在会话建立后补发才到得了面板（契约 §7-14；修复前它在 `hello.ok` 前被 sender 静默丢弃，见 REG3-2）。
- **能力声明**：`hello.capabilities`（及 HTTP `/config` 的 `features`）出现 `upgrade` 的条件是 `self_update` 命令真的注册了：平台能替换自身 exe（Windows 一律不行）、可执行文件是常规文件且所在目录可写、有服务管理器（systemd/OpenRC/procd 的 init 文件里 `ExecStart`/`command` 指向该 exe），并且进程提供了重启钩子。不满足时命令回 `failed` + `result.code="not_supported"`，能力也不声明（契约 §7-1/§7-11）。**自救**：若运行镜像已被替换/删除（`/proc/self/exe` 报 `"<path> (deleted)"`，例如回滚与本次启动竞态），`Ready()` 会剥掉该后缀重试，`bootstrap` 也会改用服务单元里指向的**安装路径**作为替换目标，因此面板仍可再发一次 `self_update` 把机器恢复到一致状态，而不是永久失去 `upgrade`（D-M7）。
### 受管文件（`files_apply` / `files_validate` / `files_rollback`）

受管文件是面板可以下发的 **xray 文件**，内容走 HTTPS（`GET /api/v2/server/machine/agent/file/<sha256>`），desired 里只有 `{name, sha256, size, kernel}`（契约 §7-1/§7-9）：

- **固定白名单与固定目录**：`config.yml`、`route.json`、`custom_inbound.json`、`custom_outbound.json`、`dns.json`、`geoip.dat`、`geosite.dat`，只写在 xray 配置目录。名字必须是纯文件名：`../evil`、绝对路径、`sub/route.json`、`agent.yml`、状态文件一律拒绝，命令不执行。
- **`config.yml` 只在 `agent.yml` 分离布局下可写**（契约 §7-2）：否则该文件就是 agent 自己的配置，面板写它等于让 agent 自杀。这种情况下 agent 不声明 `files` 能力，面板也就不会下发。
- **`files` 能力名是两个功能的交集**（契约 §3 里 `files` 只有一个名字）：面板据它决定是否在 revision 里下发 `desired.files`（受管 xray 文件），也用同一个名字决定是否提供 `file_*` 文件管理。所以只有当**两者都能服务**时才声明：受管层已接线、本地 `Files` 能到达 xray 目录（`Roots` 非空**或** `Unrestricted` 有效开启）、`agent.yml` 分离布局，且 `file_*` 命令已注册。单文件布局下 `file_*` 命令仍然注册可用（`file_list` 等照常执行，直接发命令即可），但**不声明** `files`。契约目前没有任何字段能区分这两个功能（`capabilities` 是集合，`policy.files` 只有 `roots`/`unrestricted`），这是 WP-G5 与 WP-G6 合并时的保守取舍：宁可少声明，也不让面板下发本机无法应用的 `desired.files`。风险与待决项见合并报告。
- **校验先于替换**：四个 JSON 先逐个 `core.CheckFiles`，再用**整实例预检**（`core.New` 只构造、不 `Start`，因此**不绑端口**）抓组合错误；`config.yml` 走完整 `LoadConfig`。校验不过 → 一个受管文件都不动、不重载，回 `status:"invalid"` 与带文件名/规则序号的错误。
- **blob 完整性**：边写边算 sha256，与 desired 的 `sha256`/`size` 不符**不落缓存、不替换**；`If-None-Match` 拿到 304 而本地又没有缓存时重取一次。单文件上限默认 64 MiB（`Files.MaxBytes` 可改；设为负值 = 本机禁用 geo 下发，回显式原因而不是静默跳过）。
- **原子替换与回滚**：替换前把当前文件快照成 `last_good`（缺失的文件记为"缺失"，回滚时删掉），替换走同目录临时文件 + `rename`。重载被拒（`LoadConfig` 失败）→ 恢复 `last_good` 并回 `status:"rolled_back"`。
- **geo-only 变更不重载**：`geoip.dat`/`geosite.dat` 由 xray 在规则求值时按需读取，替换后回 `reload:"not_needed"`（契约 §7-9 的 `applied_pending` 只在真正发起重载时出现）。
- **幂等**：磁盘上已是同一 `sha256` 的文件不下载、不替换、不重载（`files[].skipped=true`、`bytes=0`），并把该集合记进 `<StateDir>/filesync/applied.json`。
- **健康判定在面板侧**：agent **不在进程内等健康**。`files_apply` 在重载发起后回 `done{applied_pending:true}`，随后由面板按 `hello`/`telemetry`（60 s 内）与 `components.xray.state=running` 判定，必要时下发 `files_rollback`（契约 §7-9）。
- **`hint{what:"files"}`** 触发同一套同步（等价于 `files_apply`）；本机没有受管文件层时回 `error{code:"not_supported"}`，不静默忽略（契约 §7-5）。
- **`hint{what:"nodes"}`** 让本机 Xray 内核**立刻**重跑一次机器节点发现（内核本地 `GET /nodes/sync`，见 §13.4），不再等 60 s 轮询；内核未装/太旧/调用失败只记 warn 并退回轮询。`Modules.XrayNodes` 为假时拒绝（本机闸门，契约 §7-6/§7-13）。
- **事件**：应用成功发 `event{kind:"files.applied"}`，回滚发 `event{kind:"files.rolled_back"}`（契约 §7-10，只走 WebSocket；断线期间按 §7-14 缓存补发）。

## 8 常见拒绝原因与排错

下列信息都是真实输出，每一条由 `agent/examples/refusals_test.go` 断言。信息前缀形如 `<实例id>: <字段>: <原因>`。

| 现象（信息节选） | 原因 | 处理 |
|---|---|---|
| `listen address 0.0.0.0 is not allowed by the local policy` | `AllowListen` 默认只有 127.0.0.1 | 在 `Agent.Policy.AllowListen` 加入该地址（如 `["0.0.0.0"]`） |
| `privileged ports (below 1024) are not allowed by the local policy` | 监听 <1024 | 改用高端口，或 `PrivilegedPorts: true` |
| `ports 20080-20080 are outside the permitted range 30000-40000` | 超出 `PortRange` | 改端口或调整 `PortRange` |
| `destination 192.168.1.10 refused: private address (policy.allow_private is off)` | 目标是私网 | 确需转到内网时设 `AllowPrivate: true`；否则换公网目标 |
| `destination 127.0.0.1 refused: loopback address` / `refers to the local host` | 环回目标永远被拒（与 `AllowPrivate` 无关），`localhost` 也不行 | 目标改成本机的非环回地址或别的机器 |
| `host "x" cannot be resolved (…); targets that cannot be checked against the address policy are refused` | 域名解析失败，校验 fail-closed | 修好 DNS，或改用字面 IP |
| `host "x" resolves to 10.0.0.5: private address (policy.allow_private is off)` | 域名解析到私网 | 同私网目标 |
| `allow_any_target: not allowed by the local policy` | 出口想当开放中继 | 改成固定 `targets`；确需任意目标才设 `AllowAnyTarget: true`（等于开放中继，慎用） |
| `tunnel_exit needs fixed targets or allow_any_target` | 出口既没目标也没放开 | 给出口写 `targets` |
| `PROXY headers are forgeable there and the local policy does not allow it` | 在公网地址上收 PROXY 头 | 改监听 `127.0.0.1`（或私网地址），由本机前置代理送入 |
| `PROXY protocol is TCP only and cannot be combined with network udp` | `proxy_protocol_out`/`accept_proxy_protocol` 与 udp 同用 | 拆成 TCP、UDP 两个实例 |
| `secret: must be 16-256 characters of [A-Za-z0-9_.+/=-] (the set every engine accepts)` / `secret: required for kind "tunnel_entry" …` | 密钥缺失、过短或含非法字符（如 `!`、`~`、`:`、`@`）。报错**不会回显密钥** | 换成 16 位以上、只含字母数字和 `- _ . + / =` 的随机串 |
| `targets[0].ports: has 3 port(s) but listen.ports has 10; ranges must be the same length` | 范围长度不一致 | 让目标范围与监听范围等长 |
| `tcp port(s) 20080 on 0.0.0.0 collide with instances[0] (listen)` | 两个实例声明了重叠的监听端口 | 改端口；`0.0.0.0` 与具体地址同端口也算冲突 |
| `duplicate id (also used by instances[0])` | id 重复 | 改 id |
| `engine "gost" is not allowed by the local policy` | 被 `AllowEngines` 排除 | 调整 `AllowEngines` 或换引擎 |
| `engine "realm" cannot run this instance: kind "reverse_portal" is not supported` | 引擎不具备该能力（kind、网络、隧道类型、PROXY、策略等） | 看 §2 换引擎，或用 `engine: auto` |
| `xray 转发引擎已移除，请使用 gost 或 realm` | 用了已删除的内嵌 xray 转发引擎（v11 §2.5） | 换 `gost` / `realm` / `frp`，或用 `engine: auto` |
| `engine "realm" cannot run this instance: health checks are not supported (the engine has no failure detection)` | 写了 `balance.health`，而该引擎没有任何故障检测（realm）。frp 是主动探测，gost 是被动摘除，都放行 | 去掉 `health`，或换 gost / frp |
| `driver validation: gost: … active health checks are not implemented` | gost 只做被动摘除，不接受 `type: http`、`probe_url`、`timeout_s` | 只写 `{type: tcp, interval_s, max_fails}`，或换 frp 的反向 bridge |
| `engine "frp" cannot run this instance: balance strategy "round_robin" is not supported` | frp bridge 每端口只有一个目标，只接受 `failover` | 策略改 `failover`（可带 `health`），或换别的引擎 |
| `tunnel.cert.key_file: not used by kind "reverse_bridge" …` / `tunnel.cert.mode: kind "tunnel_entry" only supports mode "file" …` | 入口 / bridge 侧的 `cert` 只能是信任锚：`mode: file` + `cert_file`，不能带 `key_file`，不能用 `self` / `panel` | 去掉 `key_file`，`mode` 改 `file` |
| `driver validation: realm: acl: realm has no access control …` | 引擎的专属限制（ACL / limits / 证书 / UDP 隧道…），冒号后是驱动给出的原因 | 按原因换引擎或去掉该字段 |
| `tunnel.security: vless_enc 已随 xray 转发引擎移除，请改用 tls / tls_pin / tls_self` | vless_enc 是内嵌 xray 引擎的隧道安全模式，随转发引擎一起移除（v11 §2.5） | 改用 `tls` + 证书、`tls_self`，或把私有 CA 作为 `tunnel.cert.cert_file` 信任锚 |
| `a self-signed certificate cannot be verified by a realm entry …` | realm 入口只信公共 CA | 出口用 `cert.mode: file` 的公共 CA 证书 |
| `realm tunnels carry TCP only …` | realm 隧道不承载 UDP | `network` 改 `["tcp"]` |
| `no signed kernel manifest loaded (set Agent.ManifestPath)` | 外部内核需要已签名清单 | 配置 `ManifestPath`（及 `ManifestKeysPath`）并重启/重载 |
| `download failed: all 1 sources failed: http://…: scheme not allowed` | 清单里的资产是明文 `http://`，而本机没开 `Kernels.AllowHTTP` | 用 https 镜像；确需内网 http 镜像时在 `agent.yml` 写 `Kernels: {AllowHTTP: true}`（只能本机配置，面板不能下发） |
| `frp: frps-… did not become ready in time (see the log of instance …)` / `gost: process did not become ready: api not ready: …` | 实例在就绪上限内没起来（慢设备，或端口/证书/token 有问题） | 先看该实例日志；确实只是启动慢时调大 `Drivers.Frp.ReadyTimeoutSec` / `Drivers.Gost.ReadyTimeoutSec`（缺省：amd64/arm64 且非 OpenWrt 15s，其它一律 60s） |
| `json: unknown field "listn"` | 字段名拼错；解码是严格的 | 对照 §5 改字段名；JSON 里不能有注释 |
| `status: rolled_back` + `blocked` | 应用中途失败已回滚，这份内容被冻结 | 看 `message` 里的具体原因，**改内容**（改 revision 不算）后再应用 |

排错顺序建议：①看 `status`；②`rejected` 看 `validation_errors[]` 的 `field`；③实例级拒绝看 `instances[].error` 与 `considered`；④`rolled_back` / `failed` 看 `message` 和日志里 `reconcile:`、对应驱动的行；⑤端口被占看 `port conflict:` 提示（真实绑定探测，且无法区分占用者）。

## 9 安全须知

1. **`secret` 只应存在于本机 0600 文件里**：你写的 `desired.json`（请 `chmod 600`、属主 root）、Agent 状态目录（`StateDir`，文件 0600）、各驱动的私有配置（0600）。Report、日志、报错信息都经过清洗，不含 `secret`；但 `reverse.domain`（反向代理会合名，≥128 位随机）同样应当当作机密对待，清洗**不覆盖**它。
2. **不要公开粘贴 `desired.json`**。求助时请先把所有 `secret`、`reverse.domain` 和真实 IP 换成占位值。样例中的占位 secret 只用于演示，**绝不能**直接上线；多个隧道不要共用同一个 secret。
3. **PROXY 头可被伪造**，因此 `accept_proxy_protocol` 默认只允许在回环/私网地址上监听，公网监听要靠 `AllowAcceptProxyOnPublic` 本地放开（不建议）。真实来源 IP 只应来自你自己控制的前置代理。
4. **隧道出口默认只放行声明的目标**：`tunnel_exit` 必须写固定 `targets`，`allow_any_target` 需要本地 `AllowAnyTarget`；反向代理的 bridge 只服务 `targets` 声明的目的地。realm 出口不是守门员，务必用防火墙限制来源；gost 的出口还可以用 `acl.allow` 只放行入口机的地址。
5. **本地策略是根信任**，期望状态无法放宽它；默认拒绝公网监听、私网目标、任意目标、公网收 PROXY。`AllowPrivate` 打开后仍拒绝环回、链路本地、云元数据地址。
6. **优先用字面 IP 作目标**：域名只在校验时解析一次，存在 DNS 重绑定的时间窗。
7. **隧道要有认证和加密**：样例不使用 `allowInsecure` 之类的不验证选项，也不使用 `security: none`。自签证书用 gost 的 `tls_self`（两端由 `secret` 派生同一张证书），其余用公共 CA 证书，或把私有 CA 作为 `tunnel.cert.cert_file` 信任锚交给入口 / bridge。frp 的 bridge 不配信任锚时不校验 portal 证书，对抗主动中间人的场景请配信任锚，或用 gost。
8. 外部内核只从**已签名清单**安装，哈希校验失败一律拒绝（fail-closed）；期望状态无法指定 URL 或哈希。脚本执行或任意命令通道仍然不存在，外部命令一律用参数数组启动。**交互终端是例外**：它默认开启（§3），只由本机 `Terminal.Enabled` 控制，面板不能远程打开；不需要的机器请显式关闭（`Terminal: {Enabled: false}` 或 `--noterminal`），尤其是升级后的老机器。
9. **OpenWrt 上 agent 会写防火墙**（D2）：仅当平台是 OpenWrt 且本机 `Firewall.AutoOpen` 生效为 true 时，agent 为对外监听的实例写入/删除 `w1ncray_*` 规则并 `uci commit firewall` + 重载。它只碰自己前缀的 section，绝不改用户的规则、zone 与 defaults；`Firewall: {AutoOpen: false}` 在本机关闭它，其它系统上它恒为关闭。规则是 UCI 配置，重启后仍在。

## 10 安全模型变更记录（D8：交互终端）

本节是**有意识的安全模型变更**的正式记录，由 `agent/terminal/noshell_allow_test.go` 反向断言：白名单里的每个包都必须在本节里按包路径写出来，改了代码不改这里，测试就会失败。

1. **变更内容**：agent 从"没有终端、没有脚本执行、没有任意命令通道"变成"有一个**本机开关控制**的交互终端"。这是本手册与 `docs/PLAN-v6-agent-forward.md`、`docs/PLAN-v7-panel-control.md` 里"不存在终端"表述的**唯一例外**，其余约束（外部命令一律 argv 数组、期望状态不含 URL/哈希、无脚本推送）逐字不变。
2. **唯一允许起 shell 的包**：`agent/terminal`。`agent/supervisor/noshell_test.go` 的 `AllowedShellPackages` 是**包级白名单**，只有这一个条目，并附有理由；白名单之外的任何 `agent/**` 包一旦出现 `exec.Command(<shell>)`、`<shell>,"-c"`、`syscall.ForkExec/Exec`、`pty.Start*`，或 `exec.Command(<变量>)`（无法静态判定时保守报错，需 `//nolint:noshell` 显式豁免并计数），测试直接失败。
3. **本机开关**：`Terminal.Enabled` **缺省为 true**（RULINGS v9 第 17 条）。机器只能在**本地**关闭：`agent.yml` 写 `Terminal: {Enabled: false}`，或安装/关联时用 `--noterminal`（`install.sh --noterminal`、`W1nCray link --noterminal`）。面板**无法远程打开或关闭**：本机状态只通过 `hello.policy.terminal` 上报，面板据此显示"该机器已在本地关闭终端"。
4. **平台支持是运行时探测的**：`terminal.Supported()` 在运行时打开 `/dev/ptmx` 判断本机能否建立 PTY；不支持的平台/内核（部分 OpenWrt 无 devpts）**不声明** `terminal` 能力，`hello.capabilities` 与 `/config.features` 里都不会出现它。编译通过不等于能工作。
5. **会话边界**：每机最多 2 个并发会话（`Terminal.MaxSessions` 上限也是 2）；空闲 15 分钟（`IdleTimeoutS`）回收；最长 4 小时（`MaxDurationS`）回收；agent 退出或面板链路关闭时 `CloseAll` 杀掉**整个进程组**，不留孤儿 shell；单个 `term.input` 帧 ≤ 64 KiB。
6. **环境净化**：子进程只拿到固定白名单变量（`TERM/LANG/LC_ALL/LC_CTYPE/PATH/HOME/USER/LOGNAME/SHELL/TZ/PWD`），其余一律剔除——包括机器 token、任何 `Agent.*` 值、`LD_PRELOAD`/`LD_LIBRARY_PATH`/`LD_AUDIT`/`BASH_ENV`/`NODE_OPTIONS`/`PYTHONPATH` 等注入面。
7. **审计只有元数据**：`terminal.AuditEvent` 结构体里**没有任何内容字段**（编译期保证），只有会话 id、动作、时间、时长、`BytesIn`/`BytesOut`、结束原因。终端字节永远不会进入审计、日志或事件帧。
8. **`agent/fileops` 的边界**：`file_*` 只在 `Files.Roots` 内工作（默认 xray 配置目录 + agent 状态目录），`agent.yml`、`desired.json`、`last_good.json` **永不在任何 root 内**；拒绝 `..`、绝对路径、符号链接逃逸、FIFO/设备/非常规文件、目录删除；可执行位需 `Files.AllowExec`，setuid/setgid/sticky 一律拒绝；`file_read.limit` 与 `file_write` 载荷各 ≤ 128 KiB（WS 单帧 256 KiB 契约，RULINGS v9 第 9 条）。
9. **已知限制（TOCTOU）**：`os` 包没有 `openat`，`fileops` 的"逐段 Lstat + `O_NOFOLLOW` 打开"之间存在极小的 TOCTOU 窗口。因此部署要求：**root 内不应有可被非 root 用户改写的目录**。这一条已在 `agent/fileops` 的包注释里写明。
10. **`Files.Unrestricted` 三态（PLAN v10）**：`agent/fileops` 的根目录限制不再是"缺省开启"。`Files.Unrestricted` **不写**时跟随终端：终端有效开启（缺省开启）→ 文件管理**不受限**，面板可以用绝对路径（`root` 传空）读写 agent 进程有权限访问的任意文件。理由：终端本身就是一个 root shell，根目录限制没有安全增量，只剩不便。需要限制的机器必须**显式**写 `Files: {Unrestricted: false}`。两种模式下不变的部分：`agent.yml`、`desired.json`、`last_good.json` 永不可达；符号链接、FIFO/设备/非常规文件、`..`、大小上限（`MaxRead`/`MaxWrite`）规则照旧；新增的 `file_mkdir` / `file_rename` 与 `file_write` 走同一套路径规则，`file_rename` **永不覆盖**已存在的目标，`file_write append` 只追加到已存在的普通文件。本机有效值通过 `hello.policy.files.unrestricted` 上报。

## 11 已知限制与未决事项

以下是写样例和本手册时发现的、**需要代码侧决定**的不一致，均有测试或命令输出佐证；它们不影响上面样例的有效性，但会限制能写出什么：

1. **反向代理（已解决）**：语义已统一为「bridge 决定目的地」——portal 不带 `targets`（它给用户连接盖一个 TEST-NET-1 占位目的地），bridge 用自己的 `targets`（或 `allow_any_target` + 本地策略）改写每个被转发的连接；portal / 它的用户都选不了目的地。`reverse.bridge_allow` 只在 frp 上作为目的地白名单使用，gost 忽略它；新样例一律用 bridge 的 `targets`。gost / frp 反向样例均已晋升为正式样例。
2. **`balance.health`（已解决）**：`reconcile/select.go` 现在按驱动实际接受什么来判断：主动（frp）与被动摘除（gost）都放行，没有故障检测的引擎（realm）才拒绝；frp 的 `Caps` 如实声明 bridge 支持 `failover` + 主动健康检查。`auto` 优先主动探测，只能用被动时在 `considered` 里注明。`forward-gost-limits` 与 `reverse-frp-bridge` 样例已带上 `health`。
3. **私有 CA / 自签证书（已解决）**：入口 / bridge 现在可以带 `tunnel.cert: {mode: "file", cert_file}` 作信任锚（gost 作 CA 文件，frp 作 `trustedCaFile`），`key_file` 与非 `file` 模式被拒；出口 / portal 侧规则不变。gost 入口自签证书用 `tls_self`（或 `tunnel.cert` 信任锚），realm 入口只信公共 CA。**`tls_self`** 让面板不必生成 x509：两端用共享 secret 派生同一张自签证书（gost 写证书文件 + `secure`/`caFile`），realm 拒绝。
4. **`secret` 字符集（已解决）**：`validate` 收紧到三个引擎的交集 `[A-Za-z0-9_.+/=-]`，`~` `:` `@` 等在校验阶段就被拒。
5. `W1nCray check` 不校验 `desired.json` 内容，也没有 dry-run 命令。
6. 面板下发（`Agent.Panel` 的期望状态与「机器模式节点」，见 §3）已实现；多机批量配置仍属后续阶段。

## 12 重载语义（xray 与 agent 解耦）

从 v11（WP-X1 / D5）起，Xray 内核是**独立进程** `W1nCray-xray`：agent 不再与 Xray 同进程，也不再持有可重建的 xray 实例（进程内转发引擎 `driver/xray` 与 `corehost` 已删除）。因此「改 xray 配置只重建 xray、agent 与转发实例不动」由两个进程天然保证，完整的变更分类表见 §13.6。

- `agent.yml` / `config.yml` 的 `Agent:` 块变化 → 只重启 agent 进程（外部内核实例、面板链接重建）；Xray 内核进程不受影响。
- Xray 文件（`config.yml` 的 Xray 部分、`route.json`、`dns.json`、`custom_inbound.json`、`custom_outbound.json`、节点 `RuleListPath`、机器节点列表）变化 → 只由 `W1nCray-xray` 重建，agent 完全不动。
- `desired.json` → 走期望状态应用（只增删 gost / frp / realm 实例），不重建任何进程。
- `files_apply` / `files_*` 触发的重载 → `W1nCray` 请求 `W1nCray-xray` 校验并重载（`applied_pending` 在同一连接上回报），agent 与链接保持。
- `self_update` → 重启 agent 进程；`W1nCray-xray` 由服务管理器独立运行，**不中断**。

> 历史说明：v11 之前本节描述「同一个 `W1nCray` 进程里跑 xray core 与 agent」，并用 `corehost.Swappable` / `Runtime.ReattachXray` 在重建 core 后重挂实例；这些机制随进程内转发引擎一起删除，现已不存在。

## 13 程序结构（两个程序）

从 v11（WP-X1）起，原来的单一程序拆成**两个可执行文件**，可以同时运行、互不阻塞：

| 程序 | 安装方式 | 链接 Xray-core |
|---|---|---|
| `W1nCray`（agent） | `install.sh` 一键安装 | **否** |
| `W1nCray-xray`（Xray 内核） | 由 agent 按已签名清单下载安装（清单内核名 `xray`），**默认不安装** | 是 |

### 13.1 `W1nCray`（agent）

职责：面板连接（HTTP + WebSocket）、交互终端、文件管理、外部内核（gost / frp / realm）的下载与监管、转发实例、自升级、遥测。它**不链接 Xray-core**，也不建立 Xray 实例；机器模式所需的面板地址、机器 ID、令牌与 `NodeController(s)` 只由它读取后交给内核进程使用（`W1nCray-xray` 自己再读一次同样的 agent 配置）。

命令：

| 命令 | 说明 |
|---|---|
| `W1nCray run`（默认） | 常驻：agent 运行时 + 面板链接 + 终端/文件/自升级 |
| `W1nCray version` | 打印 agent 版本（不含 Xray-core 版本） |
| `W1nCray check [-c config.yml] [--online]` | **只检查 agent 配置**（agent.yml 或 `config.yml` 的 `Agent:` 块、清单路径、令牌、清单同步）；不检查 `Nodes` 与 Xray 文件——那是 `W1nCray-xray check` 的职责 |
| `W1nCray link` / `link --split` / `migrate` | 与 v10 相同；写入前的离线检查改为调用外部内核（见下） |
| `W1nCray agent-apply -f desired.json` | 只支持外部引擎（gost / frp / realm）；`engine: xray` 被拒绝 |
| `W1nCray xray status\|start\|stop\|restart\|install [version]\|remove` | 本机管理 Xray 内核服务，调用与面板路径**同一套** `agent/xraysvc`（见 §13.5） |
| `W1nCray xray install --file <文件或 .gz> --sha256 <hex>` | 离线安装本地 Xray 内核构建（见 §13.8.3） |

`link` / `link --split` 的**写入前校验**需要 Xray 侧的检查：加 `--xray-bin <路径>`，或在 `W1nCray` 同目录 / `PATH` 找到 `W1nCray-xray` 时，会执行 `<W1nCray-xray> check -c <配置>` 并把输出里以 `✗` 开头的行当作失败项参与基线比较；找不到内核时**跳过该检查并打印说明**（agent 侧仍会校验机器模式的证书模式等问题）。

### 13.2 `W1nCray-xray`（Xray 内核）

职责：Xray-core 实例；`app/dispatcher`（包装 Xray 内部 DefaultDispatcher）与 `common/limiter` 实现 Xboard 用户的**限速、设备数限制、在线 IP 统计、断开连接**；每个节点的 Xboard 控制器（静态 `Nodes` 与机器模式面板下发）；Xray 配置文件监听（`config.yml`、`route.json`、`dns.json`、`custom_inbound.json`、`custom_outbound.json`、节点 `RuleListPath`，沿用 v10 的内容指纹去重）；暂存文件校验；离线检查；本机状态接口。

命令：

| 命令 | 说明 |
|---|---|
| `W1nCray-xray run -c <config.yml>`（默认） | 常驻：Xray 实例 + 节点控制器 + 配置监听 + 状态接口 |
| `W1nCray-xray version` | 打印 `W1nCray-xray v0.6.0 (Xray-core 26.3.27)`，供清单 `version_cmd` 使用 |
| `W1nCray-xray check -c <config.yml> [--online]` | 原离线检查的 Xray 部分（节点、dns/route/自定义出入站、实例构建、机器节点列表） |
| `W1nCray-xray check-staged -c <config.yml> --dir <暂存目录> --files a,b` | 校验暂存文件集，输出 `{"ok":bool,"errors":[{"file":..,"message":..}]}`；退出码 0/1（语义同原 `CoreValidator.ValidateStaged`） |
| `W1nCray-xray x25519` | 生成 REALITY 密钥对 |

在 OpenWrt（`/etc/openwrt_release` 存在）上，agent 查找清单目标时依次尝试
`openwrt_targets["os/arch"]`（lite 变体，v11 起的格式）→ `targets["os/arch+openwrt"]`（旧格式，
继续兼容已签发的清单）→ `targets["os/arch"]`；非 OpenWrt 只看 `targets["os/arch"]`，**永不**读取
`openwrt_targets`。`targets` 的每个键都必须是纯 `os/arch`：0.5.x 的清单解析器只认
`^[a-z0-9]{2,16}/[a-z0-9]{2,16}$`，且遇到任一不合规键就拒绝整份清单（见
`tools/manifestgen/README.md`）。v11 的 `Validate` 对 `os/arch+<未知后缀>` 只忽略该目标并在
`ValidateReport` 里报告，不再整份拒绝。

### 13.3 单实例锁

两个程序各自加锁，**互不冲突**，可以同时运行：

| 程序 | 锁文件 |
|---|---|
| `W1nCray` | `<config>.lock` |
| `W1nCray-xray` | `<config>.xray.lock` |

锁是 `flock(2)`（无 flock 的平台为无操作），进程以任何方式退出都会释放；锁文件里写着持有者的 pid，抢占失败时的报错会带上它。

### 13.4 状态接口

`W1nCray-xray run` 在本机提供只读状态接口：

- Unix 系统：`/run/W1nCray/xray.sock`（Unix 套接字，权限 0600；目录可用 `W1NCRAY_RUNTIME_DIR` 覆盖，测试与非 root 开发用它）。
- Windows：`127.0.0.1` 上的随机端口，端口写入 `<config 目录>/xray.addr`。

套接字**不**放在配置目录里：配置目录在 `/etc/W1nCray`（SELinux 类型 `etc_t`），而内核服务在 SELinux 机器上的域不允许在 `etc_t` 里创建套接字（见 §13.7）。`/run/W1nCray` 由 systemd 的 `RuntimeDirectory=W1nCray` 创建，OpenRC / procd 的 init 脚本与内核自己也会创建它；目录不可用时内核退回 `<config 目录>/xray.sock`，agent 两边都读，所以升级中的旧内核也照常工作。

`GET /status` 返回：

```json
{
  "version": "0.6.0",
  "xray_core": "26.3.27",
  "started_at": 1760000000,
  "running": true,
  "nodes": [{"tag": "node173@machine3", "id": 173, "type": "vless", "users": 12, "online": 3, "error": ""}],
  "config_fingerprint": "<sha256>",
  "last_reload_at": 1760000123,
  "last_error": ""
}
```

`config_fingerprint` 就是 v10 的被监听文件内容指纹（重载成功后更新）；`running` 表示 Xray 实例是否在跑；`last_error` 是最近一次重载/启动错误。

同一个监听上还有一条**无参数**的写路由（不新增任何监听、不暴露到网络，只在本地端点上）：

`GET /nodes/sync` — 让内核**立刻**重跑一次机器节点发现（与 60 s 轮询同一套「取 version → 变了才 `requestReload`」），返回 `{"changed": bool, "version": "…"}`。`changed=false` 表示列表没变、没有重载；机器模式关闭时也是 `changed=false`（没有列表可刷新）。面板不可达时返回 `502`，运行中的节点列表保持不变。请求不接受任何路径、命令或节点数据，只接受 `GET`（其它方法 `405`）。它存在的唯一理由是 `hint{what:"nodes"}` 的降级路径：agent 调不到它（内核未装/太旧/失败）就退回轮询（§2 机器模式、§13.5）。

### 13.5 agent ↔ 内核的接入点（X2）

agent 通过 `agent/xrayapi` 的接口访问内核，**不导入任何 Xray-core 包**：

```go
type Service interface {
	Status(ctx context.Context) (Status, error)
	SyncMachineNodes(ctx context.Context) (changed bool, err error)
	CheckStaged(ctx context.Context, dir string, files []string) (StagedResult, error)
	WaitReloaded(ctx context.Context, fingerprint string) error
}
```

`agentd.Options.Xray` 与 `bootstrap.Options.Xray` 都接受它。X1 里 agent 传 `nil`，此时受管 Xray 文件的 `files_apply` 会以明确原因 **`Xray 内核未安装`** 拒绝，而不是写下一份没有实例会读取的文件。X2 起由 `agent/xraykern` 实现它：

- `Status` 读 `/run/W1nCray/xray.sock`（旧内核的 `<config 目录>/xray.sock` 仍然接受；Windows 读 `xray.addr`）的 `GET /status`，2 s 超时；连不上就是「内核没在跑」。
- `SyncMachineNodes` 读同一端点的 `GET /nodes/sync`，超时 10 s（`DefaultSyncTimeout`；比 `Status` 的 2 s 长，因为内核要替它走一次面板往返，但仍短到不会长时间占住 WebSocket 的帧读取协程）。旧内核没有该路由会返回 404，客户端把它当错误上报，调用方（`bootstrap.xrayNodeHint`）只记 warn 并退回内核的 60 s 轮询。请求不带任何参数。
- `CheckStaged` 执行**已安装当前版本**的 `W1nCray-xray check-staged -c <config> --dir <dir> --files a,b` 并解析它的 JSON；未安装时返回 **`Xray 内核未安装`**。校验用的是运行实例将来会用的同一个 loader。解析不整段 `json.Unmarshal`：stdout 里混入的日志行（Xray-core loader 自己打的）会被跳过，取**最后一个完整 JSON 对象**（`lastJSONObject`，尊重字符串与转义）；这是 agent 侧的防御，因为 agent 必须兼容清单里任意新旧的内核构建，而独立输出通道要求两边同步升级（R1-3）。
- `WaitReloaded` 在 `files_apply` 写入受管文件后，等待状态接口的 `config_fingerprint` 变成**写入后文件的指纹**，超时 30 s。指纹用 `config.Fingerprint` 对 `config.WatchedFiles` 计算——与内核（`xraynode`）**同一份代码**，所以两边不可能不一致；超时即 `files_apply` 失败，走既有的 `last_good` 回滚路径（§13.6 的 `files_apply` 行）。

### 13.5.1 服务管理（`agent/xraysvc`）

Xray 内核**不**是 agent 的子进程，而是一个独立服务：agent 重启、升级、崩溃都不影响它。`agent/xraysvc` 按机器探测后端并**自己生成**服务文件（路径与内容全部来自 agent，面板永远不能传路径或命令）：

| 后端 | 探测 | 服务文件 |
|---|---|---|
| systemd | `/run/systemd/system` 存在 | `/etc/systemd/system/W1nCray-xray.service`：`ExecStart=<当前版本二进制绝对路径> run -c <config.yml 绝对路径>`、`Restart=always`、`RestartSec=5`、`LimitNOFILE=1048576`、`WorkingDirectory=<配置目录>`、`RuntimeDirectory=W1nCray`（状态套接字目录，见 §13.4/§13.7）；`systemctl daemon-reload`、`enable`、`start` |
| OpenRC | `/sbin/openrc-run` 存在 | `/etc/init.d/W1nCray-xray`（`supervisor="supervise-daemon"`、`respawn_delay=5`、`respawn_max=0`（不限次数）、`start_pre` 里 `mkdir -p /run/W1nCray`）；`rc-update add W1nCray-xray default`、`rc-service W1nCray-xray start` |
| procd | `/sbin/procd` 与 `/etc/rc.common` 存在 | `/etc/init.d/W1nCray-xray`（`USE_PROCD=1`、`procd_set_param respawn 3600 5 0`（三个参数依次是 threshold / timeout / retry，timeout 即重启间隔）、`start_service` 里 `mkdir -p /run/W1nCray`）；`enable`、`start`；内核目录与 init 脚本追加进 `/etc/sysupgrade.conf`（去重） |
| agent 子进程 | 三者都没有 | 由 agent supervisor 运行（与 gost 相同），状态里 `managed_by: "agent"`，面板据此提示「此系统 Xray 会随 agent 重启」 |

三种后端的崩溃重启间隔统一为 **5 s**（`render.go` 的 `restartDelaySeconds`）：T1 实测 OpenRC/procd 原先等 10 s，路由器上 Xray 崩溃会比 systemd 机器多中断 5 s。只统一这个间隔，procd 的 threshold（3600 s）与两者的「不限次数」语义不变。

服务名固定为 `W1nCray-xray`。`Install`/`Upgrade`/`Rollback`/`Restart`/`Remove` 都幂等、带超时、失败可读：

- `Install`：按清单 `Ensure`（内核名 `xray`）→ 写服务 → 启动/重启 → 健康检查（状态接口 30 s 内 `running=true`）。**换版本一定重启**：服务文件内容变化、或运行中的内核报告的版本与要装的版本不同时，`activate` 用 `restart` 而不是 `start`（三个 init 系统的 `start` 对已 active 的单元是 no-op，否则旧进程会继续跑而单元与 current 指针已指向新版本）；同版本、服务文件不变的幂等重装不重启。健康检查失败时：**安装前服务在运行** → 回滚到安装前运行的版本并重启（与 `Upgrade` 一致），不会把可用的 Xray 停掉；安装前本来没有服务 → 停掉并删除刚写的服务，不留半装状态；`Ensure` 失败则什么都不写。
- `Upgrade`：装新版本 → 改服务指向 → 重启 → 健康检查；失败自动 `kernelx` 回滚到上一版本并重启，报告里带上失败原因与回滚结果。
- `Remove`：停止并禁用服务、删除服务文件、删除该内核**所有**版本；**保留** `config.yml` 与受管文件，重装即恢复。agent 子进程后端（没有 init 系统）下，删除内核文件前会等待 supervisor 的子进程真正退出（`RemoveTimeout`，默认 10 s）；超时仍在运行则返回 **`in_use`** 且**不删任何文件**（R1-8），避免删掉正在执行的二进制与回滚指针。**幂等**（D-M2）：服务不存在（从未安装，或已经卸掉）时直接成功返回，不会把 `systemctl stop` 的 `Unit … not loaded`（以及 OpenRC / procd 的等价情况）当失败上报；`kernel_remove xray` 的结果里带 `already_absent: true`。`kernel_remove xray <当前版本>`（以及 `version` 为空的历史兼容路径）才走这条整服务卸载路径；`kernel_remove xray <旧版本>` 只删该版本目录、不碰服务（§7 的 `kernel_remove` 行）。

面板命令接入：`kernel_install`（已装过则走 `Upgrade`，带自动回滚）、`kernel_remove`（`version` 为当前版本时整服务卸载并回 `uninstalled: true`；为旧版本时只删该版本、不停服务）、`kernel_rollback`、`component_restart` 在 `name=xray` 时都走这一套。`kernel_list` / `hello.kernel_entries` 里 xray 与其它内核格式一致，并附 `service`（`backend`、`state`、`managed_by`）；`state ∈ running/stopped/failed/installing/not_installed`。遥测的 `components` 里 xray 项来自状态接口：state、version、每个节点一项（在线数）、`last_error`。

### 13.5.2 启动迁移与自升级顺序

agent 启动时若配置需要 Xray（`config.yml` 有 `Nodes`，或机器模式 `Agent.Panel.MachineNodes` 为真），且服务未安装/未运行：

1. 内核已在 `kernelx` 里（例如 0.5.x 面板先下发过 `kernel_install xray`）→ 只写服务并启动；
2. 否则 → 按清单安装再启动，日志写明「检测到 Xray 节点配置，正在安装 Xray 内核」。

**顺序是硬性的**：以上动作只在自升级确认（`selfupdate` 的 `Confirm`）之后做。没有待确认的自升级时在启动后立即做（`bootstrap.Boot` 里）；有待确认时，带面板的机器在面板应答（`OnConnected`）后做，本机（无面板）在 `W1nCray` 命令确认后做。理由：确认前若看门狗回滚到 0.5.x（进程内 Xray），不能已经有 Xray 服务占着端口。

**面板不可达不再无限期推迟（R1-7）**：带面板的机器上，若 `ConfirmWindow`（默认 10 min）内面板始终没有应答，该进程会自行执行上面的启动迁移并发 `self_update.xray_started`。此时看门狗已经退出（`Deadline` 到点不回滚，唯一的回滚执行者消失），而回滚路径本身也会先停 `W1nCray-xray`（R1-16），所以「先起 Xray 再回滚」的端口冲突不会发生。

### 13.5.3 回退到 0.5.x

0.5.x 的单一程序**不会**停止 Xray 服务。从 0.6 回退到 0.5.x 之前，必须先执行：

```
W1nCray xray stop
```

（或直接 `W1nCray xray remove` 卸载 Xray 内核。）否则 0.5.x 的进程内 Xray 会与 `W1nCray-xray` 服务争抢端口。0.6 内部回滚到 0.5.x 是安全的：回滚只可能发生在自升级确认之前，而那时服务还没启动（§13.5.2）。

### 13.6 重载语义（拆分后）

| 变化的文件 | 谁反应 | 结果 |
|---|---|---|
| `agent.yml`、`config.yml` 的 `Agent:` 块 | `W1nCray` | 生效的 agent 配置确实变化 → 只重启 agent（外部内核实例、面板链接重建）；内容不变（touch）→ 什么都不做 |
| `desired.json` | `W1nCray` | 走期望状态应用（只增删实例） |
| `config.yml` 的 Xray 部分、`route.json`、`dns.json`、`custom_inbound.json`、`custom_outbound.json`、节点 `RuleListPath`、机器节点列表 | `W1nCray-xray` | 只重建 Xray 实例与节点控制器；agent 完全不受影响（两个进程） |
| `files_apply` 写入受管文件 | `W1nCray` → `W1nCray-xray` | 写入前 agent 用内核的 `check-staged` 校验；写入后重算受管文件指纹并等内核的状态接口报告它（30 s）。成功 = `reloaded`；超时/失败 = `files_apply` 失败并按既有路径回滚到 `last_good`（§13.5） |
| `self_update` | `W1nCray` | 重启 agent 进程；`W1nCray-xray` 由服务管理器独立运行，**不中断** |

拆分后 `config.yml` 同时属于两个程序：`W1nCray` 只读它的 `Agent:` 块，`W1nCray-xray` 读 Xray 部分并按上面的表监听重载。

### 13.7 SELinux（CentOS/RHEL 系，enforcing）

内核二进制装在 agent 的 state 目录（`/etc/W1nCray/state/kernels/kernels/<名字>/<版本>/`），**默认类型是 `etc_t`**——因为它在 `/etc` 下。systemd（`init_t`）执行 `etc_t` 文件时**不会**转到 `unconfined_service_t`（`/usr/local` 下的 agent 二进制是 `usr_t`，会转），进程留在 `init_t`；而 `init_t` 不允许在 `etc_t` 目录里创建套接字：

```
type=AVC msg=audit(...): avc:  denied  { create } for  pid=... comm="W1nCray-xray"
  name="xray.sock" scontext=system_u:system_r:init_t:s0
  tcontext=system_u:object_r:etc_t:s0 tclass=sock_file permissive=0
```

结果是服务启动即退出（`Error: status socket /etc/W1nCray/xray.sock: listen unix ...: bind: permission denied`），`Restart=always` 让它反复重启，健康检查永远不通过。修复分两层：

1. **状态套接字搬出配置目录**（§13.4）：`/run/W1nCray/xray.sock`。`/run/W1nCray` 是 `var_run_t`，不是配置树的一部分；systemd 用 `RuntimeDirectory=` 创建，OpenRC / procd 的 init 脚本创建，agent 的 fallback 后端与内核自己也会创建。
2. **内核二进制标为 `bin_t`**（`agent/selinux`）：`bin_t` 让 systemd 把进程放进 `unconfined_service_t`（与 agent 同域）。有 `semanage` 时对内核树加一条持久 fcontext 规则（`<KernelsDir>/kernels(/.*)?` → `bin_t`）再 `restorecon -R -F`；没有 `semanage` 时退回 `chcon -R -t bin_t`；两个工具都没有时只记一条警告——缺工具绝不能让安装失败（服务随后会以可读的错误报出来）。

打标签的时机：`kernelx` 在 `Ensure`（安装/升级）、`Rollback` 与 `InstallLocal`（本地文件安装，§13.8.3）成功后给整棵树打标签（尽力而为，只记日志）；`xraysvc` 在写服务文件、启动之前再确认一次（这里失败即中止启动）；`supervisor` 在每次启动 gost/realm/frp 子进程前确认该二进制（同一进程内按路径去重，已被整棵树覆盖的二进制直接跳过，所以不会为每个版本堆积 fcontext 规则）。`install.sh` 在安装时也做一次（`selinux_prepare`，卸载时 `selinux_forget` 删掉规则）。

SELinux 关闭时这些路径全是空操作（`agent/selinux` 先读 `/sys/fs/selinux/enforce`）；因此非 SELinux 机器与 Windows 不受影响。

### 13.8 发布产物与清单条目（WP-X3）

#### 13.8.1 `release/build.sh` 的产物

`bash release/build.sh [vX.Y.Z] [arch ...]` 为 12 个架构各产出两个程序，同一个版本号注入两个程序（agent 的 `cmd.version`、内核的 `xraynode.Version`）：

| 产物 | 程序 | 构建标签 |
|---|---|---|
| `W1nCray-linux-<arch>.gz` | agent | `fallbackroots`（内置备用根证书；agent 不含 DNS/ACME，约 12 MB） |
| `W1nCray-linux-<arch>-lite.gz` | agent | 与上一行**同内容**的副本，仅为兼容 v11 之前的安装脚本（它们按 `-lite` 名字取 OpenWrt 资产）而保留 |
| `W1nCray-linux-amd64\|arm64` | agent | 裸文件，供 v0.3.0 之前的安装脚本升级 |
| `W1nCray-xray-linux-<arch>.gz` | Xray 内核 | 无（full） |
| `W1nCray-xray-linux-<arch>-lite.gz` | Xray 内核 | `dnslite,fallbackroots`（OpenWrt） |

`SHA256SUMS` 覆盖以上全部产物。构建矩阵断言除原有的架构/PTY 检查外，还对每个产物做 `file(1)` 架构检查、在本机架构上执行 `version` 自检（交叉架构跳过并注明），并用 `go version -m` 检查 **agent 产物不含 `github.com/xtls/xray-core`**、内核产物必须含它。

#### 13.8.2 清单条目（`tools/manifestgen/examples/v11.yaml`）

agent 与 Xray 内核都是本地构建（`local:` 条目从 `dist/` 计算哈希，需要一个 mirror 提供下载地址），上游 gost/realm/frp 仍从各自 GitHub Release 取：

```yaml
  - name: xray
    version: "0.6.0"
    run:
      binary: W1nCray-xray
      version_cmd: ["version"]
      version_regex: "W1nCray-xray v?([0-9][0-9.]*)"   # 从 "W1nCray-xray v0.6.0 (Xray-core 26.3.27)" 取 0.6.0
    mirrors: ["https://<mirror>/W1nCray-xray/{version}/{asset}"]
    local:
      - {file: dist/W1nCray-xray-linux-amd64.gz,      target: linux/amd64, to: W1nCray-xray}
      - {file: dist/W1nCray-xray-linux-amd64-lite.gz, target: linux/amd64, to: W1nCray-xray, variant: fallbackroots, openwrt: true}
      # ... 其余架构相同：full -> targets[linux/<arch>]，lite -> openwrt_targets[linux/<arch>]（openwrt: true）
```

- 资产是**单文件 raw gz**（与 agent 条目相同的解包方式：`archive: gz`，`extract.from` 默认取归档基名）。
- **OpenWrt lite 构建放 `openwrt_targets`，键是不带后缀的 `os/arch`**（`openwrt: true` 的 local 条目，
  或配置里的 `openwrt_targets:`）。`targets` 的每个键都必须满足 0.5.x 的旧正则
  `^[a-z0-9]{2,16}/[a-z0-9]{2,16}$`：0.5.x 遇到任一不合规键会拒绝**整份**清单，`kernel_install` /
  `self_update` 全部 `no_manifest`（REG3-1）。`openwrt_targets` 是 0.5.x 不认识的字段，被它的
  `json.Decoder` 忽略，所以新清单在旧 agent 上可用。选择顺序与兼容理由见 `tools/manifestgen/README.md`。
- `min_agent` 故意留空：0.5.x agent 必须能先安装 Xray 内核（§2.6 的迁移顺序），所以内核条目不能要求 0.6。
- `manifestgen build -kernels xray` 只重建选定的内核条目，便于 agent/内核重新构建后单独发布，而不必重新下载全部上游资产。
- 第二个 Xray 版本（升级/回滚测试用）在示例里是**注释掉的占位条目**：本仓库没有旧构建，`release/build.sh` 只产出当前版本；用旧 tag 构建到 `dist/old/` 后取消注释即可。不要把它指向当前 `dist/` 文件——内核自检会发现版本不符。

#### 13.8.3 本地文件安装（`W1nCray xray install --file`）

`W1nCray xray install --file <W1nCray-xray 文件或 .gz> --sha256 <hex>` 用于 install.sh 的迁移和离线环境：

1. 校验文件的 sha256（必填，缺失或不是 64 位十六进制即拒绝）；
2. 解包（gzip 魔数判断，裸文件也接受）到内核目录的暂存区，执行 `version` 自检得到版本；
3. 用**与按清单安装完全相同**的 `commit` 写入 `<kernels>/xray/<版本>/` 与 `.installed.json`、`current`/`previous` 指针，因此 `kernel_list`、升级、回滚、卸载都能识别它；
4. 复用 `agent/xraysvc` 写服务并启动（与面板路径同一套实现）；安装成功后与按清单安装一样给内核树打 SELinux `bin_t` 标签（§13.7，尽力而为），启动前 `xraysvc` 再确认一次，所以本地安装的 Xray 内核与清单安装的走完全相同的 SELinux 与 `/run/W1nCray/xray.sock` 路径。

`install.sh` 的 `update` 在检测到「0.5.x 及以前的单一程序 + 配置里有 Xray 节点」时自动执行这一串步骤（见 §13.9）。

### 13.9 install.sh 的三条路径（v11）

| 路径 | 行为 |
|---|---|
| `install`（全新） | 只安装 agent（`W1nCray` 程序 + `W1nCray` 服务），**不安装 Xray 内核**；结束时提示「Xray 内核将在面板绑定节点时自动安装，或执行 `W1nCray xray install`」。`--panel URL --machine ID --token TOKEN` 一键接入保持不变。 |
| `update`（升级） | 已是 v11 agent：只更新 agent。0.5.x 及以前的**单一程序**且配置需要 Xray（`config.yml` 有 `Nodes`，或 `Agent.Panel.MachineNodes` 为真）：先下载 agent 与对应架构的 Xray 内核资产（OpenWrt 用 `-lite`）并通过 `SHA256SUMS` 校验，再按顺序 **停止旧服务 → 替换 agent → `W1nCray xray install --file ... --sha256 ...` → 启动 agent**，并打印中断时长提示。下载在停止服务之前完成。停止服务前先把旧程序与旧服务文件备份到 `<BIN>.pre-v11` 与 `<unit>.pre-v11`（R1-11）：`xray install --file` 失败时自动把两者恢复回去并重新启动旧服务，再报错退出（提示机器已恢复到原版本）；迁移成功或恢复成功后删除这两个备份。没有服务管理器（`BACKEND=none`）时不尝试安装内核，备份保留并在提示里给出路径。 |
| `uninstall` | 停止并删除 `W1nCray` 服务后，调用 `W1nCray xray remove` 停止并删除 `W1nCray-xray` 服务与内核文件（失败时脚本按当前后端自己删除 unit/init 脚本）；是否保留配置目录与原来一致（`--purge` 才删除）。 |

管理菜单新增 14–19（Xray 内核 状态/启动/停止/重启/安装/卸载），快捷命令 `W1nCray xray ...` 直接透传给程序本体（带 `-c <配置>`）。


