# W1nCray Agent 使用手册

> 面向运维。本手册描述 `feat/agent` 分支（v0.3.0 之后）的 Agent：用一个本地 JSON 文件声明「这台机器要跑哪些转发」，由 W1nCray 落到内嵌的 xray 或外部内核（gost / frp / realm）上。
> 面板远程下发（Xboard / W1nCBoard 控制）属后续阶段，见 [PLAN-v7-panel-control.md](PLAN-v7-panel-control.md)；本手册只讲本地文件这条路径。
> 手册里的样例、拒绝信息、策略对照表全部由 `agent/examples` 的测试守护：代码一变、样例或信息不再成立，`go test ./agent/examples/` 就会失败。

目录：[1 概念](#1-概念) · [2 引擎能力](#2-引擎能力与限制) · [3 Agent 配置块](#3-agent-配置块) · [4 本地策略](#4-本地策略-policy) · [5 期望状态字段](#5-期望状态字段速查) · [6 样例索引](#6-样例索引) · [7 命令](#7-命令) · [8 排错](#8-常见拒绝原因与排错) · [9 安全须知](#9-安全须知) · [10 已知限制](#10-已知限制与未决事项)

## 1 概念

- **Agent 是进程内的内核编排器**，不是另一个守护进程。它跑在 `W1nCray` 主进程里，与 Xboard 的 `Nodes` 相互独立：可以只配 Agent、不配 Nodes。
- **只接受「期望状态」，不接受命令**。你给它一份完整的 `spec.Desired`（JSON），它负责：校验 → 按本地策略过滤 → 为每个实例选引擎 → 渲染该引擎的配置 → 端口预检 → 启动/热更 → 健康检查 → 失败则回滚到上一份可用状态。文件里没有的实例会被移除（整体应用，不是增量）。
- **引擎**：`xray` 内嵌在二进制里，无需安装；`gost`、`frp`、`realm` 是外部内核，从**已签名的内核清单**安装（见 §3 `ManifestPath`），期望状态只能指定版本号，下载地址与哈希永远来自清单。
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
    { "id": "auto-simple", "state": "running", "engine": "xray", "requested_engine": "auto",
      "config_hash": "a7758ab0…", "ports": ["tcp 0.0.0.0:21300"] },
    { "id": "auto-iphash", "state": "running", "engine": "realm", "requested_engine": "auto",
      "considered": { "xray": "balance strategy \"iphash\" is not supported" },
      "config_hash": "c9d4789f…", "ports": ["tcp 0.0.0.0:21301"] }
  ],
  "kernels": { "realm": "<已安装版本>", "xray": "builtin" },
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

下表**以各驱动 `Caps()` 为准**（`driver/xray/driver.go`、`driver/gost/driver.go`、`driver/frp/frp.go`、`driver/realm/realm.go`），不要凭印象。Reconciler 在选引擎时用同一份数据拒绝不支持的特性，不会静默降级。

| 能力 | xray（内嵌） | gost（外部） | frp（外部） | realm（外部） |
|---|---|---|---|---|
| 实例类型 `kind` | forward、tunnel_entry、tunnel_exit、reverse_portal、reverse_bridge | 同 xray（全部 5 种） | **仅** reverse_portal、reverse_bridge | forward、tunnel_entry、tunnel_exit（**无反向代理**） |
| 网络 | tcp、udp | tcp、udp | tcp、udp | tcp、udp |
| 隧道载体 `tunnel.type` | tcp、tls、ws、wss、grpc、xhttp | tcp、tls、ws、wss、grpc | tcp、tls、ws、kcp、quic（**不支持 wss**） | tcp、tls、ws、wss |
| 反向代理 | 是（bridge 决定目的地；portal 不带 `targets`） | 是 | 是 | 否 |
| 接收 PROXY（`accept_proxy_protocol`） | 是 | 是 | **否** | 是 |
| 发送 PROXY（`proxy_protocol_out`，仅 TCP） | 是 | 是 | 是（仅 bridge） | 是 |
| 负载均衡策略 | round_robin、random、failover | round_robin、random、iphash、failover | 仅 failover（bridge 每端口一个目标；portal 不接受 `balance`） | round_robin、iphash |
| 健康检查（`Caps`） | active（仅 tcp） | passive | active（仅 bridge） | none |
| 统计 | counters | api | api（仅 portal） | **none（不可计量）** |
| 重载方式 | hot（增删入站，不重启内核） | api（REST 增删 service，不用整体重载） | api（frpc 仅改代理时）；**frps 改动即重启该 portal** | none（**改一个实例即重启该实例的进程，断开它的连接**） |
| 改动一个实例是否牵连其他实例 | 否 | 否 | 否（一实例一进程） | 否（一实例一进程） |
| 外部内核 / 安装体积 | 否 / 0 | 是 / ≈50 MB | 是 / ≈36 MB | 是 / ≈6.9 MB |

**`engine: auto`** 在能胜任的引擎里选：内嵌引擎优先，然后按安装体积从小到大，再按名字，即 **xray → realm → frp → gost**。选择结果和被淘汰引擎的原因写在报告的 `engine` / `considered` 里；没有任何引擎能跑时**拒绝**并列出每个引擎的原因，不会降级。写了 `balance.health` 时，`auto` 优先选主动探测（active）的引擎；只有被动摘除（passive，gost）的引擎能跑时才选它，并在 `considered` 里注明「selected with passive health checks only」；没有故障检测能力（none，realm）的引擎会被拒绝，原因为 `health checks are not supported`。注意 `W1nCray agent-apply` 不注册 xray（§7），此时 auto 会落到 realm 等外部引擎。

各引擎还有这些「表里装不下」的约束（来自驱动的校验代码与文档，`engine` 写错时会收到对应拒绝信息，见 §8）：

- **xray**：不支持 `limits`；`balance.health` 只支持 `type: tcp` 且至少两个目标，`failover` 必须带 `health`；目标权重之和 ≤ 64；多目标只能配单个监听端口；`tunnel.security` 省略时 tls/wss 用 TLS，其余用 VLESS 加密（`vless_enc`），**不接受不加密的 raw 隧道**；自签证书（`cert.mode: self`）必须配 `tls_pin`；`cert.mode` 为 `file` / `panel` 在当前内置装配里不可用（`bootstrap.buildDrivers` 没给 xray 配证书目录和面板证书源）。收 PROXY 头时按实测记录（PLAN-v6 §2.3）无头即断连。
- **gost**：不支持 `tls_pin`、`vless_enc`、`tunnel.alpn`；权重只对 `random` 策略生效（其他策略写了非 1 的权重会被拒）；`tunnel_exit` / `reverse_portal` 不支持 `proxy_protocol_out` 与 `limits`，portal 不支持 `acl`；`accept_proxy_protocol` 仅限 forward / tunnel_entry；`tunnel_exit` 的目标不能用端口范围；入口方（entry / bridge）不带 `cert` 时用系统根证书严格校验出口，所以出口应使用公共 CA 签发的证书；出口用私有 CA / 自签证书时，入口方写 `tunnel.cert: {mode: "file", cert_file: "<CA 绝对路径>"}` 把它作为信任锚（不能带 `key_file`）。`balance.health` 只支持 `type: tcp`，不接受 `timeout_s` / `probe_url`；这是被动摘除：`max_fails` 次失败后该目标暂时退出轮转，`interval_s` 是它被摘除的时长。
- **frp**：每个 portal 一个 `frps`、每个 bridge 一个 `frpc` 进程；不支持 `acl`、`limits`、`idle_profile`、`allow_any_target`；bridge 只能有一个 target（端口范围须与 `listen.ports` 等长）或用 `port_map`；公共端口不能等于控制端口。**bridge 默认不校验 portal 的证书**（frp 的默认行为），TLS 只防窃听、不防中间人；要校验就在 bridge 写 `tunnel.cert: {mode: "file", cert_file: "<CA 或 portal 证书的绝对路径>"}` 作信任锚（不能带 `key_file`，不支持客户端证书）；`balance` 只能用在 bridge 上，且只接受 `failover`（单目标），`health` 可用 `tcp` / `http`，不能与 `network` 含 udp 同用；`secret` 即 frp token（还要避开 `: @`，见 §5）。
- **realm**：无 ACL、无 limits、无健康检查（挂掉的目标仍会分到流量）；UDP 只能单目标；**隧道只支持 TCP，且只能 realm ↔ realm**；`tcp` / `tls` 隧道没有任何应用层认证（配 `secret` 会被拒），`ws` / `wss` 靠由 `secret` 派生的 path 令牌认证；只信任公共 CA 证书，不能固定指纹；entry 只能一个监听端口、不能 `port_map`；**出口不是守门员**——任何能连到出口端口的主机都能让它向目标建连，务必用防火墙把来源限制为入口机。

`idle_profile`（空闲超时预设）在各引擎的实际取值：

| 预设 | xray | gost | realm | frp |
|---|---|---|---|---|
| `tcp_long` | 3600 s | 3600 s | 无 TCP 空闲超时（预设为空操作） | 不支持 |
| `tcp_default`（TCP 的缺省） | 节点 `ConnectionConfig`（缺省 `ConnIdle: 30` s） | 300 s | 同上 | 不支持 |
| `udp_short`（UDP 的缺省，xray） | 60 s | 30 s | 30 s | 不支持 |
| `udp_long` | 120 s | 120 s | 120 s | 不支持 |

> 用 xray 转发 SSH / 数据库这类长连接时，请显式写 `"idle_profile": "tcp_long"`，否则会按 `ConnectionConfig` 的缺省（30 s 空闲）断开。gost 在未指定 UDP 预设时用 60 s。

## 3 `Agent:` 配置块

写在 `config.yml` 里（与 `Nodes` 同级，YAML）。未启用（`Enabled: false` 或整块缺省）时 Agent 完全不工作。

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
| `ManifestPath` | 空 | 已签名的内核清单。**不设置时只有内嵌 xray 可用**，gost / frp / realm 无法安装（报「no signed kernel manifest loaded (set Agent.ManifestPath)」）。设置后不再读取面板同步的持久化副本（见 §3「内核清单自动同步」） |
| `ManifestKeysPath` | 空 | 额外信任的 ed25519 公钥文件（hex，每行一个），叠加在二进制内嵌公钥之上，供本地/自托管使用；生产信任根是编译时内嵌的公钥。没有任何公钥时任何清单都会被拒（fail-closed，预期行为） |
| `StateDir` | 配置文件所在目录下的 `state` | Agent 状态目录：已应用/上次可用的期望状态、冻结记录、各驱动的私有目录、PID 目录。文件权限 0600（含 `secret`） |
| `KernelsDir` | `StateDir/kernels` | 外部内核安装目录 |
| `Policy` | 见 §4 | 本地根信任策略 |

校验：`PortRange` 必须恰好两个元素 `[lo, hi]`；`Policy.AllowEngines` 只能出现 `auto` / `xray` / `gost` / `frp` / `realm`。**建议留空**：留空表示不限制引擎，面板下发的实例可选任一引擎，实际可用性由已签名清单决定（gost / frp / realm 由 agent 按需下载安装，见 §3 与 §4）。

### 机器模式节点（`MachineNodes`）

在面板上把节点绑定到一台「机器」后，本机不必再逐个写 `Nodes`，只配一个机器令牌即可：W1nCray 用 `Agent.Panel` 的 `URL` / `MachineID` / `Token`（或 `TokenFile`）向面板查询这台机器名下的节点，并为每个节点自动起一个控制器。节点增删由面板决定，本机不改配置、不重启。

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

安装脚本在装好二进制与服务的同时，写出上面的机器模式配置（`Log` + `Agent` 段）：

| 参数 | 说明 |
|---|---|
| `--panel URL` | 面板地址。必须 `https://`；仅本机回环（`localhost` / `127.x` / `::1`）可用明文 `http://`。末尾斜杠会被去掉 |
| `--machine ID` | 面板上的机器 ID，必须是正整数 |
| `--token TOKEN` / `--token-file FILE` | 二选一提供机器令牌；`--token-file` 读文件（首尾空白与换行会被去掉） |
| `--allow-http` | 面板地址是**非回环**的 `http://` 时必须显式给出，否则拒绝安装并说明原因 |
| `--port-range LO-HI` | `Policy.PortRange`，默认 `20000-40000` |

- `--panel` / `--machine` / 令牌三者必须同时提供，缺任何一个都会以中文报错并非 0 退出；`--port-range` 与 `--allow-http` 只在 `--panel` 下有效。
- 令牌写入 `<配置目录>/agent.token`（先 `umask 077` 再写，再 `chmod 600`，内容不带换行），生成的配置用 `Agent.Panel.TokenFile` 引用它；令牌**不会**进入 `config.yml`、日志或传给子进程的参数。`uninstall` 会一并删除 `agent.token`。
- 加 `--allow-http` 时配置里会写 `AllowInsecureHTTP: true`（否则 `Agent.Panel` 会拒绝明文 http 的非回环地址）。
- 若 `config.yml` 已存在，安装**不会覆盖**：新配置写到 `<配置目录>/config.panel.yml.new`，安装以黄色警告提示如何合并，返回码仍为 0。
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
| `AllowEngines` | 空（=不限制） | 允许使用的引擎白名单。**默认不限制**：留空表示面板下发的实例可选任一引擎，xray 内嵌可用，gost / frp / realm 由 agent 按需从已签名清单下载安装（可用性由清单决定，不由本字段决定）。写了名单时，不在名单里的引擎显式指定会被拒，`auto` 只在名单内选 |

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
| `engine` | `auto` / `xray` / `gost` / `frp` / `realm` |
| `kind` | `forward` / `tunnel_entry` / `tunnel_exit` / `reverse_portal` / `reverse_bridge` |
| `listen` | `{addr, ports, port_map}`。`addr` 必须是字面 IP；`ports` 为单端口 `"8443"` 或范围 `"20000-20009"`（单端口不要写成 `"x-x"`）；`port_map`：`{"监听端口":"host:port"}`，键必须是 `ports` 内的单个端口，**覆盖** `targets` 对该端口的映射，仅限 forward / tunnel_entry |
| `network` | `["tcp"]`（缺省）、`["udp"]` 或 `["tcp","udp"]`；不可重复 |
| `targets` | `[{host, ports, weight}]`，≤64。`ports` 是单端口或与 `listen.ports` **等长**的范围（一一映射）；`weight` 0 表示 1 |
| `balance` | `{strategy, health}`；`strategy` ∈ round_robin / random / iphash / failover / least_ping（引擎支持的子集见 §2）；`health` = `{type: tcp\|http, interval_s 0–3600, timeout_s 0–300, max_fails 0–100, probe_url}`，`probe_url` 只能是以 `/` 开头的路径且仅 `type: http` 可用 |
| `proxy_protocol_out` | 0 / 1 / 2，向目标发送 PROXY 头；**仅 TCP**，不能与 `network` 含 udp 组合 |
| `accept_proxy_protocol` | 监听口要求 PROXY 头；**仅 TCP**，仅 forward / tunnel_entry / reverse_portal；公网监听需要策略放开 |
| `tunnel` | `{type, server, listen, host, path, sni, alpn, security, pin_sha256, cert}`，见下 |
| `reverse` | `{link, domain, bridge_allow}`，仅 reverse_*；`link` 只是配对标记；`domain` 是反向代理的会合名，须随机（十六进制 ≥32 字符或 base64url ≥22 字符，且字符种类 ≥8；xray 另要求 26–64 位小写字母数字）；`bridge_allow` 已废弃（反向代理由 bridge 的 `targets` 决定目的地，写了会被拒） |
| `idle_profile` | `tcp_long` / `tcp_default` / `udp_short` / `udp_long`；`tcp_*` 需要 network 含 tcp，`udp_*` 需要含 udp |
| `limits` | `{max_conns, rate_up_bps, rate_down_bps}`，0 不限；速率单位为 **bit/s**（`8000000` = 8 Mbit/s）；xray / realm / frp 不支持 |
| `acl` | `{allow, deny}`，来源 IP 或 CIDR；`allow` 非空时只放行列表内来源（xray 中 `deny` 先判）。对 `tunnel_exit` 来说「来源」是入口机的地址，可用它把出口限制为只有入口机能连（realm / frp 不支持 ACL） |
| `allow_any_target` | 仅 `tunnel_exit`，与 `targets` 互斥，且需要策略 `AllowAnyTarget` |
| `secret` | 隧道/反向链路的共享密钥，两端必须相同。16–256 字符，只允许 `[A-Za-z0-9_.+/=-]`——这是四个引擎都接受的交集（xray 不收 `~`，frp 不收 `: @`，gost 只收可打印 ASCII）；含其他字符在校验阶段就被拒绝 |

各 `kind` 要填什么：

| kind | `listen` | `tunnel` | `secret` | `targets` |
|---|---|---|---|---|
| `forward` | 必填 | 不允许 | 不允许 | 必填（或 `port_map` 覆盖每个监听端口） |
| `tunnel_entry` | 必填（用户连入的口） | 必填，写 `server`（出口的 `host:port`） | 必填 | 可选；xray 以它作为要去的目的地，须与出口声明的一致 |
| `tunnel_exit` | **不允许**（监听在 `tunnel.listen`） | 必填，写 `listen`（`ip:port`） | 必填 | 固定目标，或 `allow_any_target` 二选一 |
| `reverse_portal` | 必填（公网侧用户口） | 必填，写 `listen`（控制链路） | 必填 | 不允许（目的地由 bridge 的 targets 决定） |
| `reverse_bridge` | 只写 `ports` = portal 侧公网端口（`addr` 不用） | 必填，写 `server`（portal 的 `host:port`） | 必填 | 必填（内网目标，端口一一对应 `listen.ports`） |

`tunnel` 字段：`type` ∈ tcp / tls / ws / wss / grpc / xhttp / kcp / quic（引擎支持子集见 §2）；`security` ∈ `none` / `tls` / `tls_pin` / `vless_enc`（`vless_enc` 仅 xray；`tls_pin` 需要 `pin_sha256` = 出口叶子证书 DER 的 SHA-256，64 位十六进制；`tls`/`wss` 类型再写 `none` 或 `vless_enc` 自相矛盾会被拒）；`host`（Host 头）、`path`、`sni`（须为域名）、`alpn`（≤8 项）；`cert`：出口/portal 侧是要出示的证书 `{mode: self|file|panel, cert_file, key_file}`（`file` 模式两个文件都要）；入口/bridge 侧只能是信任锚 `{mode: "file", cert_file}`（用来校验对端，不能带 `key_file`，`self` / `panel` 被拒；哪个引擎真正采用它由驱动决定：gost、frp 采用，xray 会以 `tunnel.cert is only valid on the accepting side` 拒绝，realm 以 `a certificate belongs to the tunnel exit` 拒绝）。路径须为绝对路径（只含字母数字和 `. _ / -`，不含 `..`）。

## 6 样例索引

样例位于 [`agent/examples/testdata/`](../agent/examples/testdata/)，每个文件都是一份**完整可用**的 `spec.Desired`。用法：复制到目标机器 → 改 `secret`、IP、域名、端口 → 用 `agent-apply -f` 或 `Agent.DesiredPath` 应用。所有 `secret` 都是占位值 `CHANGE-ME-32-chars-minimum-secret`，**必须替换**；样例中的 `203.0.113.x` / `198.51.100.x` 是文档保留地址，`192.168.x.x` 是内网示例。

- 成对的样例（`*-entry` / `*-exit`、`*-bridge` / `*-portal`）分别放到**两台机器**上，`id`、`secret`、隧道类型必须一致，入口/桥端的 `tunnel.server` 指向对端的 `tunnel.listen`。
- 「agent-apply」列：xray 是内嵌引擎，`agent-apply` 不注册它，xray 样例只能由常驻的 `W1nCray` 服务通过 `Agent.DesiredPath` 应用；gost / frp / realm 样例两种方式都行（都需要 `ManifestPath` 提供内核）。
- 「本地策略」：`默认` = 不写 Policy 也能通过；`listen` = `AllowListen` 需包含 `0.0.0.0`；`private` = 需 `AllowPrivate: true`。

| 样例 | 引擎 | 场景 | 本地策略 | 注意点 |
|---|---|---|---|---|
| [forward-tcp](../agent/examples/testdata/forward-tcp.json) | xray | TCP 直连转发 | listen | 写了 `tcp_long`（空闲 1 小时）；不写则按节点 `ConnectionConfig`（缺省 30 s） |
| [forward-udp](../agent/examples/testdata/forward-udp.json) | xray | UDP 直连转发（DNS） | listen | `udp_short`；UDP 不能与 PROXY 头组合 |
| [forward-tcp-udp](../agent/examples/testdata/forward-tcp-udp.json) | xray | TCP + UDP 同端口 | listen | 两个协议各占一个端口声明，同端口不冲突 |
| [forward-port-range](../agent/examples/testdata/forward-port-range.json) | xray | 端口范围一一映射 | listen | 监听与目标范围必须等长，否则报 `ranges must be the same length` |
| [forward-port-map](../agent/examples/testdata/forward-port-map.json) | xray | `port_map`：①逐端口指定、不写 targets；②覆盖范围里的一个端口 | listen | ① 的 `port_map` 必须覆盖每个监听端口；② 的 20301 去 `port_map` 指定处，其余按 targets |
| [forward-balance](../agent/examples/testdata/forward-balance.json) | xray | 负载均衡：round_robin（权重 3:1）、random、failover | listen | failover 必须带 `health`（仅 `tcp`）；多目标只能配单个监听端口；权重和 ≤ 64 |
| [forward-acl](../agent/examples/testdata/forward-acl.json) | xray | 来源 ACL（allow 网段 + deny 单个地址） | listen | `deny` 先判；`allow` 非空即白名单；realm / frp 不支持 ACL |
| [forward-gost-limits](../agent/examples/testdata/forward-gost-limits.json) | gost | 连接数 / 带宽限制 + 被动摘除的主备 | listen | 速率单位 bit/s。`health` 是 gost 的**被动摘除**（只支持 `type: tcp`，`max_fails` 次失败后摘除 `interval_s` 秒），不是主动探测；要主动探测请用 xray |
| [proxy-send](../agent/examples/testdata/proxy-send.json) | xray | 向目标发送 PROXY v2 | listen | 目标服务必须开启接收 PROXY，否则会把头当作数据；仅 TCP |
| [proxy-accept](../agent/examples/testdata/proxy-accept.json) | xray | 接收 PROXY（前置 nginx / haproxy 送入） | **默认** | 只监听 `127.0.0.1`。PROXY 头可伪造，改成公网监听会被拒（需 `AllowAcceptProxyOnPublic`，不建议） |
| [proxy-passthrough](../agent/examples/testdata/proxy-passthrough.json) | xray | PROXY 透传：收头再发头，保留真实来源 | **默认** | 同上；上游必须真的发 PROXY 头，否则连接被断 |
| [tunnel-vless-enc-entry](../agent/examples/testdata/tunnel-vless-enc-entry.json) / [exit](../agent/examples/testdata/tunnel-vless-enc-exit.json) | xray | 隧道：raw + VLESS 加密（无需证书，最简单） | listen | 出口只放行声明的目标；入口 `targets` 必须与出口一致；两端 `secret` 相同 |
| [tunnel-tls-pin-entry](../agent/examples/testdata/tunnel-tls-pin-entry.json) / [exit](../agent/examples/testdata/tunnel-tls-pin-exit.json) | xray | 隧道：wss + 自签证书 + 指纹固定 | listen | **`pin_sha256` 由 `secret` 和 `sni` 决定**：样例里的指纹对应占位 secret + `relay.example.com`，换 secret 或 sni 后必须重算（见下） |
| [reverse-frp-portal](../agent/examples/testdata/reverse-frp-portal.json) / [bridge](../agent/examples/testdata/reverse-frp-bridge.json) | frp | 反向代理：bridge 在内网主动连出，portal 在公网开口 | portal：listen；bridge：private | bridge 的 `listen.ports` 要与 portal 的公网端口一致；bridge 默认不校验 portal 证书（可用 `tunnel.cert.cert_file` 指定信任锚）；样例带 `failover` + TCP 主动健康检查，目标挂掉时 frpc 撤下该公网端口；`secret` 就是 frp token |
| [reverse-gost-portal](../agent/examples/testdata/reverse-gost-portal.json) / [bridge](../agent/examples/testdata/reverse-gost-bridge.json) | gost | 反向代理：wss 控制链路 | portal：listen；bridge：private | portal 需公共 CA 证书文件（`cert.mode: file`）；bridge 严格校验域名，`sni` 必须对得上 |
| [realm-relay](../agent/examples/testdata/realm-relay.json) | realm | 小设备纯中继：①TCP+UDP 单目标 ②TCP 轮询（权重 2:1）+ 发送 PROXY v1 | listen | 无统计、无健康检查、无 ACL；改配置会重启该实例并断连；UDP 只能单目标 |
| [realm-wss-entry](../agent/examples/testdata/realm-wss-entry.json) / [exit](../agent/examples/testdata/realm-wss-exit.json) | realm | realm ↔ realm 的 wss 隧道 | listen | 隧道只支持 TCP；出口需**公共 CA** 签发的证书文件；认证靠 `secret` 派生的 path 令牌；务必用防火墙限制只有入口机能连出口 |
| [gost-wss-entry](../agent/examples/testdata/gost-wss-entry.json) / [exit](../agent/examples/testdata/gost-wss-exit.json) | gost | gost ↔ gost 的 wss 隧道 | listen | 入口不写 targets，目标由出口决定（出口只放行声明的目标）；出口需公共 CA 证书 |
| [engine-auto](../agent/examples/testdata/engine-auto.json) | auto | `engine: auto`：自动选引擎 | listen | 四个引擎都在时 `auto-simple` → xray、`auto-iphash` → realm（xray 不支持 iphash）；只有外部引擎时两者都落到 realm |

**重算 `tls_pin` 的指纹**：指纹是出口叶子证书 DER 的 SHA-256。xray 的自签证书由 `secret` 与出口 `tunnel.sni` 确定性生成，所以同样的 secret + sni 永远得到同一个指纹（测试里用 `xray.SelfCertPin(secret, sni)` 校验样例）。换了 `secret` 后：先在出口机应用 exit 文件（`pin_sha256` 暂时保持任意 64 位十六进制），再在任意机器上取出口实际出示的证书指纹，把结果填回**两份**文件的 `pin_sha256`：

```sh
openssl s_client -connect <出口IP>:<tunnel.listen 端口> -servername <sni> </dev/null 2>/dev/null \
  | openssl x509 -outform DER | sha256sum
```

（该命令按指纹定义推出，本手册编写时**未在真机上执行**【待确认】；以报告/日志中隧道能连通为准。）

## 7 命令

### `W1nCray agent-apply -f desired.json`

按配置里的 `Agent` 段（`-c` 指定配置文件，缺省找 `./config.yml`、`/etc/W1nCray/config.yml`）启动一次 Agent 引导，**严格解码**并应用 `desired.json` 一次，把 `Report` 以 JSON 打印到标准输出（即使失败也打印）；退出码非 0 表示未成功。注意：

- 需要配置里 `Agent.Enabled: true`，否则报 `config … has no enabled Agent section`。
- **不注册内嵌 xray**：xray 实例会被拒（`engine "xray" cannot run this instance: no driver for this engine`）；`engine: auto` 只在外部引擎里选。
- 已被启动的外部内核在命令退出后继续运行（命令自身的说明如此）。
- 它不获取实例锁，也**不是 dry-run**：会真实启动内核、占用端口。不要在常驻服务正在使用同一 `StateDir` 时并行执行【高度可能：二者共用状态目录，代码中 agent-apply 无锁】。
- 想只检查而不落地：目前没有 dry-run 命令，建议先在测试机上应用同一份文件。

### `W1nCray check`

`W1nCray check [-c config.yml] [--online]` 校验配置而不提供服务。对 Agent 它只检查：`ManifestPath`、`ManifestKeysPath` 指向的文件存在（不存在算失败）；`DesiredPath` 文件存在（不存在只是警告：启动时不会应用）。**它不校验 `desired.json` 的内容**——内容是否合法只有应用时才知道（常驻服务的日志里会有 `agent: apply <path>: …`，或用 `agent-apply` 看完整报告）。启用面板时还会打印内核清单同步的开关与间隔（§3「内核清单自动同步」）；`--online` 会顺带拉取一次清单并报告 `sequence`，但不打印内容，也不代替 agent 的本地验签。

### `W1nCray link`

`W1nCray link --panel <URL> --machine <ID> (--token <T> | --token-file <F>) [-c config.yml] [--port-range LO-HI] [--allow-http] [--dry-run] [--ignore-api-overrides] [--skip-check]` 把 v0.3 的静态节点转成机器模式，**不重启服务**。它按文本行级改写 `config.yml`（注释与无关的键原样保留）：

- 只转换 `ApiConfig.ApiHost` 的 scheme+host（含端口）与 `--panel` 一致的节点；其余节点保持静态并在报告里说明原因。
- `ApiConfig` 里有机器模式无法表达的本地覆盖（`SpeedLimit > 0`、`DeviceLimit > 0`、`RuleListPath` 非空）时该节点不转换，除非加 `--ignore-api-overrides`。
- 被转换的条目整块注释掉（块首是 `#LINKED-<日期> …` 回滚标记），它的 `ControllerConfig` 原样右移两格放进 `Agent.Panel.NodeControllers[<节点ID>]`（凭据仍只在本机）。
- 没有 `Agent:` 块时追加一个完整块（`Enabled`、`StateDir`、`Policy`（`AllowListen` / `PortRange`，不写 `AllowEngines`）、`Panel`（`Enabled` / `URL` / `MachineID` / `TokenFile` / `MachineNodes` / `NodeControllers`））；已有 `Agent:` 块时一律报错，请手工合并（不会猜位置、不会覆盖）。
- 令牌写入 `<配置目录>/agent.token`（先 `umask 077`、权限 0600、不带换行）；已存在且内容相同则跳过，内容不同则报错且不覆盖。令牌不会出现在配置、stdout、stderr 或错误里。
- 写入前做**基线对比**：先把**原配置**（同目录临时拷贝）跑一遍完整校验，收集失败项集合 B；再把生成的新配置跑一遍，收集集合 N。只有 `N` 中**新增**的失败项（`N \ B`）才中止并**不改动任何文件**（打印新增失败项的完整文本）。若 `N ⊆ B` 且 `B` 非空则继续转换，并打印显眼的警告列出原配置**转换前就有**的问题（最多 10 条，与本次转换无关）。`B`、`N` 都为空时静默通过。失败项用 `W1nCray check` 打印的 `✗` 文本做稳定标识（剔除临时文件名/时间戳等易变部分）；除离线 `check` 外还会检查机器模式下才生效的 `NodeControllers[].CertConfig.CertMode`。
- `--skip-check` 跳过上述写入前校验（会打印警告），生成结果直接写入。
- 成功后备份为 `config.yml.bak-link-<时间戳>`（0600）再原子替换。
- `--dry-run` 只打印计划（不写任何文件，包括令牌）。
- 对已转换过的配置（有 `#LINKED-` 标记且 `Agent.Panel` 已启用）再次运行会以清晰错误退出且零改动。

### 常驻服务

`Agent.DesiredPath` 设置后，修改该文件即自动应用（§3）。看结果：日志里的 `agent: <path>: <status> (<n> instance(s))`，失败时有具体错误。

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
| `engine "xray" is not allowed by the local policy` | 被 `AllowEngines` 排除 | 调整 `AllowEngines` 或换引擎 |
| `engine "realm" cannot run this instance: kind "reverse_portal" is not supported` | 引擎不具备该能力（kind、网络、隧道类型、PROXY、策略等） | 看 §2 换引擎，或用 `engine: auto` |
| `engine "xray" cannot run this instance: no driver for this engine` | 在 `agent-apply` 里用了 xray | 改由常驻服务（`DesiredPath`）应用，或换外部引擎 |
| `engine "xray" cannot run this instance: balance strategy "iphash" is not supported` | 策略该引擎没有 | 换 gost / realm，或改策略 |
| `engine "realm" cannot run this instance: health checks are not supported (the engine has no failure detection)` | 写了 `balance.health`，而该引擎没有任何故障检测（realm）。xray / frp 是主动探测，gost 是被动摘除，都放行 | 去掉 `health`，或换 xray / gost / frp |
| `driver validation: gost: … active health checks are not implemented` | gost 只做被动摘除，不接受 `type: http`、`probe_url`、`timeout_s` | 只写 `{type: tcp, interval_s, max_fails}`，或换 xray |
| `engine "frp" cannot run this instance: balance strategy "round_robin" is not supported` | frp bridge 每端口只有一个目标，只接受 `failover` | 策略改 `failover`（可带 `health`），或换别的引擎 |
| `tunnel.cert.key_file: not used by kind "reverse_bridge" …` / `tunnel.cert.mode: kind "tunnel_entry" only supports mode "file" …` | 入口 / bridge 侧的 `cert` 只能是信任锚：`mode: file` + `cert_file`，不能带 `key_file`，不能用 `self` / `panel` | 去掉 `key_file`，`mode` 改 `file` |
| `driver validation: realm: acl: realm has no access control …` | 引擎的专属限制（ACL / limits / 证书 / UDP 隧道…），冒号后是驱动给出的原因 | 按原因换引擎或去掉该字段 |
| `driver validation: xray: … limits (max_conns, rate_up_bps, rate_down_bps) are not supported by the xray driver` | xray 不支持限速/限连接 | 换 gost |
| `tunnel.security: vless_enc is only supported by the xray engine` | VLESS 加密只有 xray | 引擎改 xray，或换 `tls` + 证书 |
| `a self-signed certificate needs security tls_pin …` | xray 自签证书客户端只能用指纹验证 | `security` 改 `tls_pin` 并填 `pin_sha256` |
| `certificate files are not allowed (no certificate root configured)` | xray 的 `cert.mode: file` 在当前装配里不可用 | xray 用 `cert.mode: self` + `tls_pin`；要用真实证书的隧道请用 gost / realm |
| `a self-signed certificate cannot be verified by a realm entry …` | realm 入口只信公共 CA | 出口用 `cert.mode: file` 的公共 CA 证书 |
| `realm tunnels carry TCP only …` | realm 隧道不承载 UDP | `network` 改 `["tcp"]` |
| `no signed kernel manifest loaded (set Agent.ManifestPath)` | 外部内核需要已签名清单 | 配置 `ManifestPath`（及 `ManifestKeysPath`）并重启/重载 |
| `json: unknown field "listn"` | 字段名拼错；解码是严格的 | 对照 §5 改字段名；JSON 里不能有注释 |
| `status: rolled_back` + `blocked` | 应用中途失败已回滚，这份内容被冻结 | 看 `message` 里的具体原因，**改内容**（改 revision 不算）后再应用 |

排错顺序建议：①看 `status`；②`rejected` 看 `validation_errors[]` 的 `field`；③实例级拒绝看 `instances[].error` 与 `considered`；④`rolled_back` / `failed` 看 `message` 和日志里 `reconcile:`、对应驱动的行；⑤端口被占看 `port conflict:` 提示（真实绑定探测，且无法区分占用者）。

## 9 安全须知

1. **`secret` 只应存在于本机 0600 文件里**：你写的 `desired.json`（请 `chmod 600`、属主 root）、Agent 状态目录（`StateDir`，文件 0600）、各驱动的私有配置（0600）。Report、日志、报错信息都经过清洗，不含 `secret`；但 `reverse.domain`（反向代理会合名，≥128 位随机）同样应当当作机密对待，清洗**不覆盖**它。
2. **不要公开粘贴 `desired.json`**。求助时请先把所有 `secret`、`reverse.domain` 和真实 IP 换成占位值。样例中的占位 secret 只用于演示，**绝不能**直接上线；多个隧道不要共用同一个 secret。
3. **PROXY 头可被伪造**，因此 `accept_proxy_protocol` 默认只允许在回环/私网地址上监听，公网监听要靠 `AllowAcceptProxyOnPublic` 本地放开（不建议）。真实来源 IP 只应来自你自己控制的前置代理。
4. **隧道出口默认只放行声明的目标**：`tunnel_exit` 必须写固定 `targets`，`allow_any_target` 需要本地 `AllowAnyTarget`；反向代理的 bridge 只服务 `targets` 声明的目的地。realm 出口不是守门员，务必用防火墙限制来源；xray / gost 的出口还可以用 `acl.allow` 只放行入口机的地址。
5. **本地策略是根信任**，期望状态无法放宽它；默认拒绝公网监听、私网目标、任意目标、公网收 PROXY。`AllowPrivate` 打开后仍拒绝环回、链路本地、云元数据地址。
6. **优先用字面 IP 作目标**：域名只在校验时解析一次，存在 DNS 重绑定的时间窗。
7. **隧道要有认证和加密**：样例不使用 `allowInsecure` 之类的不验证选项，也不使用 `security: none`。自签证书必须配指纹（xray），其余用公共 CA 证书，或把私有 CA 作为 `tunnel.cert.cert_file` 信任锚交给入口 / bridge。frp 的 bridge 不配信任锚时不校验 portal 证书，对抗主动中间人的场景请配信任锚，或用 xray / gost。
8. 外部内核只从**已签名清单**安装，哈希校验失败一律拒绝（fail-closed）；期望状态无法指定 URL 或哈希。Agent 没有终端、脚本执行或任意命令通道，外部命令一律用参数数组启动。

## 10 已知限制与未决事项

以下是写样例和本手册时发现的、**需要代码侧决定**的不一致，均有测试或命令输出佐证；它们不影响上面样例的有效性，但会限制能写出什么：

1. **xray 反向代理（已解决）**：语义已统一为「bridge 决定目的地」——portal 不带 `targets`（它给用户连接盖一个 TEST-NET-1 占位目的地），bridge 用自己的 `targets`（或 `allow_any_target` + 本地策略）改写每个被转发的连接；portal / 它的用户都选不了目的地。`reverse.bridge_allow` 在此语义下已无意义，写了会被拒（改用 bridge 的 `targets`）。xray 反向样例已晋升为正式样例。
2. **`balance.health`（已解决）**：`reconcile/select.go` 现在按驱动实际接受什么来判断：主动（xray、frp）与被动摘除（gost）都放行，没有故障检测的引擎（realm）才拒绝；frp 的 `Caps` 如实声明 bridge 支持 `failover` + 主动健康检查。`auto` 优先主动探测，只能用被动时在 `considered` 里注明。`forward-gost-limits` 与 `reverse-frp-bridge` 样例已带上 `health`。
3. **私有 CA / 自签证书（已解决）**：入口 / bridge 现在可以带 `tunnel.cert: {mode: "file", cert_file}` 作信任锚（gost 作 CA 文件，frp 作 `trustedCaFile`），`key_file` 与非 `file` 模式被拒；出口 / portal 侧规则不变。xray 驱动自己的校验仍会拒绝客户端侧的 `cert`（`tunnel.cert is only valid on the accepting side`），xray 入口请用 `tls_pin` 或 `vless_enc`，realm 入口只信公共 CA。
4. **`secret` 字符集（已解决）**：`validate` 收紧到四个引擎的交集 `[A-Za-z0-9_.+/=-]`，`~` `:` `@` 等在校验阶段就被拒。
5. **xray 的 `cert.mode: file` / `panel` 在内置装配里不可用**（`bootstrap.buildDrivers` 没配证书目录和面板证书源），xray TLS 隧道目前只能 `self` + `tls_pin`。
6. `W1nCray check` 不校验 `desired.json` 内容，也没有 dry-run 命令。
7. 面板下发（`Agent.Panel` 的期望状态与「机器模式节点」，见 §3）已实现；多机批量配置仍属后续阶段。
