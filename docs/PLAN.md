# W1nCray 重构方案（v1）

> 日期：2026-10-04 · 目标：以官方稳定版 Xray-core 重构 XrayR，命名 W1nCray，对接 Xboard。
> 结论分档：【已验证】直接证据；【高度可能】间接证据；【待确认】假设。

---

## 1. 证据汇总

| # | 事实 | 证据来源 | 档位 |
|---|------|----------|------|
| E1 | XrayR 最终版 v0.9.4（2024-07-21，commit 944e8cd），依赖 xray-core v1.8.20 | `proxy.golang.org/github.com/xrayr-project/xrayr/@latest`；其 `go.mod` | 已验证 |
| E2 | Xray-core 最新**稳定版** v26.3.27（2026-03-27），之后 v26.6.1 ~ v26.9.30 全部为 prerelease；Go 模块版本 `v1.260327.0`，`@latest` 指向它 | GitHub Releases API；`proxy.golang.org/github.com/xtls/xray-core/@latest` | 已验证 |
| E3 | Xboard 节点 API：`/api/v1/server/UniProxy/{config,user,push,alive,alivelist,status}`；V2 另有 `handshake/report` | `Xboard/app/Http/Routes/V1/ServerRoute.php`、`V2/ServerRoute.php` | 已验证 |
| E4 | 鉴权：query/body 中 `token`、`node_id`、可选 `node_type`（V1 中间件可为空） | `app/Http/Middleware/Server.php` | 已验证 |
| E5 | config/user 均返回 ETag，`If-None-Match` 命中返回 304 | `UniProxyController::config/user` | 已验证 |
| E6 | config 公共字段：`protocol, listen_ip, server_port, network, networkSettings(驼峰), base_config{push_interval,pull_interval}, routes, custom_outbounds, custom_routes, cert_config` | `ServerService::buildNodeConfig` | 已验证 |
| E7 | 用户字段：`id, uuid, speed_limit(Mbps), device_limit` | `ServerService::getAvailableUsers` | 已验证 |
| E8 | push 格式 `{uid:[u,d]}`（`[0]`=上行，`[1]`=下行）| `TrafficFetchJob.php:40-41` | 已验证 |
| E9 | alive 格式 `{uid:[ip,...]}`（端口会被剥离）；alivelist 返回 `{"alive":{uid:设备数}}`，跨节点去重、TTL 300s | `DeviceStateService.php` | 已验证 |
| E10 | status 必填 `cpu, mem.total/used, swap.total/used, disk.total/used` | `UniProxyController::status` | 已验证 |
| E11 | SS2022 用户密钥 = `base64(uuid 字符串前 N 字节)`，N=16/32；server_key 仅 aes-128/256 下发，chacha20 为 null | `Server::generateServerPassword`、`Helper.php`、`buildNodeConfig` | 已验证 |
| E12 | REALITY：`tls=2` 时 `tls_settings` = `reality_settings{server_name,server_port,private_key,public_key,short_id}` | `buildNodeConfig`、`Server.php REALITY_CONFIGURATION` | 已验证 |
| E13 | cert_config 字段：`cert_mode(http/dns/self/file/content/none), domain, email, dns_provider, dns_env, http_port, cert_content, key_content` | xboard-admin-dist 打包 JS 中 zod schema；Xboard-Node `panel/types.go` CertConfig | 已验证 |
| E14 | 路由 action ∈ {block, direct, dns, proxy}；proxy 的 action_value 为 Outbound Tag；match 占位符 `example.com\n*.example.com` | `RouteController.php:26`；admin `zh-CN.js` route.form | 已验证 |
| E15 | 原 XrayR newV2board **未使用**面板 `device_limit`（`// todo`），在线 IP / 节点状态上报为空实现 | XrayR `api/newV2board/v2board.go` GetUserList、ReportNodeOnlineUsers | 已验证 |
| E16 | XrayR 限速器 `WaitN(n)` 在 n > burst 时立即报错不等待，导致大包绕过限速 | XrayR `common/limiter/rate.go`；`x/time/rate` 语义 | 已验证 |
| E17 | Xray v26 `common/mux/session.go:188` 对 Dispatch 返回的 `link.Reader` 断言 `*pipe.Reader`（XUDP）→ 不可包装该 Reader | 源码 | 已验证 |
| E18 | `CanSpliceCopy==3` 时 `CopyRawConnIfExist` 不走 splice | `proxy/proxy.go:730` | 已验证 |
| E19 | `app/router` 初始化即依赖 `routing.Dispatcher`，dispatcher 必须作为 App 在实例初始化时注册 | `app/router/router.go:323`、`core/xray.go initInstanceWithConfig` | 已验证 |
| E20 | 支持热增删用户：vmess/vless/trojan/shadowsocks/ss2022-multi/hysteria；socks/http 不支持 | `grep AddUser proxy/` | 已验证 |
| E21 | Router 支持按 ruleTag `AddRule(append)` / `RemoveRule` | `app/router/router.go:112-232` | 已验证 |
| E22 | v26 内置 hysteria2 入站（`version` 必须为 2），带宽参数迁移到 `finalmask.quicParams` | `infra/conf/hysteria.go`、`transport_internet.go:535` | 已验证 |
| E23 | 官方 Xboard-Node（Xray 内核模式）对 Xboard 字段的映射方式（作为交叉核对）；其限速依赖 cedar2025 魔改 Xray，非官方内核 | Xboard-Node `internal/kernel/xray/{config,dispatcher,xray}.go`、`go.mod replace` | 已验证 |
| E24 | 纯 Go 构造 CodeGeneratorRequest + protoc-gen-go v1.36.11 可生成 pb.go，无需 protoc 二进制 | scratchpad 原型实测 | 已验证 |

## 2. 目标与范围

### 2.1 协议支持矩阵（Xboard 节点类型 → W1nCray）

| Xboard 类型 | 支持 | 说明 |
|---|---|---|
| vmess | ✅ | tcp/ws/grpc/httpupgrade/xhttp/kcp + TLS |
| vless | ✅ | 同上 + REALITY、flow(xtls-rprx-vision)、VLESS Encryption(decryption) |
| trojan | ✅ | TLS / REALITY，传输同上 |
| shadowsocks | ✅ | 经典 AEAD 多用户；2022-blake3-aes-128/256-gcm 多用户 |
| shadowsocks 2022-chacha20 | ❌ | Xray 多用户不支持（`buildShadowsocks2022` 报错），面板亦不下发 server_key |
| hysteria (version=2) | ✅ | Xray v26 原生 hysteria2；obfs salamander、带宽 |
| hysteria v1 / tuic / anytls / naive / mieru | ❌ | 官方 Xray 无对应入站，启动时明确报错 |
| socks / http | ✅ | 不支持热更新用户，用户变化时重建入站 |

### 2.2 功能

- 多节点（一个进程对接多个 Xboard 节点），沿用 XrayR 的 YAML 结构，便于迁移。
- 节点配置/用户 ETag 增量拉取；用户热增删（不断开其他用户）。
- 流量上报（`push`，失败不清零，成功后按读取值扣减，避免丢量）。
- **新增** 在线 IP 上报（`alive`）、节点状态上报（`status`：CPU/内存/Swap/磁盘）。
- **新增** 面板 `device_limit` 生效：本地实时 + 基于 `alivelist` 的跨节点全局设备数限制（替代 XrayR 的 Redis 方案）。
- 用户限速（面板 `speed_limit` / 本地覆盖），**修复** E16，并处理 Vision splice 绕过（E18）。
- 自动限速（AutoSpeedLimit，沿用 XrayR 语义）。
- 面板路由：block / direct / proxy(custom_outbounds) / dns；本地规则文件 RuleListPath。
- 面板 custom_outbounds（Xray 原生 outbound JSON，兼容 Xboard-Node 的 `{tag,protocol,settings,proxy_tag}`）与 custom_routes（Xray 原生 rule JSON）。
- 证书：面板 cert_config（http/dns/self/file/content）优先，否则本地 CertConfig（none/file/http/tls/dns，XrayR 兼容）；ACME 用 lego，文件热重载。
- 默认屏蔽访问内网/保留网段（可关闭，`BlockPrivateIP`）。
- 配置文件变更自动重载；`x25519` 子命令；`version` 子命令。

## 3. 架构

```
main ─ cmd(cobra) ─ panel.Panel ──┬─ core: 构建/启动 Xray 实例（log/dns/policy/stats/router/outbounds）
                                   │        App 中以 w1ncray 自有 dispatcher 配置替换官方 dispatcher
                                   ├─ node.Controller × N（每个 Xboard 节点一个）
                                   │     ├─ api/xboard.Client  ← Xboard UniProxy API
                                   │     ├─ builder: Xboard 字段 → infra/conf JSON → core.InboundHandlerConfig
                                   │     ├─ 用户同步（UserManager 热更新 / socks,http 重建）
                                   │     ├─ 路由规则（router.AddRule/RemoveRule，按 inboundTag 隔离）
                                   │     ├─ 周期任务：拉取(config,user,alivelist) / 上报(push,alive,status) / 证书续期
                                   │     └─ cert.Manager
                                   └─ fsnotify 监听配置文件 → 整体重载
app/dispatcher: 包装官方 DefaultDispatcher（由官方构造器创建，保证与内核行为一致）
     ├─ Dispatch:   设备数准入 → 内层 Dispatch → 上行包装 Writer；下行用新 pipe 中转限速（不改返回 Reader 类型，E17）
     └─ DispatchLink: 设备数准入 → 包装 Reader/Writer 限速 → 限速用户 CanSpliceCopy=3（E18）
common/limiter: 每 inbound 的用户表、令牌桶（上下行独立，按块等待修复 E16）、IP 引用计数、设备数判定
```

### 3.1 设备数判定（每次新连接）

1. 用户 `device_limit<=0` → 放行（仍记录 IP 供上报）。
2. 源 IP 已在该用户本节点在线/本周期出现集合中 → 放行。
3. `local = |本节点该用户 IP 集合|`，`other = max(0, alivelist[uid] - 上次上报的本节点 IP 数)`；若 `local + other + 1 > limit` → 拒绝；否则放行并计入。

### 3.2 用户标识

Xray 用户 email = `<nodeTag>|<uid>`，统计计数器名 `user>>><email>>>>traffic>>>uplink/downlink`，上报时反解 uid。

### 3.3 路由

- 每节点一个 freedom 出站（tag=节点 tag，`sendThrough=SendIP`，`domainStrategy=DNSType`）。
- 每节点规则组（全部带 `inboundTag=[节点tag]`，ruleTag=`w1n|<节点tag>|<序号>`）按序：内网屏蔽 → custom_routes → 面板 routes（block→黑洞，direct→节点出站，proxy→节点前缀化的自定义出站）→ 本地 RuleList → 兜底到节点出站。
- 面板 `dns` 路由：汇总为 DNS 服务器（domains 绑定）；变化需重建实例 → 触发整体重载。
- 全局 route.json（RouteConfigPath）规则先于节点规则（与 XrayR 一致，用户自定义优先）。

## 4. 配置兼容（相对 XrayR）

| 项 | 处理 |
|---|---|
| PanelType | 接受 `Xboard`（推荐）以及 `NewV2board`/`V2board`（迁移兼容，按 Xboard 处理）；其他面板不支持 |
| ApiConfig.NodeType | 可选；协议以面板返回 `protocol` 为准，不一致时告警 |
| EnableVless / VlessFlow / DisableIVCheck / DisableCustomConfig | 已废弃，忽略并告警 |
| GlobalDeviceLimitConfig(Redis) | 移除，改用 Xboard alivelist（面板原生跨节点设备统计） |
| UpdatePeriodic | 0 = 跟随面板 pull_interval；>0 覆盖 |
| 其他（Log/Dns/Route/Inbound/Outbound/Connection、ListenIP、SendIP、EnableDNS、DNSType、EnableProxyProtocol、DisableSniffing、AutoSpeedLimit、Fallback、REALITY、CertConfig、SpeedLimit/DeviceLimit 本地覆盖、RuleListPath） | 保持语义 |

## 5. 改动项（新项目，均为新建文件）

工作目录 `C:\W1nC-XrayR` 原为空目录（`Get-ChildItem -Force` 无输出），**无既有文件被修改，故无需备份**。

| 文件 | 内容 | 影响/风险 |
|---|---|---|
| `go.mod` | module `w1ncray`，xray-core v1.260327.0 | 发布到 GitHub 时可改为仓库路径 |
| `main.go`, `cmd/*.go` | cobra：默认运行、`version`、`x25519` | — |
| `panel/{config,panel}.go` | 配置加载（viper）、实例构建、控制器编排、热重载 | 重载期间短暂断流（与 XrayR 相同） |
| `core/*.go` | 基础 Xray 配置组装、dispatcher 替换、入/出站与规则操作 | 依赖 infra/conf，跟随内核升级 |
| `app/dispatcher/{config.proto,config.pb.go,dispatcher.go,link.go}` | 包装官方 dispatcher | E17/E18 约束 |
| `common/limiter/*.go` | 限速、设备数、IP 追踪 | 有单测 |
| `common/cert/*.go` | lego ACME、自签、content/file | lego 全量 DNS provider 使体积增大（换取与 XrayR Provider 名完全兼容） |
| `common/serverstatus/*.go` | gopsutil 采集 | — |
| `api/xboard/*.go` | Xboard 客户端与模型 | 有 httptest 单测 |
| `node/*.go` | 控制器、入站构建、用户、路由、上报 | 有单测 |
| `tools/protogen/main.go` | 无 protoc 生成 pb.go | 仅开发用 |
| `release/config/*`, `release/w1ncray.service`, `Dockerfile`, `README.md` | 示例配置、systemd、文档 | — |

回滚：新项目，回滚即不部署 / 继续使用原 XrayR；配置文件结构兼容，可双向切换。

## 6. 被否决的方案

1. **整份复制并魔改官方 dispatcher（XrayR 做法）**：每次内核升级都需手工合并，正是 XrayR 停滞的主因 → 否决，改为包装。
2. **go:linkname 替换内核私有注册表（Xboard-Node 做法）**：依赖内核私有符号名，内核重构即失效 → 否决，改为注册自有 proto 配置并调用官方构造器（公开 API）。
3. **使用 cedar2025/wyx2685 魔改 Xray**：与“官方稳定版内核”要求不符 → 否决。
4. **每次用户变化整体重启实例（Xboard-Node 生成整份 JSON 的做法）**：会断开全部用户 → 否决，采用 UserManager 热更新。
5. **Redis 全局设备限制（XrayR）**：Xboard 已原生提供 alivelist → 否决，减少外部依赖。
6. **在 Dispatch 返回的 Reader 上直接包装限速**：违反 E17，XUDP 场景 panic → 否决，改为新 pipe 中转。

## 7. 验证方案与验收标准

| # | 验收项 | 验证手段 |
|---|---|---|
| A1 | `go build`、`go vet` 通过，交叉编译 linux/amd64、linux/arm64 | 命令输出 |
| A2 | Xboard 客户端：鉴权参数、ETag/304、push/alive/status 报文格式与 E3–E10 一致 | httptest 单测 |
| A3 | 各协议入站可由 Xboard 样例 config 构建成功（vmess-ws-tls、vless-reality-vision、vless-xhttp、trojan-grpc、ss aes-gcm、ss2022、hysteria2、socks、http），不支持协议报错清晰 | 单测 |
| A4 | SS2022 用户密钥与 Xboard `uuidToBase64` 结果一致 | 单测（与 PHP 算法对照） |
| A5 | 限速：大于 burst 的写入被正确节流；设备数：超限拒绝、已在线 IP 放行、全局计数生效 | limiter 单测 |
| A6 | 端到端：启动模拟 Xboard（httptest）+ W1nCray，真实 Xray 客户端（同版本内核）经 vmess/vless/ss/trojan 代理访问本地 HTTP 服务成功；流量上报值 > 0 且 uid 正确；alive 上报含客户端 IP；用户删除后连接被拒；限速生效（吞吐接近限速值）；设备数超限被拒 | 集成测试（Go test，回环网络） |
| A7 | 用户热增删不影响其他用户连接 | 集成测试 |
| A8 | 配置文件示例可被加载 | 单测 |

遗留/待确认：
- 【待确认】真实 Xboard 环境联调需用户在自己的面板验证（本地以源码契约 + 模拟服务验证）。
- 【待确认】hysteria2 端到端需 UDP/QUIC，环境允许时补测。

---

## 8. 实施记录（2026-10-04）

### 8.1 与方案的偏差及原因

| # | 偏差 | 原因 / 证据 |
|---|---|---|
| D1 | proto 描述符注册名改为 `w1ncray/app/dispatcher/config.proto` | 首次运行 panic：`proto: file "app/dispatcher/config.proto" is already registered`（与 xray-core 同名）。已修正 `tools/protogen` |
| D2 | Hysteria2 带宽方向：服务端 `brutalUp = down_mbps`、`brutalDown = up_mbps` | `transport/internet/hysteria/hub.go:194-199` 服务端发送速率 = `min(BrutalUp, 客户端下行)`；Xboard 订阅给客户端 `up=bandwidth.up`（客户端视角，`ClashMeta.php:597`）。Xboard-Node 直接 `brutalUp=up_mbps`，上下行不对称时会限制下载 |
| D3 | mKCP 的 `header/seed` 转换为 finalmask udp 掩码 | `infra/conf/transport_internet.go:110` v26 对 kcpSettings 中 header/seed 直接报错。掩码链顺序与旧客户端兼容性【待确认】 |
| D4 | socks/http 节点的用户标识为 UUID（非 `tag|uid`） | Xray 以用户名作为这两种协议的 email（`proxy/socks/protocol.go:162`、`proxy/http/server.go:131`），conf 中账户无 email 字段 |
| D5 | 用户数为 0 时不创建入站 | 经典 SS 在零用户时 conf 走单用户分支报错、SS2022 零用户构建为不支持热更新的单用户配置（`infra/conf/shadowsocks.go`） |
| D6 | `SendIP` 为 `0.0.0.0`/`::` 时不设置 `sendThrough` | 绑定 0.0.0.0 会导致 IPv6 目标不可达 |
| D7 | 新增 `CertConfig.HTTPPort`、`CertDir`、`BlockPrivateIP` | 面板 cert_config 含 http_port；证书需持久化目录；安全默认值 |

### 8.2 验收结果

| # | 结果 | 证据 |
|---|---|---|
| A1 | ✅ | `go vet ./...` 无输出；`gofmt -l .` 无输出；`GOOS=linux GOARCH=amd64/arm64 CGO_ENABLED=0 go build` 成功（79.0MB / 72.5MB） |
| A2 | ✅ | `api/xboard/client_test.go`：鉴权参数、ETag/304、PHP 宽松类型（字符串数字、`[]` 空对象、null）、push/alive/status/alivelist 报文 |
| A3 | ✅ | `node/build_test.go` TestBuildInbounds 17 个配置全部经 Xray conf 真实构建；TestBuildRejects 9 个不支持/错误配置给出明确错误 |
| A4 | ✅ | SS2022 用户密钥与按 PHP 算法独立计算（Python `base64.b64encode(uuid[:N])`）结果一致 |
| A5 | ✅ | `common/limiter/limiter_test.go`：设备数本地/全局/窗口、上下行独立桶、动态改速；`TestWaitNLargerThanBurst` 实证 XrayR 缺陷并验证修复 |
| A6 | ✅ | `node/e2e_test.go` 使用官方 Xray v26.3.27 客户端：vmess(tcp/ws)、vless(tcp/xhttp)、vless+REALITY+Vision、trojan+TLS(面板 self 证书)、SS aes-128-gcm、SS2022、Hysteria2+salamander、socks、http 全部可代理；流量上报 uid 正确且不重复上报；alive 含 127.0.0.1；status 已上报；错误凭据被拒 |
| A6 | ✅ | 限速 8Mbps 下载 3MB：vmess(Dispatch) 2.004s、vless(DispatchLink) 2.004s、REALITY+Vision 2.009s；不限速 8~20ms |
| A6 | ✅ | device_limit=1 时第二个源 IP（127.0.0.2）被拒，原 IP 仍可用 |
| A6 | ✅ | BlockPrivateIP、面板 block 路由、面板 proxy→custom_outbounds 均生效 |
| A7 | ✅ | TestE2EUserHotUpdate：删除用户 1 时用户 2 的进行中连接完整收完 10KB；被删用户被拒；其未上报流量仍补报一次；重新加入可用 |
| A8 | ✅ | `panel/panel_test.go`：示例配置与典型 XrayR NewV2board 配置可加载；双节点同实例运行；修改配置文件触发自动重载后两个端口仍在监听 |
| — | ✅ | 真实二进制冒烟：`W1nCray.exe -c config.yml` 对接 Python 假面板，启动监听、10s 周期拉取、status 上报真实系统数据 |

### 8.3 测试中发现的上游行为（非 W1nCray 问题）

- REALITY 首连约 5 秒：`github.com/xtls/reality` `tls.go:424`、`record_detect.go:121` 首次探测 target。后续连接 6~30ms。
- Xray hysteria **客户端**按目标地址做进程级连接缓存（`transport/internet/hysteria/dialer.go:449`），同进程多客户端会复用已认证连接；测试已规避。
- Xray v26 客户端移除 `allowInsecure`（`infra/conf/transport_internet.go:711`），自签证书需 `pinnedPeerCertSha256`。

### 8.4 未验证 / 遗留

- 【未验证】`go test -race`：本机无 gcc（cgo），无法运行数据竞争检测；建议在 Linux CI 中执行。
- 【未验证】ACME（http/tls/dns）真实签发：需要公网域名与 80/443 端口，本地仅验证了 self/content 与文件热重载路径。
- 【未验证】真实 Xboard 面板联调：以 Xboard 源码契约 + 模拟面板验证，需在实际面板上确认。
- 【待确认】mKCP finalmask 转换与旧客户端的兼容性（D3）。
- 【未验证】Linux 下 Vision splice 被禁用后的限速（Windows 无 splice，限速已在 Vision 路径验证）。
