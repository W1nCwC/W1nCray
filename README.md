# W1nCray

基于**官方稳定版 Xray-core（v26.3.27）**重构的 XrayR，专为 [Xboard](https://github.com/cedar2025/Xboard) 设计的节点后端。

- 内核：官方 `github.com/xtls/xray-core v1.260327.0`（= v26.3.27，截至 2026-10 最新的非预发布版本），不使用任何魔改分支。
- 配置：沿用 XrayR 的 `config.yml` 结构，旧配置基本可直接使用。
- 面板：对接 Xboard UniProxy 节点 API（`/api/v1/server/UniProxy/*`）。

## 相比 XrayR

| 能力 | XrayR v0.9.4（NewV2board） | W1nCray |
|---|---|---|
| Xray 内核 | v1.8.20（2024） | v26.3.27 |
| 面板 `device_limit` | 未实现（代码中为 `todo`） | ✅ 本节点实时 + 借助 Xboard `alivelist` 的跨节点全局限制 |
| 在线 IP 上报（`alive`） | 未实现 | ✅ |
| 节点负载上报（`status`） | 未实现 | ✅ CPU / 内存 / Swap / 磁盘 |
| 用户限速 | 大包可绕过（`WaitN` n>burst 直接放行） | ✅ 已修复，上下行独立令牌桶，Vision 下禁用 splice 防止绕过 |
| Hysteria2 | ❌ | ✅（含 salamander 混淆、带宽） |
| XHTTP / VLESS Encryption / ECH | ❌ | ✅ |
| 面板证书下发 `cert_config` | ❌ | ✅ http / dns / self / file / content |
| 面板自定义出站 / 自定义路由 | ❌ | ✅ |
| 默认阻止访问内网地址 | ❌ | ✅（可关闭） |
| dispatcher 实现 | 复制并魔改官方代码 | 包装官方 DefaultDispatcher（便于跟进内核升级） |

## 协议支持

| Xboard 节点类型 | 支持情况 |
|---|---|
| VMess | ✅ TCP / WS / gRPC / HTTPUpgrade / XHTTP / mKCP，可选 TLS |
| VLESS | ✅ 同上 + REALITY、`xtls-rprx-vision`、VLESS Encryption |
| Trojan | ✅ TLS 或 REALITY |
| Shadowsocks | ✅ AEAD（aes-128/256-gcm、chacha20-poly1305 等）、2022-blake3-aes-128/256-gcm |
| Hysteria2 | ✅ |
| SOCKS / HTTP | ✅（用户变更时重建该入站） |
| Shadowsocks 2022-chacha20 | ❌ Xray 多用户不支持 |
| Hysteria v1 / TUIC / AnyTLS / Naive / Mieru | ❌ 官方 Xray 无对应入站，启动时会报错提示 |
| 传输 H2 / QUIC | ❌ 已被 Xray 移除，请改用 XHTTP |

## 安装（Linux：Debian/Ubuntu、Alpine、OpenWRT 等）

支持 systemd（Debian/Ubuntu/CentOS…）、OpenRC（Alpine）、procd（OpenWRT）三种服务管理器，脚本为 POSIX sh，只依赖 busybox 自带的工具。

```bash
# 一键安装（curl 或 wget 任选其一；OpenWRT 没有 curl，用 wget）
(curl -fsSL -o /tmp/W1nCray-install.sh https://raw.githubusercontent.com/W1nCwC/W1nCray/main/install.sh \
  || wget -O /tmp/W1nCray-install.sh https://raw.githubusercontent.com/W1nCwC/W1nCray/main/install.sh) \
  && sh /tmp/W1nCray-install.sh install
# 或使用本地编译的二进制
sh install.sh install --binary ./W1nCray-linux-amd64
```

安装参数：`--lite | --full`（版本类型）、`--prefix DIR`（安装目录，空间不足时指向外部存储）、`--with-geo`（强制下载 geo 文件）、`--version vX.Y.Z`、`--url 地址`、`--binary 文件`、`--insecure-skip-verify`。

**校验失败即拒绝（fail-closed）**：从发行页下载的程序必须通过 `SHA256SUMS` 校验。缺少 `sha256sum`、取不到 `SHA256SUMS`、校验值缺失/格式错误或与文件不符，一律中止安装并保持现有程序不变。只有明知风险时才用 `--insecure-skip-verify`（或环境变量 `W1NCRAY_INSECURE_SKIP_VERIFY=1`）整体跳过校验，脚本会打印醒目警告。`--binary` 指定的本地文件不经校验。

**安装只装 agent**：`install` 安装 `W1nCray`（agent 程序 + `W1nCray` 服务），**不安装 Xray 内核**。Xray 内核（`W1nCray-xray`，见 [docs/AGENT.md](docs/AGENT.md) §13）由面板在给这台机器绑定节点时自动安装并启动，或手动执行 `W1nCray xray install`。面板一键接入参数 `--panel URL --machine ID --token TOKEN` 保持不变。

安装脚本会：

1. 按 CPU 自动选择资产（amd64 / 386 / arm64 / armv5-7 / mips / mipsle / mips64(le) / riscv64 / loong64；MIPS 通过 ELF 头判断字节序，ARM 通过 `/proc/cpuinfo` 判断 VFP，运行自检失败时自动换更低要求的版本），下载后校验 `SHA256SUMS`；
2. 安装到 `/usr/local/W1nCray/W1nCray`，配置目录 `/etc/W1nCray`，注册服务 `W1nCray`；并把管理命令放到 `/usr/local/bin/W1nCray`（OpenWRT 为 `/usr/bin/W1nCray`）；
3. **检测到 `/etc/XrayR/config.yml` 时自动迁移**（`config.yml` 以及 dns/route/出入站/规则列表、geo 文件、XrayR 已签发的证书），XrayR 的文件只读、不会被修改；没有 XrayR 时生成默认配置；
4. 缺少 `geoip.dat` / `geosite.dat` 时自动下载（OpenWRT 默认不下载，约 27 MB，需要时加 `--with-geo`）；
5. 运行 `W1nCray check --online`：向面板拉取每个节点并实际构建入站，不监听端口；
6. **XrayR 仍在运行时不会启动 W1nCray**（端口冲突），确认后再切换；
7. 升级时：已是 v11 agent 的机器只更新 agent；**0.5.x 及以前的单一程序**若配置里有 Xray 节点（`config.yml` 有 `Nodes`，或 `Agent.Panel.MachineNodes` 为真），会先下载 agent 与对应的 Xray 内核资产（OpenWrt 用 `-lite`）并通过 `SHA256SUMS` 校验，再按顺序：停止旧服务 → 替换 agent → `W1nCray xray install --file ... --sha256 ...`（启动 Xray 内核服务）→ 启动 agent。下载在停止服务之前完成，中断只有两次进程重启。

### 管理命令（装好后直接输入 `W1nCray`）

```bash
W1nCray                      # 管理菜单
W1nCray status               # 版本、运行状态、开机自启、节点数、最近错误
W1nCray check                # 检查配置并向面板验证每个节点
W1nCray start|stop|restart   # 服务控制
W1nCray enable|disable       # 开机自启
W1nCray config               # 编辑配置，保存后可立即检查
W1nCray update [vX.Y.Z] [--lite|--full]
W1nCray switch               # 停用 XrayR、启用 W1nCray；5 秒内未正常运行会自动回滚
W1nCray rollback             # 随时回到 XrayR
W1nCray migrate              # 重新迁移（先把现有 /etc/W1nCray 备份为 /etc/W1nCray.bak.<时间>）
W1nCray xray status|start|stop|restart|install|remove
                             # Xray 内核服务（与面板同一套实现；install 默认按已签名清单装最新版）
W1nCray xray install --file <W1nCray-xray 文件或 .gz> --sha256 <hex>
                             # 离线安装 Xray 内核（sha256 必填）
W1nCray uninstall [--purge]  # 卸载（同时停止并删除 Xray 内核服务；--purge 再删除配置）
```

查看日志（agent 程序本体**没有** `log` 子命令，按服务后端来）：

```bash
journalctl -u W1nCray -f         # systemd
tail -f /var/log/W1nCray.log     # OpenRC（supervise-daemon 写的文件）
logread -f -e W1nCray            # procd（OpenWRT）
```

其余 agent 子命令（`version`、`init`、`agent-apply`、带参数的 `migrate` / `check` 等）原样交给程序本体；`x25519` 属于 Xray 内核程序（`W1nCray-xray x25519`），agent 里没有。

### Alpine / OpenWRT 说明

- **Alpine**：用 OpenRC 的 `supervise-daemon` 托管，崩溃后每 10 秒无限重启，日志在 `/var/log/W1nCray.log`。
- **OpenWRT**：用 procd 托管（`respawn 3600 10 0`），日志用 `logread -e W1nCray`；内存小于 1 GiB 时自动设置 `GOMEMLIMIT`。路由器内置闪存通常装不下，请把外部存储挂载（extroot 或 USB/SD）后用 `--prefix /mnt/xxx/W1nCray` 安装。配置与服务脚本会写入 `/etc/sysupgrade.conf`，固件升级后保留配置，但程序文件需要重新执行安装命令。
- agent 现在是**单一构建**（不再链接 DNS/ACME，约 12 MB，内置备用根证书 `fallbackroots`，无系统 CA 的设备也能用 HTTPS）；`W1nCray-linux-<arch>-lite.gz` 只是同内容副本，供 v11 之前的安装脚本继续使用。Xray 内核有 full 与 `-lite`（`dnslite,fallbackroots`）两种构建，OpenWrt 上 agent 会选择 `-lite`（清单字段 `openwrt_targets`，键为纯 `linux/<arch>`；旧清单的 `linux/<arch>+openwrt` 键仍兼容读取）。
- 同一份配置同一时间只允许一个 W1nCray 实例（`<配置文件>.lock`）；Xray 内核用自己的锁（`<配置文件>.xray.lock`），两者可以同时运行。
- 从 XrayR 迁移时，路由里的旧入站 tag（形如 `V2ray_0.0.0.0_65534`）会自动映射到对应节点的入站，无需修改 `route.json`。

### 命令（程序本体）

```bash
W1nCray -c /etc/W1nCray/config.yml                     # 运行
W1nCray migrate --from /etc/XrayR --to /etc/W1nCray    # 迁移 XrayR（--dry-run 只预览，--force 覆盖）
W1nCray check -c /etc/W1nCray/config.yml [--online]    # 检查配置（--online 同时向面板验证节点）
W1nCray link --panel https://panel.example.com --machine 12 --token <T>  # 把静态节点转成机器模式（--dry-run 只预览）
W1nCray init --dir /etc/W1nCray                        # 写入默认配置
W1nCray version                                        # agent 版本与构建类型（不含 Xray-core；内核版本用 W1nCray-xray version）
W1nCray-xray x25519                                    # 生成 REALITY 密钥对（Xray 内核程序；agent 本体没有该命令）
```

面板路由中使用 `geosite:` / `geoip:` 时需要 `geosite.dat`、`geoip.dat`（默认从配置文件所在目录查找，也可用环境变量 `XRAY_LOCATION_ASSET` 指定）。

### 编译与发布

```bash
bash release/build.sh v0.6.0 [arch ...]   # 默认 12 个架构；产出 agent 与 Xray 内核的 .gz 以及 SHA256SUMS
```

v11 起每个架构产出两个程序：

| 产物 | 程序 | 说明 |
|---|---|---|
| `W1nCray-linux-<arch>.gz` | agent | 单一构建，`-tags fallbackroots`（内置备用根证书） |
| `W1nCray-linux-<arch>-lite.gz` | agent | 与上一个**同内容**的副本，仅为兼容 v11 之前的安装脚本而保留 |
| `W1nCray-linux-amd64\|arm64` | agent | 裸文件，供 v0.3.0 之前的安装脚本升级 |
| `W1nCray-xray-linux-<arch>.gz` | Xray 内核 | full 构建 |
| `W1nCray-xray-linux-<arch>-lite.gz` | Xray 内核 | `-tags dnslite,fallbackroots`，OpenWrt 使用 |

同一个版本号注入两个程序（agent 的 `cmd.version`、内核的 `xraynode.Version`）。脚本对每个产物断言架构、在本机架构上执行 `version` 自检（交叉架构跳过并注明），并检查 agent 产物不含 `github.com/xtls/xray-core`、内核产物必须含它。把 `dist/` 里的文件全部上传到 GitHub Release 即可。

内核清单条目见 [tools/manifestgen/examples/v11.yaml](tools/manifestgen/examples/v11.yaml)：agent 与 Xray 内核从本地 `dist/` 取哈希（需要 mirror 提供下载地址），gost/realm/frp 用上游 GitHub 资产。

## 配置

完整示例见 [release/config/config.yml.example](release/config/config.yml.example)。最小配置：

```yaml
Log:
  Level: warning
Nodes:
  - PanelType: Xboard
    ApiConfig:
      ApiHost: "https://xboard.example.com"
      ApiKey: "通讯密钥"
      NodeID: 1
```

修改配置文件（及其引用的 dns/route/出入站/规则文件）后会自动重载。

### 从 XrayR 迁移

推荐用安装脚本或 `W1nCray migrate` 自动迁移，它会逐项打印做了什么。转换规则：

| XrayR | W1nCray |
|---|---|
| `/etc/XrayR/...` 路径（含注释中的路径） | `/etc/W1nCray/...`，被引用的文件一并复制；XrayR 目录外的路径保留并提示 |
| `PanelType: NewV2board / V2board` | `Xboard`；SSpanel 等其他面板的节点会被移除并提示 |
| `NodeType: V2ray` + `EnableVless: true` | `NodeType: vless`（与 XrayR 发给面板的 node_type 一致），删除 EnableVless/VlessFlow |
| `DisableLocalREALITYConfig: true` | `EnableREALITY: false`（即使用面板 REALITY） |
| `DisableIVCheck`、`GlobalDeviceLimitConfig` | 删除（后者改用 Xboard 自带的跨节点设备统计，无需 Redis） |
| XrayR 申请的 ACME 证书（`cert/certificates/<域名>.crt`） | 复制到 W1nCray 证书路径，不重新签发 |
| dns.json / route.json / custom_*.json / rulelist | 原样复制，再用新内核逐条检查，不兼容项会指出文件和第几条 |

迁移后需注意：

- XrayR 的 REALITY 只在 `DisableLocalREALITYConfig: true` 时使用面板配置；W1nCray 在面板节点 `tls=2` 时直接使用面板 REALITY。
- `SendIP: 0.0.0.0` 现在表示由系统选择出口地址（XrayR 会绑定 IPv4，导致无法访问 IPv6 目标）。
- 自定义出站中的 `allowInsecure` 已被 Xray v26 移除，`check` 会提示改用 `pinnedPeerCertSha256`。

### 面板 WebSocket（实时同步）

Xboard 开启节点 WebSocket 后（后台开关 + 运行 `ws-server`），W1nCray 会通过 `/api/v2/server/handshake` 自动发现并连接，无需配置：

- 用户新增/封禁/超流量/到期、节点配置修改：**秒级生效**（不再等待 `pull_interval`）；
- 在线 IP **实时上报**：新 IP 接入后约 1 秒内上报，断开 30 秒（宽限期，避免短连接导致在线数抖动）后上报下线，未变化时每 60 秒刷新；并接收面板下发的全网设备 IP，跨节点设备限制与 Xboard 的计数方式一致；
- 未使用 WebSocket 时在线 IP 同样实时经 HTTP 上报（间隔 ≥5 秒）；但 Xboard 的 HTTP 接口无法表示"下线"，下线的 IP 要等面板 300 秒过期；
- 流量与负载仍走 HTTP；HTTP 轮询始终保留，WebSocket 断开时自动重连并回退，不影响节点工作；
- 不想使用时设置 `ControllerConfig.DisableWebSocket: true`。

面板侧要点：若 Xboard 用自定义 compose 以 `octane:start` 覆盖了启动命令，内置的 Caddy 与 ws-server 不会启动，需要单独运行 `php artisan ws-server start` 并在 Nginx 中把 `/ws` 反代到它（`proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";`）。

### Agent（内置内核管理）

除了 Xboard 节点，W1nCray 还能以“Agent”方式运行：读取一个声明式的期望状态（`spec.Desired` JSON），在本机把转发实例落到内嵌的 xray 引擎或外部内核（gost / frp / realm）上。它与 `Nodes` 相互独立，可以只配 Agent 不配 Nodes。

```yaml
Agent:
  Enabled: true
  # 期望状态文件；修改后自动（去抖 500ms）重新应用，无需整机重载
  DesiredPath: /etc/W1nCray/desired.json
  # 已签名的内核清单；不设置时只有内嵌 xray 引擎可用
  ManifestPath: /etc/W1nCray/manifest.json
  # 额外信任的 ed25519 公钥（每行一个 hex），叠加在内嵌密钥之上；本地/自托管用
  ManifestKeysPath: /etc/W1nCray/keys.txt
  # 默认：StateDir=配置目录/state，KernelsDir=StateDir/kernels
  StateDir: /etc/W1nCray/state
  KernelsDir: /etc/W1nCray/state/kernels
  # 本地根信任策略，远端下发的期望状态永远无法放宽它
  Policy:
    AllowListen: ["0.0.0.0"]      # 允许监听的地址，默认 ["127.0.0.1"]
    PrivilegedPorts: false         # 是否允许 <1024 端口
    PortRange: [20000, 40000]      # 允许的监听端口区间，0 表示不限
    AllowPrivate: false            # 是否允许转发到私网目标
    AllowEngines: []               # 允许的引擎，空=全部已安装
```

- **引擎**：`xray` 是内嵌内核（无需安装，`External: false`）；`gost`、`frp`、`realm` 需要从签名清单安装二进制。清单里的版本、URL、哈希都以清单为准，期望状态只能指定版本号。
- **信任根**：内嵌公钥（`kernel/manifest/trusted_keys.txt`）是生产信任根，发布时用 `-ldflags "-X github.com/W1nCwC/W1nCray/kernel/manifest.ExtraKeys=<hex>,<hex>"` 注入。`ManifestKeysPath` 用于本地/自托管阶段补充密钥；两者都没有时，任何清单都会被拒绝（fail-closed，这是预期行为）。
- **热载**：`DesiredPath` 变更（含 `W1nCray` 自身的重载）触发一次应用；失败会回滚到上一个可用状态，并把失败的期望状态“冻结”，直到内容变化。
- **手动应用**：`W1nCray agent-apply -f desired.json` 应用一次并打印 JSON 报告（报告不含任何 secret）。它不注册内嵌 xray 引擎，只用于外部内核；已启动的内核在命令退出后继续运行。它与常驻服务共用同一把单实例锁（`<配置文件>.lock`）：服务正在用同一份配置运行时会直接报错退出，请先 `W1nCray stop`，避免两个进程同时改写同一个 `StateDir`。

#### 面板控制（Agent.Panel）

Agent 可以连接面板（W1nCBoard / Xboard），由面板下发期望状态、接收应用结果与运行状态。**始终是 Agent 主动外连面板**，面板不会连接 Agent，因此 NAT 后的设备同样可管。线上契约见 [docs/PLAN-v7-panel-control.md](docs/PLAN-v7-panel-control.md)。

```yaml
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: https://panel.example.com     # 必须是 https（loopback 或 AllowInsecureHTTP 除外）
    MachineID: 7                       # 面板上的机器 ID
    TokenFile: /etc/W1nCray/panel.token  # 与 Token 二选一；相对路径相对于配置文件目录
    # Token: xxxxxxxx                  # 不推荐：令牌会留在配置文件里
    PullIntervalSec: 30                # 拉取期望状态的间隔，默认 30，限制在 10–300
    ReportIntervalSec: 30              # 上报运行状态的间隔，默认 30，限制在 10–300
    # AllowInsecureHTTP: false         # 仅开发用：允许明文 http:// 到非 loopback 主机
```

- **本地策略永远优先**：面板下发的期望状态与本地 `DesiredPath` 走同一套校验（`Agent.Policy`），越界就是 `rejected`，面板无法放宽。面板只能下发声明式期望状态，命令只有白名单：`refresh`（立即拉取）与 `dump_state`（回传已脱敏的最近报告与健康状态）。
- **面板不可达不影响转发**：拉取/上报失败只记日志并退避重试（30 秒起、翻倍、封顶 5 分钟，带 ±20% 抖动），已经运行的实例原样继续。启用 Agent 后，重启会先从本地 `last_good` 恢复实例，再去连面板，所以面板宕机时重启也不会丢转发。
- **每次应用都会回执**：无论 `applied` / `rejected` / `failed` / `rolled_back`，都向面板发送 ack；ack 发送失败会在下一轮重试。期望状态含未知字段或 revision 不一致时，Agent 不应用，直接回 `rejected`。
- **令牌文件权限**：`TokenFile` 在类 Unix 系统上若 group/other 可读（`mode & 077 != 0`）会被拒绝，请 `chmod 600`。令牌不会出现在日志、错误信息或命令行里。`W1nCray check` 会离线检查这一段（读取令牌文件、校验 URL 与权限，不联网）。
- **一台机器只配一个来源**：`Agent.Panel` 与 `Agent.DesiredPath` 同时配置时，两者都会应用，后到者生效；通常应只选其一。

### 规则与行为说明

- **路由顺序**：节点安全规则（内网屏蔽）→ 面板路由 / 自定义路由 / 本地 RuleList → 全局 `route.json` → 节点兜底出站。所有节点规则都限定在本节点入站上，互不影响。
- **面板路由 match**：按 Xboard 后台写法 `example.com`、`*.example.com` 匹配域名及子域名；也支持 Xray 原生前缀（`domain:`、`full:`、`regexp:`、`geosite:`、`geoip:` 等）、IP/CIDR；含正则特殊字符的条目按正则处理（兼容 XrayR 时代的写法）。
- **proxy 动作**：`action_value` 为面板该节点 `custom_outbounds` 中的 tag，或本地 `custom_outbound.json` 中的 tag。
- **dns 动作**：作为 Xray DNS 服务器生效；面板 DNS 路由变更会触发一次整体重载。
- **custom_outbounds / custom_routes**：按 Xray 原生 outbound / routing rule JSON 解释（同时兼容 Xboard-Node 的 `{tag, protocol, settings, proxy_tag}` 写法）。
- **证书**：节点下发 `cert_config` 时优先使用面板配置，否则使用本地 `CertConfig`。证书文件每小时被 Xray 自动重新加载，到期前 30 天自动续期。
- **限速**：面板 `speed_limit`（Mbps）作用于每个用户在本节点的上行与下行（各自独立计算）；本地 `SpeedLimit > 0` 时覆盖面板值。
- **设备数**：同一用户在本节点的不同源 IP 数，加上 Xboard 统计到的其他节点上的设备数，超过 `device_limit` 时拒绝新 IP。

## 已知限制

- REALITY：每次启动后，第一个连接到某个 target 的握手会等待约 5 秒（Xray 的 REALITY 库在探测 target 的握手特征，属上游行为）。
- mKCP：Xray v26 把 header/seed 迁到了 finalmask，W1nCray 会自动转换，但与旧客户端的兼容性未经实测。
- Xray v26 **客户端**已移除 `allowInsecure`（改为 `pinnedPeerCertSha256`）。使用自签证书（`cert_mode: self`）时，新版客户端需配置证书指纹。
- 所有节点运行在同一个 Xray 实例中，因此共享 DNS 与全局路由配置。

## 开发

```bash
go test ./...            # 单元测试 + 端到端测试（真实 Xray 客户端经各协议代理）
go run ./tools/protogen  # 重新生成 app/dispatcher/config.pb.go（无需 protoc）
sh tests/install_test.sh # 安装脚本测试（dash / busybox ash / bash 均可，不碰系统）
go test -tags dnslite,fallbackroots ./common/cert/ ./core/ # lite 构建
```

设计与验证记录见 [docs/PLAN.md](docs/PLAN.md)、[docs/PLAN-v2-migration.md](docs/PLAN-v2-migration.md)。

## 许可

[MPL-2.0](LICENSE)。本项目参考了 XrayR（MPL-2.0）的设计与配置格式，基于 Xray-core（MPL-2.0）构建；`migrate/testdata/xrayr-v0.9.4/` 为 XrayR 原版示例文件，仅作迁移测试样本。
