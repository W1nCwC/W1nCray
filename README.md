# W1nCray

对接 [Xboard](https://github.com/cedar2025/Xboard) 节点 API 的节点后端，基于官方稳定版 Xray-core 构建（XrayR 的重写）。

## 与 Xboard 的关系

W1nCray 作为 Xboard 的**节点后端**运行：它按 Xboard 的 UniProxy 节点 API 拉取节点配置与用户，在本机用 Xray 内核把节点跑起来，并把流量、在线 IP 与节点负载回传给面板。

- 普通节点模式：`/api/v1/server/UniProxy/{config,user,push,alive,alivelist,status}`（`api/xboard/client.go:5–10`）。
- 机器（Machine）模式：`/api/v2/server/machine/agent/node/*`，由面板决定这台机器跑哪些节点（`api/xboard/client.go:14–20,40`）。

## 两个程序

安装包里有**两个独立的程序**，各自是一个服务：

| 程序 | 职责 | 是否链接 Xray-core |
|---|---|---|
| `W1nCray` | agent：安装/升级、面板连接、节点管理、转发内核、终端与文件管理 | 否 |
| `W1nCray-xray` | Xray 内核：真正跑节点入站的程序 | 是 |

安装器只安装 agent（`W1nCray` 程序 + 服务），**不安装 Xray 内核**：内核由面板在给这台机器绑定节点时自动安装，或手动执行 `W1nCray xray install`（`install.sh:1830–1831`）。这一拆分由测试守住：agent 主包不得依赖 `github.com/xtls/xray-core`，内核程序必须依赖（`deps_test.go:16–32`）。

## 核心能力

- **面板实时同步**：面板开启节点 WebSocket 后自动发现并连接，用户变更、节点配置修改秒级生效；HTTP 轮询始终保留作为兜底，断开自动重连。可设置 `ControllerConfig.DisableWebSocket: true` 关闭（`node/ws.go:19–29,33–63`；`nodecfg/config.go:48`）。
- **在线 IP 上报与设备数限制**：按源 IP 统计在线设备并上报，接收面板下发的全网设备 IP 以做跨节点限制（`node/devices.go:50–107`；`node/report.go`）。
- **节点状态与负载上报**：CPU / 内存 / Swap / 磁盘（`node/report.go:108–137`）。
- **用户限速**：面板 `speed_limit`（Mbps）与本地 `ApiConfig.SpeedLimit`，上下行独立；另有超速自动限速 `AutoSpeedLimitConfig`（`node/controller.go:375–405,417–430`；`node/report.go:139–194`；`nodecfg/config.go:63–69`）。
- **默认阻止访问内网**：`BlockPrivateIP` 未写时即为开启，命中内网/保留地址的流量被阻断（`nodecfg/config.go:104–109`；`node/rules.go:15–30,138–140`）。
- **面板证书下发**：节点 `cert_config` 优先于本地 `CertConfig`；支持 `none`、`file`、`self`、`http`、`tls`、`dns` 模式，以及面板直接下发证书内容（`node/controller.go:689–711`；`common/cert/cert.go:87–108`；`common/certcfg/certcfg.go:21–30`）。
- **路由与自定义出入站**：面板路由（`block` / `direct` / `proxy` / `dns`）、本地 RuleList、`custom_outbounds` / `custom_routes`、全局 `dns.json` / `route.json` / `custom_inbound.json` / `custom_outbound.json`（`node/rules.go:136–193,196–209,236–283`）。
- **配置热重载**：`config.yml` 及其引用的 DNS / 路由 / 出入站 / 规则文件变化后自动重建，无需重启（`config/watch.go:18–40`；`xraynode/service.go:874–929`）。
- **外部转发内核**：agent 可经面板管理外部转发内核（gost / frp / realm）（`driver/gost`、`driver/frp`、`driver/realm`；`agent/spec/spec.go:22–26`）。

## 支持的节点协议

依赖 Xray-core `v1.260327.0`（`go.mod:14`）。

| 节点类型 | 说明 |
|---|---|
| VMess | 传输与安全由面板节点配置决定；用户 UUID（`node/build.go:22,201–205`） |
| VLESS | 可选 flow（面板下发，如 `xtls-rprx-vision`）、`decryption`（VLESS Encryption，默认 `none`）、REALITY、回落（`node/build.go:23,207–224,142–147,281–299`） |
| Trojan | TLS 或 REALITY（`node/build.go:24,226–234,130–139`） |
| Shadowsocks | 普通 AEAD 加密；`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm` 支持多用户（`node/build.go:25,236–256`） |
| Hysteria2 | 仅 v2；salamander 混淆；上下行带宽（`node/build.go:26,258–262,431–453`） |
| SOCKS / HTTP | 用户变更时重建该入站（`node/build.go:27–28,264–276,59–63`） |

传输方式：`tcp(raw)`、`ws`、`httpupgrade`、`grpc`、`xhttp`（面板写 `splithttp`）、`kcp`（面板写 `mkcp`）；Shadowsocks / SOCKS / HTTP 固定 `tcp`，Hysteria2 固定 `hysteria`（`node/build.go:367–385,387–458`）。TLS 启用条件见 `node/build.go:129–147`，ECH 见 `:504–508,574–598`，PROXY protocol 见 `:477–479`，流量嗅探见 `:176–181`。

不支持：`tuic`、`anytls`、`naive`、`mieru`，Hysteria v1，已被 Xray 移除的传输 `h2` / `http` / `quic`（请改用 xhttp），Shadowsocks 插件，以及多用户下的 `2022-blake3-chacha20-poly1305`（`node/build.go:43–57,454–456,236–244`）。

## 快速安装

支持 systemd（Debian / Ubuntu / CentOS 等）、OpenRC（Alpine）、procd（OpenWRT）；脚本为 POSIX sh（`install.sh:1–5,133–145`）。

```sh
# 把 VER 换成 Releases 页上的最新正式版；安装器默认取“含预发布的最新版”，所以示例显式指定版本
VER=v0.8.4
curl -fsSL -o /tmp/w1ncray-install.sh \
  "https://github.com/W1nCwC/W1nCray/releases/download/${VER}/install.sh"
sh /tmp/w1ncray-install.sh install --version "${VER}"
```

OpenWRT 等没有 curl 的环境用 wget 取同一个地址，或直接从发行页下载 `install.sh` 资产。

**校验失败即拒绝（fail-closed）**：下载的程序必须通过发行页校验值校验——脚本先试逐资产的 `<资产名>.sha256`，再回退到合并的 `SHA256SUMS`；缺少 `sha256sum`、取不到校验值或校验不匹配都会中止安装并保持现有程序不变。只有明知风险时才用 `--insecure-skip-verify` 跳过（`install.sh:345–387,1833–1836`）。

安装会按 CPU 自动选择资产（amd64、386、arm64、armv5/6/7、mips、mipsle、mips64、mips64le、riscv64、loong64，见 `release/build.sh:47–60`），把程序装到 `/usr/local/W1nCray/W1nCray`、配置写到 `/etc/W1nCray`、管理命令放到 `/usr/local/bin/W1nCray`（OpenWRT 为 `/usr/bin/W1nCray`）（`install.sh:38–49,106–123`）。

常用参数（`install.sh:1225–1307`）：

- `--lite` / `--full`、`--prefix DIR`（安装目录，路由器内置闪存不够时指向外部存储）、`--with-geo` / `--no-geo`（是否下载 geo 数据文件）。
- `--binary FILE`、`--url URL`、`--version vX.Y.Z`（三选一，`--binary` 指定的本地文件不校验）。
- `--panel URL --machine ID (--token TOKEN | --token-file FILE)`：面板一键接入（机器模式）。面板地址必须是 https，仅回环地址可用明文 http，非回环 http 需显式加 `--allow-http`；令牌建议用 `--token-file`，它只写入 `<配置目录>/agent.token`（权限 600），不写进配置文件、日志或子进程参数（`install.sh:1844–1853,1427–1437`）。
- `--port-range LO-HI`（机器模式允许监听的端口区间，默认 20000-40000）、`--noterminal`（关闭本机交互终端）、`-y` / `--yes`（非交互确认）、`--insecure-skip-verify`。

机器模式示例（占位符请替换）：

```sh
sh /tmp/w1ncray-install.sh install --version "${VER}" \
  --panel https://panel.example.com --machine 1 --token-file /root/machine.token
```

## 管理命令

装好后直接输入 `W1nCray`（`install.sh:1800–1821`）：

```text
W1nCray                     打开管理菜单
W1nCray start|stop|restart  启动 / 停止 / 重启服务
W1nCray status              版本、运行状态、开机自启、WebSocket 与最近错误
W1nCray check               检查配置并向面板验证每个节点
W1nCray config              编辑配置文件，保存后可立即检查
W1nCray enable|disable      开机自启 开 / 关
W1nCray update [版本号] [--lite|--full]   更新程序
W1nCray migrate             重新迁移 XrayR 配置（先备份）
W1nCray switch [-y]         停用 XrayR、启用 W1nCray（失败自动回滚）
W1nCray rollback            停用 W1nCray、恢复 XrayR
W1nCray uninstall [--purge] [-y]          卸载（--purge 同时删除配置）
W1nCray xray status|start|stop|restart|install|remove   管理 Xray 内核服务
W1nCray xray install --file <W1nCray-xray 文件或 .gz> --sha256 <hex>   离线安装内核
```

其它子命令交给程序本体，例如 `W1nCray version`、`W1nCray -c /etc/W1nCray/config.yml`；REALITY 密钥对属于内核程序：`W1nCray-xray x25519`（`install.sh:1819–1821`；`cmd/w1ncray-xray/main.go:227–237`）。

### 服务与日志

服务名是 `W1nCray`（Xray 内核为独立的 `W1nCray-xray`）。按后端查看日志（`install.sh:510–544,561–568,646,691–717`）：

```sh
journalctl -u W1nCray -f         # systemd
tail -f /var/log/W1nCray.log     # OpenRC（supervise-daemon 写的文件）
logread -f -e W1nCray            # procd（OpenWRT）
```

- systemd：`Restart=always`、`RestartSec=5`，`WorkingDirectory` 为配置目录。
- OpenRC（Alpine）：`supervise-daemon` 托管，崩溃后每 10 秒重启。
- procd（OpenWRT）：`respawn 3600 10 0`；内存小于 1 GiB 时自动设置 `GOMEMLIMIT`。路由器内置闪存通常装不下，请把外部存储挂载后用 `--prefix` 安装。配置与服务脚本会写入 `/etc/sysupgrade.conf`，固件升级后配置保留，但程序文件需要重新执行安装命令（`install.sh:876–886,1518–1520`）。

## 配置

配置文件默认在 `/etc/W1nCray/config.yml`（`install.sh:38–42`）。最小示例（完整示例见 [release/config/config.yml.example](release/config/config.yml.example)）：

```yaml
Log:
  Level: warning
Nodes:
  - PanelType: Xboard
    ApiConfig:
      ApiHost: "https://xboard.example.com"
      ApiKey: "<通讯密钥>"
      NodeID: 1
```

机器模式下，agent 自身配置由安装器写入 `/etc/W1nCray/agent.yml`，一般不需要手写；只要它存在，就整体覆盖 `config.yml` 里遗留的 `Agent:` 段，`config.yml` 只保留 Xray 内核的配置（`install.sh:40–42,1848–1849`）。

安装器在首次安装时还会：按 CPU 架构自检，跑不起来就自动换更低要求的版本；检测到 `/etc/XrayR/config.yml` 时自动迁移（XrayR 的文件只读、不会被改动）；缺少 `geoip.dat` / `geosite.dat` 时按需下载（`--no-geo` 可跳过）（`install.sh:1000–1013,450–475`）。已是拆分后版本的机器执行 `update` 只更新 agent（`install.sh:1837–1842`）。

路由里使用 `geosite:` / `geoip:` 需要 `geosite.dat` / `geoip.dat`；环境变量 `XRAY_LOCATION_ASSET` 指向数据文件所在目录，服务单元已默认设为配置目录（`install.sh:527,575`；`release/config/config.yml.example:9–13`）。

## 从 XrayR 迁移

安装脚本检测到 `/etc/XrayR/config.yml` 时会自动迁移（XrayR 的文件只读），也可以手动执行：

```sh
W1nCray migrate --from /etc/XrayR --to /etc/W1nCray [--dry-run] [--force]
```

`--dry-run` 只预览，`--force` 覆盖目标目录里已存在的文件（`cmd/migrate.go:33–36`）。命令会逐项打印它做了什么，转换后的配置建议再用 `W1nCray check -c /etc/W1nCray/config.yml --online` 核对。

## 从源码构建

需要 Go 1.26.0 或更高（`go.mod:3`）。

```sh
go build -o W1nCray .                         # agent
go build -o W1nCray-xray ./cmd/w1ncray-xray   # Xray 内核程序
```

发布产物由 `bash release/build.sh [vX.Y.Z] [arch ...]` 生成到 `dist/`（含每个架构的 agent 与内核 `.gz` 以及 `SHA256SUMS`），不指定版本号时版本为 `dev`（`release/build.sh:26–28,47–60,69–122`）。

测试：

```sh
go test ./...            # 单元测试与端到端测试
sh tests/install_test.sh # 安装脚本测试（dash / busybox ash / bash 均可，不碰系统）
```

## 许可

[MPL-2.0](LICENSE)。本项目参考了 XrayR（MPL-2.0）的设计与配置格式，基于 Xray-core（MPL-2.0）构建。
