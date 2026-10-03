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

## 安装（Linux）

```bash
mkdir -p /usr/local/W1nCray /etc/W1nCray
cp W1nCray /usr/local/W1nCray/ && chmod +x /usr/local/W1nCray/W1nCray
cp release/config/* /etc/W1nCray/ && cp /etc/W1nCray/config.yml.example /etc/W1nCray/config.yml
cp release/W1nCray.service /etc/systemd/system/ && systemctl daemon-reload
systemctl enable --now W1nCray
```

面板路由中使用 `geosite:` / `geoip:` 时，需要把 `geosite.dat`、`geoip.dat` 放到 `/etc/W1nCray/`（默认从配置文件所在目录查找，也可用环境变量 `XRAY_LOCATION_ASSET` 指定）。

### 编译

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X w1ncray/cmd.version=v1.0.0" -o W1nCray .
```

### 命令

```bash
W1nCray -c /etc/W1nCray/config.yml   # 运行
W1nCray version                      # 版本与内核版本
W1nCray x25519                       # 生成 REALITY 密钥对
```

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

1. `PanelType` 可保留 `NewV2board`，或改为 `Xboard`。
2. 协议、flow、传输、TLS/REALITY 均以面板为准；`NodeType`、`EnableVless`、`VlessFlow` 不再需要（保留也不报错）。
3. `GlobalDeviceLimitConfig`（Redis）已移除，改用 Xboard 自带的跨节点设备统计，无需 Redis。
4. `DisableIVCheck` 已随 Xray 移除，忽略。
5. 新增 `BlockPrivateIP`（默认开启）、`CertConfig.HTTPPort`、`CertDir`。
6. `SendIP: 0.0.0.0` 现在表示由系统选择出口地址（XrayR 会绑定 IPv4 导致 IPv6 目标不可达）。

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
```

设计与验证记录见 [docs/PLAN.md](docs/PLAN.md)。

## 许可

本项目参考了 XrayR（MPL-2.0）的设计与配置格式，基于 Xray-core（MPL-2.0）构建。发布前请补充 LICENSE 文件。
