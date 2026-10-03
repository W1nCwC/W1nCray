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
# 一键安装（从 GitHub Releases 下载对应架构的二进制）
bash <(curl -fsSL https://raw.githubusercontent.com/W1nCwC/W1nCray/main/install.sh) install
# 或使用本地编译的二进制
bash install.sh install --binary ./W1nCray-linux-amd64
```

安装后脚本保存在 `/usr/local/W1nCray/install.sh`，之后的命令都用它执行。

安装脚本会：

1. 安装到 `/usr/local/W1nCray/W1nCray`，配置目录 `/etc/W1nCray`，注册 systemd 服务 `W1nCray`；
2. **检测到 `/etc/XrayR/config.yml` 时自动迁移**（`config.yml` 以及 dns/route/出入站/规则列表、geo 文件、XrayR 已签发的证书），XrayR 的文件只读、不会被修改；没有 XrayR 时生成默认配置；
3. 缺少 `geoip.dat` / `geosite.dat` 时自动下载；
4. 运行 `W1nCray check --online`：向面板拉取每个节点并实际构建入站，不监听端口；
5. **XrayR 仍在运行时不会启动 W1nCray**（端口冲突），确认后再切换。

```bash
bash /usr/local/W1nCray/install.sh switch     # 停用 XrayR、启用 W1nCray；5 秒内未正常运行会自动回滚
bash /usr/local/W1nCray/install.sh rollback   # 随时回到 XrayR
bash /usr/local/W1nCray/install.sh migrate    # 重新迁移（先把现有 /etc/W1nCray 备份为 /etc/W1nCray.bak.<时间>）
bash /usr/local/W1nCray/install.sh check | status | log | uninstall [--purge]
```

### 命令

```bash
W1nCray -c /etc/W1nCray/config.yml                     # 运行
W1nCray migrate --from /etc/XrayR --to /etc/W1nCray    # 迁移 XrayR（--dry-run 只预览，--force 覆盖）
W1nCray check -c /etc/W1nCray/config.yml [--online]    # 检查配置（--online 同时向面板验证节点）
W1nCray init --dir /etc/W1nCray                        # 写入默认配置
W1nCray version                                        # 版本与内核版本
W1nCray x25519                                         # 生成 REALITY 密钥对
```

面板路由中使用 `geosite:` / `geoip:` 时需要 `geosite.dat`、`geoip.dat`（默认从配置文件所在目录查找，也可用环境变量 `XRAY_LOCATION_ASSET` 指定）。

### 编译与发布

```bash
bash release/build.sh v1.0.0   # 产出 dist/W1nCray-linux-amd64、W1nCray-linux-arm64 与 SHA256SUMS
```

把 `dist/` 里的文件上传到 GitHub Release，`install.sh install` 即可直接下载。

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

设计与验证记录见 [docs/PLAN.md](docs/PLAN.md)、[docs/PLAN-v2-migration.md](docs/PLAN-v2-migration.md)。

## 许可

[MPL-2.0](LICENSE)。本项目参考了 XrayR（MPL-2.0）的设计与配置格式，基于 Xray-core（MPL-2.0）构建；`migrate/testdata/xrayr-v0.9.4/` 为 XrayR 原版示例文件，仅作迁移测试样本。
