# W1nCray 方案 v2：仓库初始化、安装脚本、XrayR 自动迁移

> 日期：2026-10-04 · 依赖 v1（docs/PLAN.md）已完成的代码。

## 1. 证据

| # | 事实 | 证据 | 档位 |
|---|---|---|---|
| M1 | XrayR 默认文件：`/etc/XrayR/{config.yml,dns.json,route.json,custom_inbound.json,custom_outbound.json,rulelist,geoip.dat,geosite.dat}` | XrayR v0.9.4 `release/config/` | 已验证 |
| M2 | XrayR 默认 `route.json` 在 v26 下构建失败：`this rule has no effective fields`（`"domain": []` 规则） | 本地实测 core.New | 已验证 |
| M3 | 同一规则在 Xray v1.8.20 下同样报错并中止 router 初始化 → 能在 XrayR 上运行的配置不会含此类规则 | v1.8.20 `app/router/config.go:121`、`router.go:59-61` | 已验证 |
| M4 | XrayR ACME 证书存于 `<XRAY_LOCATION_CONFIG 或工作目录>/cert/certificates/<域名>.crt/.key`，ACME 模式忽略 CertFile/KeyFile | `common/mylego/mylego.go:17-26,151-163`、`inboundbuilder.go:280-299` | 已验证 |
| M5 | XrayR REALITY：`DisableLocalREALITYConfig: true` → 面板 REALITY；否则 `EnableREALITY` → 本地；都为 false 时不使用 REALITY | `inboundbuilder.go:213-246` | 已验证 |
| M6 | XrayR newV2board 发送 `node_type`：`V2ray`+`EnableVless` → `vless`，否则小写 NodeType | `api/newV2board/v2board.go` New() | 已验证 |
| M7 | Xboard V1 中间件按 `node_type` 过滤节点；类型不符返回 "Server does not exist" | `Middleware/Server.php`、`ServerService::getServer` | 已验证 |
| M8 | v26 对已移除写法给出带迁移提示的错误（allowInsecure、H2/QUIC、Legacy XTLS、mKCP header/seed 等） | `infra/conf/*.go` PrintRemovedFeatureError | 已验证 |
| M9 | 本机无 Linux 环境（无 Docker、WSL2 内核未安装） | 命令输出 | 已验证 |
| M10 | XrayR 官方 service 工作目录为 `/usr/local/XrayR`（ACME 证书因此落在 `/usr/local/XrayR/cert/certificates/`） | 无法直接核实（XrayR-release 仓库已删除） | 【高度可能】，迁移时同时搜索配置目录与该目录，故不依赖此假设 |

## 2. 设计

### 2.1 `W1nCray migrate`（Go，可单独使用，安装脚本调用）

```
W1nCray migrate [--from /etc/XrayR] [--to /etc/W1nCray] [--dry-run] [--force]
```

原则：**原 XrayR 目录只读不改**；只做可确定无歧义的转换；JSON 内容不改写语义，迁移后用新内核实际构建并逐项报告。

转换规则（YAML 用 yaml.v3 Node 处理，保留注释）：

| 项 | 转换 | 依据 |
|---|---|---|
| 字符串值中以 XrayR 目录开头的路径 | 改写为 W1nCray 目录 | — |
| PanelType `NewV2board`/`V2board` | → `Xboard` | — |
| 其他 PanelType（SSpanel 等） | 删除该节点并报告；无剩余节点则失败 | W1nCray 只支持 Xboard |
| `NodeType` + `EnableVless` | 换算为 Xboard 类型（V2ray+EnableVless→vless、V2ray→vmess、Shadowsocks-Plugin→shadowsocks、其余小写）；删除 EnableVless/VlessFlow/DisableCustomConfig | M6、M7（保持与 XrayR 发送的 node_type 一致） |
| `DisableLocalREALITYConfig: true` | → `EnableREALITY: false`，删除该键 | M5 |
| `DisableIVCheck`、`GlobalDeviceLimitConfig` | 删除并报告（后者改由 Xboard alivelist 实现） | v1 方案 |
| 其余键 | 原样保留 | — |

文件：
- 复制 `dns.json, route.json, custom_inbound.json, custom_outbound.json, rulelist` 以及 config 中引用、位于 XrayR 目录内的文件（含 file 模式证书）；目录外的引用保持原路径并报告。
- geo 文件：依次在 XrayR 目录、`/usr/local/XrayR`、`/usr/local/share/xray`、`/usr/share/xray` 查找并复制。
- ACME 证书（dns/http/tls 且有 CertDomain）：在 `<XrayR目录>/cert/certificates`、`/usr/local/XrayR/cert/certificates` 查找 `<域名>.crt/.key`，复制到 W1nCray 将使用的路径（CertFile/KeyFile 均设置时用之，否则 `CertDir/<域名>.crt|.key`），避免重新签发。
- 目标 config.yml 已存在且无 `--force` → 拒绝。

### 2.2 `W1nCray check -c config.yml [--online]`

- 离线：加载配置 + 用新内核构建实例（dns/route/出入站文件、geo 规则），不监听端口。
- `--online`：额外向面板拉取每个节点的配置与用户，校验协议支持并构建入站（已有证书时含 TLS；未有证书时说明将于启动时获取，不触发 ACME）。

### 2.3 `install.sh`

```
install.sh install  [--binary 路径 | --url 地址]   安装/升级；若无 W1nCray 配置且存在 XrayR 配置则自动迁移；最后执行 check
install.sh migrate  [--force]                      重新迁移（先把现有 /etc/W1nCray 备份为 /etc/W1nCray.bak.<时间戳>）
install.sh switch   [-y]                           停用 XrayR、启用 W1nCray；5 秒后不是 active 则自动回滚
install.sh rollback                                停用 W1nCray、恢复 XrayR
install.sh uninstall [--purge]
```

默认**不停止 XrayR**（端口冲突），切换必须显式执行 `switch`。

### 2.4 仓库

`git init`，先提交 v1 基线（作为可追溯备份），再提交本次改动。

## 3. 改动清单

| 文件 | 类型 | 内容 |
|---|---|---|
| `migrate/migrate.go`、`migrate/migrate_test.go` | 新增 | 迁移逻辑与测试（以 XrayR v0.9.4 示例配置为样本） |
| `cmd/migrate.go`、`cmd/check.go` | 新增 | 子命令 |
| `node/check.go` | 新增 | 在线检查 |
| `common/cert/cert.go` | 修改 | 导出 `TargetPaths`（迁移与运行时共用同一路径规则） |
| `install.sh` | 新增 | 安装/迁移/切换/回滚 |
| `README.md`、`docs/PLAN.md` | 修改 | 文档 |
| `.gitattributes` | 新增 | 保证 `*.sh` 为 LF 换行（Windows 下编辑） |

备份：被修改的已有文件复制到 `C:\W1nC-XrayR-backup\<时间戳>\` 并核对哈希；同时 git 基线提交。

## 4. 被否决的方案

1. **迁移时自动改写 JSON 语义**（如删除无效规则、去掉 allowInsecure）：会悄悄改变路由/安全行为 → 否决，改为构建检查 + 明确报告（M3 说明无效规则本不可能在 XrayR 上运行）。
2. **安装时自动停止 XrayR 并切换**：生产节点会立即断流且无人值守失败时难以恢复 → 否决，改为显式 `switch` + 自动回滚。
3. **用正则/sed 改写 config.yml**：易误伤、无法可靠删除嵌套键 → 否决，用 YAML AST。

## 5. 验收标准

| # | 验收项 | 手段 |
|---|---|---|
| B1 | XrayR v0.9.4 示例 config.yml 迁移：路径改写、PanelType/NodeType/REALITY/废弃键转换正确，注释保留，原目录未改动 | 单测（对原目录做迁移前后哈希比对） |
| B2 | SSpanel 节点被剔除并报告；全部不支持时失败 | 单测 |
| B3 | ACME 证书与 file 模式证书被复制到 W1nCray 实际使用的路径，运行时 `cert.Manager` 认可（不重新签发） | 单测 |
| B4 | 迁移结果可被 `LoadConfig` 加载并构建实例；含 v26 不兼容写法时 `check` 指出具体文件与原因 | 单测 |
| B5 | dry-run 不写任何文件；目标已存在且无 --force 时拒绝 | 单测 |
| B6 | `install.sh` 语法正确 | `bash -n` |
| B7 | `install.sh install/migrate/check` 在真实 Linux（用户 VPS，经授权）上运行，不影响运行中的 XrayR | 待用户提供 SSH 密钥访问 |

---

## 6. 实施记录（2026-10-04）

### 6.1 偏差

| # | 偏差 | 原因 |
|---|---|---|
| V1 | 新增 `W1nCray init`（默认配置以 go:embed 打包进二进制） | 单独下载的 install.sh 拿不到仓库中的示例配置 |
| V2 | 模块路径改为 `github.com/W1nCwC/W1nCray`，install.sh 默认仓库 `W1nCwC/W1nCray` | 用户提供 GitHub 用户名 |
| V3 | 新增 `release/build.sh` | 产出 install.sh 期望的 `W1nCray-linux-<arch>` 文件名 |
| V4 | `core.CheckFiles` 逐文件、逐条构建 | 整体构建的错误不含文件名，无法定位 |
| V5 | ACME 模式下不对 CertFile/KeyFile 报"文件不存在" | XrayR 在 ACME 模式忽略这两个字段（M4），报错会误导 |

### 6.2 验收结果

| # | 结果 | 证据 |
|---|---|---|
| B1 | ✅ | `TestMigrate`：路径、PanelType、NodeType(V2ray+EnableVless→vless 等)、REALITY、废弃键转换正确；注释保留；迁移前后 XrayR 目录所有文件 SHA-256 一致 |
| B2 | ✅ | SSpanel 节点被移除并告警；`TestMigrateXrayRExampleOnlySSpanel`：XrayR 原版示例（仅 SSpanel）迁移失败并说明原因，改为 NewV2board 后可迁移并加载 |
| B3 | ✅ | XrayR lego 证书复制到 `cert.TargetPaths`，`cert.Manager.Ensure` 返回 renewed=false（不重新签发）；file 模式证书一并复制 |
| B4 | ✅ | 迁移结果被 `panel.LoadConfig` 加载、`core.CheckFiles` 通过；`TestCheckNamesBrokenFile` 精确报告 `route.json rules[2] ... no effective fields` |
| B5 | ✅ | dry-run 不创建目标目录；目标已存在且无 --force 拒绝；源=目标拒绝 |
| B6 | ✅ | `bash -n install.sh`、`bash -n release/build.sh` 通过；文件为 LF |
| B7 | ⏳ | 等待用户提供 VPS 的 SSH 密钥访问 |
| — | ✅ | 全量回归 `go test ./...` 通过；CLI 实测 `migrate --dry-run` / `migrate` / `check` 输出与退出码符合预期 |
