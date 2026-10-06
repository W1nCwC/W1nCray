# PLAN v8 — W1nCBoard 原生适配 W1nCray（取代 xboard-node 兼容）

状态：2026-10-06 起草。前置：v7（agent ⇄ 面板契约）已部署（面板机 + 落地机 `v0.4.0-dev+4645357`，agent 默认不启用）。

## 0 用户决策（原话要点）
1. agent 与面板之间用 **machine token 认证**（nezha/komari 式），不要求用户持有"生产签名密钥"；内核镜像托管由我决定。
2. 补齐面板端缺的**管理接口和管理页**。
3. **移除** Xboard 现有的"服务器管理"页（管理后台 `/server/machine`，中文菜单名"服务器管理"，生成的是 cedar2025/xboard-node 安装命令）。
4. W1nCBoard **不再兼容 xboard-node**，改为适配自家 W1nCray。

## 1 证据（已验证，文件:行号来自代码走查）
| 事实 | 位置 |
|---|---|
| 线上 3 个节点用 **V1 `UniProxy`** + `/api/v2/server/handshake` + WS，认证 = `server_token`+`node_id` | `W1nCray: api/xboard/client.go:30`、`api/xboard/ws.go:46` |
| xboard-node 专属：`/api/v2/server/{handshake,report}`、`/api/v2/server/machine/{nodes,status}`、WS 机器模式、`MachineController::installCommand`（指向 cedar2025/xboard-node） | W1nCBoard `routes/V2/ServerRoute.php`、`V2/Admin/Server/MachineController.php:205-213`、`NodeWorker.php:205-261` |
| 旧兼容/第三方：`/api/v1/server/UniProxy/*`（`@deprecated`）、`ShadowsocksTidalab`、`TrojanTidalab` | `V1/ServerRoute.php`、`Middleware/Server.php:11-13` |
| 管理后台是预编译 SPA；菜单写死在前端包；hash 路由；登录态 `localStorage["Xboard_access_token"]`；有插件扩展点但表达力有限 | `frontend-overlay/admin/assets/index-CxNodesub11.js`（菜单 `Vlt`@5095556，路由 `path:"machine"`@4405776） |
| 管理 API 前缀 `/api/v2/{secure_path}/…`，鉴权仅 `admin` 中间件（`is_admin`） | `AdminRoute.php:29-32`、`Middleware/Admin.php:19-29` |

**推论**：旧接口不能先删——线上节点还在用 V1 UniProxy + handshake。顺序必须是 *加新 → 迁移 → 删旧*。

## 2 阶段
### 阶段 1：管理接口 + 管理页（纯加法，可立即部署）
- **WP-A1 管理 API**（PHP）：`/api/v2/{secure_path}/w1ncray/*`
  - machines：`fetch / save / drop / resetToken / token / installCommand`
  - instances：`list / put / delete / validate / apply / rollback`
  - history：`revisions / diff / audit / commands(list, enqueue refresh|dump_state)`
  - 全部走 `AgentConfigService`（与 `agent:instance` CLI 共用校验/审计/乐观版本检查）。
- **WP-A2 管理页**（无构建的原生 JS + 一个 Blade/静态壳）：机器列表（在线/版本/内核/应用状态）、实例编辑（带校验错误展示）、修订历史/回滚、审计、命令。登录态复用 SPA 的 localStorage token。
- **WP-A3 SPA 补丁脚本**（精确字符串替换 + 断言 + 新文件名防缓存，沿用用户既有补丁流程）：`/server/machine` 路由改为跳转到新页；菜单文案"服务器管理"→"W1nCray 服务器"；`manifest.json`/`index.html` 同步。
- 旧页下线：`MachineController::installCommand`（xboard-node）移除；`fetch/save` 保留给"节点管理"页里的机器下拉。

### 阶段 2：原生节点协议（让线上节点迁出 V1 UniProxy）
- 面板：`/api/v2/server/machine/agent/{nodes,users,traffic,alive,status}`，机器 token 认证（`AgentMachineAuth`，节点必须属于该机器），复用 `ServerService`（buildNodeConfig / getAvailableUsers / processTraffic / processStatus / DeviceStateService）。
- W1nCray：`api/wnp` 客户端；`Agent.Panel` 增加 `MachineNodes: true`，面板下发的节点由 agent 自动增删，不再逐节点写 `ApiKey/NodeID`。
- `install.sh install --panel URL --machine ID --token T`（一键安装，token 落 0600 文件）。
- 灰度：先在测试机跑通，再在落地机上 **一个节点一个节点** 切换，保留回滚（旧 `Nodes:` 块不删，仅注释停用）。

### 阶段 3：移除旧接口（在 W1nCBoard 仓库；生产在迁移完成后才部署）
- 删除：`handshake/report/machine/{nodes,status}`、V1 UniProxy、Tidal Lab 控制器与路由、WS 的单节点/机器旧模式、对应测试与文档。
- 面板机部署前再次确认：`/api/v1/server/*` 与 `/api/v2/server/*` 近 24h 无请求。

### 内核托管与签名（回应"生产签名密钥可以不用吗"）
- agent ⇄ 面板认证 = machine token，**不需要**任何签名密钥。
- 签名只用于"下载 gost/frp/realm 可执行文件"这一步，防的是镜像/面板被攻破后向所有落地机下发恶意二进制。我建议保留（已实现、fail-closed），但**由我生成并保管密钥对**，用户不用管：公钥编进发布版，私钥只在发布机用于 `tools/manifestgen`。
- 托管：内核镜像 + `manifest.json` 作为 W1nCray 仓库 GitHub Release 资产（与现有 `install.sh` 下载二进制同源）。**对外发布前需用户确认**（发布到 GitHub 属于对外动作）。
- 仅用内置 xray 时不涉及以上任何东西。

## 3 验收
- 阶段 1：管理 API 的 PHP 测试全绿；管理页在测试机上真实登录后可完成"建机器 → 建实例 → 发布 → agent 应用 → 回滚"；SPA 补丁脚本有断言，旧页路径跳转到新页。
- 阶段 2：测试机上 W1nCray 仅凭 machine token 拉到节点并成功起 xray、用户可连、流量上报面板；与 V1 UniProxy 模式并行不冲突。
- 阶段 3：删除后全量测试绿，且 grep 不到 xboard-node/UniProxy/Tidal 引用。

## 4 风险与回滚
- 生产改动一律：先备份（DB dump / 二进制 / 配置 / 前端文件）→ 纯新增优先 → 验证 → 记录回滚命令。
- 前端补丁只改一个 bundle 副本（新文件名），回滚 = `manifest.json` 指回 `index-CxNodesub11.js`。
- 阶段 3 的删除只进仓库，**不在生产执行**，直到用户确认迁移完成。
