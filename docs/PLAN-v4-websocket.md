# 方案 v4：W1nCray 支持 Xboard 节点 WebSocket

> 日期：2026-10-04 · 依据：用户面板实际运行的 Xboard 代码（commit 60ba571，`app/WebSocket/*`、`NodeSyncService`、`NodeRegistry` 与 master 一致）与官方 Xboard-Node `internal/panel/ws.go`（交叉核对）。

## 1. 证据（协议）

| # | 事实 | 来源 | 档位 |
|---|---|---|---|
| W1 | 发现：`POST /api/v2/server/handshake`（body `token`,`node_id`）→ `{"websocket":{"enabled":bool,"ws_url":...}}`；enabled 需后台开关 + ws-server 心跳 | `V2/Server/ServerController.php` | 已验证（用户面板返回 `enabled:true, ws_url: wss://panel.example.com/ws`） |
| W2 | 连接：`ws_url?token=..&node_id=..`；token 错误/节点不存在时在握手阶段直接 close（不回 101） | `NodeWorker::authenticateNode` | 已验证 |
| W3 | 认证成功：`clearAllNodeDevices(nodeId)` → 发 `auth.success` → 推 `sync.config{config}` + `sync.users{users}` | `NodeWorker.php:186-201`、`NodeEventHandlers::pushFullSync` | 已验证 |
| W4 | `sync.config.config` = `buildNodeConfig()`，**不含 base_config**（HTTP config 含） | `NodeSyncService::notifyConfigUpdated`、`UniProxyController::config` | 已验证 |
| W5 | `sync.users{users:[{id,uuid,speed_limit,device_limit}]}`；`sync.user.delta{action:add\|remove, users:[...]}`（remove 仅含 id） | `NodeSyncService` | 已验证 |
| W6 | `sync.devices{users:{uid:[ip...]}}`；用户面板版本未做 `array_values`，IP 列表可能编码为 JSON 对象 | `DeviceStateService::getUsersDevices`（与 master 差异） | 已验证 |
| W7 | 服务端每 55s 发 `{"event":"ping"}`，客户端应回 `pong`（刷新 `node_ws_alive`） | `NodeWorker::PING_INTERVAL`、`handlePong`；Xboard-Node 回 pong | 已验证 |
| W8 | `report.devices` data 为 `{uid:[ip]}` 或 `{devices:{...}}`，服务端与旧值求差集——**必须是本节点完整快照**；随后 ≤10s 回推 `sync.devices` | `NodeEventHandlers::handleDeviceReport`、`NodeWorker` 10s 定时器 | 已验证 |
| W9 | 设备记录 TTL 300s | `DeviceStateService::TTL` | 已验证 |
| W10 | `node.status` → 刷新 LAST_CHECK_AT + `updateMetrics`；流量**不**经 WS | `NodeEventHandlers::handleNodeStatus` | 已验证 |
| W11 | 断开：`clearAllNodeDevices` + 删除 `node_ws_alive`（此后面板不再推送） | `NodeWorker::onClose` | 已验证 |
| W12 | 仅 `node_ws_alive` 为真时面板才推送 | `NodeSyncService::isNodeOnline` | 已验证 |
| W13 | `gorilla/websocket v1.5.3` 已在依赖树（xray-core 间接依赖） | `go.mod` | 已验证 |

## 2. 设计

- 新增 `api/xboard/ws.go`：`Handshake()`、`WSClient`（连接、读循环、写队列、ping→pong、指数退避重连 1s→60s+抖动、稳定 2 分钟重置退避；URL 中 token 在错误/日志中打码；支持环境代理）。
- `node` 控制器：
  - 启动后调用 handshake；enabled 则运行 WSClient，否则每个 pull 周期重试 handshake。`ControllerConfig.DisableWebSocket: true` 可关闭。
  - 事件处理：`sync.config` → `applyNode`（沿用上次 base_config 的间隔）；`sync.users` → `applyUsers`；`sync.user.delta` → 在当前面板用户表上增删后 `applyUsers`；`sync.devices` → 限速器记录各用户全网 IP 集合。
  - 配置变化判断改为**剔除 base_config 后比较**（W4），避免 HTTP/WS 交替触发入站重建。
  - WS 在线时：每 60s 及认证成功后立即发 `report.devices`（本节点完整快照，W8/W9）；每 60s 发 `node.status`；HTTP 的 alive 上报暂停（避免双写）。流量、负载仍走 HTTP。
  - HTTP 轮询保留作兜底（ETag 304 成本低），WS 断开期间行为与现在完全一致。
- `common/limiter`：设备判定在有全网 IP 集合时使用 `|全网IP − 本节点IP|` 作为其他节点设备数（比 alivelist 计数精确）；无 WS 时仍用 alivelist。

## 3. 改动清单

| 文件 | 内容 |
|---|---|
| `api/xboard/ws.go`、`ws_test.go` | 新增 |
| `api/xboard/model.go` | 宽松解析 IP 列表（数组/对象）、handshake 响应模型 |
| `node/ws.go`、`node/config.go`、`node/controller.go`、`node/report.go` | 事件处理、配置开关、配置比较、上报切换 |
| `common/limiter/limiter.go`、测试 | 全网 IP 集合 |
| `node/e2e_ws_test.go` | 模拟 Xboard WS 服务端 + 真实 Xray 客户端端到端 |
| `release/config/config.yml.example`、`README.md` | 文档 |

回滚：git（修改前 `6373d48`）；运行时可设 `DisableWebSocket: true` 退回纯 HTTP。

## 4. 被否决的方案

1. **WS 在线时停止 HTTP 轮询**：漏掉事件（如 WS 重连间隙的变更）将无法自愈 → 否决，保留低成本 ETag 轮询。
2. **流量也走 WS**：服务端没有对应事件（W10）→ 不可行。
3. **机器模式（machine_id 多节点复用一条连接）**：需面板配置"机器"并改变鉴权方式，用户当前为单节点 token 模式 → 暂不实现。

## 5. 验收

| # | 标准 |
|---|---|
| D1 | handshake 解析；enabled=false 时不连接、按周期重试 |
| D2 | 连接 URL 携带 token/node_id；ping 回 pong；认证成功后立即发送 report.devices 完整快照 |
| D3 | `sync.user.delta add/remove` 秒级生效：真实 Xray 客户端在推送后立即可用/被拒，其他用户不受影响 |
| D4 | `sync.users`、`sync.config`（无 base_config）正确应用，且相同配置不会重建入站 |
| D5 | `sync.devices` 数组与对象两种格式均可解析，并用于跨节点设备限制 |
| D6 | 服务端断开后自动重连；WS 不可用期间 HTTP 轮询与上报照常 |
| D7 | 错误/日志中不出现 token |
| D8 | 全量回归通过 |
| D9 | 用户 VPS 实连真实面板（需用户同意部署）：面板日志出现 `[WS] Node#… connected` / `Full sync pushed`，后台修改用户秒级生效 |
