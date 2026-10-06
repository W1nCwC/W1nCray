# 方案 v7：面板控制（W1nCray agent ↔ 面板）线上契约与分工

> 日期：2026-10-06 · 状态：已确认方向（用户："Xboard 当 dashboard，W1nCray 当 agent；Xboard 大改就做成 W1nCBoard"）
> 基线：`feat/agent`（v6 阶段 0–1 已合并并验收）。本文是 **契约**：Go 客户端（`agent/panelclient`）与面板服务端（W1nCBoard，PHP/Laravel）必须各自按它实现，任何一端要改契约先改本文。

## 1. 原则（沿用 v6，不重复论证）

1. **agent 主动外连，面板从不连 agent**（NAT 后设备同样可管）。
2. **面板只下发声明式期望状态**（`agent/spec.Desired`），不下发命令串/脚本；命令只有固定白名单。
3. **本地策略（`Agent.Policy`）是根信任**：面板下发的任何内容都要先过 `agent/validate`，越界即 `rejected`，远程不可放宽。
4. **HTTPS 必须**；token 不进 URL/query/argv/日志；密钥（`instance.secret`）只在 HTTPS 响应体里出现。
5. **DB 为真相源，WS 只是提示**（v1 先不做 WS，纯 HTTP 拉取；WS hint 留作 v1.1，不影响本契约）。
6. **离线可用**：面板不可达时 agent 继续运行 last-good，重启后从本地 `last_good` 恢复（见 §6 WP-C），绝不因面板不可达而停转发。

## 2. 身份与认证

- 一台机器 = Xboard 已有的 `v2_server_machine` 一行（`id` + `token`）。W1nCBoard 沿用，不新建身份体系。
- 每个请求头：`X-Machine-Id: <int>`、`Authorization: Bearer <token>`、`Content-Type: application/json`、`User-Agent: W1nCray-agent/<version>`。
- 面板用 `hash_equals` 比 token；`is_active=false` → 403；失败响应体不得回显 token。
- 客户端拒绝非 HTTPS（loopback 主机或显式 `AllowInsecureHTTP: true` 例外，仅开发）。响应体上限 4 MiB。
- 面板侧限速：每机器每端点 ≥ 1 req/s 即 429；客户端遇 429/5xx 退避（30 s 起，×2，封顶 5 min，±20% 抖动）。

## 3. 端点（前缀 `/api/v2/server/machine/agent`）

所有请求/响应均为 JSON，字段 snake_case。响应统一 `Content-Type: application/json`。错误：`{"error":"<机器可读码>","message":"<可读>"}` + 对应 HTTP 状态码（401 token 错、403 停用、404 机器不存在、409 冲突、422 校验、429、5xx）。

### 3.1 `POST /config` —— 拉取期望状态

请求：
```json
{
  "schema": 1,
  "instance_id": "9f2c1a7e",
  "agent_version": "0.4.0",
  "have_revision": 41,
  "have_hash": "sha256:ab12…",
  "platform": {"os": "linux", "arch": "mipsle", "libc": "musl"},
  "engines": ["xray", "gost", "realm"],
  "kernels": {"gost": "3.3.0", "realm": "2.9.6"}
}
```
- `instance_id`：agent 进程每次启动随机生成（8–16 hex），用于 report 的 `seq` 去重与计数器归零判断。
- `have_*`：agent 当前已**成功应用**的 `(revision, hash)`；从未应用过为 `0` / `""`。
- `engines`：本机已注册的引擎；`kernels`：已安装的外部内核版本（用于面板置灰不可用选项）。

响应 200 —— 无变化：
```json
{"schema": 1, "unchanged": true, "revision": 41}
```
响应 200 —— 有变化：
```json
{
  "schema": 1,
  "revision": 42,
  "hash": "sha256:cd34…",
  "issued_at": 1790000000,
  "desired": { "version": 1, "revision": 42, "instances": [ … ] },
  "commands": [
    {"id": "01JAB…", "type": "refresh", "args": {}, "expires_at": 1790000060}
  ]
}
```
- `desired` 即 `agent/spec.Desired`（`desired.revision` 必须等于外层 `revision`），客户端**严格解码**（未知字段 = 拒绝并 ack `rejected`，防协议漂移）。
- `hash` 对客户端是**不透明**的相等标识（面板用任意稳定算法生成，建议 sha256 of 规范化 JSON）；客户端只做相等比较并在 ack/下次请求里回显。
- 面板在**没有任何期望状态**（该机器从未配置）时返回 `desired` 为 `{"version":1,"revision":0,"instances":[]}`，agent 据此保持空状态（不报错）。
- `commands` 可为空/省略；每条带过期时间，过期客户端忽略。
- `revision` 单调递增（回滚也是新建 N+1）。客户端若收到 `revision` 小于已应用值且 `hash` 不同：照常应用但记 WARN（面板数据库被还原的场景）。

### 3.2 `POST /ack` —— 应用结果（每次尝试应用后必发，含 rejected/failed/rolled_back）

```json
{
  "schema": 1,
  "instance_id": "9f2c1a7e",
  "revision": 42,
  "hash": "sha256:cd34…",
  "report": { /* agent/reconcile.Report，已脱敏、不含 secret */ }
}
```
响应：`{"ok": true}`。幂等（同 `(machine, revision, hash, report.at)` 重复提交无副作用）。`report.status ∈ applied|partial|failed|rolled_back|rejected`。面板对 `rolled_back/rejected/failed` 的 `hash` 做标记，UI 展示 `report.validation_errors` 与每实例 `error`。客户端发送失败要重试（最多保留最近一次未送达的 ack，进程内存即可）。

### 3.3 `POST /report` —— 周期状态（默认每 30 s）

```json
{
  "schema": 1,
  "instance_id": "9f2c1a7e",
  "seq": 123,
  "ts": 1790000030,
  "applied_revision": 42,
  "applied_hash": "sha256:cd34…",
  "health": {"ok": true, "diffs": []},
  "instances": [
    {"id": "hk-ssh", "state": "running", "engine": "gost",
     "bytes_up": 123456, "bytes_down": 654321, "conns_active": 3, "conns_total": 120}
  ],
  "kernels": {"gost": "3.3.0", "xray": "builtin"},
  "host": {"cpu": 12.5, "mem_total": 1073741824, "mem_used": 402653184,
           "swap_total": 0, "swap_used": 0, "disk_total": 0, "disk_used": 0,
           "net_in_speed": 0, "net_out_speed": 0, "uptime_s": 86400}
}
```
- `instances[*].bytes_*`/`conns_*` 是**累计值，仅在同一 `instance_id` 内单调**；`instance_id` 变化 = agent 重启 = 计数器归零，面板按差分处理。xray/gost/frp 有统计；realm 无统计则省略这四个字段（`null`/缺省），面板据此显示「不支持计量」。
- `host` 可选（取自 `common/serverstatus`；取不到的字段省略）。
- `seq` 对每个 `instance_id` 从 1 递增，面板对 `(machine, instance_id, seq)` 去重（幂等）。
- 响应：`{"ok": true, "ack_seq": 123}`；响应体里也可带 `commands`（同 3.1 结构）作为命令快速通道。

### 3.4 `POST /command-result` —— 命令回执

```json
{"schema": 1, "instance_id": "9f2c1a7e", "id": "01JAB…", "status": "done", "result": {"revision": 42}}
```
`status ∈ done|failed|expired`；响应 `{"ok": true}`。

### 3.5 命令白名单（v1）

| type | args | 行为 |
|---|---|---|
| `refresh` | `{}` | 立即执行一次 `/config` 拉取 |
| `dump_state` | `{}` | 回执 `result` = `{"report": <Reconciler.Last()>, "health": <Reconciler.Health()>}`（已脱敏） |

任何其他 `type`：客户端回 `failed`（`result.error="unsupported command"`），**不执行**。命令不含 shell/路径/URL 参数。

## 4. 面板侧（W1nCBoard）要提供的数据与管理 API（摘要，细节由实现任务定稿）

- 表（前缀 `v2_`）：`agent_instance`（每机器的实例，`spec` JSON，`secret` 用 `Crypt::encryptString`）、`agent_revision`（不可变快照，`UNIQUE(machine_id, revision)`，含 `hash`）、`agent_machine_state`（最近 ack/report、`applied_revision`、`last_report_at`、`kernels`、`blocked_hash`）、`agent_instance_status`（最近 report 的每实例状态）、`agent_audit`（谁改了什么，diff 脱敏）、`agent_command`（待下发命令）。
- 管理端 API（`admin` 鉴权，不挂会记录嵌套 body 的通用 `log` 中间件）：机器列表、实例 CRUD、`validate`（服务端 dry-run，复刻 `agent/validate` 的 schema 级规则）、`apply`（`base_revision` 乐观锁，不匹配 409；写 N+1 快照）、`rollback`（把历史快照复制为 N+1）、revision 列表/diff、状态/审计查询、命令入队。
- 管理页：独立页面（Xboard 管理端是闭源预编译前端，无扩展点）。登录沿用 Sanctum token。

## 5. 非目标（v1 不做）

WS 推送 hint、`restart_instance`/任意命令、面板签名、多面板、规则级计费映射。

## 6. 工作包与路径归属（并行执行，路径互不重叠）

| WP | 内容 | 允许修改的路径 | 状态 |
|---|---|---|---|
| WP-A | Go：`agent/panelclient`（HTTP 客户端 + 拉取/ack/上报/命令循环）+ 接入 `bootstrap`/`panel` 配置 | `agent/panelclient/**`、`agent/bootstrap/remote*.go`、`panel/config.go`、`panel/panel.go`、`panel/check.go`、README 增节 | 待派 |
| WP-B | Go：`agent/examples/**`（五种 kind × 引擎的期望状态样例，经 `validate`+`Render` 测试守住不漂移）+ `docs/AGENT.md`（中文使用手册） | `agent/examples/**`、`docs/AGENT.md` | 待派 |
| WP-C | Go：`Reconciler.Stop`（停内核但**不清空**持久化状态）+ `Boot` 恢复 last_good + `Shutdown` 语义修正 | `agent/reconcile/**`（仅新增 Stop 及测试）、`agent/bootstrap/bootstrap.go`、`agent/bootstrap/bootstrap_test.go` | 待派 |
| WP-D | PHP：W1nCBoard 后端（迁移、模型、agent 端点、管理 API） | 面板仓库（见 §7） | 环境就绪后派 |
| WP-E | W1nCBoard 管理页（独立页面） | 面板仓库 | 依赖 WP-D |

## 7. W1nCBoard 仓库约定

- 起点：上游 `cedar2025/Xboard`（本地浅克隆），不是用户魔改版；魔改版的差异需要对其面板做只读检查（需用户另行同意）后再决定如何合入。
- 位置：`C:\W1nCBoard`（独立 git 仓库，用户的 Go 项目仓库不混放）。PHP/Composer/数据库测试在 <test-host> 上进行（本机无 PHP/Docker，已获用户允许）。
