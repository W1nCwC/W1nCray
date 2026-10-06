# PLAN v9 — 设计评审裁决（最终依据）

四份实现设计（`.dsh/out/DESIGN-{go-core,go-ops,php-backend,ui}.md`）经评审后，**以下裁决覆盖设计文档里与之冲突的内容**。契约以 `docs/WS-PROTOCOL.md`（含 §7 Rulings v1.1）为准。

## 架构
1. `agent.yml` 分离（D1）：类型放新包 `agent/agentcfg`，`panel` 用别名转发；加载优先级 `agent.yml` > `config.yml` 的 `Agent:` 块；字段名两处完全相同。`check` 首屏报告它的解析错误。写 `agent.yml` 一律原子 + 备份。
2. 受管文件含 `config.yml`，但仅当机器已使用 `agent.yml` 分离布局时才允许写；写前必须在暂存副本上做完整 `LoadConfig` 预检；替换后**不在进程内等健康**，由面板按 `hello/telemetry` 恢复情况判定并下发 `files_rollback`（`ReloadForAgent` 串行化，校验失败不 shutdown）。
3. 自升级条目放在签名清单 `kernels` 里，名字 `agent` 为**保留名**（`kernel_*` 命令拒绝它，面板内核列表隐藏它）。`install.sh` 的 systemd 单元改 `Restart=always`；回滚助手能否在 `KillMode=control-group` 下存活是 G4 的**第一个实测项**。"起不来→看门狗回滚；连不上→只上报"。
4. xray 节点按需启停：`hint{what:"nodes"}`，按节点启停（`node.Controller.Close`），整实例 reload 仅作带日志的兜底。
5. 能力门禁：agent 在 `hello.capabilities` 与 HTTP `config` 请求的 `features` 里声明；面板只对声明支持的 agent 才在 desired 里放新键。阶段 1 不新增 desired 键。
6. 同一时刻只有一条通道带负载：WS 连接时 HTTP `/report` 省略 `host`；面板按 `ts` 去重；仅 HTTP 的 agent 仍须落库遥测（HTTP 路径也要 `ingestHost`）。
7. 断线不补发遥测；`conns` 可空；内嵌 xray 不填资源。
8. PTY：`creack/pty`（12 个 GOARCH 已验证可编译），运行时 `Supported()` 探测失败则不声明 `terminal`；`noshell_test.go` 仅对 `agent/terminal` 包放行并写明理由；构建矩阵断言进 `release/build.sh`。
9. `file_*` 上限 128 KiB；写可执行位默认拒绝（`Files.AllowExec`）；roots 排除 `agent.yml`、`desired.json`、`last_good.json`。

17. **终端默认开启**（用户 2026-10 决定，覆盖上面第 8 条里"默认关"的任何暗示与设计文档里的 `--terminal`）：`Terminal.Enabled` 缺省为 true；机器本地关闭用 `Terminal.Enabled: false`，安装脚本/`link` 的开关是 `--noterminal`；面板在 `hello.policy.terminal=false` 时显示"该机器已在本地关闭终端"。**注意**：已部署的机器升级到带终端的版本后会默认获得终端能力；升级说明里必须写明这一点。

## 面板（PHP）
10. 独立 Workerman 进程 `w1ncray:ws-server`，路径 `/w1ncray-ws`，**不碰**旧 `/ws`（生产老节点在用）。单进程起步（`count=1`）；连接对象进程内为权威，Redis 只放 Octane→网关的推送通道与"机器在线"标记；注册表必须有 `remove()/count()` 并在 `onClose` 调用。
11. 命令：WS 推送**不** `markSent`；长命令先回 `accepted`；agent 按命令 id 去重。
12. 清理任务放网关进程的定时器（容器里没有调度器）；删除机器必须连带删除样本。
13. `kernels` 列保持原形状，新增 `kernel_entries` 列放 `KernelEntry[]`。在线判定取 `max(last_poll_at, ws_last_seen_at)`（窗口分别 360 s / 70 s）。
14. 审计脱敏键加入 `content*`、`data`、`manifest_json`；文件上传不走 JSON body。ticket：单次、30 s、**不绑 IP**；审计 IP 仅在对端属于可信代理时取 `X-Forwarded-For`；`/ws/ticket` 加限流；要求 Redis 缓存驱动，签发时断言。
15. 高风险（终端 ticket、`self_update`、受管文件之外的写）要求管理员重新输入密码。
16. 反代：生产是 nginx，新增 `location = /w1ncray-ws`（升级头，关闭或裁剪该路径的 query 日志）。**生产变更，部署前需用户同意。**

## API 路径命名（以前端设计 §3 为准，PHP 按此实现）
`GET monitor/latest?machine_id=` · `GET monitor/history?machine_id=&hours=` · `POST ws/ticket {machine_id, purpose:"live"|"terminal", confirm_password?}`
· `GET kernels?machine_id=` · `POST kernels/install|remove|rollback|refresh` · `GET commands/one?id=`
· `GET files?machine_id=` · `POST files/put|publish|rollback|apply|validate|geo|op` · `GET terminal/sessions`。
前端设计里的"PHP 工作包 WP-B"取消：服务端只由 PHP 设计的工作包负责。

## 分期派工
- 第 1 批（互不改同一文件）：GO-WS、GO-TEL、GO-CFG、PHP-GW。
- 第 2 批：GO-WIRE（接线）、GO-LINK（link/install.sh/文档）、PHP-MON（落库+监控 API）、UI-A（契约/实时通道/注册）→ UI-C（概览）。
- 第 3 批：内核命令、受管文件、升级、终端、文件管理（Go + PHP + UI 并行）。
