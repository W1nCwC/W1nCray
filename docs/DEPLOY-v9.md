# DEPLOY-v9 — PLAN v9 生产部署运行手册（可审阅、可回滚）

面向：面板机 `167.253.156.95`（宝塔 + docker + nginx，站点 `subscribe.w1nc.xyz`）与落地机
`82.152.167.105`（systemd `W1nCray.service`，当前 v0.4.1）。

本文只描述**怎么部署**；不描述功能。功能与契约见
`docs/PLAN-v9-agent-platform.md`、`docs/RULINGS-v9.md`、`docs/WS-PROTOCOL.md`、`docs/AGENT.md`。
面板侧网关的独立说明见 W1nCBoard `docs/DEPLOY-W1NCRAY-WS.md`。

> **本目录里的脚本不会自己跑。** 每一步都是独立的 bash 脚本，可以单独执行、单独回滚；
> `run-all.sh` 只是按顺序调用它们，并在每两步之间要求人工输入 `yes`。
> 所有 `ssh`/`scp` 都经过 `lib.sh` 的函数，默认走 SOCKS5 代理
> `connect.exe -S 127.0.0.1:7890 %h %p`（可用 `PROXY_CMD` 覆盖）。

---

## 0 部署前需要用户确认的事项

这四件事必须在开跑前定下来，脚本不会替你做决定。

| # | 事项 | 默认 | 影响 / 怎么定 |
|---|---|---|---|
| 1 | **落地机是否开启终端** | **否**（`ENABLE_TERMINAL=no`） | 本版本终端能力**默认开启**（RULINGS v9 第 17 条）。脚本默认取保守值：`ENABLE_TERMINAL=no` 会给 `W1nCray link` 加 `--noterminal`，在 `agent.yml` 写入 `Terminal: {Enabled: false}`。要保留终端就显式 `ENABLE_TERMINAL=yes`。注意：面板仍要求管理员重输密码才签发终端 ticket，但**面板被攻破 ≈ 开了终端的机器被攻破**（与 nezha/komari 同级）。落地机上目前跑着 3 个节点，用户需要知情。 |
| 2 | **nginx 与 compose 变更的窗口** | 无默认 | 第 30 步用 `kill -USR1 <swoole master>` 平滑重载 Octane 工作进程（与以往部署的 USR1 重载等效，不重启容器、不中断请求）。第 40 步 nginx 是 `reload`，**不掉连接**。需要用户给出可接受的时间窗，并避开订阅高峰。 |
| 3 | **是否同时升级落地机 agent** | 由 `W1NCRAY_BINARY` 是否提供决定 | 只做面板侧（第 00–60 步）不需要任何 agent 二进制；面板侧完成后老 agent 会走 HTTP 轮询继续工作，只是没有实时通道。第 70 步会让落地机的 3 个节点**中断 3–10 秒**（一次 `systemctl restart`）。 |
| 4 | **签名清单的托管** | 本次不托管 | 面板只做**存储与分发**，它既不签名也不验签（`app/Services/Agent/ManifestStore.php`）。`php artisan agent:manifest put <manifest.json>` 要求：正整数 `sequence`（不能倒退，相等=幂等重传）、`signature{alg:"ed25519",key_id,sig}`、≤ 1 MiB。**发布方的 ed25519 私钥不在面板仓库里**，位置未知——用户需要确认用哪一份 manifest、序号是多少、由谁签。不托管时 agent 只用内嵌 xray，`kernel_*` 与 `self_update` 不可用（fail-closed，不静默降级）。 |

补充确认（不在四问之内但同样需要拍板）：

- **落地机是否已有 `agent.token`（0600）**：第 70 步的分离布局迁移需要它，脚本**永远不会**创建或接收令牌明文，只接受文件路径（`TOKEN_FILE`）。
- **旧 UniProxy API 的处理**：新版 W1nCBoard 已删除 `V1/Server/{Shadowsocks,Trojan}TidalabController`、`V2/Server/{Machine,Server}Controller`、`Http/Middleware/{Server,ServerV2}.php`、`Http/Routes/V1/ServerRoute.php`、`Http/Routes/V2/ServerRoute.php`。**默认脚本不动这些文件**（纯新增/覆盖，`panel-files.txt` 里没有 `D` 条目）。见 §7。
- **`public/assets/admin` 是 git submodule**：部署目标必须已经含有 `assets/index-DiYa-_z_.css` 与 `assets/codicon-ngg6Pgfi.ttf`，否则 sub13 布局会坏。

---

## 1 总览与顺序

```
00 preflight            只读侦察：可达性 / 容器 / compose / nginx / 待迁移 / 落地机版本
10 panel-files          面板 PHP+JS 增量覆盖（只增不改删），不重启
20 migrate              4 个新迁移（加表加列），不重启
30 gateway-service      compose override + 新进程 w1ncray-ws(:8077) + octane:reload（平滑）
40 nginx-w1ncray-ws     location = /w1ncray-ws + nginx -t + reload
50 spa-patch            sub13 七个文件覆盖 public/assets/admin + 删掉 stock locales
60 verify-panel         面板侧验收（只读）
70 agent-upgrade        落地机二进制升级 + agent.yml 分离布局 + 重启
80 verify-agent         面板侧确认机器重新在线（只读）
```

**为什么是这个顺序**：正在跑的 Octane/Horizon 进程持有启动时的路由表与已编译类，
在它们脚下覆盖文件不会立刻生效——直到第 30 步重建容器。所以“先落文件、再迁移、后重启”
之间**不存在**“新控制器要读还没建的表”的窗口。

### 每一步的线上影响一览

| 步 | 是否重启 | 中断范围 | 失败判据 |
|---|---|---|---|
| 00 | 否 | 无 | 任一主机不可达 / 8077 已被占用 |
| 10 | 否 | 无（请求期间可能读到新旧混合文件，窗口数秒） | 远程缺文件、`php -l` 失败、`artisan list` 看不到新命令 |
| 20 | 否 | 无；纯加表加列 | `migrate --force` 非 0；`migrate:status` 仍 pending；新表查不动 |
| 30 | 平滑重载 Octane | 无（在途请求完成后切换） | 8077 未监听；`docker compose config` 校验失败；面板 90 秒内不恢复 |
| 40 | nginx reload | 无掉线 | `nginx -t` 失败；经 nginx 的 upgrade 返回 404/502 |
| 50 | 否 | 无（已打开的浏览器保持旧 bundle，需硬刷新） | manifest 未指向 sub13；`*.custom3.js` ≠ 3；stock locale 仍存在 |
| 60 | 否 | 无 | 任一项检查失败（脚本退出码 1） |
| 70 | **是**（落地机） | 该机 3 个节点 3–10 秒 | 服务未 active；2083/65533/65535 未监听；`check` 不通过 |
| 80 | 否 | 无 | 面板看不到机器在线（ruling 13 规则） |

---

## 2 各步详解

每一步的脚本都打印：将要做什么、精确的远端命令、以及**本步的回滚指令**。
所有脚本支持 `--dry-run`（只打印不改动）；`--offline` 会连只读探测也跳过。

### 00 preflight（只读）

```bash
scripts/deploy-v9/00-preflight.sh
```

- **前置**：本机有 `bash`、`ssh`、`scp`、`tar`、`connect.exe`；SOCKS5 代理 `127.0.0.1:7890` 在跑。
- **备份**：无（不改动）。
- **执行**：`ssh` 探测两台主机；面板上看容器、compose 服务、8076/8077 监听、nginx 站点配置、
  `migrate:status`、`CACHE_DRIVER`；落地机上看版本、`/etc/W1nCray` 布局、监听端口、磁盘。
- **验证**：两台主机都打印 `REACHABLE`。
- **回滚**：不需要。
- **失败判据**：任一主机不可达；`$PANEL_ROOT/artisan` 不存在；找不到 nginx 站点配置
  （此时用 `PANEL_NGINX_CONF=... ` 覆盖后重跑）。

> 预检会告诉你生产 compose 里到底有哪些服务。**如果 `ws-server` 不是 compose 服务**
> （而是单容器里的 supervisord program），第 30 步的 override 仍然可用，但 `depends_on: redis`
> 需要改成实际服务名，或者删掉 `depends_on`。

### 10 panel-files（面板代码）

```bash
scripts/deploy-v9/make-panel-manifest.sh      # 只在需要重新生成清单时跑（本地）
scripts/deploy-v9/10-panel-files.sh
```

- **前置**：`panel-files.txt` 里的每个文件在本机 worktree 里存在（脚本自己校验）；
  远端 `$PANEL_ROOT` 是 Laravel 检出。
- **备份**：`/root/w1ncray-deploy-<时间戳>-panel-files/`，内含
  `backup/`（已存在文件的原文）、`overwritten.txt`、`added.txt`、`STEP.txt`。
- **执行**：`tar` 流经 `ssh` 覆盖到 `/www/wwwroot/xboard`；然后 `chown -R www:www`。
- **验证**：清单里每个文件在远端存在；对每个 `.php` 在容器内跑 `php -l`；
  `artisan list` 能看到 `w1ncray:ws-server`、`agent:manifest`、`w1ncray:prune-samples`。
- **回滚**：`scripts/deploy-v9/10-panel-files.sh --rollback-only --stage <stage>`
  （恢复 `overwritten.txt`、删除 `added.txt`），再按第 30 步的方式重建容器让旧代码生效。
- **失败判据**：清单缺失；拷贝后仍有文件不存在；`php -l` 任一失败（脚本自动回滚本步）。

`panel-files.txt` 由 `git diff` 加“W1nCray 作用域全量”生成（宁可多拷不可漏拷：多拷一个未变文件
无害，漏一个会让面板 `require` 失败），共 **211 个文件**。生成脚本带**交叉校验**：
`git diff 128ec1f..HEAD` 里除“故意删除”之外每一个改动文件都必须出现在清单里，否则报错退出。
作用域（目录整体展开）：`app/Http/Controllers/V2/Admin/W1nCray`、`app/Http/Controllers/V2/Agent`、
`app/Services/Agent`、`app/WebSocket`、`database/migrations`、`public/w1ncray`、
`resources/views/w1ncray`；单文件：5 个 `app/Console/Commands`（Agent/网关/清理/裁剪）、
`app/Console/Kernel.php`、`app/Http/Controllers/V2/Admin/Server/MachineController.php`、
`app/Http/Kernel.php`、`app/Http/Middleware/{AgentNodeScope,W1nCrayRequestLog}.php`、
`app/Http/Routes/V2/` 下 13 个路由文件、12 个 `app/Models/{Agent*,ServerMachine*}.php`、
`app/Services/{DeviceStateService,ServerService}.php`、`config/w1ncray.php`、
`storage/app/w1ncray/.gitignore`。

### 20 migrate（数据库）

```bash
DB_DUMP_CMD='<你自己的备份命令>' scripts/deploy-v9/20-migrate.sh
```

- **前置**：第 10 步已把 4 个迁移文件放进容器（脚本逐个 `test -f`）。
- **备份**：本脚本**不猜** MySQL 在哪（容器里还是宿主机）。设 `DB_DUMP_CMD` 就执行它；
  不设就只依赖迁移自身的 `down()`。回滚是数据级的，请自行决定要不要 dump。
- **执行**：`docker exec xboard-web-1 php artisan migrate --force`。
- **验证**：`migrate:status` 里 `2026_10_06/07` 无 pending；5 张新表可 `count()`；
  `v2_agent_machine_state.kernel_entries` 与 `v2_agent_host_sample.swap_total` 存在。
- **回滚**：`docker exec xboard-web-1 php artisan migrate:rollback --step=4 --force`
  （会 drop `v2_agent_host_sample`、`v2_agent_terminal_session`、`v2_agent_file*` 与新增列）。
- **失败判据**：`migrate --force` 非 0；仍 pending；表查不动。
- **迁移内容**（都是纯新增，都有 `down()`，都用 `hasTable/hasColumn` 守卫，可重复执行）：

  | 迁移 | 内容 |
  |---|---|
  | `2026_10_06_100000_agent_telemetry` | `v2_agent_machine_state` 加 8 个可空列（`host_info`/`telemetry`/`components`/`capabilities`/`policy`/`ws_connected_at`/`ws_last_seen_at`/`telemetry_at`）；新建 `v2_agent_host_sample` |
  | `2026_10_07_000001_agent_terminal_sessions` | 新建 `v2_agent_terminal_session`（外键 → `v2_server_machine` cascade） |
  | `2026_10_07_000002_agent_managed_files` | 新建 `v2_agent_file_blob` / `v2_agent_file` / `v2_agent_file_version` |
  | `2026_10_07_000003_agent_host_sample_extend` | `v2_agent_host_sample` 加 `swap_*`/`uptime_s`/`load5`/`load15`/`conns_udp`/`procs`；`v2_agent_machine_state` 加 `kernel_entries` |

### 30 gateway-service（新进程 + 重启面板容器）

```bash
scripts/deploy-v9/30-gateway-service.sh
```

- **前置**：8077 空闲；8076 上旧节点 WS 在跑；`CACHE_DRIVER=redis`（脚本会打印现状，不强制）。
- **备份**：不改动基础 compose 文件。新文件是 `<root>/compose.w1ncray-ws.yaml`（override），
  回滚=删掉它。
- **执行**：装 override → `docker compose -f <base> -f compose.w1ncray-ws.yaml up -d w1ncray-ws`
  → `kill -USR1 <swoole master>`（平滑）。
- **验证**：8077 监听；`docker compose ps`；容器内 `storage/logs/w1ncray-ws-server.{pid,log}` 存在；
  `artisan list` 有新命令；`http://127.0.0.1:7001` 有响应。
- **回滚**：`scripts/deploy-v9/30-gateway-service.sh --rollback-only`
  （`stop` + `rm -f` 新服务 + 删 override）。旧 `/ws` 与 8076 **全程未被提及**。
- **失败判据**：`docker compose config` 拒绝合并后的配置；8077 未监听；面板 90 秒内不恢复。

`compose.w1ncray-ws.yaml` 要点：端口只发布到 `127.0.0.1:8077`，容器内 `W1NCRAY_WS_HOST=127.0.0.1`；
`ENABLE_*` 全部关掉只留网关，`ENABLE_REDIS=false`（避免在网关容器里再起一个 redis）；
卷与基础文件里 `web`/`ws-server` 共用同一组；`CACHE_DRIVER=redis`（ticket 必需：网关进程不是 web 进程）。

### 40 nginx-w1ncray-ws（反代路径）

```bash
scripts/deploy-v9/40-nginx-w1ncray-ws.sh
```

- **前置**：站点配置存在；当前 `nginx -t` 通过（脚本会先测一次）。
- **备份**：`/root/<配置文件名>.bak-w1ncray-<时间戳>`。
- **执行**：把 `location = /w1ncray-ws {...}` 插到旧 `location = /ws {` 之前
  （找不到就插到 `location ^~ / {` 之前，两者都找不到就报错退出且不改文件）→ `nginx -t` → `reload`。
- **验证**：经 nginx 的 WebSocket upgrade 返回 `101`；旧 `/ws` 块原样还在。
- **回滚**：`scripts/deploy-v9/40-nginx-w1ncray-ws.sh --rollback-only --backup <bak 文件>`。
- **失败判据**：找不到锚点；`nginx -t` 失败（脚本自动还原备份且不 reload）。

关键参数：`proxy_read_timeout 300s` / `proxy_send_timeout 300s`（协议静默窗口 70 s，必须 ≥75 s；
300 s 也给终端会话留余量）、`access_log off`（浏览器 ticket 在 query string 里，
浏览器无法在 upgrade 上设请求头——设计 R9）。`=` 精确匹配保证 `/w1ncray-ws` 永远不会被旧 `/ws`
或 `location ^~ /` 吃掉。

### 50 spa-patch（sub13 管理端 SPA）

```bash
scripts/deploy-v9/50-spa-patch.sh
```

- **前置**：目标已有 `assets/index-DiYa-_z_.css` 与 `assets/codicon-ngg6Pgfi.ttf`（脚本检查并警告）。
- **备份**：`/root/w1ncray-deploy-<时间戳>-spa-sub13/`（含被删除的 stock locale 原文）。
- **执行**：覆盖 `public/assets/admin/` 下 7 个文件
  （`index.html`、`manifest.json`、`w1nc-autorefresh.js`、`assets/index-CxNodesub13.js`、
  `locales/{zh-CN,en-US,ru-RU}.custom3.js`），然后**删除**
  `locales/{zh-CN,en-US,ru-RU}.js`。
- **验证**：`manifest.json` 指向 `assets/index-CxNodesub13.js`；`*.custom3.js` 恰好 3 个；
  stock locale 恰好 0 个；被引用的 css/ttf 存在。
- **回滚**：`scripts/deploy-v9/50-spa-patch.sh --rollback-only --stage <stage>`
  （恢复覆盖项、删除新增项、把 stock locale 放回去）。
- **失败判据**：manifest 未指向 sub13；locale 数量不对；stock locale 仍在（会盖掉补丁包）。

**为什么必须删 stock locale**：真正的管理端入口是 `resources/views/admin.blade.php`，
它读 `public/assets/admin/manifest.json` 并 **glob `locales/*.js`**。
排序后 `en-US.custom3.js` < `en-US.js`，stock 包会**后加载并覆盖**补丁包。
注意 `admin.blade.php` 本身**不需要改**——sub13 的 bundle 自己会注入
`../w1nc-autorefresh.js`（`PANEL-PATCHES.md` 里“index.html 带 script 标签”的说法与实际不符）。

### 60 verify-panel（只读）

```bash
scripts/deploy-v9/60-verify-panel.sh
```

检查：容器状态 → 8077/8076 监听 → 经 nginx 的 101 → 网关对匿名 upgrade 回 `role_unknown`
（curl 看不到 4400 关闭码，要 `wscat`）→ Redis `w1ncray:ws:agent:*` → SPA manifest 与
`/assets/admin/*`、`/w1ncray/*` 的 HTTP 200 → 无 pending 迁移。
任一项失败退出码 1，并打印各步的回滚命令。**此步只读，不需要回滚。**

### 70 agent-upgrade（落地机）

```bash
ENABLE_TERMINAL=no \
W1NCRAY_BINARY=dist/W1nCray-linux-amd64 \
PANEL_URL=https://subscribe.w1nc.xyz \
MACHINE_ID=3 \
TOKEN_FILE=/etc/W1nCray/agent.token \
scripts/deploy-v9/70-agent-upgrade.sh
```

- **前置**：本地二进制是 ELF（脚本检查 magic `7f454c46`，Windows/脚本文件一律拒绝）；
  落地机磁盘足够；`agent.token` 已存在（缺失会警告并要求确认）。
- **备份**：`/usr/local/W1nCray/W1nCray.bak-<时间戳>` 与 `/etc/W1nCray.bak-<时间戳>`。
- **执行**：上传到 `W1nCray.next` → **先**用新二进制跑 `version` 和
  `check -c /etc/W1nCray/config.yml`（必须出现“检查通过”）→ `systemctl stop` → 原子替换 →
  `systemctl start` → 检查 2083/65533/65535 → `link --dry-run` → `link` → `systemctl restart`。
- **验证**：`version`；服务 active；`check` 通过；三个端口在听；日志无 `level=error`/`panic`；
  `agent.yml` 存在；`ENABLE_TERMINAL=no` 时必须有 `Terminal: {Enabled: false}`。
- **回滚**：`scripts/deploy-v9/70-agent-upgrade.sh --rollback-only --rollback-ts <时间戳>`。
  服务起不来时脚本**自动**回滚二进制与 `/etc/W1nCray`。
- **失败判据**：新二进制不认当前配置（此时**什么都没改**）；服务未 active；
  端口未监听；`link` 非 0。

`link` 细节：它**不重启服务**，只打印“下一步 `W1nCray restart`”；它会自己备份
`config.yml.bak-link-<时间戳>` 与 `agent.yml.bak-<时间戳>`；`agent.yml` 已存在且已关联面板时
**拒绝覆盖**（需 `--force`，脚本此时选择不动它并提示手工加 `Terminal: {Enabled: false}`）。
`ENABLE_TERMINAL=no` → 加 `--noterminal` → 在 `agent.yml` 根写一行 `Terminal: {Enabled: false}`。

### 80 verify-agent（只读）

```bash
MACHINE_ID=3 scripts/deploy-v9/80-verify-agent.sh
# 需要等它重连时：WAIT_S=120 MACHINE_ID=3 scripts/deploy-v9/80-verify-agent.sh
```

在线判定用 RULINGS v9 第 13 条：`now - max(last_poll_at, ws_last_seen_at)`
落在对应窗口内（HTTP 360 s / WS 70 s）。脚本打印 `agent_version`、`capabilities`、
`policy_terminal`、遥测年龄、Redis presence marker、网关 pid/log、旧 8076 仍在。
失败退出码 1 并给出排查路径。

---

## 3 全量回滚顺序

按**与部署相反的顺序**回滚。每一步都能单独跑，`run-all.sh` 不参与回滚。

```bash
# 1. 落地机回到升级前（二进制 + /etc/W1nCray），节点中断数秒
scripts/deploy-v9/70-agent-upgrade.sh --rollback-only --rollback-ts <TS>

# 2. 管理端 SPA 回到 sub12/sub11（index.html + manifest.json 是指针）
scripts/deploy-v9/50-spa-patch.sh --rollback-only --stage /root/w1ncray-deploy-<TS>-spa-sub13

# 3. nginx 去掉 /w1ncray-ws 并 reload（不掉线）
scripts/deploy-v9/40-nginx-w1ncray-ws.sh --rollback-only --backup /root/<conf>.bak-w1ncray-<TS>

# 4. 停掉网关、删 override
scripts/deploy-v9/30-gateway-service.sh --rollback-only

# 5. 数据库回滚 4 个迁移（会 drop 两张新表与新列）
docker exec xboard-web-1 php artisan migrate:rollback --step=4 --force

# 6. 面板代码回到第 10 步之前，然后重建容器
scripts/deploy-v9/10-panel-files.sh --rollback-only --stage /root/w1ncray-deploy-<TS>-panel-files
docker exec xboard-web-1 kill -USR1 <swoole master>
```

顺序理由：先让 agent 回到旧二进制（旧二进制不认 `agent.yml` 时仍能读 `config.yml` 的
`Agent:` 块），再撤前端与反代，最后撤面板代码与表——这样任何中间状态都还有一条能用的通道。
第 5、6 步顺序可互换，但**第 6 步之后必须重建容器**，否则 Octane 仍跑着新代码。

---

## 4 风险清单

| 风险 | 说明 | 缓解 |
|---|---|---|
| **终端能力默认开启** | 本版本 `Terminal.Enabled` 缺省为 **true**（RULINGS v9 第 17 条，`agent/agentcfg/agentcfg.go` 里 `TerminalEnabled()` 对 nil 返回 true）。已部署机器升级后**自动获得终端能力**。 | 脚本默认 `ENABLE_TERMINAL=no` → `--noterminal`。已有 `agent.yml` 的机器脚本**不会**覆盖，会提示手工加 `Terminal: {Enabled: false}`。面板侧签发 ticket 仍需管理员重输密码。 |
| **Redis 单点** | 网关的 presence marker、Octane→网关推送通道、ticket 全在 Redis。`CACHE_DRIVER` 不是 `redis` 时 ticket 会被断言拒绝（ruling 14）。 | 预检打印 `CACHE_DRIVER` 现状；网关容器显式设 `CACHE_DRIVER=redis`；Redis 挂掉时网关不崩，但 ticket 签发失败、机器在线状态失真。 |
| **旧 `/ws` 必须不动** | 生产老节点仍在用 `127.0.0.1:8076` 与 `location = /ws`。 | 第 30/40 步的代码里没有 `ws-server`/`/ws` 的写操作；第 60/80 步显式检查 8076 仍在监听、旧 location 块仍在。 |
| **每次 PHP 部署后必须重启网关** | 网关是独立 Workerman 进程，`count=1`（契约，不是默认值——连接对象与两个注册表都在进程内，Redis 只放推送通道与在线标记）。它持有启动时的代码。 | 第 30 步重建 `web horizon` 后，若之后再改面板 PHP，必须 `docker compose -f <base> -f compose.w1ncray-ws.yaml up -d --force-recreate w1ncray-ws`。**不要**把 `numprocs`/`count` 调大。 |
| **浏览器缓存与 importmap 版本参数** | sub13 的 bundle 名是内容指纹（`index-CxNodesub13.js`），但 `admin.blade.php` 走 `manifest.json`，浏览器可能仍持旧 bundle。 | 第 50 步后硬刷新（Ctrl-F5）；回滚只需把 `index.html`+`manifest.json` 指回 `sub12`/`sub11`。 |
| **manifest 签名密钥与托管清单** | 面板**不签名不验签**，只存分发；私钥不在本仓库，位置未知。`sequence` 必须正整数且不可倒退。 | 第 0 节第 4 问先定清单来源与序号；不托管时 agent 只用内嵌 xray，`kernel_*`/`self_update` 不可用（fail-closed）。 |
| **旧 UniProxy API 仍保留** | 新版删掉了 `Tidalab` 控制器、`V2/Server/{Machine,Server}Controller`、`Http/Middleware/{Server,ServerV2}.php`、`Routes/V1/ServerRoute.php`、`Routes/V2/ServerRoute.php`。**默认部署不删**（`panel-files.txt` 只含存在文件）。 | 这些文件留着不会被自动加载（路由注册已改），但属于死代码。要删见 §7，且删之前必须确认没有别的代码引用它们。 |
| **面板容器重建 = 面板中断** | 第 30 步 3–8 秒。 | 选窗口；`docker compose up -d` 而不是 `down`；脚本轮询 7001 直到恢复。 |
| **`panel-files.txt` 漏文件** | 漏一个文件就是面板 `require` 致命错误。 | 清单是“作用域全量”而非仅 diff；第 10 步逐个 `test -f` + `php -l` + `artisan list`；失败自动回滚。 |
| **`public/assets/admin` 是 submodule** | 目标缺 `assets/index-DiYa-_z_.css`/`codicon-ngg6Pgfi.ttf` 时布局会坏。 | 第 50 步检查并警告。 |
| **`link` 覆盖 agent.yml** | `link` 在 `agent.yml` 已存在时拒绝（需 `--force`）。 | 脚本遇到已关联的 `agent.yml` 就不动它，只提示手工关闭终端。 |
| **`__respawn` 与 systemd `KillMode`** | `self_update` 的回滚助手能否在 systemd 默认 `KillMode=control-group` 下存活，`docs/AGENT.md` §7.1 明确要求在目标机实测。 | 本次部署**不使用** `self_update`；升级走人工替换 + systemd。首次启用 `self_update` 前必须先实测。 |
| **生产 compose 内容未知** | 仓库里只有 sample（`compose.split.sample.yaml` 最接近），真实文件被 gitignore。 | 第 30 步用 override 而不是改基础文件；预检打印真实服务列表；`depends_on` 若与实际不符按提示调整。 |

---

## 5 脚本清单与环境变量

| 文件 | 作用 |
|---|---|
| `lib.sh` | `rsh`/`probe`/`rput`/`tar_manifest`/`backup_files`/`restore_files`；主机、路径、密钥、代理集中定义 |
| `00-preflight.sh` | 只读侦察 |
| `make-panel-manifest.sh` | 生成/复核 `panel-files.txt`（本地，不连服务器） |
| `panel-files.txt` | 第 10 步要拷贝的精确文件清单（提交进仓库，便于 review） |
| `10-panel-files.sh` | 面板代码覆盖 + 校验 + 回滚 |
| `20-migrate.sh` | 4 个迁移 + 校验 |
| `30-gateway-service.sh` | compose override + 新服务 + 重建 web/horizon |
| `compose.w1ncray-ws.yaml` | override 模板（`@IMAGE@`/`@PORT@` 占位） |
| `40-nginx-w1ncray-ws.sh` | nginx location + `-t` + reload |
| `50-spa-patch.sh` | sub13 覆盖 + 删 stock locale |
| `60-verify-panel.sh` | 面板侧验收（只读） |
| `70-agent-upgrade.sh` | 落地机二进制 + `agent.yml` 分离 |
| `80-verify-agent.sh` | agent 侧验收（只读） |
| `run-all.sh` | 顺序驱动，每步之间要求输入 `yes` |

集中变量（都在 `lib.sh` 顶部，可用环境变量覆盖）：

```
PANEL_HOST=root@167.253.156.95      LANDING_HOST=root@82.152.167.105
SSH_KEY=  SSH_PORT=22  SSH_OPTS=...
PROXY_CMD='connect.exe -S 127.0.0.1:7890 %h %p'
PANEL_ROOT=/www/wwwroot/xboard      PANEL_CODE=/www
PANEL_WEB_CONTAINER=xboard-web-1    PANEL_COMPOSE_FILE=compose.yaml
PANEL_WS_OVERRIDE=compose.w1ncray-ws.yaml
PANEL_NGINX_CONF=/www/server/panel/vhost/nginx/subscribe.w1nc.xyz.conf
PANEL_NGINX_LOG=/www/wwwlogs/subscribe.w1nc.xyz.log
PANEL_GATEWAY_PORT=8077             PANEL_LEGACY_PORT=8076
PANEL_HTTP_PORT=7001                PANEL_NGINX_SCHEME=http  PANEL_NGINX_PORT=80
PANEL_SPA_DIR=public/assets/admin   PANEL_W1NCRAY_DIR=public/w1ncray
PANEL_BACKUP_BASE=/root
LANDING_BIN=/usr/local/W1nCray/W1nCray  LANDING_CONF_DIR=/etc/W1nCray
LANDING_SERVICE=W1nCray.service         LANDING_TOKEN_FILE=/etc/W1nCray/agent.token
PANEL_SRC=C:/W1nCBoard
NGINX_TEST_CMD='/www/server/nginx/sbin/nginx -t'
NGINX_RELOAD_CMD='/etc/init.d/nginx reload'
PANEL_SITE_HOST=subscribe.w1nc.xyz   CURL_INSECURE=   # 站点只监听 443 时设 -k
```

第 40/60 步对 nginx 的探测默认打 `http://127.0.0.1:80`；站点只监听 443 时用
`PANEL_NGINX_SCHEME=https PANEL_NGINX_PORT=443 CURL_INSECURE=-k`。

**脚本里没有任何令牌、密码或邮箱明文**。令牌只以**文件路径**出现（`TOKEN_FILE`、
`PANEL_ADMIN_TOKEN_FILE`），且从不回显。`lib.sh` 的 `guard_path()` 在任何 `rm -rf`/`cp -a`
之前拒绝空路径、`/`、`/root`、`/etc`、`/www`、`/usr` 这类系统路径与非绝对路径。

### 二进制怎么来

```bash
# 在 W1nCray 检出里（本 worktree 或 feat/agent）：
bash release/build.sh v0.5.0 amd64        # -> dist/W1nCray-linux-amd64 (+ .gz + SHA256SUMS)
ENABLE_TERMINAL=no W1NCRAY_BINARY=$PWD/dist/W1nCray-linux-amd64 ... 70-agent-upgrade.sh
```

`release/build.sh` 会把版本号用 `-ldflags -X .../cmd.version=` 注入；不传就是 `dev`。
落地机是 `linux/amd64`（v0.4.1 时代就是 `W1nCray-linux-amd64`）。
**下载发行包时先校验 `SHA256SUMS`**；`install.sh` 默认 fail-closed，本手册走人工替换，
但第 70 步会用新二进制自己跑一次 `check`，等价于一次离线预检。

---

## 6 验证清单（部署完成后逐条打勾）

- [ ] `scripts/deploy-v9/60-verify-panel.sh` 退出码 0
- [ ] `scripts/deploy-v9/80-verify-agent.sh` 退出码 0（机器在线）
- [ ] 浏览器硬刷新管理端，`#/server/page` 打开 W1nCray 页面（不是跳转）
- [ ] 概览页显示实时遥测曲线（说明 WS 通道在带负载）
- [ ] 终端标签页对**已关闭终端**的机器显示“该机器已在本地关闭终端”
- [ ] 旧 `/ws`：`curl -i -N -H 'Connection: Upgrade' ... http://127.0.0.1:8076/ws` 行为与部署前一致
- [ ] `ss -tlnp | grep 8076` 仍在（旧节点没掉线）
- [ ] `docker exec xboard-web-1 php artisan w1ncray:ws-server status` 正常
- [ ] 记录每一步打印的备份目录（`/root/w1ncray-deploy-*`、`/root/*.bak-w1ncray-*`、
      `/usr/local/W1nCray/W1nCray.bak-*`、`/etc/W1nCray.bak-*`）

---

## 7 附：旧 UniProxy 文件与 `agent:manifest`

**旧 UniProxy 文件（默认不做）**。新树删除了这些文件，但本手册默认不删（纯新增部署）：

```
app/Http/Controllers/V1/Server/ShadowsocksTidalabController.php
app/Http/Controllers/V1/Server/TrojanTidalabController.php
app/Http/Controllers/V2/Server/MachineController.php
app/Http/Controllers/V2/Server/ServerController.php
app/Http/Middleware/Server.php
app/Http/Middleware/ServerV2.php
app/Http/Routes/V1/ServerRoute.php
app/Http/Routes/V2/ServerRoute.php
```

要删就单独做一次，**先确认没有别的代码引用它们**（`grep` 类名），删完必须重建容器：

```bash
cd /www/wwwroot/xboard
mkdir -p /root/w1ncray-deploy-legacy-removed
for f in <上面的列表>; do [ -e "$f" ] && { mkdir -p "/root/w1ncray-deploy-legacy-removed/$(dirname "$f")"; cp -a "$f" "/root/w1ncray-deploy-legacy-removed/$f"; rm -f "$f"; }; done
docker exec xboard-web-1 kill -USR1 <swoole master>
```

回滚：把 `/root/w1ncray-deploy-legacy-removed/` 里的文件拷回去，再重建容器。

**签名清单**：

```bash
docker cp /root/manifest.json xboard-web-1:/tmp/manifest.json
docker exec xboard-web-1 php artisan agent:manifest show
docker exec xboard-web-1 php artisan agent:manifest put /tmp/manifest.json
docker exec xboard-web-1 rm -f /tmp/manifest.json
```

`put` 会校验：正整数 `sequence`（相等=幂等重传，倒退=拒绝）、
`signature{alg:"ed25519", key_id, sig}`、≤1 MiB。存到
`storage/app/w1ncray/manifest.json`（目录 0750 / 文件 0640）。
agent 侧通过 `GET /api/v2/server/machine/agent/manifest` 拉取并**在本地验签**
（内置 ed25519 公钥 `kernel/manifest/trusted_keys.txt`，可用 `ExtraKeys` ldflags 追加）。
回滚：`php artisan agent:manifest delete`（agent 回落到内嵌 xray）。
