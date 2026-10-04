# 方案 v3：首次真机安装（用户 VPS）发现的问题

> 日期：2026-10-04 · 来源：用户在自己的 VPS 上执行 `install.sh install` 的完整输出（XrayR → W1nCray 迁移，3 个节点）。

## 1. 问题与证据

| # | 现象 | 根因与证据 | 档位 |
|---|---|---|---|
| F1 | 超时错误中打印出完整请求 URL，含 `token=<通讯密钥>` | `net/http` 的 `*url.Error` 自带完整 URL；`api/xboard/client.go` 将其原样包装返回，控制台与 journal 均会记录 | 已验证 |
| F2 | node119：`shadowsocks plugin "none" is not supported` | Xboard 后台插件选项为 `{value:"none",label:"None"}`（xboard-admin-dist 打包 JS），"无插件"存为字符串 `"none"`；Xboard 订阅仅在 `plugin && plugin_opts` 均非空时下发插件（`app/Protocols/Clash.php:134`） | 已验证 |
| F3 | node138：拉取用户 `Client.Timeout exceeded while awaiting headers` | 面板端为何慢【待确认】（单次输出无法区分面板负载与网络抖动）；XrayR 使用 resty `SetRetryCount(3)`（`api/newV2board/v2board.go` New），W1nCray 无重试 | 已验证（无重试）/ 待确认（面板侧原因） |
| F4 | node173（vmess 无 TLS）提示"未找到证书，启动时将重新申请"；check 输出大量 `[Debug]` | 迁移时未区分节点是否用 TLS（迁移阶段无法得知面板 tls 设置）；`panel.Check` 使用配置中的日志级别 | 已验证 |

## 2. 改动

| 文件 | 改动 | 风险 |
|---|---|---|
| `api/xboard/client.go` | 错误中的 token 替换为 `***`；GET 请求在网络错误/5xx 时最多 3 次尝试（退避 1s、2s），POST 不重试 | 无（POST 不重试，避免重复上报流量） |
| `node/build.go` | plugin 为空/`none`，或 plugin_opts 为空 → 视为无插件；真实插件（obfs、v2ray-plugin 等）仍明确报不支持 | 与 Xboard 订阅行为一致 |
| `migrate/migrate.go` | 证书提示注明"仅当该节点启用 TLS 时需要" | 文案 |
| `panel/check.go` | check 时内核日志级别最高为 warning | 仅影响 check |
| 测试 | 新增 token 打码、GET 重试/POST 不重试、plugin none 用例 | — |

回滚：git 历史（`df00617` 为修改前版本）。

## 3. 验收

| # | 标准 |
|---|---|
| C1 | 任何客户端错误字符串中不出现 token（单测） |
| C2 | GET 首次 5xx/网络错误后重试成功；POST 失败只请求一次（单测） |
| C3 | Xboard 样例 `plugin:"none"`、`plugin:"obfs"`+空 opts 可构建；`plugin:"obfs"`+opts 明确报错（单测） |
| C4 | 全量回归通过 |
| C5 | 用户 VPS 上重新 check（需用户升级后执行） |
