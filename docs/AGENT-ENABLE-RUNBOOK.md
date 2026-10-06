# 启用 agent 的操作手册（落地机 + 面板）

> 前提：面板侧已部署 agent API（W1nCBoard `agent:instance` 命令与 6 张 `v2_agent_*` 表），
> 落地机已升级到带 agent 的 W1nCray。**默认全部不启用**，按下面步骤逐步打开，每步都可回退。

## 0 现状检查
```bash
# 面板机
docker exec xboard-web-1 php artisan agent:instance status <machineId>
# 落地机
/usr/local/W1nCray/W1nCray version
systemctl is-active W1nCray
```

## 1 面板：创建 machine（拿到 id 和 token）
machine 是面板已有概念（`v2_server_machine`）。创建后记下 `id` 与 `token`；token 只给落地机，不写进聊天/命令行历史。

## 2 落地机：写 token 文件（权限 0600）+ 配置
```bash
umask 077; printf '%s' '<machine token>' > /etc/W1nCray/agent.token
```
`/etc/W1nCray/config.yml` 追加（先备份 `cp -a /etc/W1nCray /etc/W1nCray.bak-$(date +%F-%H%M%S)`）：
```yaml
Agent:
  Enabled: true
  StateDir: /etc/W1nCray/state
  Policy:
    AllowListen: ["0.0.0.0"]
    PortRange: [20000, 30000]     # agent 只允许监听这个范围，面板无法放宽
    AllowEngines: ["xray"]        # 试点只用内置 xray；gost/frp/realm 需要已签名清单
  Panel:
    Enabled: true
    URL: https://<面板域名>
    MachineID: <machineId>
    TokenFile: /etc/W1nCray/agent.token
```
```bash
/usr/local/W1nCray/W1nCray check -c /etc/W1nCray/config.yml   # 必须“检查通过”
systemctl restart W1nCray
```
`Policy` 是本地信任根：端口范围、允许的内核、目标网段都以它为准，面板下发的配置不能突破。

## 3 面板：建一个试点实例并发布
`pilot.json`（例：把本机 20080 转发到 `203.0.113.10:80`，用内置 xray）：
```json
{"id":"pilot-1","enabled":true,"engine":"xray","kind":"forward",
 "listen":{"addr":"0.0.0.0","ports":"20080"},"network":["tcp"],
 "targets":[{"host":"203.0.113.10","ports":"80"}]}
```
```bash
docker exec xboard-web-1 php artisan agent:instance put <machineId> --file=/www/pilot.json
docker exec xboard-web-1 php artisan agent:instance validate <machineId>
docker exec xboard-web-1 php artisan agent:instance apply <machineId> --comment="pilot"
docker exec xboard-web-1 php artisan agent:instance status <machineId>   # 看 applied revision / apply_status
```
agent 每 30 秒拉取一次，应用后回报。实际验证：`nc -vz <落地机IP> 20080`。

## 4 回退（任一步出问题）
| 层级 | 做法 |
|---|---|
| 单个实例 | `agent:instance delete <machineId> pilot-1` → `apply`；或 `rollback <machineId> <revision>` |
| 关闭 agent | 落地机 config 里 `Agent.Enabled: false`（或删整个 `Agent:` 块）→ `systemctl restart W1nCray` |
| 回退二进制 | `cp /usr/local/W1nCray/W1nCray.bak-<时间戳> /usr/local/W1nCray/W1nCray && systemctl restart W1nCray` |
| 面板侧 | 删除备份目录 `added-files.txt` 里列出的文件；`DROP` 6 张 `v2_agent_*` 表并删除对应 migrations 记录；Octane 发 `USR1` |

## 5 要用 gost / frp / realm 时（试点之后）
需要你的 ed25519 签名密钥：公钥写入 `kernel/manifest/trusted_keys.txt`（或编译时注入），用 `tools/manifestgen`
签出清单并托管内核镜像，落地机再配置 `ManifestPath`。未配置时 agent 只会使用内置 xray，并明确报错，不会静默降级。
