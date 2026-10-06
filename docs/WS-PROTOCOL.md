# W1nCray agent ⇄ W1nCBoard WebSocket protocol (v1)

Status: contract for PLAN v9. Go (`agent/ws`, `agent/telemetry`, …) and PHP (`app/WebSocket/Agent*`) implement it
in parallel; neither side may invent fields. Change this file first, then both sides.

## 1 Transport and authentication
- **One persistent WebSocket per machine**, opened by the agent (outbound only): `wss://<panel>/w1ncray-ws`
  (a path of its own, served by a separate Workerman process; the legacy `/ws` is untouched).
- **Agent auth = request headers** on the upgrade: `X-Machine-Id: <id>` and `Authorization: Bearer <machine token>`.
  The token is **never** in the URL. Failure → close with code 4401 (bad credentials) / 4403 (machine disabled).
- **Browser auth = single-use ticket** in the query: `wss://<panel>/w1ncray-ws?ticket=<ticket>` (browsers cannot set
  headers). A ticket is issued by `POST …/w1ncray/ws/ticket {machine_id}` (admin only), lives 30 s, is consumed once.
- The role of a connection is decided by the upgrade: `X-Machine-Id` present → `agent`; `ticket` present → `browser`;
  neither → close 4400.
- The HTTP polling API (`/api/v2/server/machine/agent/*`) stays valid: it is the fallback and still carries desired
  state, acks and blobs. The WebSocket accelerates and adds streams; it never replaces the audited HTTP path.
- Frames: **JSON text only**, ≤ 256 KiB each. Binary data (terminal bytes) is base64 inside `d`.
- Keepalive: either side sends `{"t":"ping"}` every 25 s; the peer answers `{"t":"pong"}`. 70 s of silence closes
  the connection. The agent reconnects with exponential backoff 1 s → 60 s (jitter ±20 %), forever.

## 2 Envelope
```json
{"t":"<type>","id":"<correlation id, optional>","d":{ … }}
```
Unknown `t` → the receiver replies `{"t":"error","id":<same>,"d":{"code":"unknown_type","message":"…"}}` and keeps going.

## 3 agent → panel
| `t` | `d` | notes |
|---|---|---|
| `hello` | `{agent_version, instance_id, seq, platform:{os,arch,libc}, host_info:HostInfo, capabilities:[…], policy:{terminal:bool, files:{roots:[…],unrestricted:bool}, modules:{xray_nodes:bool}}, kernels:[KernelEntry]}` | first message after upgrade; `capabilities` ⊆ `["terminal","files","kernel","upgrade","xray_nodes","telemetry"]` |
| `telemetry` | `Telemetry` (below) | every `telemetry_s` (default 5) |
| `components` | `{ts, items:[Component]}` | every `components_s` (default 15) and on any state change |
| `cmd.result` | `{status:"done"|"failed", result:any, error?:string}` with the command's `id` | answer to `cmd` |
| `term.opened` | `{session}` | |
| `term.data` | `{session, data:"<base64>"}` | PTY output |
| `term.exit` | `{session, code, reason?}` | shell exited / closed / limit hit |
| `term.error` | `{session, code, message}` | e.g. `terminal_disabled` |
| `event` | `{kind, level, message, data?}` | e.g. `kernel.installed`, `apply.rejected`, `self_update.started` |
| `ping`/`pong` | `{}` | |

### HostInfo (static-ish, sent in `hello`, refreshed on change)
`{hostname, os, os_version, kernel_version, arch, cpu_model, cpu_cores, cpu_threads, mem_total, swap_total,
disks:[{mount,fstype,total}], virtualization, boot_time, ips:{private:[…],public:[…]}, timezone}` — any field may be
absent when unknown; never invent a value.

### Telemetry (dynamic)
`{ts, cpu_pct, load:{l1,l5,l15}, mem:{total,used}, swap:{total,used}, disks:[{mount,total,used}],
net:{in_bps,out_bps,in_total,out_total}, conns:{tcp,udp}, procs, uptime_s}` — `ts` is unix seconds;
bandwidth is bytes/second summed over non-loopback interfaces; totals are cumulative bytes since boot.

### Component
`{name:"agent"|"xray"|"gost"|"realm"|"frp", kind:"agent"|"kernel", version, state:"running"|"stopped"|"failed"|"starting"|"not_installed",
pid?, uptime_s?, restarts?, cpu_pct?, rss?, instances:[{id, state, conns?, up_bytes?, down_bytes?}]}`.

### KernelEntry
`{name, version, current:bool, previous:bool, path, size_bytes, installed_at, in_use:bool}`.

## 4 panel → agent
| `t` | `d` | notes |
|---|---|---|
| `hello.ok` | `{server_time, intervals:{telemetry_s, components_s}, session:"<id>"}` | answer to `hello` |
| `hint` | `{what:"desired"|"files"|"nodes"|"manifest"}` | agent pulls the named resource over HTTP now (no payload) |
| `cmd` | `{type, args, ttl_s}` with `id` | agent answers `cmd.result` with the same `id`; unanswered after `ttl_s` = expired |
| `term.open` | `{session, cols, rows}` | requires local policy `terminal=true`, else `term.error terminal_disabled` |
| `term.input` | `{session, data:"<base64>"}` | ≤ 64 KiB |
| `term.resize` | `{session, cols, rows}` | |
| `term.close` | `{session}` | |
| `ping`/`pong`/`error` | | |

### Command types (`cmd.d.type`)
| type | args | result |
|---|---|---|
| `refresh` | `{}` | pulls desired now |
| `dump_state` | `{}` | redacted state dump |
| `kernel_list` | `{}` | `{kernels:[KernelEntry], catalog:[{name,versions:[…]}]}` |
| `kernel_install` | `{name, version?}` | installs from the signed manifest (empty version = newest) |
| `kernel_remove` | `{name, version}` | refuses the version in use; result lists freed bytes |
| `kernel_rollback` | `{name}` | |
| `component_restart` | `{name}` | restarts a kernel process (not the agent) |
| `self_update` | `{version}` | version listed for `agent` in the signed manifest; verified; swap + restart; auto-rollback |
| `file_list` | `{root, path}` | `{entries:[{name,type,size,mode,mtime}]}` |
| `file_read` | `{root, path, offset?, limit?}` | `{data:"<base64>", size, eof}` (limit ≤ 1 MiB) |
| `file_write` | `{root, path, data:"<base64>", mode?, sha256?}` | atomic write; refuses outside roots |
| `file_delete` | `{root, path}` | |
| `files_apply` | `{}` | same as `hint files` but reports the apply outcome (validate → swap → reload → confirm/rollback) |

All file commands are confined to the roots in the agent's local policy (`policy.files.roots`), unless
`policy.files.unrestricted` is set locally. Path traversal, symlink escapes and non-regular files are refused.

## 5 browser ⇄ panel
Browser messages (after a valid ticket):
| `t` | `d` |
|---|---|
| `sub` | `{machine_id}` — subscribe to live `telemetry` / `components` / `event` of one machine |
| `term.open` | `{machine_id, cols, rows}` → panel creates the session id, forwards to the agent |
| `term.input` / `term.resize` / `term.close` | as above, with the `session` the panel returned in `term.opened` |
The panel forwards `telemetry`, `components`, `event`, `term.*` from the agent to subscribed / paired browsers.
A browser may hold at most one terminal session per machine; the panel enforces ≤ 3 per admin.

## 6 Panel persistence (what must survive)
- Latest `host_info`, `telemetry`, `components`, `kernels`, `capabilities`, `policy` per machine (JSON columns).
- A downsampled `telemetry` history (one row / 30 s / machine, 7 days, pruned by a scheduled job).
- Audit rows (never the terminal bytes): session start/stop (who, machine, ip, duration, byte counts), every file
  write/delete (path, sha256, size), every kernel install/remove, every `self_update`.


## 7 Rulings v1.1 (from the implementation-design review; these override anything above that disagrees)
1. **Capability gating.** The agent's `hello.capabilities` is the feature list. The HTTP `config` request carries the same
   list as `features`. The panel puts a new `desired` key (`files`, later others) into a revision **only for an agent that
   declared the matching capability**: the agent decodes desired strictly, so an unknown key would reject the whole revision.
   Phase 1 adds no desired key.
2. **`telemetry.conns` may be `null`** (not readable on this platform); `components` of the embedded engine (`xray`) carry
   no `pid/cpu_pct/rss` (it shares the agent process).
3. **No replay.** `telemetry`/`components` are live data: nothing is queued while disconnected, nothing is resent on reconnect.
4. **`cpu_cores`** = physical cores, **`cpu_threads`** = logical CPUs.
5. **`hint` for something the agent does not support** is answered with `error{code:"not_supported"}`, never silently ignored.
6. **`policy.modules.xray_nodes` is a LOCAL gate** (agent.yml, default on). The panel asks for nodes with `hint{what:"nodes"}`;
   the agent then pulls the machine's node list: empty = stop all node controllers, otherwise start those (per node, no full reload).
7. **Long commands** answer immediately with `cmd.result{status:"accepted"}` (within `ttl_s`), then a final `done|failed`.
   The panel keeps the command `pending` until the final result; the WS push never marks it `sent` (HTTP fallback may deliver
   the same command again: the agent de-duplicates by command id).
8. **Size limits:** `file_read.limit` and `file_write` payload are each **≤ 128 KiB raw** (fits the 256 KiB frame after base64).
   Anything larger goes through the managed-files blob download over HTTPS.
9. **New commands:** `files_validate {}` (stage + `core.CheckFiles`/`LoadConfig`, no write, no reload) and
   `files_rollback {}` (restore the last good managed files and reload). `files_apply` answers `accepted`, then
   `done{applied_pending:true}` once the reload was initiated; the **panel** judges health (a `hello`/`telemetry` within 60 s and
   `components.xray.state=running`) and sends `files_rollback` otherwise.
10. **Events:** `self_update.started|rolled_back|stalled`, `kernel.installed|removed`, `files.applied|rolled_back`.
11. **Self-update lives in the signed manifest as a `kernels` entry named `agent`** (reserved name: `kernel_install/remove/rollback`
    refuse it, the panel's kernel list hides it; only `self_update` uses it). It reuses all manifest validation and revocation.
    "New process cannot start" is handled by a watchdog on the host: a detached helper run from a **copy of the previous binary**
    (never the unproven new one) watches the single-instance lock and rolls the update back when the service manager is only
    restarting a binary that cannot run. On systemd that helper is started through `systemd-run` in its own transient unit,
    outside the service cgroup, because `KillMode=control-group` would otherwise kill it with the service it is watching.
    "Started but cannot reach the panel" is only reported (`self_update.stalled`), never auto-rolled back.
12. **High-risk operations** (issuing a terminal ticket, `self_update`, writes outside managed files) require the admin to
    re-enter their password (`confirm_password`, checked server side, rate limited).
13. **Local gates the panel can never relax:** `Terminal.Enabled` (**default true** by the owner's decision; a machine opts out locally with `Terminal.Enabled: false`, installer/`link` flag `--noterminal`), `Files.Roots`, `Files.Unrestricted`,
    `Files.AllowExec` (refuse writes with an exec bit), `Modules.XrayNodes`. `agent.yml` and the agent state files
    (`desired.json`, `last_good.json`) are never inside any root.
