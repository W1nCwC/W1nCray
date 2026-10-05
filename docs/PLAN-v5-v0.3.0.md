# 方案 v5：W1nCray v0.3.0

> 日期：2026-10-05 · 用户确认的范围：①管理菜单 + 快捷命令（类似 XrayR）②Alpine / OpenWRT 一键安装与运行 ③单实例保护 ④XrayR 旧入站 tag 兼容。
> ①② 依赖平台调研（子智能体进行中），完成后补充第 3 节；③④ 与平台无关，先实施。

## 1. 单实例保护

### 证据
| # | 事实 | 来源 | 档位 |
|---|---|---|---|
| L1 | Xboard 对同一 node_id 只保留一条 WebSocket，新连接会关闭旧连接 | 面板 `NodeRegistry::add`（L21-23） | 已验证 |
| L2 | 2026-10-05 02:40:26–02:40:44 node213/214 每 1–5 秒断开重连，节点日志 `close 1006`，计时格式 `WARN[0006]` 为终端前台运行 | 面板 laravel 日志、用户提供的节点日志 | 已验证（现象）/ 高度可能（成因：前台进程与服务并存） |

### 设计
- 运行模式（根命令）启动时对 `<配置文件>.lock` 加**排他非阻塞锁**（Linux `flock(2)`，进程退出由内核自动释放，不会残留死锁）；锁文件写入 PID。
- 已被占用：立即退出，提示「已有 W1nCray 实例在使用该配置运行（PID n）：请先停止服务或查看日志」。
- 仅运行模式加锁；`check`/`migrate`/`x25519` 等不受影响。不同配置文件的实例互不影响。
- Windows 仅用于开发测试：无锁实现（build tag 区分）。

## 2. XrayR 旧入站 tag 兼容

### 证据
| # | 事实 | 来源 | 档位 |
|---|---|---|---|
| T1 | XrayR 入站 tag = `fmt.Sprintf("%s_%s_%d", NodeType, ListenIP, Port)`，NodeType 为配置原文（如 `V2ray`，即使 EnableVless） | XrayR v0.9.4 `service/controller/controller.go` buildNodeTag；newV2board `parseV2rayNodeResponse` NodeType=c.NodeType | 已验证 |
| T2 | W1nCray 入站 tag = `node<ID>@<面板主机>`；迁移时 NodeType 已换算为 Xboard 类型，原文丢失 | `node/controller.go`、`migrate` | 已验证 |
| T3 | 用户 route.json 用 `inboundTag: ["V2ray_0.0.0.0_65534"]` 分流到 `ca-socks`，迁移后失效，流量落入后续规则（`direct4`） | 用户提供 | 已验证 |

### 设计
- 识别：`inboundTag` 中形如 `<名称>_<合法IP>_<端口>` 的元素视为 XrayR 旧 tag（中间段必须能被解析为 IP，降低误判）；若已存在同名入站（自定义入站）则不改。
- 映射：按**端口**找到监听该端口的 W1nCray 节点（同机端口唯一；面板改端口后自动跟随），替换为节点 tag。
- 位置：`core.RuleManager` 组合规则时改写全局 route.json 规则（节点规则不受影响）；每个映射首次生效时记录一条 info 日志。
- `W1nCray check --online`：列出 route.json 中的旧 tag 及其对应的新 tag，建议改成新写法。

## 3. 管理菜单 / Alpine / OpenWRT

调研报告：`scratchpad/research-alpine-openwrt.md`（子智能体产出；证据为 OpenRC/procd/busybox/uclient/Go 官方源码与文档、Alpine minirootfs 实测、本机交叉编译）。**以下结论均无 Alpine / OpenWRT 真机验证**；其中我自己复现并确认的：去掉 lego DNS provider 后 amd64 79,188,128 → 35,901,600 字节（-43.3 MB, -54.7%，go list 依赖包 778 个）。

### 3.1 证据摘要（决定设计的）
| # | 事实 | 档位 |
|---|---|---|
| P1 | OpenWRT 默认 busybox 无 `install`/`od`/`stat`/`curl`/`bash`；24.10 及以前无 `timeout`；`wget`=uclient-fetch（默认 ca-bundle+HTTPS、校验证书、跟随≤10 次重定向、无重试选项、失败退出码非 0） | 已验证（Config-defaults.in、uclient 源码） |
| P2 | Alpine minirootfs 有可校验证书的 HTTPS wget（外部 ssl_client）和 ca-certificates，无 bash/curl；docker 镜像无 openrc | 已验证 |
| P3 | Debian dash 0.5.11/0.5.12 不支持 `set -o pipefail`（当前 install.sh 用了） | 已验证 |
| P4 | OpenRC：自动重启要 `supervisor=supervise-daemon` 且不能自写 start/stop/status；`respawn_max=0` 无限；`output_log`/`error_log` 写文件；`rc_ulimit`；`status` 在子进程反复崩溃时仍报 started | 已验证 / 高度可能 |
| P5 | procd：`respawn 3600 10 0` 无限；`stdout/stderr 1` 进 syslog（`logread -e`）；`limits nofile`；23.05 及更早 `status` 在实例存在时即报 running，**必须用 `running` 子命令** | 已验证 |
| P6 | MIPS `uname -m` 不分大小端，需读 ELF 头 EI_DATA；OpenWRT 主流 MIPS 内核关 FP，**只能 softfloat**；ARM 选错 GOARM 时 Go 运行时自检退出，`version` 自检可拦住 | 已验证 |
| P7 | 12 个 linux 目标均可静态交叉编译（amd64/386/arm64/arm5/6/7/mips/mipsle/mips64/mips64le/riscv64/loong64）；stripped 66–86 MB；精简版 32–39 MB；gzip 后 mipsle 精简 11.8 MB / 完整 21.5 MB | 已验证 |
| P8 | XrayR 在 Alpine 的两个社区脚本：服务名都是 `XrayR`、配置 `/etc/XrayR/config.yml`；其一加入自定义 runlevel `xrayr`（不是 default）；OpenWRT 上未找到任何证据 | 已验证 / 未知 |
| P9 | OpenWRT /tmp 是 tmpfs（占内存）；`df -Pk` 可用；sysupgrade 只保留 /etc/config 等，需把 /etc/W1nCray 加入 /etc/sysupgrade.conf；geo 文件仅在规则用到 geosite:/geoip: 时才读取 | 已验证 / 高度可能 |

### 3.2 设计

**A. 服务后端抽象**（install.sh 内一组 `svc_*` 函数）：`systemd`（检测 `/run/systemd/system`）、`openrc`（`rc-service` + `/sbin/openrc-run`）、`procd`（`/sbin/procd` 或 `/etc/openwrt_release`）。接口：`svc_install/remove/start/stop/restart/enable/disable/is_active/is_enabled/log`，XrayR 同样走这套接口（`svc_*_xrayr`）。检测不到任何后端：安装二进制与配置，提示手动前台运行（`W1nCray run`）。
- systemd：沿用现有 unit；日志 `journalctl -u W1nCray`。
- OpenRC：报告 1a 的脚本（supervise-daemon、`respawn_delay=10`、`respawn_max=0`、`rc_ulimit`、`output_log=/var/log/W1nCray.log` 超 10MB 时 start_pre 截断）；日志 `tail -f`；XrayR 自启检测扫描 `/etc/runlevels/*/XrayR` 并在 rollback 时恢复原 runlevel；`is_active` 判定为 `rc-service status` 成功且 `pidof` 两次取值（间隔 2s）PID 相同。
- procd：报告 1b 的脚本（`respawn 3600 10 0`、`stdout/stderr 1`、`limits nofile`，`GOMEMLIMIT` 按 MemTotal×40% 写入）；`is_active` 用 `/etc/init.d/W1nCray running`；日志 `logread -e W1nCray`；不设置 `procd_set_param file`（W1nCray 自己监听配置变更）；探测 `/etc/init.d/XrayR`（未知，探测不到按无 XrayR 处理）。

**B. install.sh 改为 POSIX sh**：`#!/bin/sh`，`set -eu`，不使用 pipefail（管道失败显式判断）、`[[`、`<()`、`echo -e`、`install`、`od`、`stat`、`timeout`；`mktemp`/`cp -a`/`readlink -f`/`sha256sum`/`hexdump`/`dd`/`df -Pk` 为各平台默认存在。一行安装命令：`(curl -fsSL -o /tmp/W1nCray-install.sh URL || wget -q -O /tmp/W1nCray-install.sh URL) && sh /tmp/W1nCray-install.sh install`（先落地再执行，stdin 不被脚本占用）。
- 架构检测按报告 §3 映射表；MIPS 读 `/bin/busybox`（不存在则 `/bin/sh`）ELF 头；ARM 按 `/proc/cpuinfo` Features 选 v7/v6/v5 并用 `version` 自检兜底、失败降级；不支持的架构明确报错。
- 下载：先查目标分区 `df -Pk` 空闲空间，临时文件放目标目录而非 /tmp；下载 `.gz`（busybox 有 gunzip）；校验 SHA256SUMS；OpenWRT 默认装精简版（`dnslite`），其他系统默认完整版，`--lite` / `--full` 可指定；精简版遇到不在 6 个之内的 DNS provider 时 `check` 报错并提示改装完整版。
- OpenWRT：默认不下载 geo 文件（`--with-geo` 开启；`check` 发现规则用到而文件缺失时提示）；把 `/etc/W1nCray` 与 init 脚本追加进 `/etc/sysupgrade.conf`；`--prefix` 指定外部存储安装目录；空间不足拒绝安装并说明。
- 兼容旧版升级路径：已安装用户的旧 `/usr/local/W1nCray/install.sh` 会下载原名 `W1nCray-linux-amd64|arm64`（未压缩）并用 SHA256SUMS 校验，故**发布时继续附带这两个未压缩文件和对应校验和**，新增的 .gz 与其他架构另列。

**C. 管理菜单与快捷命令**：`/usr/local/bin/W1nCray`（OpenWRT 为 `/usr/bin/W1nCray`）改为指向管理脚本（install.sh 的 `basename` 为 W1nCray 时进入管理模式）；真正的程序在 `/usr/local/W1nCray/W1nCray`（unit/init 脚本使用完整路径）。无参数 → 中文菜单（顶部显示版本、运行状态、开机自启、服务管理器）；`start|stop|restart|status|log|check|config|enable|disable|update [版本]|migrate|switch|rollback|uninstall|version|x25519|run`；未识别的参数原样 `exec` 给程序本体（`migrate --from …`、`check -c …`、`init` 等现有用法不变）。`run` 前台运行，已有实例运行时被单实例锁拒绝。`status` 显示节点与 WebSocket 状态（取自最近日志）。

**D. Go 代码**：`common/cert` 按构建标签拆出 DNS provider 查找：默认（完整，行为不变）、`dnslite`（alidns/cloudflare/dnspod/godaddy/namesilo/tencentcloud）、`nodnsproviders`；新增 `cert.DNSProviderSupported(name)`，`check`/`migrate` 在启动前报错；内置根证书 `x509roots/fallback` 只在 `dnslite` 构建中引入（+0.15 MB，系统有 CA 时优先用系统的）。

**E. release/build.sh**：矩阵 amd64、386(softfloat)、arm64、armv5/6/7、mips/mipsle(softfloat)、mips64/mips64le(softfloat)、riscv64、loong64；每个架构出完整版与 `-lite`；资产为 `.gz`（另附 amd64/arm64 完整版未压缩，见 B）；统一 SHA256SUMS。

### 3.3 被否决的方案
1. 继续用 bash：Alpine/OpenWRT 默认没有，装 bash 会占用路由器空间 → 否。
2. 按符号表估算体积后只去掉“大 provider”：实测 provider 注册表占 >50%，估算严重偏低 → 改用构建标签整体拆分。
3. MIPS 同时发 hardfloat：OpenWRT 内核关 FP，hardfloat 会 SIGILL 且 `version` 自检拦不住 → 只发 softfloat。
4. 自定义 Xray 功能导入列表以进一步瘦身：需跟随 Xray 版本维护、未实测 → 本版不做。
5. 用 GitHub Actions 构建发布：当前 gh 令牌无 `workflow` 权限，需要用户在浏览器授权 → 暂缓，仍本地构建上传。

### 3.4 限制与风险
- 无 Alpine/OpenWRT 真机验证。拟在隔离环境验证：Alpine minirootfs 与 OpenWRT x86_64 rootfs 用 `chroot` + `unshare -pf` 在 Linux 机器上运行真实的 OpenRC / procd（需要一台可用于测试的 Linux 机器，生产机器上做需用户授权）；本机用 busybox ash / dash / shfmt(posix) 做语法与函数级测试。
- 16/32 MB flash 的路由器即使精简版也装不下，需外部存储（extroot）或大容量 NAND。
- `uclient-fetch` 在旧版（21.02）上能否跟随 GitHub 跨主机跳转未在真机验证。
- MIPS 上的运行内存与性能未实测（本机 Windows amd64 空闲约 29–39 MB）。
- 老 XrayR 用户的 DNS provider 不在精简版 6 个之内时需要改装完整版（`check` 提示）。

## 4. 验收
| # | 标准 |
|---|---|
| V1 | 同一配置启动第二个实例：立即退出并给出提示；第一个实例不受影响；第一个退出后可正常启动 |
| V2 | route.json 中 `V2ray_0.0.0.0_<port>` 规则在节点监听该端口时生效（真实流量走指定出站），端口变化后跟随；自定义入站同名 tag 不被改写 |
| V3 | `check --online` 输出旧 tag → 新 tag 对照 |
| V4 | 全量回归通过 |
| V5 | install.sh：`dash -n`、`busybox ash -n`、`shfmt -ln posix` 通过；架构检测/服务后端选择/XrayR 探测在模拟环境中对各映射表项给出预期结果 |
| V6 | 三种服务后端（systemd / OpenRC / procd）的脚本在真实 init 下安装、启动、崩溃自动重启、停止、开机自启启用/禁用、日志查看均正常（隔离环境；无法验证的写明） |
| V7 | `W1nCray`（无参数）出现菜单；status/log/check/uninstall 等快捷命令可用；未识别参数透传给程序本体 |
| V8 | 12 个目标的完整版与 lite 版均可构建；lite 版遇到不支持的 DNS provider 时 check 在启动前报错，http/tls/file 证书不受影响 |
| V9 | 已安装旧版用户可通过旧 install.sh 升级到新版（未压缩 amd64/arm64 资产与校验和保持可用） |

## 5. 实施记录（2026-10-05）

| # | 结果 | 证据 |
|---|---|---|
| V4 | 【已验证】Windows 上 `go build ./...`、`go test ./core ./common/... ./migrate ./panel` 通过（`cmd` 的锁测试带 unix 构建标签，需在 Linux 上跑） | 本次命令输出 |
| V5 | 【已验证】`tests/install_test.sh` 在 dash、busybox-w32 ash、bash 下各 178/178 通过；`dash -n`/`bash -n` 通过。覆盖：架构映射与 ARM/MIPS 回退、校验和（篡改/缺项）、三种服务脚本生成、安装/升级/XrayR 共存/OpenWRT lite/--prefix、switch/rollback/自动回滚、管理命令分发与透传、菜单、卸载与 `--purge` 路径保护 | 测试输出 |
| V7 | 【已验证】（模拟后端）菜单、status/log/check/start/stop/enable/disable、未识别参数透传 | 同上 |
| V8 | 【部分验证】已构建 amd64 / armv5 / mipsle 的 full 与 lite（gzip -t 通过，mipsle softfloat 交叉编译成功）；其余 9 个目标与完整 12×2 矩阵未在本次构建，lite 的 DNS 行为见 `common/cert/dns_*_test.go`（各构建标签） | build.sh 输出 |
| V9 | 【待确认】build.sh 保留 amd64/arm64 裸文件并写入 SHA256SUMS，但未用旧版 install.sh 实测升级 | — |
| V1/V2/V3 | 此前已验证（锁测试、legacy tag 端到端、check 对照输出），见前文 | — |
| V6 | 【待确认】OpenRC/procd 的真实 init 下行为未验证（脚本内容已按调研结果生成并通过 `sh -n`），需要 Alpine / OpenWRT 真机或 chroot 环境 | — |

`install.sh` 的 `latest_tag` 在 atom 回退路径上加了 `head -n1`（测试夹具暴露了同一行多个条目时会输出多个 tag 的隐患）。
