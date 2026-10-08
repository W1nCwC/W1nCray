#!/bin/sh
# W1nCray installer and manager.
#
# POSIX sh: runs under dash (Debian/Ubuntu), busybox ash (Alpine, OpenWRT) and
# bash. Service backends: systemd, OpenRC (Alpine), procd (OpenWRT).
#
#   sh install.sh install [--lite|--full] [--prefix DIR] [--with-geo]
#                         [--binary FILE | --url URL | --version vX.Y.Z]
#                         [--insecure-skip-verify]
#                         [--panel URL --machine ID (--token TOKEN | --token-file FILE)
#                          [--allow-http] [--port-range LO-HI]]
#
# --panel writes a "machine mode" config: the agent links out to the panel and
# receives its nodes and forwarding rules. The machine token is stored in
# $CONF_DIR/agent.token (0600) and never written to config.yml or the logs.
#
# Release downloads are checked against SHA256SUMS and refused when the check
# is impossible or fails; --insecure-skip-verify (or
# W1NCRAY_INSECURE_SKIP_VERIFY=1) is the only way to skip it.
#
# After installation the same script is the `W1nCray` command: run it without
# arguments for a menu, or use the shortcuts (see `W1nCray help`). XrayR files
# are never modified; XrayR keeps running until `W1nCray switch`.
#
# v11 split the program in two: this script installs the *agent* (W1nCray) only.
# The Xray kernel (W1nCray-xray) is a separate program and service that the
# panel installs when a node is bound to the machine, or that an operator
# installs locally with `W1nCray xray install`. `update` migrates a pre-v11
# single program that serves Xray nodes: it downloads the agent and the kernel,
# stops the old service, replaces the agent, installs the kernel service and
# starts the agent again.

set -eu

REPO="${W1NCRAY_REPO:-W1nCwC/W1nCray}"
ROOT="${W1NCRAY_ROOT:-}"
CONF_DIR="$ROOT/etc/W1nCray"
CONF="$CONF_DIR/config.yml"
# The agent's own configuration (D1). It wins as a whole over any Agent: block
# left in config.yml, so the installer writes it here and never into config.yml.
AGENT_CONF="$CONF_DIR/agent.yml"
ENVFILE="$CONF_DIR/install.env"
XRAYR_DIR="${XRAYR_DIR:-$ROOT/etc/XrayR}"
XRAYR_UNIT="XrayR"
# The Xray kernel's fixed service name (agent/xraysvc.ServiceName).
XRAY_UNIT="W1nCray-xray"
GEO_BASE="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
DEFAULT_PREFIX="$ROOT/usr/local/W1nCray"
# Seconds to watch a service after start / switch (tests shorten them).
WAIT_START="${W1NCRAY_WAIT:-2}"
WAIT_SWITCH="${W1NCRAY_WAIT:-5}"
# Size needed to download, unpack and replace (KiB): gzip + binary + old binary.
NEED_KB_LITE=90000
NEED_KB_FULL=170000
# Release downloads are verified against SHA256SUMS and refused otherwise.
# Only an explicit opt-out (--insecure-skip-verify, or this variable set to 1)
# skips the check. It never applies to --binary files, which are not checked.
INSECURE_SKIP_VERIFY=0
if [ "${W1NCRAY_INSECURE_SKIP_VERIFY:-}" = 1 ]; then
	INSECURE_SKIP_VERIFY=1
fi

# ---- output ----------------------------------------------------------------

if [ -t 1 ]; then
	ESC="$(printf '\033')"
	C_RED="${ESC}[31m"
	C_GREEN="${ESC}[32m"
	C_YELLOW="${ESC}[33m"
	C_OFF="${ESC}[0m"
else
	C_RED=""
	C_GREEN=""
	C_YELLOW=""
	C_OFF=""
fi
red() { printf '%s%s%s\n' "$C_RED" "$*" "$C_OFF"; }
green() { printf '%s%s%s\n' "$C_GREEN" "$*" "$C_OFF"; }
yellow() { printf '%s%s%s\n' "$C_YELLOW" "$*" "$C_OFF"; }
die() {
	red "错误: $*" >&2
	exit 1
}

need_root() {
	[ -n "$ROOT" ] && return 0
	[ "$(id -u)" -eq 0 ] || die "请使用 root 运行"
}

# ask "question" -> 0 for yes. Non-interactive runs must pass -y.
ask() {
	if [ "${ASSUME_YES:-0}" -eq 1 ]; then
		return 0
	fi
	[ -t 0 ] || die "非交互环境请加 -y 确认"
	printf '%s [y/N] ' "$1"
	read -r _ans || _ans=""
	case "$_ans" in y | Y | yes | YES) return 0 ;; esac
	return 1
}

# ---- environment -----------------------------------------------------------

is_openwrt() { [ -f "$ROOT/etc/openwrt_release" ]; }

# load_env reads what `install` recorded (install prefix, build flavor).
load_env() {
	BIN_DIR="$DEFAULT_PREFIX"
	FLAVOR=""
	if [ -f "$ENVFILE" ]; then
		# shellcheck disable=SC1090
		. "$ENVFILE"
	fi
	BIN="$BIN_DIR/W1nCray"
	if is_openwrt; then
		MGR="$ROOT/usr/bin/W1nCray"
	else
		MGR="$ROOT/usr/local/bin/W1nCray"
	fi
	BACKEND="$(detect_backend)"
}

save_env() {
	mkdir -p "$CONF_DIR"
	{
		printf 'BIN_DIR=%s\n' "$BIN_DIR"
		printf 'FLAVOR=%s\n' "$FLAVOR"
	} >"$ENVFILE"
}

detect_backend() {
	if [ -n "${W1NCRAY_BACKEND:-}" ]; then
		echo "$W1NCRAY_BACKEND"
	elif [ -d "$ROOT/run/systemd/system" ]; then
		echo systemd
	elif is_openwrt || [ -x "$ROOT/sbin/procd" ]; then
		echo procd
	elif command -v rc-service >/dev/null 2>&1 && [ -x "$ROOT/sbin/openrc-run" ]; then
		echo openrc
	else
		echo none
	fi
}

# elf_endian FILE prints l (little) or b (big) from the ELF header (EI_DATA,
# offset 5). `uname -m` does not tell MIPS endianness; OpenWRT has no `od`.
elf_endian() {
	[ -r "$1" ] || return 1
	_e="$(dd if="$1" bs=1 skip=5 count=1 2>/dev/null | tr '\001\002' 'lb')"
	case "$_e" in l | b)
		echo "$_e"
		return 0
		;;
	esac
	_e="$(hexdump -s 5 -n 1 -e '1/1 "%d"' "$1" 2>/dev/null || true)"
	case "$_e" in
	1)
		echo l
		return 0
		;;
	2)
		echo b
		return 0
		;;
	esac
	return 1
}

elf_probe_file() {
	if [ -n "${W1NCRAY_ELF_PROBE:-}" ]; then
		echo "$W1NCRAY_ELF_PROBE"
		return 0
	fi
	for _f in "$ROOT/bin/busybox" "$ROOT/bin/sh" "$ROOT/bin/ls"; do
		if [ -r "$_f" ]; then
			readlink -f "$_f" 2>/dev/null || echo "$_f"
			return 0
		fi
	done
	return 1
}

mips_arch() { # $1 = base name (mips|mips64)
	_f="$(elf_probe_file)" || die "无法判断 CPU 字节序（找不到可读的 /bin/busybox 或 /bin/sh）"
	_e="$(elf_endian "$_f")" || die "无法从 $_f 的 ELF 头判断字节序"
	if [ "$_e" = l ]; then
		case "$1" in
		mips) echo mipsle ;;
		*) echo mips64le ;;
		esac
	else
		echo "$1"
	fi
}

arm_variant() {
	_feat="$(grep -m1 -i '^Features' "${W1NCRAY_CPUINFO:-/proc/cpuinfo}" 2>/dev/null || true)"
	case " $_feat " in
	*" vfpv3 "* | *" vfpv3d16 "* | *" vfpv4 "*) echo armv7 ;;
	*" vfp "*) echo armv6 ;;
	*) echo armv5 ;;
	esac
}

# detect_arch prints the release architecture name (docs/PLAN-v5-v0.3.0.md).
detect_arch() {
	_m="${W1NCRAY_UNAME_M:-$(uname -m)}"
	case "$_m" in
	x86_64 | amd64) echo amd64 ;;
	i386 | i486 | i586 | i686) echo 386 ;;
	aarch64 | arm64) echo arm64 ;;
	armv7* | armv8l) arm_variant ;;
	armv6*)
		_v="$(arm_variant)"
		if [ "$_v" = armv5 ]; then echo armv5; else echo armv6; fi
		;;
	armv5*) echo armv5 ;;
	mips) mips_arch mips ;;
	mips64) mips_arch mips64 ;;
	riscv64) echo riscv64 ;;
	loongarch64) echo loong64 ;;
	*) die "不支持的 CPU 架构: $_m" ;;
	esac
}

# arch_fallbacks lists the architectures to try, best first: a CPU that lacks
# the FPU a GOARM level needs is detected by the binary's own `version` check.
arch_fallbacks() {
	case "$1" in
	armv7) echo "armv7 armv6 armv5" ;;
	armv6) echo "armv6 armv5" ;;
	*) echo "$1" ;;
	esac
}

default_flavor() {
	if is_openwrt; then echo lite; else echo full; fi
}

asset_name() { # arch flavor -> name of the .gz asset
	if [ "$2" = lite ]; then
		echo "W1nCray-linux-$1-lite.gz"
	else
		echo "W1nCray-linux-$1.gz"
	fi
}

# The Xray kernel is a separate program with its own asset names. On OpenWrt the
# lite build (-tags dnslite,fallbackroots) is the one to install, exactly like
# the agent's OpenWrt flavor.
xray_asset_name() { # arch flavor -> name of the Xray kernel .gz asset
	if [ "$2" = lite ]; then
		echo "W1nCray-xray-linux-$1-lite.gz"
	else
		echo "W1nCray-xray-linux-$1.gz"
	fi
}

xray_flavor() { # the Xray kernel flavor for this machine
	if is_openwrt; then echo lite; else echo full; fi
}

# ---- downloads -------------------------------------------------------------

download() { # url dest
	if command -v curl >/dev/null 2>&1; then
		curl -fL --retry 3 --connect-timeout 15 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -T 30 -O "$2" "$1"
	else
		die "需要 curl 或 wget"
	fi
}

fetch_text() { # url -> body on stdout
	_t="$(mktemp)"
	if download "$1" "$_t" >/dev/null 2>&1; then
		cat "$_t"
		rm -f "$_t"
		return 0
	fi
	rm -f "$_t"
	return 1
}

# latest_tag prints the newest release tag, pre-releases included
# (releases/latest skips them). The atom feed needs no API user agent.
latest_tag() {
	_tag=""
	_body="$(fetch_text "https://api.github.com/repos/$REPO/releases?per_page=1" 2>/dev/null)" || _body=""
	_tag="$(printf '%s\n' "$_body" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')" || _tag=""
	if [ -z "$_tag" ]; then
		_body="$(fetch_text "https://github.com/$REPO/releases.atom" 2>/dev/null)" || _body=""
		_tag="$(printf '%s\n' "$_body" | grep -m1 -o 'releases/tag/[^"<]*' | sed 's#releases/tag/##' | head -n1)" || _tag=""
	fi
	[ -n "$_tag" ] || return 1
	echo "$_tag"
}

sha256_of() { sha256sum "$1" | awk '{print $1}'; }
have_sha256sum() { command -v sha256sum >/dev/null 2>&1; }

# verify_sha256 FILE ASSET TAG checks FILE against the release SHA256SUMS. It
# fails closed: a missing sha256sum, a missing or unreadable SHA256SUMS, a
# missing or malformed digest and a mismatch all abort the installation. The
# only way past it is the explicit opt-out (--insecure-skip-verify or
# W1NCRAY_INSECURE_SKIP_VERIFY=1), which skips the check altogether.
verify_sha256() {
	if [ "$INSECURE_SKIP_VERIFY" = 1 ]; then
		red "警告: 已跳过 SHA256 校验（--insecure-skip-verify）：$2 未经验证，可能被篡改或损坏！" >&2
		return 0
	fi
	have_sha256sum ||
		die "未找到 sha256sum，无法校验下载文件的完整性。请安装 sha256sum（coreutils 或 busybox），或改用 --binary 提供本地文件；明知风险仍要继续请加 --insecure-skip-verify"
	_sums="$(mktemp)"
	if ! download "https://github.com/$REPO/releases/download/$3/SHA256SUMS" "$_sums" >/dev/null 2>&1 || [ ! -s "$_sums" ]; then
		rm -f "$_sums"
		die "无法获取 $3 的 SHA256SUMS，拒绝安装未经校验的程序。请检查网络或版本号；明知风险仍要继续请加 --insecure-skip-verify"
	fi
	_want="$(awk -v n="$2" '{f=$2; sub(/^\*/, "", f); if (f == n) {print $1; exit}}' "$_sums")"
	rm -f "$_sums"
	[ -n "$_want" ] || die "SHA256SUMS 中没有 $2 的校验值"
	case "$_want" in
	*[!0-9A-Fa-f]*) die "SHA256SUMS 中 $2 的校验值不是十六进制: $_want" ;;
	esac
	[ "${#_want}" -eq 64 ] || die "SHA256SUMS 中 $2 的校验值长度不是 64: $_want"
	_want="$(printf '%s' "$_want" | tr 'A-F' 'a-f')"
	_got="$(sha256_of "$1")"
	[ "$_want" = "$_got" ] || die "SHA256 校验失败（期望 $_want，实际 $_got）"
	green "SHA256 校验通过: $2"
}

free_kb() { # directory -> free KiB of its filesystem
	_d="$1"
	while [ ! -d "$_d" ] && [ "$_d" != "/" ] && [ -n "$_d" ]; do
		_d="$(dirname "$_d")"
	done
	df -Pk "$_d" 2>/dev/null | awk 'NR==2 {print $4}'
}

check_space() { # dir flavor
	if [ -n "${W1NCRAY_SKIP_SPACE_CHECK:-}" ]; then
		return 0
	fi
	_need="$NEED_KB_FULL"
	[ "$2" = lite ] && _need="$NEED_KB_LITE"
	_free="$(free_kb "$1")"
	case "$_free" in '' | *[!0-9]*) return 0 ;; esac
	if [ "$_free" -lt "$_need" ]; then
		red "$1 所在分区空间不足：可用 $((_free / 1024)) MB，需要约 $((_need / 1024)) MB（下载 + 解压 + 替换）。"
		if is_openwrt; then
			red "路由器内置闪存通常装不下：请挂载外部存储（extroot 或 USB/SD），再用 --prefix /mnt/xxx/W1nCray 安装，并优先使用精简版（--lite）。"
		else
			red "请释放空间，或用 --prefix 指定空间更大的目录。"
		fi
		exit 1
	fi
}

# ---- binary ----------------------------------------------------------------

# fetch_binary SOURCE FLAVOR leaves the verified binary at $NEWBIN.
# SOURCE: latest | version:TAG | file:PATH | url:URL
fetch_binary() {
	_src="$1"
	_fl="$2"
	RELEASE_TAG=""
	CHOSEN_ARCH=""
	mkdir -p "$BIN_DIR"
	check_space "$BIN_DIR" "$_fl"
	TMPD="$BIN_DIR/.dl.$$"
	mkdir -p "$TMPD"
	trap 'rm -rf "$TMPD"' EXIT INT TERM
	NEWBIN="$TMPD/W1nCray"
	case "$_src" in
	file:*)
		_f="${_src#file:}"
		[ -f "$_f" ] || die "找不到文件: $_f"
		case "$_f" in
		*.gz) gunzip -c "$_f" >"$NEWBIN" ;;
		*) cp "$_f" "$NEWBIN" ;;
		esac
		;;
	url:*)
		download "${_src#url:}" "$TMPD/dl" || die "下载失败: ${_src#url:}"
		case "${_src#url:}" in
		*.gz) gunzip -c "$TMPD/dl" >"$NEWBIN" ;;
		*) mv "$TMPD/dl" "$NEWBIN" ;;
		esac
		;;
	*)
		if [ "$_src" = latest ]; then
			_tag="$(latest_tag)" || die "无法获取 $REPO 的发布版本（可用 --binary 指定本地文件）"
		else
			_tag="${_src#version:}"
		fi
		# Recorded for the v11 migration: it must download the matching Xray
		# kernel asset from the very same release.
		RELEASE_TAG="$_tag"
		_arch="$(detect_arch)"
		_ok=0
		for _a in $(arch_fallbacks "$_arch"); do
			_asset="$(asset_name "$_a" "$_fl")"
			yellow "下载 W1nCray $_tag ($_a, $_fl) ..."
			download "https://github.com/$REPO/releases/download/$_tag/$_asset" "$TMPD/dl.gz" || die "下载失败: $REPO $_tag $_asset"
			verify_sha256 "$TMPD/dl.gz" "$_asset" "$_tag"
			gunzip -c "$TMPD/dl.gz" >"$NEWBIN" || die "解压失败: $_asset"
			rm -f "$TMPD/dl.gz"
			chmod 755 "$NEWBIN"
			if "$NEWBIN" version >/dev/null 2>&1; then
				_ok=1
				CHOSEN_ARCH="$_a"
				break
			fi
			yellow "$_a 版本无法在此 CPU 上运行，尝试更低要求的版本"
		done
		[ "$_ok" -eq 1 ] || die "下载的程序无法运行（架构不符或文件损坏）"
		;;
	esac
	chmod 755 "$NEWBIN"
	"$NEWBIN" version >/dev/null 2>&1 || die "程序无法运行（架构不符或文件损坏）"
}

# fetch_xray_kernel TAG ARCH leaves the verified Xray kernel asset at $XRAYGZ
# and its sha256 at $XRAYSHA. It is the same release and the same SHA256SUMS
# check as fetch_binary; the flavor is lite on OpenWrt. Unlike the agent, the
# kernel cannot be executed here (that is what `W1nCray xray install` does), so
# the architecture is the one the agent's own version check already proved.
fetch_xray_kernel() {
	_tag="$1"
	_arch="$2"
	_fl="$(xray_flavor)"
	_asset="$(xray_asset_name "$_arch" "$_fl")"
	yellow "下载 W1nCray-xray $_tag ($_arch, $_fl) ..."
	download "https://github.com/$REPO/releases/download/$_tag/$_asset" "$TMPD/xray.gz" || die "下载失败: $REPO $_tag $_asset"
	verify_sha256 "$TMPD/xray.gz" "$_asset" "$_tag"
	XRAYGZ="$TMPD/xray.gz"
	XRAYASSET="$_asset"
	XRAYSHA="$(sha256_of "$XRAYGZ")"
}

# ---- service backends ------------------------------------------------------
# Every backend defines be_<name>_<op>; `svc OP ARGS` dispatches. Units are
# named by the argument (W1nCray, XrayR).

svc() {
	_op="$1"
	shift
	"be_${BACKEND}_${_op}" "$@"
}

# systemd ---------------------------------------------------------------------

be_systemd_install() {
	sed -e "s#@BIN@#$BIN#g" -e "s#@CONF@#$CONF#g" -e "s#@CONF_DIR@#$CONF_DIR#g" >"$ROOT/etc/systemd/system/W1nCray.service" <<'EOF'
[Unit]
Description=W1nCray Xboard node backend
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=@CONF_DIR@
ExecStart=@BIN@ -c @CONF@
Restart=always
RestartSec=5
LimitNOFILE=1048576
Environment=XRAY_LOCATION_ASSET=@CONF_DIR@

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
}
be_systemd_remove() {
	rm -f "$ROOT/etc/systemd/system/$1.service"
	systemctl daemon-reload
}
be_systemd_exists() { systemctl list-unit-files "$1.service" --no-legend 2>/dev/null | grep -q "^$1.service"; }
be_systemd_active() { systemctl is-active --quiet "$1" 2>/dev/null; }
be_systemd_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }
be_systemd_start() { systemctl start "$1"; }
be_systemd_stop() { systemctl stop "$1"; }
be_systemd_restart() { systemctl restart "$1"; }
be_systemd_enable() { systemctl enable "$1" >/dev/null 2>&1; }
be_systemd_disable() { systemctl disable "$1" >/dev/null 2>&1; }
be_systemd_log() { journalctl -u "$1" -n "$2" --no-pager; }
be_systemd_follow() { journalctl -u "$1" -n 20 -f; }
be_systemd_levels() { :; }

# OpenRC (Alpine) -------------------------------------------------------------

be_openrc_install() {
	mkdir -p "$ROOT/etc/init.d"
	sed -e "s#@BIN@#$BIN#g" -e "s#@CONF@#$CONF#g" -e "s#@CONF_DIR@#$CONF_DIR#g" >"$ROOT/etc/init.d/W1nCray" <<'EOF'
#!/sbin/openrc-run
# W1nCray Xboard node backend (OpenRC)

name="W1nCray"
description="W1nCray Xboard node backend"

supervisor="supervise-daemon"
command="@BIN@"
command_args="-c @CONF@"
directory="@CONF_DIR@"

# Restart after a crash, forever, 10 s apart.
respawn_delay=10
respawn_max=0

rc_ulimit="-n 1048576"

output_log="/var/log/W1nCray.log"
error_log="/var/log/W1nCray.log"

supervise_daemon_args="--env XRAY_LOCATION_ASSET=@CONF_DIR@"

depend() {
	need localmount
	after net firewall
	use dns
}

start_pre() {
	# Keep the log from growing without bound.
	if [ -f "$output_log" ] && [ "$(wc -c <"$output_log")" -gt 10485760 ]; then
		: >"$output_log"
	fi
	return 0
}
EOF
	chmod 755 "$ROOT/etc/init.d/W1nCray"
}
be_openrc_remove() { rm -f "$ROOT/etc/init.d/$1"; }
be_openrc_exists() { [ -x "$ROOT/etc/init.d/$1" ]; }
be_openrc_active() { rc-service "$1" status >/dev/null 2>&1; }
# Runlevels a service is enabled in (XrayR community scripts used a custom one).
be_openrc_levels() {
	for _d in "$ROOT"/etc/runlevels/*; do
		[ -e "$_d/$1" ] && printf '%s\n' "${_d##*/}"
	done
	return 0
}
be_openrc_enabled() { [ -n "$(be_openrc_levels "$1")" ]; }
be_openrc_start() { rc-service "$1" start; }
be_openrc_stop() { rc-service "$1" stop; }
be_openrc_restart() { rc-service "$1" restart; }
be_openrc_enable() {
	_lv="${2:-default}"
	rc-update add "$1" "$_lv" >/dev/null 2>&1
}
be_openrc_disable() {
	for _l in $(be_openrc_levels "$1"); do
		rc-update del "$1" "$_l" >/dev/null 2>&1 || true
	done
}
be_openrc_log() { tail -n "$2" "$ROOT/var/log/$1.log" 2>/dev/null || echo "（没有日志文件 /var/log/$1.log）"; }
be_openrc_follow() { tail -n 20 -f "$ROOT/var/log/$1.log"; }

# procd (OpenWRT) -------------------------------------------------------------

be_procd_install() {
	_env="XRAY_LOCATION_ASSET=$CONF_DIR"
	# Small routers: let Go collect garbage before memory runs out.
	_mem="$(awk '/^MemTotal:/ {print int($2 / 1024)}' "$ROOT/proc/meminfo" 2>/dev/null || true)"
	case "$_mem" in '' | *[!0-9]*) ;; *)
		if [ "$_mem" -lt 1024 ]; then
			_env="$_env GOMEMLIMIT=$((_mem * 40 / 100))MiB"
		fi
		;;
	esac
	mkdir -p "$ROOT/etc/init.d"
	sed -e "s#@BIN@#$BIN#g" -e "s#@CONF@#$CONF#g" -e "s#@ENV@#$_env#g" >"$ROOT/etc/init.d/W1nCray" <<'EOF'
#!/bin/sh /etc/rc.common
# W1nCray Xboard node backend (procd)

USE_PROCD=1
START=99
STOP=10

start_service() {
	procd_open_instance
	procd_set_param command "@BIN@" -c "@CONF@"
	procd_set_param env @ENV@
	procd_set_param limits nofile="1048576 1048576"
	# Restart after a crash, forever, 10 s apart.
	procd_set_param respawn 3600 10 0
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param term_timeout 10
	procd_close_instance
}
EOF
	chmod 755 "$ROOT/etc/init.d/W1nCray"
}
be_procd_remove() { rm -f "$ROOT/etc/init.d/$1"; }
be_procd_exists() { [ -x "$ROOT/etc/init.d/$1" ]; }
# `status` reports "running" for a dead instance on OpenWRT <= 23.05; use `running`.
be_procd_active() {
	if "$ROOT/etc/init.d/$1" running >/dev/null 2>&1; then
		return 0
	fi
	return 1
}
be_procd_enabled() { "$ROOT/etc/init.d/$1" enabled >/dev/null 2>&1; }
be_procd_start() { "$ROOT/etc/init.d/$1" start; }
be_procd_stop() { "$ROOT/etc/init.d/$1" stop; }
be_procd_restart() { "$ROOT/etc/init.d/$1" restart; }
be_procd_enable() { "$ROOT/etc/init.d/$1" enable; }
be_procd_disable() { "$ROOT/etc/init.d/$1" disable; }
be_procd_log() { logread -e "$1" | tail -n "$2"; }
be_procd_follow() { logread -f -e "$1"; }
be_procd_levels() { :; }

# none ------------------------------------------------------------------------

no_backend() { die "没有检测到可用的服务管理器（systemd / OpenRC / procd）。可手动前台运行: $BIN -c $CONF"; }
be_none_install() { no_backend; }
be_none_remove() { :; }
be_none_exists() { return 1; }
be_none_active() { return 1; }
be_none_enabled() { return 1; }
be_none_start() { no_backend; }
be_none_stop() { no_backend; }
be_none_restart() { no_backend; }
be_none_enable() { no_backend; }
be_none_disable() { no_backend; }
be_none_log() { no_backend; }
be_none_follow() { no_backend; }
be_none_levels() { :; }

# log_hint [follow] prints the command that reads this machine's agent log. The
# program itself has no `log` subcommand (running it directly answers
# `unknown command "log"`), so every hint names the real command of the detected
# backend: journalctl on systemd, the file the OpenRC supervise-daemon writes
# (be_openrc_install sets output_log/error_log), logread on procd. "follow"
# asks for the live view. With no service manager the log is the terminal.
log_hint() {
	case "$BACKEND" in
	systemd)
		if [ "${1:-}" = follow ]; then
			printf 'journalctl -u W1nCray -f'
		else
			printf 'journalctl -u W1nCray'
		fi
		;;
	openrc)
		if [ "${1:-}" = follow ]; then
			printf 'tail -f %s' "$ROOT/var/log/W1nCray.log"
		else
			printf 'tail -n 100 %s' "$ROOT/var/log/W1nCray.log"
		fi
		;;
	procd)
		if [ "${1:-}" = follow ]; then
			printf 'logread -f -e W1nCray'
		else
			printf 'logread -e W1nCray'
		fi
		;;
	*)
		printf '%s -c %s' "$BIN" "$CONF"
		;;
	esac
}

# daemon_pids prints the PIDs of the running program. busybox pidof also matches
# scripts by name, which would include this manager script itself.
daemon_pids() {
	_all="$(pidof W1nCray 2>/dev/null || true)"
	_out=""
	for _p in $_all; do
		_exe="$(readlink "/proc/$_p/exe" 2>/dev/null || true)"
		case "$_exe" in
		"$BIN" | "$BIN "*) _out="$_out $_p" ;;
		esac
	done
	echo $_out
}

# stable_running UNIT SECONDS: running, and the same process the whole time
# (supervisors report a crash-looping service as started).
stable_running() {
	svc active "$1" || return 1
	_p1="$(daemon_pids)"
	sleep "$2"
	svc active "$1" || return 1
	_p2="$(daemon_pids)"
	[ "$_p1" = "$_p2" ]
}

xrayr_present() {
	svc exists "$XRAYR_UNIT" || [ -f "$XRAYR_DIR/config.yml" ]
}

# ---- commands --------------------------------------------------------------

require_bin() {
	[ -x "$BIN" ] || die "W1nCray 尚未安装（找不到 $BIN）。先执行: sh install.sh install"
}

run_check() {
	echo
	if "$BIN" check -c "$CONF" --online; then
		return 0
	fi
	red "配置检查未通过，请修改 $CONF 后执行: W1nCray check"
	return 1
}

# run_check_offline validates the config without contacting the panel. Machine
# mode uses it: the panel may be unreachable while the agent is being
# installed, and the agent retries in the background, so a network hiccup must
# not keep the service from starting.
run_check_offline() {
	echo
	if "$BIN" check -c "$CONF"; then
		return 0
	fi
	red "配置检查未通过，请修改 $CONF 后执行: W1nCray check"
	return 1
}

backup_conf() {
	if [ -d "$CONF_DIR" ]; then
		_b="$CONF_DIR.bak.$(date +%Y%m%d-%H%M%S)"
		cp -a "$CONF_DIR" "$_b"
		green "已备份 $CONF_DIR -> $_b"
	fi
}

# self_copy installs this script as the manager command and next to the binary.
self_copy() {
	_self=""
	if [ -f "${W1NCRAY_SELF:-$0}" ]; then
		_self="${W1NCRAY_SELF:-$0}"
	fi
	if [ -z "$_self" ]; then
		_self="$BIN_DIR/install.sh.dl"
		download "https://raw.githubusercontent.com/$REPO/main/install.sh" "$_self" || {
			yellow "未能保存安装脚本副本，管理命令 W1nCray 不可用；请重新下载 install.sh 执行"
			rm -f "$_self"
			return 0
		}
	fi
	if [ "$_self" != "$BIN_DIR/install.sh" ]; then
		cp "$_self" "$BIN_DIR/install.sh.new"
		mv "$BIN_DIR/install.sh.new" "$BIN_DIR/install.sh"
	fi
	chmod 755 "$BIN_DIR/install.sh"
	mkdir -p "$(dirname "$MGR")"
	cp "$BIN_DIR/install.sh" "$MGR.new"
	chmod 755 "$MGR.new"
	mv "$MGR.new" "$MGR"
	[ "$_self" = "$BIN_DIR/install.sh.dl" ] && rm -f "$_self"
	return 0
}

ensure_geo() {
	for _f in geoip.dat geosite.dat; do
		if [ -s "$CONF_DIR/$_f" ]; then
			continue
		fi
		yellow "下载 $_f ..."
		if download "$GEO_BASE/$_f" "$CONF_DIR/$_f.tmp"; then
			mv "$CONF_DIR/$_f.tmp" "$CONF_DIR/$_f"
		else
			rm -f "$CONF_DIR/$_f.tmp"
			yellow "下载 $_f 失败；仅当路由使用 geosite:/geoip: 时需要，可稍后手动放入 $CONF_DIR"
		fi
	done
}

# selinux_prepare makes an SELinux host ready for the kernel binaries: the
# runtime directory the Xray kernel publishes its status socket in, and the
# bin_t label on the kernel tree.
#
# Without the label a kernel installed under /etc/W1nCray/state keeps the etc_t
# type; systemd then starts it in init_t instead of unconfined_service_t, and
# init_t may not create the status socket in the etc_t configuration directory
# (CentOS Stream 9: "bind: permission denied" + an AVC on xray.sock). semanage
# makes the label survive a relabel and a reboot; chcon is the fallback; a host
# with neither tool is left alone with a warning, never a failed installation.
selinux_prepare() {
	[ -e /sys/fs/selinux/enforce ] || return 0
	_mode="$(cat /sys/fs/selinux/enforce 2>/dev/null)"
	case "$_mode" in 0 | 1) ;; *) return 0 ;; esac
	# systemd creates this with RuntimeDirectory=W1nCray; OpenRC, procd and the
	# agent's own supervisor rely on it already existing.
	mkdir -p "$ROOT/run/W1nCray" 2>/dev/null || true
	_kd="$CONF_DIR/state/kernels/kernels"
	mkdir -p "$_kd" 2>/dev/null || return 0
	if command -v semanage >/dev/null 2>&1 && command -v restorecon >/dev/null 2>&1; then
		semanage fcontext -a -t bin_t "$_kd(/.*)?" >/dev/null 2>&1 || true
		restorecon -R -F "$_kd" >/dev/null 2>&1 || true
		green "SELinux: 内核目录 $_kd 已持久标记为 bin_t"
	elif command -v chcon >/dev/null 2>&1; then
		chcon -R -t bin_t "$_kd" >/dev/null 2>&1 || true
		yellow "SELinux: 内核目录 $_kd 已用 chcon 标记为 bin_t（未装 semanage，全盘 relabel 后需重新执行）"
	else
		yellow "SELinux 已启用，但 semanage 与 chcon 都不可用；内核服务可能被 SELinux 拒绝（请安装 policycoreutils 与 policycoreutils-python-utils）"
	fi
	return 0
}

# selinux_forget removes the persistent fcontext rule selinux_prepare added.
# The kernel files themselves are removed by the agent (or by --purge), so only
# the local customisation has to go; a machine without semanage has nothing to
# forget.
selinux_forget() {
	command -v semanage >/dev/null 2>&1 || return 0
	_kd="$CONF_DIR/state/kernels/kernels"
	semanage fcontext -d -t bin_t "$_kd(/.*)?" >/dev/null 2>&1 || true
	return 0
}

# OpenWRT's sysupgrade only keeps /etc/config and listed files.
keep_on_sysupgrade() {
	is_openwrt || return 0
	_sc="$ROOT/etc/sysupgrade.conf"
	touch "$_sc"
	for _p in "/etc/W1nCray/" "/etc/init.d/W1nCray"; do
		grep -qxF "$_p" "$_sc" 2>/dev/null || printf '%s\n' "$_p" >>"$_sc"
	done
}

# drop_sysupgrade_entries removes what keep_on_sysupgrade added; the config
# directory entry stays unless the config itself is purged. The Xray kernel
# service adds its own init-script entry on procd (agent/xraysvc); it is dropped
# here too so uninstall leaves no dangling line.
drop_sysupgrade_entries() { # $1 = 1 to drop the config directory entry too
	is_openwrt || return 0
	_sc="$ROOT/etc/sysupgrade.conf"
	[ -f "$_sc" ] || return 0
	_tmp="$(mktemp)"
	grep -vxF "/etc/init.d/W1nCray" "$_sc" >"$_tmp" || true
	grep -vxF "/etc/init.d/W1nCray-xray" "$_tmp" >"$_tmp.2" || true
	mv "$_tmp.2" "$_tmp"
	if [ "$1" -eq 1 ]; then
		grep -vxF "/etc/W1nCray/" "$_tmp" >"$_tmp.2" || true
		mv "$_tmp.2" "$_tmp"
	fi
	cat "$_tmp" >"$_sc"
	rm -f "$_tmp"
}

# ---- panel machine mode -----------------------------------------------------
# The panel's admin page hands out a one-liner like
#
#   bash <(curl -fsSL .../install.sh) install --panel URL --machine ID --token T
#
# which installs the binary and the service and additionally writes a config
# where the agent links out to the panel and receives its nodes. The token is
# the only secret involved: it lives in $CONF_DIR/agent.token (0600) and is
# referenced through Agent.Panel.TokenFile, never written into config.yml.

# yaml_dq STRING prints STRING as a double-quoted YAML scalar, so a URL with
# YAML metacharacters (#, :, quotes, backslashes) cannot break the document.
yaml_dq() {
	printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
}

# is_loopback_host HOST matches what the agent's client accepts as loopback:
# localhost, 127.0.0.0/8 and ::1.
is_loopback_host() {
	case "$1" in
	localhost | "[::1]") return 0 ;;
	127.*)
		case "${1#127.}" in
		'' | *[!0-9.]*) return 1 ;;
		*) return 0 ;;
		esac
		;;
	esac
	return 1
}

# panel_url URL ALLOW_HTTP prints the URL without trailing slashes, or prints
# an explanation to stderr and returns non-zero. It never calls die: it runs
# inside a command substitution, where exit would only leave the subshell.
panel_url() {
	_url="$1"
	_allow_http="$2"
	while [ "${_url%/}" != "$_url" ]; do
		_url="${_url%/}"
	done
	case "$_url" in
	https://*)
		_scheme=https
		_host="${_url#https://}"
		;;
	http://*)
		_scheme=http
		_host="${_url#http://}"
		;;
	*)
		red "错误: --panel 的地址必须以 https:// 开头（仅本机回环可用 http://）: $_url" >&2
		return 1
		;;
	esac
	[ -n "$_host" ] || {
		red "错误: --panel 的地址缺少主机名: $_url" >&2
		return 1
	}
	case "$_host" in
	*[![:print:]]*)
		red "错误: --panel 的地址不能包含控制字符（如换行、制表符）" >&2
		return 1
		;;
	esac
	case "$_host" in
	*@*)
		red "错误: --panel 的地址不能包含用户名或密码" >&2
		return 1
		;;
	esac
	if [ "$_scheme" = http ]; then
		_hp="${_host%%/*}"
		case "$_hp" in
		"[::1]"*) _h="[::1]" ;;
		*:*) _h="${_hp%:*}" ;;
		*) _h="$_hp" ;;
		esac
		if ! is_loopback_host "$_h" && [ "$_allow_http" -ne 1 ]; then
			red "错误: --panel 使用明文 http:// 且不是本机回环地址；机器令牌会以明文在网络中传输。确认网络可信后请加 --allow-http" >&2
			return 1
		fi
	fi
	printf '%s' "$_url"
}

# nodes_block FILE prints the top-level `Nodes:` block: from the `Nodes:` line
# up to the next non-indented line (the next top-level key). A missing file
# prints nothing.
nodes_block() {
	[ -f "$1" ] || return 0
	sed -n '/^Nodes:/,/^[^[:space:]#]/p' "$1" 2>/dev/null || true
}

# has_static_nodes FILE: true when FILE still has v0.3 static nodes, i.e. a
# top-level `Nodes:` block with at least one NodeID entry. `Nodes: []` (what
# `W1nCray init` writes) is not a static node list.
has_static_nodes() {
	nodes_block "$1" | grep -q 'NodeID[[:space:]]*:'
}

# static_node_ids FILE prints the NodeIDs found in the static `Nodes:` block,
# in order and space separated (e.g. "173 119 138"); empty when there are none.
static_node_ids() {
	_ids="$(nodes_block "$1" |
		sed -n 's/.*NodeID[[:space:]]*:[[:space:]"]*\([0-9][0-9]*\).*/\1/p' |
		tr '\n' ' ')"
	printf '%s' "${_ids% }"
}

# ---- v11 migration detection ------------------------------------------------
# A pre-v11 program is a single binary that serves Xray in-process and prints
# "W1nCray <v> (Xray-core <v>, <flavor>)". The v11 agent prints
# "W1nCray <v> (agent, <flavor>)".

is_single_program() {
	[ -x "$BIN" ] || return 1
	"$BIN" version 2>/dev/null | grep -q 'Xray-core'
}

# machine_nodes_on: true when the effective agent configuration turns on
# Panel.MachineNodes (the panel owns the node list). agent.yml wins over the
# Agent: block of config.yml, exactly like LoadConfig.
machine_nodes_on() {
	for _f in "$AGENT_CONF" "$CONF"; do
		if [ -f "$_f" ] && grep -q '^[[:space:]]*MachineNodes:[[:space:]]*true' "$_f" 2>/dev/null; then
			return 0
		fi
	done
	return 1
}

# xray_nodes_configured: true when this machine's configuration needs the Xray
# kernel: config.yml has static Nodes, or machine mode owns them.
xray_nodes_configured() {
	has_static_nodes "$CONF" && return 0
	machine_nodes_on
}

# xray_hint tells a fresh installation where the Xray kernel comes from.
xray_hint() {
	yellow "Xray 内核未安装：本机只装了 agent（W1nCray）。"
	yellow "在面板给这台机器绑定节点后，agent 会自动安装 Xray 内核；也可现在手动安装："
	yellow "  W1nCray xray install            # 按已签名清单安装最新版"
	yellow "  W1nCray xray install --file <W1nCray-xray .gz> --sha256 <hex>   # 离线安装"
}

# ---- v11 migration: backup and restore --------------------------------------
# The 0.5.x -> 0.6 migration replaces the running single program in place and
# rewrites its service file. Both are saved first, so a failed
# `xray install --file` can put the working 0.5.x node back instead of leaving
# the machine with no Xray at all (R1-11). The backups are removed again once
# the migration succeeded, or once the restore proved the machine is whole.

MIG_BIN_BAK=""
MIG_UNIT_BAK=""

# svc_unit_file NAME prints the service file the current backend owns for NAME
# ("" when the backend keeps none).
svc_unit_file() {
	case "$BACKEND" in
	systemd) printf '%s' "$ROOT/etc/systemd/system/$1.service" ;;
	openrc | procd) printf '%s' "$ROOT/etc/init.d/$1" ;;
	*) printf '' ;;
	esac
}

# migration_backup saves the pre-v11 binary and its service file next to them.
# It runs before the first destructive step (stopping the old service, replacing
# the binary, rewriting the service file).
migration_backup() {
	MIG_BIN_BAK=""
	MIG_UNIT_BAK=""
	if [ -f "$BIN" ]; then
		MIG_BIN_BAK="$BIN.pre-v11"
		cp -p "$BIN" "$MIG_BIN_BAK" || die "备份旧程序 $BIN 失败，未做任何改动"
	fi
	_mig_unit="$(svc_unit_file W1nCray)"
	if [ -n "$_mig_unit" ] && [ -f "$_mig_unit" ]; then
		MIG_UNIT_BAK="$_mig_unit.pre-v11"
		cp -p "$_mig_unit" "$MIG_UNIT_BAK" || die "备份旧服务文件 $_mig_unit 失败，未做任何改动"
	fi
}

# migration_restore puts the saved binary and service file back and starts the
# service. It returns non-zero when the machine could not be restored; the
# backups are then kept for the operator.
migration_restore() {
	[ -n "$MIG_BIN_BAK" ] && [ -f "$MIG_BIN_BAK" ] || return 1
	# Replace by rename: cp over a binary that is still executing fails with
	# ETXTBSY.
	cp -p "$MIG_BIN_BAK" "$BIN.restore" || return 1
	mv -f "$BIN.restore" "$BIN" || return 1
	if [ -n "$MIG_UNIT_BAK" ] && [ -f "$MIG_UNIT_BAK" ]; then
		_mig_unit="$(svc_unit_file W1nCray)"
		if [ -n "$_mig_unit" ]; then
			cp -p "$MIG_UNIT_BAK" "$_mig_unit" || return 1
		fi
	fi
	case "$BACKEND" in
	systemd) systemctl daemon-reload >/dev/null 2>&1 || true ;;
	esac
	svc start W1nCray || return 1
	return 0
}

# migration_forget removes the backups of a migration that succeeded or was
# fully undone.
migration_forget() {
	if [ -n "$MIG_BIN_BAK" ]; then
		rm -f "$MIG_BIN_BAK"
	fi
	if [ -n "$MIG_UNIT_BAK" ]; then
		rm -f "$MIG_UNIT_BAK"
	fi
	MIG_BIN_BAK=""
	MIG_UNIT_BAK=""
}

# panel_config DEST writes the xray side of the machine-mode config. The agent's
# own configuration lives in agent.yml (agent_config below); config.yml never
# carries an Agent: block any more (D1, ruling 1).
panel_config() {
	{
		printf 'Log: {Level: info}\n'
	} >"$1"
}

# agent_config DEST URL ID LO HI TOKENFILE ALLOW_HTTP NOTERMINAL writes agent.yml.
# It is atomic (temporary file + mv in the same directory) and an existing
# agent.yml is backed up first: the file takes part in LoadConfig, so a
# half-written one would keep the service from starting.
agent_config() {
	_dest="$1"
	_tmp="$(mktemp "$CONF_DIR/.agent.yml.XXXXXX")" || die "无法在 $CONF_DIR 创建临时文件"
	{
		printf '# W1nCray agent configuration (agent.yml).\n'
		printf '# This file wins as a whole over the Agent: block of config.yml, which is ignored.\n'
		printf '# The interactive terminal is ON by default; Terminal: {Enabled: false} turns it off locally.\n'
		printf 'Enabled: true\n'
		printf 'StateDir: %s\n' "$(yaml_dq "$CONF_DIR/state")"
		printf 'Policy:\n'
		printf '  AllowListen: ["0.0.0.0"]\n'
		printf '  PortRange: [%s, %s]\n' "$4" "$5"
		# No AllowEngines: an empty list means "no restriction", so instances
		# the panel pushes (gost/frp/realm included) are accepted when their
		# signed manifest makes them available. A hard-coded ["xray"] would
		# reject them.
		if [ "$8" -eq 1 ]; then
			printf 'Terminal: {Enabled: false}\n'
		fi
		printf 'Panel:\n'
		printf '  Enabled: true\n'
		printf '  URL: %s\n' "$(yaml_dq "$2")"
		printf '  MachineID: %s\n' "$3"
		printf '  TokenFile: %s\n' "$(yaml_dq "$6")"
		if [ "$7" -eq 1 ]; then
			printf '  AllowInsecureHTTP: true\n'
		fi
		printf '  MachineNodes: true\n'
	} >"$_tmp" || {
		rm -f "$_tmp"
		die "写入 agent.yml 失败"
	}
	chmod 600 "$_tmp" 2>/dev/null || true
	if [ -f "$_dest" ]; then
		_bak="$_dest.bak-$(date +%Y%m%d-%H%M%S)"
		_i=1
		while [ -e "$_bak" ]; do
			_bak="$_dest.bak-$(date +%Y%m%d-%H%M%S)-$_i"
			_i=$((_i + 1))
		done
		cp "$_dest" "$_bak" || {
			rm -f "$_tmp"
			die "备份 $_dest 失败"
		}
		chmod 600 "$_bak" 2>/dev/null || true
		green "已备份原有 agent.yml 到 $_bak"
	fi
	mv "$_tmp" "$_dest" || {
		rm -f "$_tmp"
		die "替换 $_dest 失败"
	}
}

# agent_panel_linked FILE: true when FILE is an agent.yml that already links to
# a panel (a top-level Panel: block with Enabled: true). Such a file is live
# configuration and is never overwritten by the installer.
agent_panel_linked() {
	[ -f "$1" ] || return 1
	sed -n '/^Panel:/,/^[^[:space:]#]/p' "$1" 2>/dev/null |
		grep -q '^[[:space:]]*Enabled:[[:space:]]*true'
}

# panel_hint URL ID PENDING tells the admin the machine is linked. It never
# prints the token. PENDING=1 means the machine-mode config is not active yet
# (written to config.panel.yml.new for merging, or to be applied by `link`).
panel_hint() {
	[ -n "$1" ] || return 0
	if [ "${3:-0}" -eq 1 ]; then
		yellow "已关联面板 $1（机器 ID $2），但配置尚未生效：请按上面的提示完成接入并重启服务，之后 agent 将自动领取节点与转发规则"
	else
		green "已关联面板 $1（机器 ID $2），agent 将自动领取节点与转发规则"
	fi
	yellow "查看日志：$(log_hint follow)（实时）或 W1nCray status"
}

cmd_install() {
	_src="latest"
	_flavor=""
	_prefix=""
	_geo=""
	_panel=""
	_machine=""
	_token=""
	_token_file=""
	_port_range=""
	_allow_http=0
	_noterminal=0
	_panel_pending=0
	while [ $# -gt 0 ]; do
		case "$1" in
		--binary)
			[ $# -ge 2 ] || die "--binary 需要文件路径"
			_src="file:$2"
			shift 2
			;;
		--url)
			[ $# -ge 2 ] || die "--url 需要地址"
			_src="url:$2"
			shift 2
			;;
		--version)
			[ $# -ge 2 ] || die "--version 需要版本号"
			_src="version:$2"
			shift 2
			;;
		--lite)
			_flavor=lite
			shift
			;;
		--full)
			_flavor=full
			shift
			;;
		--keep-flavor) shift ;;
		--prefix)
			[ $# -ge 2 ] || die "--prefix 需要目录"
			_prefix="$2"
			shift 2
			;;
		--with-geo)
			_geo=yes
			shift
			;;
		--no-geo)
			_geo=no
			shift
			;;
		--panel)
			[ $# -ge 2 ] || die "--panel 需要面板地址"
			_panel="$2"
			shift 2
			;;
		--machine)
			[ $# -ge 2 ] || die "--machine 需要机器 ID"
			_machine="$2"
			shift 2
			;;
		--token)
			[ $# -ge 2 ] || die "--token 需要令牌"
			_token="$2"
			shift 2
			;;
		--token-file)
			[ $# -ge 2 ] || die "--token-file 需要文件路径"
			_token_file="$2"
			shift 2
			;;
		--allow-http)
			_allow_http=1
			shift
			;;
		--noterminal)
			_noterminal=1
			shift
			;;
		--port-range)
			[ $# -ge 2 ] || die "--port-range 需要 LO-HI"
			_port_range="$2"
			shift 2
			;;
		--insecure-skip-verify)
			INSECURE_SKIP_VERIFY=1
			shift
			;;
		-y | --yes)
			ASSUME_YES=1
			shift
			;;
		*) die "未知参数: $1" ;;
		esac
	done
	need_root

	# Machine mode (--panel): validate everything before touching the machine,
	# so a typo cannot leave a half-configured host behind.
	_panel_lo=20000
	_panel_hi=40000
	if [ -n "$_panel" ] || [ -n "$_machine" ] || [ -n "$_token" ] || [ -n "$_token_file" ]; then
		[ -n "$_panel" ] || die "缺少 --panel：--panel、--machine 与令牌（--token 或 --token-file）必须同时提供"
		[ -n "$_machine" ] || die "缺少 --machine：--panel、--machine 与令牌（--token 或 --token-file）必须同时提供"
		if [ -n "$_token" ] && [ -n "$_token_file" ]; then
			die "--token 与 --token-file 只能提供一个"
		fi
		if [ -z "$_token" ] && [ -z "$_token_file" ]; then
			die "缺少令牌：请用 --token 或 --token-file 提供面板令牌"
		fi

		_machine_raw="$_machine"
		case "$_machine" in
		'' | *[!0-9]*) die "--machine 必须是正整数，收到: $_machine_raw" ;;
		esac
		_machine="$(printf '%s' "$_machine" | sed 's/^0*//')"
		[ -n "$_machine" ] || _machine=0
		[ "$_machine" -gt 0 ] || die "--machine 必须是正整数，收到: $_machine_raw"

		case "$_port_range" in
		'') ;;
		*-*)
			_panel_lo="${_port_range%%-*}"
			_panel_hi="${_port_range#*-}"
			case "$_panel_lo" in '' | *[!0-9]*) die "--port-range 需要 LO-HI 形式（例如 20000-40000），收到: $_port_range" ;; esac
			case "$_panel_hi" in '' | *[!0-9]*) die "--port-range 需要 LO-HI 形式（例如 20000-40000），收到: $_port_range" ;; esac
			if [ "$_panel_lo" -lt 1 ] || [ "$_panel_hi" -gt 65535 ] || [ "$_panel_lo" -gt "$_panel_hi" ]; then
				die "--port-range 无效: $_port_range（需要 1-65535 且 LO <= HI）"
			fi
			;;
		*) die "--port-range 需要 LO-HI 形式（例如 20000-40000），收到: $_port_range" ;;
		esac

		if [ -n "$_token_file" ]; then
			[ -f "$_token_file" ] || die "--token-file 找不到文件: $_token_file"
			[ -r "$_token_file" ] || die "--token-file 文件不可读: $_token_file"
			# Read it without ever putting the secret on a command line.
			# The whitespace is listed explicitly instead of using
			# tr's '[:space:]' class: the BusyBox builds checked here
			# (OpenWrt 21.02's v1.33.2 and 23.05's v1.36.1) are compiled
			# without CONFIG_FEATURE_TR_CLASSES, so they treat the class
			# as the literal set { [ : s p a c e ] } and silently delete
			# those characters from the token, which made the agent fail
			# with 401 bad_credentials (D-M5). Anything else left over
			# (e.g. \v or \f) is refused by the check below.
			_token="$(tr -d ' \t\r\n' <"$_token_file")"
		fi
		[ -n "$_token" ] || die "面板令牌为空：请检查 --token / --token-file 提供的内容"
		case "$_token" in
		*[[:space:]]*) die "面板令牌不能包含空白字符（空格、换行、制表符）" ;;
		esac

		_panel="$(panel_url "$_panel" "$_allow_http")" || exit 1
	elif [ -n "$_port_range" ] || [ "$_allow_http" -eq 1 ] || [ "$_noterminal" -eq 1 ]; then
		die "--port-range、--allow-http 与 --noterminal 只在 --panel 机器模式下有意义"
	fi
	# The flag is forwarded to the `W1nCray link` command the installer prints.
	_noterminal_arg=""
	[ "$_noterminal" -eq 1 ] && _noterminal_arg=" --noterminal"

	[ -n "$_prefix" ] && BIN_DIR="$_prefix"
	BIN="$BIN_DIR/W1nCray"
	# An upgrade keeps the flavor that was installed unless told otherwise.
	[ -z "$_flavor" ] && _flavor="$FLAVOR"
	[ -z "$_flavor" ] && _flavor="$(default_flavor)"
	FLAVOR="$_flavor"

	_was_active=0
	if [ -x "$BIN" ] && svc active W1nCray 2>/dev/null; then
		_was_active=1
	fi

	# v11 migration (PLAN v11 §2.6): a pre-v11 single program that serves Xray
	# nodes must become the agent plus the W1nCray-xray kernel service. Both
	# downloads happen before anything is stopped, so the interruption is only
	# the two process restarts.
	_migrate_xray=0
	if is_single_program && xray_nodes_configured; then
		case "$_src" in
		latest | version:*)
			_migrate_xray=1
			;;
		*)
			yellow "检测到 0.5.x 单一程序与 Xray 节点配置，但本次用的是本地/自定义程序源，无法自动下载匹配的 Xray 内核。"
			yellow "升级完成后请执行 W1nCray xray install 安装 Xray 内核（见 docs/AGENT.md §13）。"
			;;
		esac
	fi

	fetch_binary "$_src" "$FLAVOR"
	if [ "$_migrate_xray" -eq 1 ]; then
		fetch_xray_kernel "${RELEASE_TAG:-}" "${CHOSEN_ARCH:-$(detect_arch)}"
		yellow "迁移到 v11：停止旧的单一程序 -> 替换 agent -> 安装并启动 Xray 内核服务 -> 启动 agent。"
		yellow "下载已完成；中断只包含这两次重启（通常几秒到几十秒），期间经 Xray 节点的连接会断开。"
		# Save the old program and its service file before the first
		# destructive step: a failed kernel install must be able to put the
		# working 0.5.x node back (R1-11).
		migration_backup
		if [ "$BACKEND" != none ]; then
			svc stop W1nCray >/dev/null 2>&1 || true
		fi
	fi
	mv "$NEWBIN" "$BIN"
	if [ "$_migrate_xray" -ne 1 ]; then
		rm -rf "$TMPD"
		trap - EXIT INT TERM
	fi
	green "已安装 $("$BIN" version | head -n1)"

	mkdir -p "$CONF_DIR"
	save_env
	self_copy
	selinux_prepare

	# Machine mode: the token goes to its own 0600 file and never into
	# config.yml, the logs or any subprocess argument.
	if [ -n "$_panel" ]; then
		_umask="$(umask)"
		umask 077
		# printf is a shell builtin: the secret never reaches an argv.
		printf '%s' "$_token" >"$CONF_DIR/agent.token"
		umask "$_umask"
		chmod 600 "$CONF_DIR/agent.token"
		_token=""
		green "已保存面板令牌到 $CONF_DIR/agent.token（权限 600）"
	fi

	if [ -n "$_panel" ]; then
		if [ -f "$XRAYR_DIR/config.yml" ]; then
			yellow "机器模式下不迁移 XrayR 配置（$XRAYR_DIR/config.yml 未被修改）；需要静态节点可稍后执行: W1nCray migrate"
		fi
		if [ ! -f "$CONF" ]; then
			panel_config "$CONF"
			green "已生成机器模式配置 $CONF"
		fi
		if agent_panel_linked "$AGENT_CONF"; then
			# A live agent.yml is never replaced: the operator's link would be
			# lost. Re-linking is an explicit step (link --force backs it up).
			_panel_pending=1
			yellow "检测到已有 agent 配置 $AGENT_CONF（已关联面板），未覆盖它。"
			if [ "$_noterminal" -eq 1 ]; then
				yellow "（--noterminal 未写入：请在 $AGENT_CONF 里手工加 Terminal: {Enabled: false}，或用 W1nCray link --force --noterminal ...）"
			fi
			yellow "如需重新关联，请先备份并删除该文件，或执行 W1nCray link --force ...（link 会先备份）"
		elif [ -f "$CONF" ] && has_static_nodes "$CONF"; then
			# v0.3 static nodes: `link` migrates them (and any old Agent: block)
			# to agent.yml, so no .new file is written and nothing is merged by
			# hand. Only guidance is printed here; link itself is never run from
			# the installer.
			_panel_pending=1
			_ids="$(static_node_ids "$CONF")"
			yellow "检测到已有配置 $CONF，未覆盖它。"
			if [ -n "$_ids" ]; then
				yellow "配置里的静态节点 NodeID: $_ids"
			fi
			yellow "机器模式下节点由面板下发：请先在面板把这些 NodeID 绑定到机器 $_machine（未绑定的节点不会生效）。"
			yellow "绑定后先看迁移计划（不会改动配置，也不会重启服务）:"
			yellow "  W1nCray link --panel $_panel --machine $_machine --token-file $CONF_DIR/agent.token$_noterminal_arg --dry-run"
			yellow "确认计划无误后去掉 --dry-run 执行:"
			yellow "  W1nCray link --panel $_panel --machine $_machine --token-file $CONF_DIR/agent.token$_noterminal_arg"
			yellow "最后重启服务: W1nCray restart"
			yellow "（agent 配置写入 $AGENT_CONF：静态节点与旧的 Agent 段都由 W1nCray link 迁移，无需手工合并）"
		else
			if [ -f "$CONF" ]; then
				yellow "检测到已有配置 $CONF，未覆盖它（agent 配置写入 $AGENT_CONF）。"
				if grep -q '^Agent:' "$CONF" 2>/dev/null; then
					yellow "注意：$CONF 里还有旧的 Agent: 段；agent.yml 生效后它会被忽略（需要时用 W1nCray link 迁移）。"
				fi
			fi
			agent_config "$AGENT_CONF" "$_panel" "$_machine" "$_panel_lo" "$_panel_hi" "$CONF_DIR/agent.token" "$_allow_http" "$_noterminal"
			green "已生成 agent 配置 $AGENT_CONF（agent 配置与 config.yml 分离，无需手工合并）"
		fi
	elif [ ! -f "$CONF" ]; then
		if [ -f "$XRAYR_DIR/config.yml" ]; then
			green "检测到 XrayR 配置，开始迁移（XrayR 文件只读，不会被修改）"
			"$BIN" migrate --from "$XRAYR_DIR" --to "$CONF_DIR"
		else
			"$BIN" init --dir "$CONF_DIR"
			yellow "已生成默认配置，请编辑 $CONF 填写 ApiHost / ApiKey / NodeID（W1nCray config）"
		fi
	else
		yellow "保留现有配置 $CONF（重新迁移请执行: W1nCray migrate）"
	fi

	if [ "$_geo" = yes ] || { [ "$_geo" != no ] && ! is_openwrt; }; then
		ensure_geo
	elif is_openwrt; then
		yellow "OpenWRT 默认不下载 geo 文件（约 27 MB）；路由规则用到 geosite:/geoip: 时请加 --with-geo"
	fi

	if [ "$BACKEND" = none ]; then
		yellow "没有检测到可用的服务管理器（systemd / OpenRC / procd），程序与配置已就位但未注册为服务。"
		yellow "可手动前台运行: $BIN -c $CONF   （或 W1nCray run）"
		if [ "$_migrate_xray" -eq 1 ]; then
			yellow "Xray 内核尚未安装：请执行 W1nCray xray install --file <文件> --sha256 $XRAYSHA"
			if [ -n "$MIG_BIN_BAK" ]; then
				yellow "（旧 0.5.x 程序已备份到 $MIG_BIN_BAK，需要回退时手工替换回 $BIN）"
			fi
		else
			xray_hint
		fi
		panel_hint "$_panel" "$_machine" "$_panel_pending"
		return 0
	fi
	svc install
	keep_on_sysupgrade
	if is_openwrt; then
		yellow "提示：固件升级（sysupgrade）后配置会保留，但程序文件需要重新执行安装命令"
	fi

	if [ "$_migrate_xray" -eq 1 ]; then
		# Replace the in-process Xray with the kernel service before the agent
		# comes back: the kernel serves the nodes while the agent restarts.
		if ! "$BIN" -c "$CONF" xray install --file "$XRAYGZ" --sha256 "$XRAYSHA"; then
			# The v11 agent is already in place and the 0.5.x service is
			# stopped: put the old binary and its service file back and start
			# the service again, so the node keeps serving instead of staying
			# down (R1-11).
			if migration_restore; then
				migration_forget
				red "Xray 内核安装失败；已恢复到原版本并重新启动服务：$("$BIN" version | head -n1)"
				die "请重新下载 $XRAYASSET 后重试: W1nCray xray install --file <文件> --sha256 $XRAYSHA"
			fi
			die "Xray 内核安装失败，且自动恢复原版本失败。旧程序备份: $MIG_BIN_BAK，旧服务文件备份: $MIG_UNIT_BAK；请手工恢复后重试。"
		fi
		migration_forget
		rm -rf "$TMPD"
		trap - EXIT INT TERM
		green "Xray 内核服务已安装并启动（迁移完成）"
	fi

	if [ "$_was_active" -eq 1 ]; then
		svc restart W1nCray
		green "W1nCray 已重启（升级完成）"
		panel_hint "$_panel" "$_machine" "$_panel_pending"
		return 0
	fi
	_failed=0
	if [ -n "$_panel" ]; then
		run_check_offline || _failed=1
	else
		run_check || _failed=1
	fi
	if xrayr_present && { svc active "$XRAYR_UNIT" || svc enabled "$XRAYR_UNIT"; }; then
		yellow "XrayR 仍在运行/开机自启，为避免端口冲突，W1nCray 暂未启动。"
		yellow "确认无误后执行: W1nCray switch   （失败会自动回滚到 XrayR）"
	elif [ "$_failed" -eq 0 ]; then
		svc enable W1nCray
		svc start W1nCray
		green "W1nCray 已启动并设为开机自启。管理命令: W1nCray（菜单）、W1nCray status、查看日志: $(log_hint follow)"
	fi
	panel_hint "$_panel" "$_machine" "$_panel_pending"
	if [ "$_migrate_xray" -ne 1 ]; then
		xray_hint
	fi
}

cmd_update() {
	require_bin
	# "W1nCray update v1.2.3" is shorthand for "--version v1.2.3".
	case "${1:-}" in
	v[0-9]*)
		_v="$1"
		shift
		set -- --version "$_v" "$@"
		;;
	esac
	# Fetch the newest script first: it may know new platforms or flags.
	_new="$BIN_DIR/install.sh.latest"
	if download "https://raw.githubusercontent.com/$REPO/main/install.sh" "$_new" >/dev/null 2>&1 && [ -s "$_new" ]; then
		chmod 755 "$_new"
		mv "$_new" "$BIN_DIR/install.sh"
		exec sh "$BIN_DIR/install.sh" install "$@"
	fi
	rm -f "$_new"
	yellow "未能获取最新的安装脚本，使用当前脚本更新"
	cmd_install "$@"
}

cmd_migrate() {
	need_root
	require_bin
	[ -f "$XRAYR_DIR/config.yml" ] || die "未找到 $XRAYR_DIR/config.yml"
	backup_conf
	"$BIN" migrate --from "$XRAYR_DIR" --to "$CONF_DIR" --force
	run_check || true
	if svc active W1nCray; then
		yellow "W1nCray 正在运行，配置文件变更会自动重载"
	fi
}

cmd_check() {
	require_bin
	run_check
}

cmd_switch() {
	need_root
	require_bin
	run_check || die "检查未通过，未做切换"
	ask "将停止并禁用 XrayR、启用 W1nCray，确认？" || die "已取消"
	if svc exists "$XRAYR_UNIT"; then
		# Remember where XrayR was enabled (OpenRC runlevel) for rollback.
		svc levels "$XRAYR_UNIT" >"$CONF_DIR/xrayr.levels" 2>/dev/null || true
		svc stop "$XRAYR_UNIT" || true
		svc disable "$XRAYR_UNIT" || true
	fi
	svc enable W1nCray
	svc start W1nCray
	if stable_running W1nCray "$WAIT_SWITCH"; then
		green "切换完成，W1nCray 运行中。回滚: W1nCray rollback"
		svc log W1nCray 20 || true
	else
		red "W1nCray 启动失败，自动回滚到 XrayR"
		svc log W1nCray 50 || true
		cmd_rollback
		exit 1
	fi
}

cmd_rollback() {
	need_root
	svc stop W1nCray >/dev/null 2>&1 || true
	svc disable W1nCray >/dev/null 2>&1 || true
	if svc exists "$XRAYR_UNIT"; then
		_lv="default"
		if [ -s "$CONF_DIR/xrayr.levels" ]; then
			_lv="$(head -n1 "$CONF_DIR/xrayr.levels")"
		fi
		svc enable "$XRAYR_UNIT" "$_lv"
		svc start "$XRAYR_UNIT" || true
		sleep 2
		if svc active "$XRAYR_UNIT"; then green "已恢复 XrayR"; else red "XrayR 未能启动，请查看它的日志"; fi
	else
		yellow "未找到 XrayR 服务，仅停止了 W1nCray"
	fi
}

cmd_start() {
	need_root
	require_bin
	svc start W1nCray
	stable_running W1nCray "$WAIT_START" && green "已启动" || red "启动后未能保持运行，请查看日志: $(log_hint)"
}
cmd_stop() {
	need_root
	svc stop W1nCray
	green "已停止"
}
cmd_restart() {
	need_root
	require_bin
	svc restart W1nCray
	stable_running W1nCray "$WAIT_START" && green "已重启" || red "重启后未能保持运行，请查看日志: $(log_hint)"
}
cmd_enable() {
	need_root
	svc enable W1nCray
	green "已设为开机自启"
}
cmd_disable() {
	need_root
	svc disable W1nCray
	green "已取消开机自启"
}

cmd_log() {
	if [ "${1:-}" = "-n" ]; then
		svc log W1nCray "${2:-100}"
	else
		svc follow W1nCray
	fi
}

cmd_status() {
	if [ -x "$BIN" ]; then
		printf '版本:       %s\n' "$("$BIN" version 2>/dev/null | head -n1)"
	else
		printf '版本:       未安装（%s）\n' "$BIN"
	fi
	printf '服务管理器: %s\n' "$BACKEND"
	if svc exists W1nCray; then
		if svc active W1nCray; then
			_pid="$(daemon_pids)"
			printf '运行状态:   %s运行中%s（PID %s）\n' "$C_GREEN" "$C_OFF" "${_pid:-?}"
		else
			printf '运行状态:   %s未运行%s\n' "$C_RED" "$C_OFF"
		fi
		if svc enabled W1nCray; then printf '开机自启:   是\n'; else printf '开机自启:   否\n'; fi
	else
		printf '运行状态:   服务未安装\n'
	fi
	if [ -f "$CONF" ]; then
		_n="$(grep -c '^[[:space:]]*ApiHost:' "$CONF" 2>/dev/null || true)"
		printf '配置:       %s（%s 个节点）\n' "$CONF" "${_n:-0}"
	fi
	if xrayr_present; then
		if svc active "$XRAYR_UNIT"; then
			printf 'XrayR:      %s仍在运行%s（可执行 W1nCray switch 切换）\n' "$C_YELLOW" "$C_OFF"
		else
			printf 'XrayR:      已安装，未运行\n'
		fi
	fi
	if svc exists W1nCray; then
		echo "--- 最近的 WebSocket 与错误日志"
		svc log W1nCray 300 2>/dev/null | grep -E 'websocket|level=(error|warning)' | tail -n 8 || true
	fi
}

cmd_config() {
	need_root
	[ -f "$CONF" ] || die "找不到配置文件 $CONF"
	"${EDITOR:-vi}" "$CONF"
	if [ -x "$BIN" ] && ask "检查修改后的配置？"; then
		run_check || true
	fi
}

cmd_uninstall() {
	_purge=0
	for _a in "$@"; do
		case "$_a" in
		--purge) _purge=1 ;;
		-y | --yes) ASSUME_YES=1 ;;
		esac
	done
	need_root
	if [ "$_purge" -eq 1 ]; then
		ask "将卸载 W1nCray 并删除配置目录 $CONF_DIR，确认？" || die "已取消"
	else
		ask "将卸载 W1nCray（保留配置目录 $CONF_DIR），确认？" || die "已取消"
	fi
	svc stop W1nCray >/dev/null 2>&1 || true
	svc disable W1nCray >/dev/null 2>&1 || true
	svc remove W1nCray || true
	# The Xray kernel service is separate (PLAN v11 §2.2): stop and remove it
	# too. Its own command deletes the kernel files and keeps config.yml; when
	# it cannot run, the service is removed by backend so no dangling unit or
	# init script is left behind.
	if [ -x "$BIN" ]; then
		if ! "$BIN" -c "$CONF" xray remove; then
			yellow "W1nCray xray remove 未能完成，按当前服务后端清理 $XRAY_UNIT"
			if [ "$BACKEND" != none ]; then
				svc stop "$XRAY_UNIT" >/dev/null 2>&1 || true
				svc disable "$XRAY_UNIT" >/dev/null 2>&1 || true
				svc remove "$XRAY_UNIT" || true
			fi
		fi
	fi
	rm -f "$BIN" "$BIN.pre-v11" "$BIN_DIR/install.sh" "$MGR"
	rmdir "$BIN_DIR" 2>/dev/null || true
	drop_sysupgrade_entries "$_purge"
	selinux_forget
	# The machine token is a secret: never leave it behind. Only the expected
	# config directory is touched (same guard as --purge below).
	case "$CONF_DIR" in
	*/etc/W1nCray) rm -f "$CONF_DIR/agent.token" ;;
	esac
	if [ "$_purge" -eq 1 ]; then
		case "$CONF_DIR" in
		*/etc/W1nCray) rm -rf "$CONF_DIR" ;;
		*) die "拒绝删除异常的配置目录路径: $CONF_DIR" ;;
		esac
		green "已卸载并删除 $CONF_DIR"
	else
		green "已卸载（保留配置 $CONF_DIR）"
	fi
}

cmd_run() {
	require_bin
	exec "$BIN" -c "$CONF" "$@"
}

# cmd_xray passes straight through to the program's `xray` command (status,
# start, stop, restart, install [--file ... --sha256 ...], remove). The Xray
# kernel is a service of its own, so the installer never rewrites its unit: the
# program owns it (agent/xraysvc).
cmd_xray() {
	require_bin
	case "${1:-}" in
	status) ;;
	*) need_root ;;
	esac
	"$BIN" -c "$CONF" xray "$@"
}

usage() {
	cat <<'EOF'
W1nCray 管理命令

  W1nCray                    打开管理菜单
  W1nCray start|stop|restart 启动 / 停止 / 重启服务
  W1nCray status             版本、运行状态、开机自启、WebSocket 与最近错误
  W1nCray check              检查配置并向面板验证每个节点
  W1nCray config             编辑配置文件，保存后可立即检查
  W1nCray enable|disable     开机自启 开 / 关
  W1nCray update [版本号] [--lite|--full]  更新程序（默认保持当前的版本类型）
  W1nCray migrate            重新迁移 XrayR 配置（先备份）
  W1nCray switch [-y]        停用 XrayR、启用 W1nCray（失败自动回滚）
  W1nCray rollback           停用 W1nCray、恢复 XrayR
  W1nCray uninstall [--purge] [-y]  卸载（--purge 同时删除配置）
  W1nCray xray status|start|stop|restart|install|remove
                             管理 Xray 内核服务（与面板同一套实现）
  W1nCray xray install --file <W1nCray-xray 文件或 .gz> --sha256 <hex>
                             离线安装 Xray 内核（sha256 必填）
  W1nCray run                前台运行（已有实例在运行时会被拒绝）
  W1nCray version | init ...  程序本体的命令
  W1nCray-xray x25519 | version | check ...  Xray 内核程序本体的命令

首次安装:
  sh install.sh install [--lite|--full] [--prefix DIR] [--with-geo]
                        [--binary 文件 | --url 地址 | --version vX.Y.Z]
                        [--insecure-skip-verify]
                        [--panel 面板地址 --machine 机器ID (--token 令牌 | --token-file 文件)
                         [--allow-http] [--port-range 20000-40000] [--noterminal]]

  安装只装 agent（W1nCray 程序 + 服务），不安装 Xray 内核：Xray 内核由面板在
  绑定节点时自动安装，或手动执行 W1nCray xray install。

  下载的发行包必须通过 SHA256SUMS 校验，缺少 sha256sum / SHA256SUMS 或不匹配都会拒绝安装；
  明知风险仍要跳过时才加 --insecure-skip-verify（或设置 W1NCRAY_INSECURE_SKIP_VERIFY=1）。

升级（update）:
  已是 v11 agent 的机器只更新 agent。
  0.5.x 及以前的单一程序若配置里有 Xray 节点（config.yml 有 Nodes，或
  Agent.Panel.MachineNodes 为真），会先下载 agent 与对应的 Xray 内核资产（OpenWrt 用
  lite），校验 SHA256SUMS 后按顺序：停止旧服务 -> 替换 agent -> 安装并启动 Xray 内核
  服务 -> 启动 agent；下载在停止服务之前完成，中断只有两次进程重启。

面板一键接入（机器模式）:
  --panel 会写出 agent 配置：agent 启动后自动向面板领取本机器的节点与转发规则。
  --panel / --machine 与令牌（--token 或 --token-file，二选一）必须同时提供。
  令牌只写入 <配置目录>/agent.token（权限 600），不会写进 config.yml、agent.yml、日志或子进程参数。
  agent 自己的配置写在 <配置目录>/agent.yml（它整体覆盖 config.yml 里遗留的 Agent: 段）：
  config.yml 只保留 xray 内核的配置。已有的 agent.yml 若已关联面板则不会被覆盖（重复安装幂等）。
  面板地址必须是 https://；仅本机回环地址（localhost / 127.x / ::1）可用明文 http://，
  非回环的 http:// 必须显式加 --allow-http（令牌会明文传输，仅限可信网络）。
  --port-range 指定允许监听的端口区间，默认 20000-40000。
  --noterminal 在本机关闭交互终端（终端默认开启）；它同时透传给提示里的 W1nCray link 命令。
  已有静态 Nodes 时按提示先在面板绑定这些节点，再用 W1nCray link ... --dry-run 迁移
  （link 把静态节点与旧的 Agent: 段迁移到 agent.yml，由你手动执行）。
EOF
	# The log command depends on the service backend; print it live instead of
	# advertising a `log` subcommand the program itself does not have.
	printf '\n查看日志（服务后端 %s）: %s\n' "$BACKEND" "$(log_hint follow)"
}

menu() {
	while :; do
		echo
		echo "================ W1nCray 管理菜单 ================"
		if [ -x "$BIN" ]; then
			printf '  版本: %s\n' "$("$BIN" version 2>/dev/null | head -n1)"
		fi
		_state="未安装服务"
		if svc exists W1nCray; then
			if svc active W1nCray; then _state="运行中"; else _state="未运行"; fi
			if svc enabled W1nCray; then _state="$_state / 开机自启"; else _state="$_state / 未自启"; fi
		fi
		printf '  状态: %s    服务管理器: %s\n' "$_state" "$BACKEND"
		cat <<'EOF'
--------------------------------------------------
   1. 启动        2. 停止        3. 重启
   4. 查看状态    5. 实时日志    6. 检查配置
   7. 编辑配置    8. 开机自启开关    9. 更新程序
  10. 从 XrayR 迁移配置   11. 切换到 W1nCray   12. 回滚到 XrayR
  13. 卸载
  Xray 内核（独立服务）:
  14. 状态   15. 启动   16. 停止   17. 重启   18. 安装   19. 卸载
   0. 退出
==================================================
EOF
		printf '请选择: '
		read -r _c || return 0
		case "$_c" in
		1) cmd_start ;;
		2) cmd_stop ;;
		3) cmd_restart ;;
		4) cmd_status ;;
		5) cmd_log ;;
		6) cmd_check || true ;;
		7) cmd_config ;;
		8)
			if svc enabled W1nCray; then cmd_disable; else cmd_enable; fi
			;;
		9) cmd_update ;;
		10) cmd_migrate ;;
		11) cmd_switch ;;
		12) cmd_rollback ;;
		13) cmd_uninstall ;;
		14) cmd_xray status || true ;;
		15) cmd_xray start || true ;;
		16) cmd_xray stop || true ;;
		17) cmd_xray restart || true ;;
		18) cmd_xray install || true ;;
		19) cmd_xray remove || true ;;
		0 | q | Q | exit) return 0 ;;
		*) yellow "无效的选择" ;;
		esac
	done
}

# dispatch COMMAND [ARGS...]. Run as the `W1nCray` command, anything that is
# not a management command goes to the agent program itself (W1nCray migrate
# --from ..., W1nCray agent-apply -f desired.json, W1nCray -c config.yml); the
# installer script rejects it. The Xray kernel program's own commands
# (W1nCray-xray x25519 ...) are not reachable through this script.
dispatch() {
	_cmd="${1:-}"
	[ $# -gt 0 ] && shift
	case "$_cmd" in
	install) cmd_install "$@" ;;
	update) cmd_update "$@" ;;
	start) cmd_start ;;
	stop) cmd_stop ;;
	restart) cmd_restart ;;
	enable) cmd_enable ;;
	disable) cmd_disable ;;
	status) cmd_status ;;
	log) cmd_log "$@" ;;
	check) if [ "$AS_MANAGER" = 1 ] && [ $# -gt 0 ]; then
		require_bin
		exec "$BIN" check "$@"
	else cmd_check; fi ;;
	config) cmd_config ;;
	migrate) if [ "$AS_MANAGER" = 1 ] && [ $# -gt 0 ]; then
		require_bin
		exec "$BIN" migrate "$@"
	else cmd_migrate; fi ;;
	switch)
		case "${1:-}" in -y | --yes) ASSUME_YES=1 ;; esac
		cmd_switch
		;;
	rollback) cmd_rollback ;;
	uninstall) cmd_uninstall "$@" ;;
	xray) cmd_xray "$@" ;;
	run) cmd_run "$@" ;;
	menu) menu ;;
	help | -h | --help) usage ;;
	"")
		if [ "$AS_MANAGER" = 1 ] && [ -t 0 ]; then menu; else usage; fi
		;;
	*)
		if [ "$AS_MANAGER" = 1 ]; then
			require_bin
			exec "$BIN" "$_cmd" "$@"
		fi
		usage
		exit 1
		;;
	esac
}

main() {
	ASSUME_YES=0
	AS_MANAGER=0
	case "${0##*/}" in W1nCray) AS_MANAGER=1 ;; esac
	load_env
	dispatch "$@"
}

# Sourced by the tests (tests/install_test.sh) without running main.
if [ -z "${W1NCRAY_LIB:-}" ]; then
	main "$@"
fi
