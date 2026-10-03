#!/usr/bin/env bash
# W1nCray installer: install / upgrade, migrate from XrayR, switch, roll back.
#
#   bash install.sh install  [--binary FILE | --url URL | --version vX.Y.Z]
#   bash install.sh migrate                 re-run the XrayR migration (backs up /etc/W1nCray)
#   bash install.sh check                   validate the config against the panel
#   bash install.sh switch   [-y]           stop XrayR, start W1nCray (automatic rollback on failure)
#   bash install.sh rollback                stop W1nCray, start XrayR again
#   bash install.sh status | log
#   bash install.sh uninstall [--purge]
#
# XrayR files are never modified. XrayR keeps running until `switch`.

set -euo pipefail

REPO="${W1NCRAY_REPO:-W1nCwC/W1nCray}"
BIN_DIR="/usr/local/W1nCray"
BIN="$BIN_DIR/W1nCray"
LINK="/usr/local/bin/W1nCray"
CONF_DIR="/etc/W1nCray"
CONF="$CONF_DIR/config.yml"
UNIT="/etc/systemd/system/W1nCray.service"
XRAYR_DIR="${XRAYR_DIR:-/etc/XrayR}"
XRAYR_UNIT="XrayR"
GEO_BASE="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
SELF="$BIN_DIR/install.sh"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
die() { red "错误: $*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "请使用 root 运行"; }
need_systemd() { command -v systemctl >/dev/null 2>&1 || die "需要 systemd"; }

arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) die "不支持的架构: $(uname -m)" ;;
	esac
}

download() { # url dest
	if command -v curl >/dev/null 2>&1; then
		curl -fL --retry 3 --connect-timeout 15 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "需要 curl 或 wget"
	fi
}

unit_exists() { systemctl list-unit-files "$1.service" --no-legend 2>/dev/null | grep -q "^$1.service"; }
unit_active() { systemctl is-active --quiet "$1" 2>/dev/null; }
unit_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }
xrayr_present() { unit_exists "$XRAYR_UNIT" || [ -f "$XRAYR_DIR/config.yml" ]; }

write_unit() {
	cat >"$UNIT" <<EOF
[Unit]
Description=W1nCray Xboard node backend
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$CONF_DIR
ExecStart=$BIN -c $CONF
Restart=on-failure
RestartSec=10
LimitNOFILE=1048576
Environment=XRAY_LOCATION_ASSET=$CONF_DIR

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
}

fetch_binary() { # source args -> path of a verified binary
	local src="$1" url tmp
	tmp="$(mktemp)"
	case "$src" in
	file:*) cp "${src#file:}" "$tmp" ;;
	url:*) download "${src#url:}" "$tmp" ;;
	version:*)
		url="https://github.com/$REPO/releases/download/${src#version:}/W1nCray-linux-$(arch)"
		download "$url" "$tmp" || die "下载失败: $url"
		;;
	latest)
		url="https://github.com/$REPO/releases/latest/download/W1nCray-linux-$(arch)"
		download "$url" "$tmp" || die "下载失败: $url（尚未发布 Release 时请用 --binary 指定本地文件）"
		;;
	esac
	chmod +x "$tmp"
	"$tmp" version >/dev/null 2>&1 || die "二进制无法运行（架构不符或文件损坏）"
	echo "$tmp"
}

# save_self keeps a copy of this script for later commands; when it runs from
# a pipe (bash <(curl ...)) it is fetched from the repository instead.
save_self() {
	if [ -f "$0" ] && [ "$(readlink -f "$0")" != "$SELF" ]; then
		install -m 0755 "$0" "$SELF"
	elif [ ! -f "$SELF" ]; then
		download "https://raw.githubusercontent.com/$REPO/main/install.sh" "$SELF" && chmod 0755 "$SELF" ||
			yellow "未能保存安装脚本副本，后续命令请重新下载 install.sh 执行"
	fi
}

ensure_geo() {
	local f
	for f in geoip.dat geosite.dat; do
		if [ ! -s "$CONF_DIR/$f" ]; then
			yellow "下载 $f ..."
			if download "$GEO_BASE/$f" "$CONF_DIR/$f.tmp"; then
				mv "$CONF_DIR/$f.tmp" "$CONF_DIR/$f"
			else
				rm -f "$CONF_DIR/$f.tmp"
				yellow "下载 $f 失败；仅当路由使用 geosite:/geoip: 时需要，可稍后手动放入 $CONF_DIR"
			fi
		fi
	done
}

backup_conf() {
	if [ -d "$CONF_DIR" ]; then
		local b
		b="$CONF_DIR.bak.$(date +%Y%m%d-%H%M%S)"
		cp -a "$CONF_DIR" "$b"
		green "已备份 $CONF_DIR -> $b"
	fi
}

run_check() {
	echo
	if "$BIN" check -c "$CONF" --online; then
		return 0
	fi
	red "配置检查未通过，请根据上面的提示修改 $CONF 后执行: bash $SELF check"
	return 1
}

cmd_install() {
	local src="latest"
	while [ $# -gt 0 ]; do
		case "$1" in
		--binary) src="file:$2"; shift 2 ;;
		--url) src="url:$2"; shift 2 ;;
		--version) src="version:$2"; shift 2 ;;
		*) die "未知参数: $1" ;;
		esac
	done
	need_root
	need_systemd

	local tmp was_active=0
	tmp="$(fetch_binary "$src")"
	unit_active W1nCray && was_active=1
	mkdir -p "$BIN_DIR"
	install -m 0755 "$tmp" "$BIN"
	rm -f "$tmp"
	ln -sf "$BIN" "$LINK"
	save_self
	green "已安装 $("$BIN" version)"

	mkdir -p "$CONF_DIR"
	if [ ! -f "$CONF" ]; then
		if [ -f "$XRAYR_DIR/config.yml" ]; then
			green "检测到 XrayR 配置，开始迁移（XrayR 文件只读，不会被修改）"
			"$BIN" migrate --from "$XRAYR_DIR" --to "$CONF_DIR"
		else
			"$BIN" init --dir "$CONF_DIR"
			yellow "已生成默认配置，请编辑 $CONF 填写 ApiHost / ApiKey / NodeID"
		fi
	else
		yellow "保留现有配置 $CONF（重新迁移请执行: bash $SELF migrate）"
	fi
	ensure_geo
	write_unit

	if [ "$was_active" -eq 1 ]; then
		systemctl restart W1nCray
		green "W1nCray 已重启（升级完成）"
		return
	fi
	local check_failed=0
	run_check || check_failed=1
	if xrayr_present && { unit_active "$XRAYR_UNIT" || unit_enabled "$XRAYR_UNIT"; }; then
		yellow "XrayR 仍在运行/开机自启，为避免端口冲突，W1nCray 暂未启动。"
		yellow "确认无误后执行: bash $SELF switch   （失败会自动回滚到 XrayR）"
	elif [ "$check_failed" -eq 0 ]; then
		systemctl enable --now W1nCray
		green "W1nCray 已启动并设为开机自启"
	fi
}

cmd_migrate() {
	need_root
	[ -x "$BIN" ] || die "请先执行 install"
	[ -f "$XRAYR_DIR/config.yml" ] || die "未找到 $XRAYR_DIR/config.yml"
	backup_conf
	"$BIN" migrate --from "$XRAYR_DIR" --to "$CONF_DIR" --force
	ensure_geo
	run_check || true
	if unit_active W1nCray; then
		yellow "W1nCray 正在运行，配置文件变更会自动重载"
	fi
}

cmd_switch() {
	local yes=0
	[ "${1:-}" = "-y" ] && yes=1
	need_root
	need_systemd
	[ -x "$BIN" ] || die "请先执行 install"
	run_check || die "检查未通过，未做切换"
	if [ "$yes" -ne 1 ]; then
		read -r -p "将停止并禁用 XrayR、启用 W1nCray，确认？[y/N] " a
		case "$a" in y | Y | yes) ;; *) die "已取消" ;; esac
	fi
	if unit_exists "$XRAYR_UNIT"; then
		systemctl stop "$XRAYR_UNIT" || true
		systemctl disable "$XRAYR_UNIT" >/dev/null 2>&1 || true
	fi
	systemctl enable --now W1nCray
	sleep 5
	if unit_active W1nCray; then
		green "切换完成，W1nCray 运行中。回滚: bash $SELF rollback"
		journalctl -u W1nCray -n 20 --no-pager || true
	else
		red "W1nCray 启动失败，自动回滚到 XrayR"
		journalctl -u W1nCray -n 50 --no-pager || true
		cmd_rollback
		exit 1
	fi
}

cmd_rollback() {
	need_root
	need_systemd
	systemctl stop W1nCray >/dev/null 2>&1 || true
	systemctl disable W1nCray >/dev/null 2>&1 || true
	if unit_exists "$XRAYR_UNIT"; then
		systemctl enable --now "$XRAYR_UNIT"
		sleep 2
		unit_active "$XRAYR_UNIT" && green "已恢复 XrayR" || red "XrayR 未能启动，请检查: journalctl -u $XRAYR_UNIT"
	else
		yellow "未找到 XrayR 服务，仅停止了 W1nCray"
	fi
}

cmd_uninstall() {
	need_root
	systemctl disable --now W1nCray >/dev/null 2>&1 || true
	rm -f "$UNIT" "$LINK"
	rm -rf "$BIN_DIR"
	systemctl daemon-reload || true
	if [ "${1:-}" = "--purge" ]; then
		rm -rf "$CONF_DIR"
		green "已卸载并删除 $CONF_DIR"
	else
		green "已卸载（保留配置 $CONF_DIR）"
	fi
}

usage() {
	cat <<'EOF'
用法: bash install.sh <命令>
  install  [--binary FILE | --url URL | --version vX.Y.Z]  安装/升级；有 XrayR 配置时自动迁移
  migrate                 重新迁移 XrayR 配置（先备份 /etc/W1nCray）
  check                   检查配置并向面板验证节点
  switch   [-y]           停用 XrayR、启用 W1nCray（失败自动回滚）
  rollback                停用 W1nCray、恢复 XrayR
  status | log            查看状态 / 实时日志
  uninstall [--purge]     卸载（--purge 同时删除 /etc/W1nCray）
EOF
}

main() {
	local c="${1:-}"
	[ $# -gt 0 ] && shift
	case "$c" in
	install) cmd_install "$@" ;;
	migrate) cmd_migrate ;;
	check) run_check ;;
	switch) cmd_switch "$@" ;;
	rollback) cmd_rollback ;;
	status) systemctl status W1nCray --no-pager || true ;;
	log) journalctl -u W1nCray -f ;;
	uninstall) cmd_uninstall "$@" ;;
	*) usage; exit 1 ;;
	esac
}

main "$@"
