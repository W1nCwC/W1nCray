#!/usr/bin/env bash
# Builds the v11 release assets into dist/ with the names install.sh downloads.
#
# Two programs are built for every target of the matrix, and both carry the
# same version number:
#
#   agent (the W1nCray program, built from the repository root; it does NOT
#   link Xray-core):
#     W1nCray-linux-<arch>.gz        the single agent build, with -tags
#                                    fallbackroots so a device without a system
#                                    CA bundle can still do HTTPS
#     W1nCray-linux-amd64|arm64      raw binary, kept for scripts older than
#                                    v0.3.0
#     W1nCray-linux-<arch>-lite.gz   byte-for-byte copy of the .gz above. It
#                                    exists only because install.sh releases
#                                    before v11 ask for the "-lite" name on
#                                    OpenWrt; the agent has no separate lite
#                                    build any more (no DNS providers, no ACME)
#
#   Xray kernel (./cmd/w1ncray-xray):
#     W1nCray-xray-linux-<arch>.gz       full build
#     W1nCray-xray-linux-<arch>-lite.gz  -tags dnslite,fallbackroots (OpenWrt)
#
#   SHA256SUMS                         checksums of every artifact above
#
# Usage: bash release/build.sh [vX.Y.Z] [arch ...]   (default: all architectures)
#   The version is optional: `build.sh amd64 mipsle` builds those two targets
#   with the default version, `build.sh v0.6.0 amd64 mipsle` pins it.
set -euo pipefail
version="${1:-dev}"
shift || true

# The first positional argument is historically the version. A bare
# architecture name is accepted as shorthand (see the usage line) so the WP-X3
# acceptance command `build.sh amd64 mipsle` builds those targets instead of
# treating "amd64" as a version string.
case "$version" in
	amd64 | 386 | arm64 | armv7 | armv6 | armv5 | mips | mipsle | mips64 | mips64le | riscv64 | loong64)
		set -- "$version" "$@"
		version="dev"
		;;
esac

cd "$(dirname "$0")/.."

# name:GOARCH:extra env (softfloat: routers rarely have an FPU)
targets=(
	"amd64:amd64:"
	"386:386:GO386=softfloat"
	"arm64:arm64:"
	"armv7:arm:GOARM=7"
	"armv6:arm:GOARM=6"
	"armv5:arm:GOARM=5"
	"mips:mips:GOMIPS=softfloat"
	"mipsle:mipsle:GOMIPS=softfloat"
	"mips64:mips64:GOMIPS64=softfloat"
	"mips64le:mips64le:GOMIPS64=softfloat"
	"riscv64:riscv64:"
	"loong64:loong64:"
)
want=("$@")

mod=github.com/W1nCwC/W1nCray
# The same version goes into both programs: cmd.version for the agent and
# xraynode.Version for the kernel (which prints it as "W1nCray-xray v...").
agent_ldflags="-s -w -X $mod/cmd.version=$version"
xray_ldflags="-s -w -X $mod/xraynode.Version=$version"

rm -rf dist
mkdir -p dist

# build_agent NAME GOARCH EXTRA builds the single agent program and its assets.
build_agent() {
	name="$1"
	goarch="$2"
	extra="$3"
	out="dist/W1nCray-linux-$name"
	echo "build $out"
	env CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" ${extra:+"$extra"} \
		go build -trimpath -tags fallbackroots \
		-ldflags "$agent_ldflags" -o "$out" .
	gzip -9 -n -c "$out" >"$out.gz"
	# Compatibility copy: pre-v11 install.sh versions pick the "-lite" name on
	# OpenWrt. Same bytes, same SHA256SUMS entry, so the check still passes.
	cp "$out.gz" "$out-lite.gz"
	if [ "$name" = amd64 ] || [ "$name" = arm64 ]; then
		: # the raw file stays for installers older than v0.3.0
	else
		rm -f "$out"
	fi
}

# build_xray NAME GOARCH EXTRA FLAVOR builds the Xray kernel program.
build_xray() {
	name="$1"
	goarch="$2"
	extra="$3"
	flavor="$4"
	tags=""
	suffix=""
	if [ "$flavor" = lite ]; then
		tags="dnslite,fallbackroots"
		suffix="-lite"
	fi
	out="dist/W1nCray-xray-linux-$name$suffix"
	echo "build $out"
	env CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" ${extra:+"$extra"} \
		go build -trimpath -tags "$tags" \
		-ldflags "$xray_ldflags" -o "$out" ./cmd/w1ncray-xray
	gzip -9 -n -f "$out"
}

for t in "${targets[@]}"; do
	IFS=: read -r name goarch extra <<<"$t"
	if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " =~ " $name " ]]; then
		continue
	fi
	build_agent "$name" "$goarch" "$extra"
	build_xray "$name" "$goarch" "$extra" full
	build_xray "$name" "$goarch" "$extra" lite
done
(cd dist && sha256sum -- * | grep -v ' SHA256SUMS$' >SHA256SUMS)

# ---- build-matrix assertions (WP-G6 acceptance 1 / design section 6.8) ------
#
# Every product of this script must be a real executable for its architecture,
# and the interactive terminal (agent/terminal, creack/pty) must compile for all
# of them. A platform whose PTY does not build falls back to
# agent/terminal/pty_unsupported.go, reports Supported() == false at runtime and
# never declares the "terminal" capability in hello.capabilities; the check
# below fails the build instead of silently shipping such a product, because
# this release matrix is exactly the set the design validated.
terminal_archs="amd64 386 arm arm64 mips mipsle mips64 mips64le riscv64 loong64"

# gunzip_to ARTIFACT DEST copies ARTIFACT to DEST, decompressing a .gz.
gunzip_to() {
	if [ "${1##*.}" = gz ]; then
		gzip -dc "$1" >"$2"
	else
		cp "$1" "$2"
	fi
}

# check_artifact ARTIFACT GOARCH LABEL asserts the architecture (with file(1),
# when present) and runs the binary's `version` when this machine is the target.
# A cross build cannot be executed here; that is skipped and noted.
check_artifact() {
	artifact="$1"
	goarch="$2"
	label="$3"
	# "file" output wording varies between distributions and locales, so the
	# check is a case-insensitive search for the architecture's short name and
	# it is skipped when the tool is absent (the compiler already guarantees
	# the target, this is a belt-and-braces assertion on the artifact).
	if command -v file >/dev/null 2>&1; then
		probe="$(mktemp)"
		gunzip_to "$artifact" "$probe"
		desc="$(file -b "$probe" | tr 'A-Z' 'a-z')"
		rm -f "$probe"
		case "$goarch" in
			amd64) want_desc="x86-64" ;;
			386) want_desc="386" ;;  # "80386" or "i386" depending on the file database
			arm64) want_desc="aarch64" ;;
			arm) want_desc="arm" ;;
			# file reports the MIPS family as "mips" (32-bit) or "mips64"
			# depending on the database; both names are accepted for both
			# widths, since the byte order is what the compiler fixed.
			mips64) want_desc="mips" ;;
			mips64le) want_desc="mips" ;;
			mips) want_desc="mips" ;;
			mipsle) want_desc="mips" ;;
			riscv64) want_desc="risc-v" ;;
			loong64) want_desc="loongarch" ;;
			*) want_desc="$goarch" ;;
		esac
		case "$desc" in
			*"$want_desc"*) ;;
			*) echo "build matrix: $artifact ($label) does not look like $goarch: $desc" >&2; exit 1 ;;
		esac
	fi
	# The binary must run on this machine when this machine is the target:
	# 'version' answers without a config file, so it is a real smoke test.
	if [ "$goarch" = "$(go env GOARCH)" ] && [ "$(go env GOOS)" = linux ]; then
		probe="$(mktemp)"
		gunzip_to "$artifact" "$probe"
		chmod +x "$probe"
		v="$(env -i "$probe" version 2>/dev/null || true)"
		rm -f "$probe"
		if [ -z "$v" ]; then
			echo "build matrix: $artifact ($label) does not answer 'version'" >&2
			exit 1
		fi
	else
		echo "build matrix: $artifact ($label) version self-check skipped (cross build for linux/$goarch on $(go env GOOS)/$(go env GOARCH))"
	fi
}

# check_modules ARTIFACT WANT: WANT=xray-core requires github.com/xtls/xray-core
# in the binary's module list, WANT=no-xray-core forbids it. The check reads the
# embedded build info, so it works on a cross-compiled binary too.
check_modules() {
	artifact="$1"
	want_mod="$2"
	probe="$(mktemp)"
	gunzip_to "$artifact" "$probe"
	if ! mods="$(go version -m "$probe" 2>/dev/null)"; then
		rm -f "$probe"
		echo "build matrix: go version -m $artifact failed (no build info?)" >&2
		exit 1
	fi
	rm -f "$probe"
	case "$want_mod" in
		xray-core)
			if ! printf '%s\n' "$mods" | grep -q 'github.com/xtls/xray-core'; then
				echo "build matrix: $artifact does not link github.com/xtls/xray-core; it is not the Xray kernel" >&2
				exit 1
			fi
			;;
		no-xray-core)
			if printf '%s\n' "$mods" | grep -q 'github.com/xtls/xray-core'; then
				echo "build matrix: the agent artifact $artifact links github.com/xtls/xray-core" >&2
				exit 1
			fi
			;;
	esac
}

built_archs=""
for t in "${targets[@]}"; do
	IFS=: read -r name goarch extra <<<"$t"
	if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " =~ " $name " ]]; then
		continue
	fi
	built_archs="$built_archs $goarch"  # GOARCH, the unit of the terminal matrix (armv5..7 are all arm)

	# ---- agent ----
	# The full flavor of amd64/arm64 is shipped uncompressed next to the .gz;
	# every other architecture is gzipped in place. Check whichever exists.
	agent_gz="dist/W1nCray-linux-$name.gz"
	agent_raw="dist/W1nCray-linux-$name"
	if [ -f "$agent_gz" ]; then
		agent_art="$agent_gz"
	elif [ -f "$agent_raw" ]; then
		agent_art="$agent_raw"
	else
		echo "build matrix: neither $agent_gz nor $agent_raw exists" >&2
		exit 1
	fi
	check_artifact "$agent_art" "$goarch" agent
	# The split (WP-X1) must hold for the shipped binary, not only in
	# `go list -deps`: the agent carries no Xray-core.
	check_modules "$agent_art" no-xray-core

	# ---- Xray kernel ----
	for flavor in "" "-lite"; do
		xray_art="dist/W1nCray-xray-linux-$name$flavor.gz"
		if [ ! -f "$xray_art" ]; then
			echo "build matrix: $xray_art does not exist" >&2
			exit 1
		fi
		check_artifact "$xray_art" "$goarch" "xray$flavor"
	done
	check_modules "dist/W1nCray-xray-linux-$name.gz" xray-core
done

# The declared terminal matrix must be exactly the platforms the release ships,
# and the PTY package must compile for every one of them with CGO disabled. The
# first assertion only applies to a full build: a partial build (an explicit
# architecture list) is a development shortcut, not a release.
if [ ${#want[@]} -eq 0 ]; then
	for a in $terminal_archs; do
		case " $built_archs " in
			*" $a "*) ;;
			*) echo "build matrix: the terminal matrix lists $a, which this release does not build" >&2; exit 1 ;;
		esac
	done
fi
for a in $terminal_archs; do
	env CGO_ENABLED=0 GOOS=linux GOARCH="$a" go build -o /dev/null ./agent/terminal || {
		echo "build matrix: agent/terminal does not compile for linux/$a" >&2
		exit 1
	}
done
# darwin is part of the design's matrix even though this script only ships
# Linux assets; assert it here so a change that breaks it is caught in the same
# run.
for a in amd64 arm64; do
	env CGO_ENABLED=0 GOOS=darwin GOARCH="$a" go build -o /dev/null ./agent/terminal || {
		echo "build matrix: agent/terminal does not compile for darwin/$a" >&2
		exit 1
	}
done
# Windows has no PTY: the package must still build, with Supported() == false.
env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /dev/null ./agent/terminal || {
	echo "build matrix: agent/terminal does not compile for windows/amd64" >&2
	exit 1
}

echo "build matrix: ok (${#targets[@]} linux targets, agent + W1nCray-xray, terminal on $terminal_archs)"
ls -l dist
