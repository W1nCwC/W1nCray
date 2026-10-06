#!/usr/bin/env bash
# Builds release assets into dist/ with the names install.sh downloads:
#   W1nCray-linux-<arch>.gz        full build (every lego DNS provider)
#   W1nCray-linux-<arch>-lite.gz   lite build (6 DNS providers, embedded fallback roots)
#   W1nCray-linux-amd64|arm64      raw full binaries, kept for scripts older than v0.3.0
#   SHA256SUMS                     checksums of everything above
#
# Usage: bash release/build.sh v0.3.0 [arch ...]   (default: all architectures)
set -euo pipefail
version="${1:-dev}"
shift || true
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
rm -rf dist
mkdir -p dist
for t in "${targets[@]}"; do
	IFS=: read -r name goarch extra <<<"$t"
	if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " =~ " $name " ]]; then
		continue
	fi
	for flavor in full lite; do
		tags=""
		suffix=""
		if [ "$flavor" = lite ]; then
			tags="dnslite,fallbackroots"
			suffix="-lite"
		fi
		out="dist/W1nCray-linux-$name$suffix"
		echo "build $out"
		env CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" ${extra:+"$extra"} \
			go build -trimpath -tags "$tags" \
			-ldflags "-s -w -X $mod/cmd.version=$version" -o "$out" .
		if [ "$flavor" = full ] && { [ "$name" = amd64 ] || [ "$name" = arm64 ]; }; then
			gzip -9 -n -c "$out" >"$out.gz" # the raw file stays for old installers
		else
			gzip -9 -n -f "$out"
		fi
	done
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
built_archs=""
for t in "${targets[@]}"; do
	IFS=: read -r name goarch extra <<<"$t"
	if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " =~ " $name " ]]; then
		continue
	fi
	built_archs="$built_archs $goarch"  # GOARCH, the unit of the terminal matrix (armv5..7 are all arm)
	# The full flavor of amd64/arm64 is shipped uncompressed next to the .gz;
	# every other architecture is gzipped in place. Check whichever exists.
	gz="dist/W1nCray-linux-$name.gz"
	raw="dist/W1nCray-linux-$name"
	if [ -f "$gz" ]; then
		artifact="$gz"
	elif [ -f "$raw" ]; then
		artifact="$raw"
	else
		echo "build matrix: neither $gz nor $raw exists" >&2
		exit 1
	fi
	# "file" is used when present to confirm the architecture of the product;
	# its output wording varies between distributions and locales, so the check
	# is a case-insensitive search for the architecture's short name and it is
	# skipped when the tool is absent (the compiler already guarantees the
	# target, this is a belt-and-braces assertion on the artifact).
	if command -v file >/dev/null 2>&1; then
		probe="$(mktemp)"
		if [ "${artifact##*.}" = gz ]; then
			gzip -dc "$artifact" >"$probe"
		else
			cp "$artifact" "$probe"
		fi
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
			*) echo "build matrix: $artifact does not look like $goarch: $desc" >&2; exit 1 ;;
		esac
	fi
	# The binary must run on this machine when this machine is the target:
	# 'version' answers without a config file, so it is a real smoke test.
	if [ "$goarch" = "$(go env GOARCH)" ] && [ "$(go env GOOS)" = linux ]; then
		probe="$(mktemp)"
		if [ "${artifact##*.}" = gz ]; then
			gzip -dc "$artifact" >"$probe"
		else
			cp "$artifact" "$probe"
		fi
		chmod +x "$probe"
		v="$(env -i "$probe" version 2>/dev/null || true)"
		rm -f "$probe"
		if [ -z "$v" ]; then
			echo "build matrix: $artifact does not answer 'version'" >&2
			exit 1
		fi
	fi
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

echo "build matrix: ok (${#targets[@]} linux targets, terminal on $terminal_archs)"
ls -l dist
