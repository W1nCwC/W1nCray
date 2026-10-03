#!/usr/bin/env bash
# Builds release binaries into dist/ with the names install.sh downloads:
#   dist/W1nCray-linux-amd64, dist/W1nCray-linux-arm64
# Usage: bash release/build.sh v1.0.0
set -euo pipefail
version="${1:-dev}"
cd "$(dirname "$0")/.."
mkdir -p dist
for arch in amd64 arm64; do
	CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
		-ldflags "-s -w -X github.com/W1nCwC/W1nCray/cmd.version=$version" \
		-o "dist/W1nCray-linux-$arch" .
done
(cd dist && sha256sum W1nCray-linux-* >SHA256SUMS)
ls -l dist
