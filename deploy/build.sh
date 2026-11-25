#!/usr/bin/env bash
# Build the two images offline: static binaries on the host, then docker build --network none.
#   bash deploy/build.sh [TAG_PREFIX]      (default idp-browser: images idp-browser:<version> and idp-browser-proxy:<version>)
# The Chromium base is taken from CHROMIUM_IMAGE if set (an image already in the Docker daemon), else the pinned digest of
# deploy/Dockerfile is pulled with tools/pull_image.sh's retries (or loaded with crane: see docs/RUNBOOK.md).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
[[ -z "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]] || VERSION="$VERSION-dirty"
PREFIX="${1:-idp-browser}"
OUT=build/image
umask 022
rm -rf "$OUT" && mkdir -p "$OUT/browser" "$OUT/proxy"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/browser/idp-browser" ./cmd/idp-browser
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/proxy/idp-browser-proxy" ./cmd/idp-browser-proxy
cp deploy/Dockerfile "$OUT/browser/Dockerfile"
cp deploy/Dockerfile.proxy "$OUT/proxy/Dockerfile"
ARGS=()
if [[ -n "${CHROMIUM_IMAGE:-}" ]]; then ARGS=(--build-arg "CHROMIUM_IMAGE=$CHROMIUM_IMAGE"); fi
docker build --network none -q "${ARGS[@]}" -t "$PREFIX:$VERSION" "$OUT/browser" >/dev/null
docker build --network none -q -t "$PREFIX-proxy:$VERSION" "$OUT/proxy" >/dev/null
echo "OK: $PREFIX:$VERSION $(docker image inspect --format '{{.Id}}' "$PREFIX:$VERSION" | cut -c1-19)… $PREFIX-proxy:$VERSION $(docker image inspect --format '{{.Id}}' "$PREFIX-proxy:$VERSION" | cut -c1-19)…"
