#!/usr/bin/env bash
# Render one real page of the public web through the real images and print what came back.
#   bash deploy/smoke-real.sh https://example.com/        (make smoke-real URL=https://example.com/ [CHROMIUM_IMAGE=...])
#
# It builds the two images (deploy/build.sh, offline; CHROMIUM_IMAGE is the Chromium base already in the Docker daemon, as for
# make test-browser), then starts on throwaway Docker networks:
#   proxy     the egress proxy, on an ordinary network (internet) and on the internal one
#   renderer  the renderer, on the internal network ONLY: it reaches the proxy and nothing else, as in deploy/kubernetes
# makes a throwaway P-256 key pair for the caller "idp-web" and the proxy's admin key, signs one request exactly as idp-web will
# (internal/caller), posts it from a third container on the internal network, and prints the answer and the proxy's audit summary.
# Every container, network, file and (unless KEEP_IMAGES=1) image it made is removed at the end, also when it fails.
set -uo pipefail
cd "$(dirname "$0")/.."
URL="${1:-${URL:-}}"
[[ -n "$URL" ]] || { echo "usage: bash deploy/smoke-real.sh URL   (URL is an http or https address)" >&2; exit 2; }
ID="$$"
PREFIX="idp-browser-smoke-$ID"
INT="$PREFIX-int"; EXT="$PREFIX-ext"
WORK="$(mktemp -d)"
trap 'cleanup' EXIT
cleanup() {
  docker rm -f "$PREFIX-renderer" "$PREFIX-proxy" >/dev/null 2>&1
  docker network rm "$INT" "$EXT" >/dev/null 2>&1
  if [[ "${KEEP_IMAGES:-}" != 1 ]]; then docker rmi "$PREFIX:$VERSION" "$PREFIX-proxy:$VERSION" >/dev/null 2>&1; fi
  rm -rf "$WORK"
}
VERSION="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
[[ -z "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]] || VERSION="$VERSION-dirty"

# the images, and the helper that signs and summarizes (a static binary run from a mounted directory)
CHROMIUM_IMAGE="${CHROMIUM_IMAGE:-}" bash deploy/build.sh "$PREFIX" >/dev/null || { echo "image build failed" >&2; exit 1; }
CGO_ENABLED=0 go build -trimpath -o "$WORK/smoke" ./cmd/idp-browser-smoke || exit 1
CGO_ENABLED=0 go run ./cmd/idp-browser-smoke keygen "$WORK" || exit 1
chmod 755 "$WORK"

docker network create --internal "$INT" >/dev/null || exit 1
docker network create "$EXT" >/dev/null || exit 1
docker create --name "$PREFIX-proxy" --network "$EXT" --network-alias proxy --read-only --cap-drop ALL \
  -v "$WORK:/k:ro" \
  -e IDP_BROWSER_PROXY_LISTEN=0.0.0.0:3128 -e IDP_BROWSER_PROXY_ADMIN_LISTEN=0.0.0.0:3129 -e IDP_BROWSER_PROXY_METRICS=0.0.0.0:9591 \
  -e IDP_BROWSER_PRIVATE_NETWORK=true -e IDP_BROWSER_PROXY_ADMIN_KEY_FILE=/k/admin.key \
  "$PREFIX-proxy:$VERSION" >/dev/null || exit 1
docker network connect --alias proxy "$INT" "$PREFIX-proxy" || exit 1
docker start "$PREFIX-proxy" >/dev/null || exit 1
# seccomp is unconfined for Chromium's own sandbox (no gVisor here), as in make test-browser; the network is what is limited
docker run -d --name "$PREFIX-renderer" --network "$INT" --network-alias renderer --read-only --cap-drop ALL --security-opt seccomp=unconfined \
  --user 10600:10600 --tmpfs /profile:rw,uid=10600,gid=10600,size=2g --tmpfs /tmp:rw,exec,mode=1777,size=256m --memory 4g \
  -v "$WORK:/k:ro" \
  -e IDP_BROWSER_LISTEN=0.0.0.0:8590 -e IDP_BROWSER_METRICS=0.0.0.0:9590 -e IDP_BROWSER_PRIVATE_NETWORK=true \
  -e IDP_BROWSER_CALLER_KEYS_FILE=/k/caller.pub -e IDP_BROWSER_CALLER_AUDIENCE=http://renderer:8590/render \
  -e IDP_BROWSER_PROXY=proxy:3128 -e IDP_BROWSER_PROXY_ADMIN=http://proxy:3129 -e IDP_BROWSER_PROXY_ADMIN_KEY_FILE=/k/admin.key \
  "$PREFIX:$VERSION" >/dev/null || exit 1

echo "== render $URL"
docker run --rm --name "$PREFIX-client" --network "$INT" -v "$WORK:/k:ro" --entrypoint /k/smoke "$PREFIX-proxy:$VERSION" \
  render -base http://renderer:8590 -ops http://renderer:9590 -audience http://renderer:8590/render -key /k/caller.key "$URL"
status=$?
echo "== from the renderer's network (no way out but the proxy): direct connections to the internet must fail"
if docker run --rm --name "$PREFIX-isolation" --network "$INT" --entrypoint /k/smoke -v "$WORK:/k:ro" "$PREFIX-proxy:$VERSION" \
     probe 93.184.216.34:80 1.1.1.1:443 8.8.8.8:53; then
  echo "  ok: the internal network has no way out"
else
  echo "  PROBLEM: a connection got out of the internal network without the proxy"
fi
docker logs "$PREFIX-proxy" 2>&1 | docker run --rm -i --name "$PREFIX-audit" --entrypoint /k/smoke -v "$WORK:/k:ro" "$PREFIX-proxy:$VERSION" audit
exit $status
