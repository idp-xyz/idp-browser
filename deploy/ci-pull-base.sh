#!/usr/bin/env bash
# Pull the Chromium base image of the renderer (the platform's mirror of chromedp's headless-shell, by digest) for CI, with retries
# for the registry's anonymous rate limits, and say clearly what is wrong when it cannot be had.
#   bash deploy/ci-pull-base.sh IMAGE
# The mirror package ghcr.io/idp-xyz/mirror must be PUBLIC for an anonymous pull: until its owner makes it public, or when this
# image has not been copied into it yet (the platform's mirror workflow, releases/mirror-images.yaml), the pull is refused and
# every attempt fails the same way.
set -uo pipefail
IMAGE="${1:?usage: ci-pull-base.sh IMAGE}"
WAITS=(${IDP_PULL_WAITS:-10 20 40})
for ((try = 1; ; try++)); do
  if msg="$(docker pull -q "$IMAGE" 2>&1 >/dev/null)"; then
    echo "pulled $IMAGE"
    exit 0
  fi
  if ((try > ${#WAITS[@]})); then
    last="$(tail -n 1 <<<"$msg" | cut -c1-300)"
    echo "::error title=Chromium base image::the mirror package ghcr.io/idp-xyz/mirror is not public yet (or this image is not mirrored): could not pull $IMAGE after $try attempts: $last"
    echo "the mirror package ghcr.io/idp-xyz/mirror is not public yet (or this image is not mirrored)" >&2
    echo "  image: $IMAGE" >&2
    echo "  last error: $last" >&2
    echo "  to fix: make the package public (GitHub: the org's Packages > mirror > Package settings > Change visibility)," >&2
    echo "  and check that the image is in releases/mirror-images.yaml and the mirror workflow has copied it" >&2
    exit 2
  fi
  echo "pull $IMAGE: attempt $try failed: $(tail -n 1 <<<"$msg" | cut -c1-200); again in ${WAITS[try - 1]} s" >&2
  sleep "${WAITS[try - 1]}"
done
