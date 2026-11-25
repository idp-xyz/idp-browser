# idp-browser build and test entry points.
#
#   make test           everything that needs no Chromium: vet, unit tests with the race detector, the manifests (tests/deploy)
#   make test-browser   the tests that need Chromium, run inside the image as the pod's user (needs Docker and the Chromium base
#                       image in the daemon: see docs/RUNBOOK.md, "Chromium 镜像的获取")
#   make image          build the two images offline (deploy/build.sh)
#   make smoke-real URL=https://...   render one real page through the real images and print what came back (deploy/smoke-real.sh)
TEST_IMAGE_PREFIX ?= idp-browser-test
# CHROMIUM_IMAGE (optional): a Chromium base already in the Docker daemon, instead of the pinned digest of deploy/Dockerfile
CHROMIUM_IMAGE ?=
# extra arguments of the browser tests, for example TESTFLAGS="-test.run TestJS"
TESTFLAGS ?=

.PHONY: build vet test image test-browser smoke-real

build:
	go build -o bin/ ./cmd/...

vet:
	gofmt -l . | (! grep .) && go vet ./... && go vet -tags browser ./...

# ./... includes tests/deploy: the Kubernetes manifests against the code (the egress policy against internal/addr).
# Without the browser tag, so nothing here starts Chromium.
test: vet
	go test -race ./...

image:
	CHROMIUM_IMAGE=$(CHROMIUM_IMAGE) bash deploy/build.sh

# The browser tests are one static binary (no cgo, so no race detector) that runs in the renderer's own image: the same
# Chromium, the same libraries, the same user (10600), a read-only root filesystem, a tmpfs for the profile and all capabilities
# dropped. Seccomp is unconfined because Chromium's own sandbox needs user namespaces, which Docker's default profile refuses;
# in Kubernetes the RuntimeClass (gVisor or Kata) is the sandbox (ADR-0001 D9). The container is named and is removed by --rm.
test-browser:
	@mkdir -p build/test
	CGO_ENABLED=0 go test -c -tags browser -o build/test/browser.test ./tests/browser
	CHROMIUM_IMAGE=$(CHROMIUM_IMAGE) bash deploy/build.sh $(TEST_IMAGE_PREFIX)
	@IMG=$$(docker images --format '{{.Repository}}:{{.Tag}}' | grep "^$(TEST_IMAGE_PREFIX):" | head -1); \
	docker run --rm --name idp-browser-test-run-$$$$ --user 10600:10600 --read-only --cap-drop ALL --security-opt seccomp=unconfined \
	  --tmpfs /profile:rw,uid=10600,gid=10600,size=3g --tmpfs /tmp:rw,exec,mode=1777,size=512m --memory 6g \
	  -v $$PWD/build/test:/t:ro --entrypoint /t/browser.test $$IMG -test.v -test.timeout 20m $(TESTFLAGS)

# One render of a real page of the public web, through the two images on throwaway Docker networks (the renderer's has no way
# out but the proxy). Needs Docker, the Chromium base image in the daemon (CHROMIUM_IMAGE=...) and internet for the proxy.
smoke-real:
	@test -n "$(URL)" || { echo "usage: make smoke-real URL=https://example.com/ [CHROMIUM_IMAGE=...]"; exit 2; }
	CHROMIUM_IMAGE=$(CHROMIUM_IMAGE) bash deploy/smoke-real.sh "$(URL)"
