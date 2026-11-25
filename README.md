# idp-browser

The browser of the IDP TELOS platform: a render pool that idp-web uses to read pages whose text is made by JavaScript (layer 1), later browsing sessions and member takeover (layers 2 and 3). Plan: the platform repository, `docs/adr/browser-capability-plan.md`.

This repository holds **layer 1** (tasks L1-1 and L1-2 of the plan): the render pool and the browser egress proxy.

```
idp-web ──POST /render (signed, ES256)──▶ idp-browser ──▶ Chromium (one browser context per render)
                                               │                    │
                                  register/finish a render          └─ every request ─▶ idp-browser-proxy ──▶ the public internet
                                  (admin port, shared key)               (public addresses only, per-render budget, audit)
```

| Binary | What it is | Image |
|---|---|---|
| `cmd/idp-browser` | the renderer: `POST /render {url, timeoutMs, maxBytes}`, the pool of Chromium processes (chromedp) | `idp-browser`: a pinned Chromium (chromedp `headless-shell`) and the binary, no shell |
| `cmd/idp-browser-proxy` | the egress proxy: CONNECT and plain-HTTP forwarding to public addresses only | `idp-browser-proxy`: one static binary |

Why two binaries and not a mode of one: the renderer pod may reach only the proxy and the proxy pod may reach the internet and not the cluster (NetworkPolicy); one pod cannot have both rules, and the pod that is on the internet should not carry a browser (ADR-0001 D3).

## The API

`POST /render`, body `{"url": "https://example.com/a", "timeoutMs": 15000, "maxBytes": 5242880}` (`timeoutMs` 1000 to 60000, default 15000; `maxBytes` 1024 to 20 MiB, default 5 MiB). Header `Authorization: Bearer <assertion>`: idp-web's ES256 signature over the request (`internal/caller`; ADR-0001 D8).

Success, 200: `{"finalUrl", "html", "status", "title", "requests", "blocked", "bytes", "ms", "truncated"?, "limit"?, "settled"}`.
Failure: `{"error": {"code": "<reason code>", "message": "..."}}` with 400 `invalid_request`, 422 `not_allowed`, 502 `render_failed` and `blocked_by_site`, 503 `render_busy`, 504 `render_timeout`, and 401 `unauthorized` for a request that is not idp-web's.

## Build and test

| Command | What it does |
|---|---|
| `make test` | vet, `go test -race ./...`: the proxy, the signature, the service, the address rules, the manifests (`tests/deploy`). Needs no Chromium. |
| `make test-browser` | the tests that need Chromium (`tests/browser`, build tag `browser`): builds the images offline, then runs one static test binary **inside the renderer image** as the pod's user. Needs Docker and the Chromium base image in the daemon (`CHROMIUM_IMAGE=<image>` if it has another name; see `docs/RUNBOOK.md`). `TESTFLAGS="-test.run TestWebRTC"` runs one. |
| `make smoke-real URL=https://…` | renders one real page through the real images on throwaway networks (renderer has no way out but the proxy), signs the request as idp-web will, prints the answer and the proxy's audit summary; removes everything it started. See RUNBOOK 7.1. |
| `make image` | `deploy/build.sh`: both images, offline. |

## Documents

- `docs/adr/ADR-0001-browser-design.md`: the decisions, with the removal table (each control removed once, the test that fails).
- `docs/RUNBOOK.md`: deployment, settings, the Chromium image and its updates, failure table.
- `deploy/kubernetes/`: the manifests (namespace `idp-browser`, RuntimeClass as a setting, NetworkPolicy).

## Licences

This repository: PolyForm Noncommercial 1.0.0 (`LICENSE`). Dependencies: chromedp v0.24.0 and cdproto v0.160.8 (MIT), `golang.org/x/net` and `golang.org/x/text` (BSD-3-Clause), `gopkg.in/yaml.v3` (MIT and Apache-2.0, tests only), `github.com/go-json-experiment/json` (BSD-3-Clause). Chromium (the image): BSD-3-Clause and the licences of its third-party components, as shipped by chromedp's `headless-shell` build (ADR-0001 D10).
