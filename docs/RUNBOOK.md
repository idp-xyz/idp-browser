# idp-browser 运维手册

适用：idp-browser（渲染池，idp-web 读取"正文由 JavaScript 生成"的网页时调用）和它的出网代理 idp-browser-proxy。设计与取舍见 [`adr/ADR-0001-browser-design.md`](adr/ADR-0001-browser-design.md)；为什么要有它见平台仓库的 `docs/adr/browser-capability-plan.md`。本手册讲部署、设置、Chromium 镜像、排障；整平台在 compose 与 kind 上的验收是平台任务 L1-4。

## 1. 它是什么，怎么接

- 两个 Deployment：**renderer**（`idp-browser`：服务加 Chromium，端口 8590 是 API，9590 是 `/healthz` `/readyz` `/metrics`）和 **proxy**（`idp-browser-proxy`：端口 3128 是代理，3129 是管理口，9591 是运维口）。
- 只有 **idp-web** 能调 renderer：NetworkPolicy 只放 `idp-web` 命名空间里 `app.kubernetes.io/component: web` 的 Pod 进 8590；每个请求还必须带 idp-web 用 ES256 签的调用者断言（受众是 `http://idp-browser.idp-browser.svc.cluster.local:8590/render`，请求体摘要，30 秒有效，只能用一次）。直连的、没签名的、签错的、过期的、重放的请求在起任何浏览器之前就被 401 拒绝。
- Chromium **没有别的出口**：renderer Pod 的出口策略只放代理的 3128 和 3129（外加 kube-dns，给服务解析代理的 Service 名；Chromium 自己不解析任何名字）。代理 Pod 才能出公网，且只放 80 与 443、减去 `internal/addr` 拒绝的全部 IPv4 段。
- **代理在内存里记着每次渲染**（renderer 渲染前用管理口登记一个随机令牌，渲染完注销并取回用量），所以一次渲染的登记和它的请求必须到同一个代理 Pod：Service 用 `sessionAffinity: ClientIP`，清单里 `replicas: 1`、策略 `Recreate`。代理 Pod 重启会让正在渲染的页面失败（`render_failed`），idp-web 可以再问一次。
- idp-web 需要的设置（平台任务 L1-3/L1-4）：renderer 的地址 `http://idp-browser.idp-browser.svc.cluster.local:8590/render`（也是签名的受众，两处必须逐字相同）、签名私钥（P-256，PEM；对应公钥放进 renderer 的 ConfigMap `idp-browser-caller-keys`）、调用者名 `idp-web`（renderer 只接受这一个）。

## 2. 部署

```bash
# 1. 命名空间（restricted，带配额）
kubectl apply -f deploy/kubernetes/namespace.yaml
# 2. 密钥：都不在仓库里
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out idp-web-render.key    # idp-web 的签名私钥，交给 idp-web
openssl pkey -in idp-web-render.key -pubout -out caller.pub
kubectl -n idp-browser create configmap idp-browser-caller-keys --from-file=caller.pub=caller.pub
kubectl -n idp-browser create secret generic idp-browser-proxy-admin-key --from-literal=admin.key="$(openssl rand -hex 32)"
# 3. RuntimeClass：在 deploy/kubernetes/settings.yaml 里选（runtimeClass 与 isolatedBy 两项），集群里要有它
# 4. 镜像换成构建出的、按摘要固定的（kustomization.yaml 的 images），再应用
kubectl apply -k deploy/kubernetes
kubectl -n idp-browser rollout status deploy/idp-browser deploy/idp-browser-proxy
```

`/readyz` 在 renderer 上要两件事都对：Chromium 可执行文件在，代理的管理口应答。`kubectl -n idp-browser logs deploy/idp-browser` 里 `idp-browser listening` 之后才接请求。

**镜像**：`bash deploy/build.sh`（宿主上静态编译，`docker build --network none`），得到 `idp-browser:<提交>` 与 `idp-browser-proxy:<提交>`，推到自己的 registry，把 `kustomization.yaml` 里的 `registry.example.com/idp/...` 和 `sha256:000…` 换成真实值（按摘要，不用标签）。

## 3. 设置

renderer（`cmd/idp-browser/main.go` 顶部有同一张表；密钥一律读文件，不读环境变量）：

| 设置 | 缺省 | 说明 |
|---|---|---|
| `IDP_BROWSER_LISTEN` / `_METRICS` | `127.0.0.1:8590` / `127.0.0.1:9590` | 非回环地址要 `IDP_BROWSER_PRIVATE_NETWORK=true`（运维声明：只有 idp-web 到得了） |
| `IDP_BROWSER_CALLER_KEYS_FILE`、`_CALLER_AUDIENCE`、`_CALLER` | 必填、必填、`idp-web` | idp-web 的公钥（可多把，轮换用）、受众、唯一被接受的调用者 |
| `IDP_BROWSER_POOL` | 2 | Chromium 进程数，也是同时渲染数；一个进程一次只渲染一页 |
| `IDP_BROWSER_RECYCLE_AFTER` | 50 | 一个进程渲染这么多次后换新 |
| `IDP_BROWSER_RECYCLE_MEMORY_MB` | 1024 | 一次渲染后进程树的内存比这个进程**第一次渲染时的基线**多出这么多，就换新（看增长，不看绝对值） |
| `IDP_BROWSER_RENDER_MEMORY_MB` | 1536 | 渲染**期间**进程树的内存比**渲染开始时的基线**（上下文刚建好）多出这么多，渲染以 `render_failed` 结束、进程被杀（0 关闭）。看增长而不是绝对值：不同内核的 /proc 记法不同（gVisor 里 statm 的 shared 恒为 0，空闲的 headless-shell 树就量出约 1.6 GiB），基线抵消这个常数。内存的读法：`/proc/<pid>/status` 的 `RssAnon`（匿名页：页面分配的东西，不含共享库），没有就用 statm 的驻留减共享，共享为 0 就用整个驻留集 |
| `IDP_BROWSER_NO_SANDBOX` + `IDP_BROWSER_ISOLATED_BY` | `false` + 空 | `--no-sandbox` 只在 Pod 跑在 gVisor 或 Kata 下才允许：设了前者而后者不是 `gvisor` 或 `kata`，服务**拒绝启动**（退出码 2） |
| `IDP_BROWSER_PROFILE_DIR` | `/profile` | 浏览器配置目录；清单里是内存 tmpfs。启动时会清掉上次被杀留下的 `p*-*` 目录 |
| `IDP_BROWSER_PROXY`、`_PROXY_ADMIN`、`_PROXY_ADMIN_KEY_FILE` | 必填 | 代理的 `host:port`、管理口 URL、共享密钥（至少 32 字节） |
| `IDP_BROWSER_TIMEOUT_MS` / `_MAX_TIMEOUT_MS` | 15000 / 60000 | 请求没给 `timeoutMs` 时的时间；请求能要的最大值 |
| `IDP_BROWSER_MAX_BYTES` / `_MAX_MAX_BYTES` | 5 MiB / 20 MiB | HTML 的上限 |
| `IDP_BROWSER_SCROLL` | `true` | 页面稳定后滚到底一次，触发懒加载 |
| `IDP_BROWSER_SETTLE_MS` | 5000 | load 之后最多等网络和 DOM 安静这么久 |
| `IDP_BROWSER_QUEUE_WAIT_MS` | 2000 | 没有空闲浏览器时，请求最多等这么久，然后 `render_busy` |
| `IDP_BROWSER_MAX_REQUESTS`、`_MAX_TOTAL_BYTES`、`_MAX_RESPONSE_BYTES` | 空（用代理的） | 每次渲染向代理要的预算，只会被代理压低，不会被抬高 |
| `IDP_BROWSER_BLOCK_TYPES` | `image,media,font` | 渲染器根本不取的资源类型（CDP 的 Fetch 按类型拒绝）：文本阅读用不到，却是现代页面的大部分请求和字节。响应里计入 `skipped`（不进 `requests`、不进 `blocked`、不占请求预算），指标 `idp_browser_requests_skipped_total`。设了但为空：什么都不拒。`document` 不可拒绝。每次渲染最多跳过 10 倍请求预算个，之后按普通请求计（防页面循环重试失败的图片）。 |
| `IDP_BROWSER_PORTS` | 80,443 | 页面可以用的端口；**必须与代理的相同** |
| `IDP_BROWSER_USER_AGENT` | Chromium 自己的 | |
| `IDP_BROWSER_TEST_ORIGINS` | 无 | **只给测试**：不受地址规则约束的 `host:port`。`tests/deploy` 保证清单里没有它 |

proxy（`cmd/idp-browser-proxy/main.go`）：`IDP_BROWSER_PROXY_LISTEN`（3128）、`_ADMIN_LISTEN`（3129）、`_ADMIN_KEY_FILE`、`IDP_BROWSER_PORTS`（80,443）、`_PROXY_MAX_REQUESTS`（300）、`_PROXY_MAX_BYTES`（20 MiB）、`_PROXY_MAX_RESPONSE_BYTES`（10 MiB）（三个是上限）、`IDP_BROWSER_DIAL_FAMILY`（`prefer-ipv4` 缺省，也可 `dual`、`ipv4-only`、`ipv6-only`，写错启动失败）、`_PROXY_MAX_CONNS`（256）。

## 4. Chromium 镜像

- **用的是什么**：chromedp 的 `headless-shell`（Docker Hub `chromedp/headless-shell`，基于 Debian trixie-slim），Chromium **159.0.8154.13**，多平台索引的摘要 `sha256:381353d3530ab9d579d2fe8b9c0f4519c995617f5a71daf6bb649e2d12005bd9`（`deploy/Dockerfile` 里的 `CHROMIUM_IMAGE`）。许可：Chromium 与其第三方组件各自的许可（BSD-3-Clause 为主），驱动库 chromedp 与 cdproto 是 MIT。
- **为什么是它**：官方 Chromium 构建的无头外壳（不带窗口系统，没有 GUI 的依赖），固定版本、有摘要；Debian 的 `chromium` 包要么跟着发行版更新、不能按摘要固定，要么要 apt 联网构建。最终镜像是 `FROM scratch`，只拷出 Chromium 的目录、它和 NSS、fontconfig 要用的共享库、字体：没有 shell、没有 apt、没有 coreutils。
- **加入平台的镜像镜像清单**（`releases/mirror-images.yaml`，平台任务 L1-4 做）：

  ```yaml
  - source: docker.io/chromedp/headless-shell@sha256:381353d3530ab9d579d2fe8b9c0f4519c995617f5a71daf6bb649e2d12005bd9   # mirror:upstream (an entry of the list names the source)
    tag: "159.0.8154.13"
    target: ghcr.io/idp-xyz/mirror:docker.io__chromedp__headless-shell__159.0.8154.13
  ```

  （2026-11-23 经 docker.m.daocloud.io 与 docker.1ms.run 两个镜像站得到，两者一致，Docker Hub 当时 502：按清单头部的说明加 `resolvedVia: mirrors`，等 GitHub 上跑过一次后删掉。）`deploy/Dockerfile` 的 `CHROMIUM_IMAGE` 缺省已经是镜像的引用（同一个摘要），不需要在平台里再换。
- **本机没有它时**：Docker Hub 拉不动是常态。`bash tools/pull_image.sh docker.io/chromedp/headless-shell@sha256:381353…`（平台仓库，带重试）；还不行就用 crane，经镜像站，再 `docker load`：

  ```bash
  crane pull --platform linux/amd64 docker.m.daocloud.io/chromedp/headless-shell@sha256:381353d3530ab9d579d2fe8b9c0f4519c995617f5a71daf6bb649e2d12005bd9 hs.tar
  docker load -i hs.tar && docker tag <载入时打印的名字> chromium-base:159   # 载入的名字是 ...:i-was-a-digest
  make test-browser CHROMIUM_IMAGE=chromium-base:159
  ```
- **跟进 Chromium 的安全更新**：Chromium 每四周一个大版本，安全修复更勤。节奏：每月第一个工作日看 `crane ls docker.io/chromedp/headless-shell`（或镜像站）有没有新的稳定版本；**有安全公告（CVE）的版本立即跟，其余每月一次**。步骤：取新版本的索引摘要 → 改 `deploy/Dockerfile` 的 `CHROMIUM_IMAGE` 与镜像清单（tag 和 digest）→ `make test-browser`（要全绿）→ 构建、扫描（`tools/scan_images.sh`）→ BOM 升级。Chromium 落后一个月以上，要在运维记录里写明理由。

## 5. 隔离：本机与 Kubernetes

- **Kubernetes**：renderer Pod 用 gVisor 或 Kata 的 RuntimeClass（`settings.yaml`），Chromium 以 `--no-sandbox` 运行（`IDP_BROWSER_NO_SANDBOX=true` 加 `IDP_BROWSER_ISOLATED_BY`）。原因：Chromium 自己的沙箱要用户命名空间，Pod 的 seccomp（`RuntimeDefault`）不给；放开 seccomp 比不用 Chromium 沙箱更糟。容器的安全边界就是 RuntimeClass：根文件系统只读、非 root（10600）、`capabilities: drop ALL`、无服务账号令牌、内存和 CPU 上限，配置目录与 `/tmp` 是内存 tmpfs，Pod 里没有任何秘密（只有 idp-web 的公钥和与代理共享的管理口密钥，后者 Chromium 进程拿不到：它的环境是空的，`NoInheritEnv`）。**这个设置是运维的声明，服务无法验证它**：别在没有 RuntimeClass 的集群里设 `IDP_BROWSER_ISOLATED_BY`。
- **本机与测试**：不设 `IDP_BROWSER_NO_SANDBOX`，Chromium 用自己的沙箱。Docker 默认的 seccomp 档会拦用户命名空间，所以 `make test-browser` 用 `--security-opt seccomp=unconfined`，同时 `--cap-drop ALL`、`--read-only`、用户 10600、内存 6 GiB。要在 gVisor 下跑同一套测试：`IDP_BROWSER_TEST_NO_SANDBOX=gvisor`，容器用 `--runtime=runsc`。
- **compose**（平台任务 L1-4）：renderer 和 proxy 两个服务，renderer 放在只能到 proxy 的内部网络上，proxy 放在能出网的网络上；用 `runtime: runsc`（如果主机有）。没有 runsc 就不要设 `IDP_BROWSER_NO_SANDBOX`，把 seccomp 档放开（`seccomp:unconfined`）让 Chromium 用自己的沙箱。

## 6. 日志与指标

- renderer：JSON 日志，每个渲染一行 `render`（状态、请求数、拒绝数、字节、毫秒，**没有 URL**）；失败一行 `render refused or failed`（原因码与消息）。`caller assertion refused` 是被拒的请求，原因在 `why`，调用者看到的只有 401。
- proxy：每个请求一行 `egress`：`render`（渲染 id）、`host`、`port`、`decision`（`allow`/`deny`）、`reason`、`bytes`、`ms`。**没有路径、查询串、请求体**（代码里没有这样的字段）。`reason`：`ok`，或 `no_credential` `unknown_render` `bad_token` `expired`（没有活的凭据，渲染 id 为空）、`port`、`bad_host`、`not_public`（地址不是公网）、`unresolved`、`limit_requests` `limit_bytes` `limit_response`、`deadline`、`upstream`。
- `/metrics`：renderer 的 `idp_browser_renders_total{outcome=...}`（`ok` 或原因码）、`_renders_active`、`_processes`、`_process_starts_total`、`_process_recycles_total`；proxy 的 `idp_browser_proxy_requests_total{decision}`、`_live_renders`。告警建议：`render_failed` 占比、`not_public` 拒绝突增（页面在探测内网）、`render_busy`、进程换新速度。

## 7. 故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| renderer 启动失败，`--no-sandbox is refused` | 设了 `IDP_BROWSER_NO_SANDBOX` 没设 `IDP_BROWSER_ISOLATED_BY` | 在 gVisor/Kata 下设 `gvisor` 或 `kata`；否则别开 `NO_SANDBOX` |
| `/readyz` 503 | Chromium 路径不对，或代理的管理口不通 | 看响应正文；`kubectl -n idp-browser get endpoints idp-browser-proxy`；NetworkPolicy 要放 3129 |
| 每个渲染都是 `render_failed`："the egress proxy is not available" | 管理口的密钥两边不同，或代理没起 | 对比两个 Pod 里 `admin.key`；看代理日志 |
| 渲染 `render_failed`，消息 `ERR_PROXY_CONNECTION_FAILED` | 浏览器连不上本次渲染的跳点（本机回环） | Chromium 的 `--host-resolver-rules` 把回环字面量的 `EXCLUDE` 弄丢了；看 `internal/render/flags.go`。Pod 的网络栈里 127.0.0.1 要能用 |
| 渲染 `render_failed`，消息 `ERR_TUNNEL_CONNECTION_FAILED` | 代理拒绝了 CONNECT：看代理的 `egress` 行里 `reason` | `not_public`：目标是私网/元数据，或名字解析出一个私网答案；`port`：端口不在列表；`unresolved`：代理的 DNS 解析不出 |
| 渲染 `not_allowed` 但 URL 看着是公网的 | 名字解析出了私网地址（含混合答案），或重定向到了私网 | 代理日志里该主机 `not_public`；这是设计，不要放开 |
| `render_failed`，消息 `the address is a file, not a web page` | 地址返回的是 PDF、压缩包等文件，Chromium 要下载它，而下载被禁 | 设计如此；文件由 idp-web 自己的 PDF 读取处理，不该转给渲染池 |
| `render_timeout` 很多 | 页面一直不 load；跨境慢；`timeoutMs` 太小 | idp-web 传更大的 `timeoutMs`（上限 60 s）；看代理 `ms`；国内跨境见计划第 9 节 |
| `blocked_by_site` | 验证码、反爬、或 Akamai/Imperva 的"无权限"页（HTTP 200） | 如实报告，不重试，不绕过。信号清单见 ADR D4（S1 到 S5）。误报：看日志 `blocked by site` 的 `signal` |
| `render_busy` | 所有浏览器都在渲染 | 调高 `IDP_BROWSER_POOL`（每个约 1 GiB）或副本数；`IDP_BROWSER_QUEUE_WAIT_MS` |
| 内存涨、Pod 被杀 | 浏览器进程累积 | 看 `_process_recycles_total`；调低 `RECYCLE_AFTER` 或 `RECYCLE_MEMORY_MB`；Pod 内存上限要大于 `POOL × RENDER_MEMORY_MB` |
| 401 `unauthorized`，日志 `caller assertion refused` | 见 `why`：`signed with a key this server does not hold`（密钥对不上）、`made for ...`（受众与 idp-web 配的不是逐字相同）、`expired`（两边时钟差超过 30 秒）、`made for another request`（idp-web 签的不是它发的那个请求体）、`presented before`（重放） | 对照 idp-web 的私钥与 ConfigMap 的公钥；受众逐字比较 |
| 渲染页面里图片或脚本缺 | 页面超出了预算：响应里 `limit` 是 `requests`、`bytes` 或 `response` | 预算是有意的；确需更大，调代理的上限 |
| gVisor 下 Chromium 起不来 | 见平台 `deploy/kubernetes/RUNBOOK.md` 的 gVisor 条目（平台 `systrap`/`kvm`） | 同那里 |
| `make test-browser` 找不到镜像 | Docker 拉不动 Chromium 基础镜像 | 第 4 节：crane 经镜像站 |
| `make test-browser` 里 Chromium 起不来："No usable sandbox" | 容器的 seccomp 档拦了用户命名空间 | `Makefile` 里已有 `seccomp=unconfined`；在别的容器环境里要同样放开，或用 gVisor 加 `IDP_BROWSER_TEST_NO_SANDBOX=gvisor` |

### 7.1 用真实网页冒烟：`make smoke-real`

CA 根证书、真实 TLS、真实站点的行为，测试里的自签名源站验证不了。`make smoke-real URL=https://…/ [CHROMIUM_IMAGE=…]`（`deploy/smoke-real.sh`）：构建两个镜像（离线，同 `make test-browser`，Chromium 基础镜像要已在 Docker 里），在两个临时 Docker 网络上启动代理（能出网）和渲染器（只在内部网络，只到得了代理），生成一次性的 P-256 密钥（调用者 `idp-web`）和管理口密钥，**按 idp-web 将会用的方式**签一个请求（`internal/caller`）从第三个容器发出，打印渲染的 HTTP 状态、`finalUrl`、页面状态、标题、`requests`、`blocked`、`bytes`、`ms`、`settled`、可见文字的前 300 个字符（或原因码），再打印代理审计的汇总（主机、决定、原因、次数、字节），并检验内部网络确实没有别的出路。结束时删掉容器、网络、密钥目录和它构建的镜像（`KEEP_IMAGES=1` 留下镜像）。用法：新环境第一次部署前、升级 Chromium 之后、怀疑某个站点读不了的时候。注意：页面请求数超过 300 的站点（改前国家统计局首页 442 个、15.9 MB，现在默认不取图片、媒体、字体：23 个请求、0.5 MB）会触到请求预算（响应里 `limit: requests`），正文仍在；要放宽就调代理与渲染器的 `MAX_REQUESTS`。

## 8. 安全边界（运维要知道的）

- **渲染器不做策略，代理做**：页面能发出的每个请求（主页面、子资源、重定向、WebSocket、`<img>`、`<iframe>`）都经代理，代理按 idp-web 的地址规则逐个检查，只拨检查过的地址；NetworkPolicy 在集群这一层再拦一次。
- **代理看不见 TLS 里面**：它数的是"请求"= CONNECT 隧道与明文请求。一条 HTTP/2 连接里的上千个请求它数不到；那一部分由渲染器自己用 CDP 数（页面的请求，超过预算就在浏览器里拒绝），其余由字节预算兜底。跨站 iframe 的子请求不经渲染器的计数（Chromium 的站点隔离保持开启），只受代理的计数与字节预算约束。
- **每次渲染一个全新的浏览器上下文**：没有 Cookie、缓存、存储，渲染完销毁；一个进程同一时刻只渲染一页。**任何不正常结束（超时、崩溃、内存、预算以外的失败）之后，那个浏览器进程连同子进程被杀、配置目录被删**，下一次渲染起新的。
- **不绕过反爬、不处理登录**：遇到验证码或"无权限"页如实报 `blocked_by_site`。
