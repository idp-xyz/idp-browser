# ADR-0001　idp-browser 的设计（第一层：渲染池与浏览器出网代理）

| 项 | 内容 |
|---|---|
| 状态 | 已接受（2026-11-24，随任务 L1-1 与 L1-2；平台计划 `docs/adr/browser-capability-plan.md`，2026-11-23 确认，选择点 1 到 7 均按建议） |
| 范围 | 渲染池服务（`cmd/idp-browser`）、浏览器出网代理（`cmd/idp-browser-proxy`）、Chromium 镜像与加固、回收与审计、部署清单。不含：idp-web 一侧的调用与新原因码（L1-3）、compose 与 kind 的接入、PATH M6 和 BOM（L1-4）、第二、三层（会话、接管） |
| 依据 | 计划第 0 到 3 节、第 6 节 D1 与 D2、第 8 节选择点 1（独立组件）、2（Go 加 chromedp）、7（只在 `needs_script` 渲染，加租户的"总是渲染"名单，由 idp-web 处理）；idp-web ADR-0001 D2、D6 到 D8、D12、D13；idp-sandbox ADR-0001 D13、D22、D24（快乐眼球）；idp-mcp ADR-0001 D44（调用者断言）；RFC 8305 |

## 1. 背景与边界

计划把"让 agent 读到靠 JavaScript 生成正文的页面"放在第一层：idp-web 抓取后判定 `needs_script`，转交渲染池；渲染池给这一次请求开一个全新的浏览器上下文，打开页面，取渲染后的 DOM 和最终地址，交回 idp-web，由它照旧提取、分段、引用、防注入。本 ADR 只记仓库自己的决策。浏览器是很大的攻击面，所以安全上的两个原则贯穿全文：**浏览器自己不做任何网络策略，所有请求都经一个逐地址检查的代理；浏览器进程不持有任何秘密，被攻破时能拿到的只有它自己和它的代理。**

## 2. 决策

| # | 决策 | 理由 |
|---|---|---|
| D1 | **两个二进制、两个镜像：`idp-browser`（渲染器加 Chromium）和 `idp-browser-proxy`（只有代理）。代理不是渲染器的一个模式。** | NetworkPolicy 按 Pod 生效：渲染器 Pod 只许到代理，代理 Pod 许到公网不许到集群；一个 Pod 不能同时有这两条。出公网的那个 Pod 也不该带浏览器。代价是渲染的登记要走一条管理口（D5）。选择点 1（独立组件）与 2（Go 加 chromedp）沿用计划 |
| D2 | **驱动库：chromedp v0.24.0 与 cdproto v0.160.8（均 MIT）。** 其余依赖：`golang.org/x/net`（IDNA，BSD-3-Clause）、`golang.org/x/text`（BSD-3-Clause）、`github.com/go-json-experiment/json`（cdproto 用，BSD-3-Clause）、`gopkg.in/yaml.v3`（只在测试里，MIT 与 Apache-2.0）。Chromium：BSD-3-Clause 及其第三方组件的许可，随 chromedp 的 `headless-shell` 构建分发。本仓库：PolyForm Noncommercial 1.0.0。 | 计划 D2。chromedp 的核心只用标准库，用管道（`--remote-debugging-pipe`）而不是调试端口连浏览器：没有监听的端口，Pod 里别的进程连不上它 |
| D3 | **地址规则是 idp-web 的 `internal/addr` 的复制，不共享代码；复制只改了一处：`Options.Ports`（可配置的端口列表，缺省 80 和 443）。** 代理对**每一个**请求用它：先看端口，再用 `addr.TargetWith` 解析主机的写法（拒绝非规范的 IP 写法 `2130706433`、`0x7f.1`、`127.1`，拒绝用户信息，IDNA 转换），再自己解析名字，**每一个答案**都要是公网（含 IPv4 映射的 IPv6，NAT64、6to4、Teredo 等嵌 IPv4 的段整段拒绝），有一个不是就整个拒绝（混合答案是攻击者控制的名字），然后只拨检查过的地址。 | 沿用 idp-web ADR-0001 D6 到 D8 与沙箱 D22，同一批 IANA 表。漂移变成测试失败：`addr` 的测试（含 20 个 SSRF 地址和模糊测试种子）随复制一起带来，`tests/deploy` 把 NetworkPolicy 的 `except` 与 `addr.Public` 在整个 IPv4 空间上逐 /24 对比 |
| D4 | **渲染的接口、原因码与等待方式。** `POST /render {url, timeoutMs, maxBytes}` → `{finalUrl, html, status, title, requests, blocked, bytes, ms, truncated?, limit?, settled}`。原因码固定六个：`render_timeout`（页面没在时限内加载，或加载后主线程不应答）、`render_failed`（浏览器、网络或页面失败：崩溃、内存、导航错误如重定向循环、结束在浏览器自己的错误页、代理不可用）、`blocked_by_site`、`render_busy`、`invalid_request`、`not_allowed`（URL 本身，或它的重定向，不是公网的 http/https，**或页面所在的主机被代理拒绝**）。**等待**：load 事件（若 load 迟迟不来，到时限的 60% 后只要 DOMContentLoaded 已到就继续，因为常有一个挂住的第三方脚本）→ 等网络空闲 500 ms 且 DOM 静止 1 s，最多 `IDP_BROWSER_SETTLE_MS`（5 s）→ 滚到底一次（可关）→ 再等一轮（最多 2 s）→ 读 `outerHTML`（加 doctype）、`location.href`、标题、状态码、可见文字。HTML 超过 `maxBytes` 在页内先截（只传前 `maxBytes` 个 UTF-16 单元）再按字节在字符边界截，`truncated: true`，不是错误。`limit` 说明页面用光了哪项预算（`requests`、`bytes`、`response`），也不是错误。 | 计划第 3 节。**`blocked_by_site` 的信号**：与 idp-web 自己读取时的判据（ADR-0001 D12）同一条规则——标记只在可见文字很少时才算，长文章里提到验证码不算：S1 源码里有已知挑战的标记（Cloudflare `_cf_chl_opt`、`cf-chl-`、`challenge-platform`，AWS WAF `gokuprops`，HUMAN `px-captcha`，DataDome `captcha-delivery.com`，Imperva `/_incapsula_resource`，Akamai `errors.edgesuite.net`，阿里云 `_____tmd_____`，`geetest`）且可见文字不超过 1000 字；S2 整个标题是 "Just a moment..." "Access Denied" "Pardon Our Interruption" 一类（且文字不超过 1000 字）；S3 可见文字含 "verify you are human" "captcha" "正在进行安全检测" "请完成安全验证" 一类，且文字不超过 300 字；**S4 拒绝页的话：可见文字含 "It appears you don't have permission to view this webpage"（FedEx，Akamai 后面，HTTP 200，2026-11-23 实测）、"You don't have permission to access … Reference #18.…"（Akamai）、"we can't process your request right now"、"Request unsuccessful. Incapsula incident ID"、"访问过于频繁" 一类，且文字不超过 1000 字**；S5 状态码 403 或 429 且可见文字不超过 300 字。每条规则在 `detect_test.go` 里各有一个必须命中的页和一个同样的词出现在长文章里、必须放过的页 |
| D5 | **渲染的登记协议。** 渲染器渲染前在代理的管理口 `PUT /v1/renders/{id}`（Bearer 密钥，至少 32 字节，常量时间比较）登记：渲染 id、随机令牌（32 字节）、存活时间（时限加 15 秒）、预算；渲染完 `DELETE` 注销，并取回用量（`requests`、`blocked`、字节、触到的上限、被拒绝的主机与原因）。浏览器的每个请求带 `Proxy-Authorization: Basic base64(id:令牌)`；代理对没有、格式错、id 不存在、令牌不对、已过期、已注销的请求一律回 407，什么都不看、不拨。预算的上限是代理的配置，登记时只能要更少。**令牌不给浏览器**：见 D6 的跳点。登记表在代理的内存里，所以一次渲染的登记和它的请求要到同一个代理 Pod：Service 用 `sessionAffinity: ClientIP`，清单里一个副本、`Recreate`；代理重启会让进行中的渲染失败，idp-web 可再问一次。 | 任务书要求"渲染器与代理共享一个随机的每次渲染令牌，代理必须拒绝没有有效活令牌的请求"。注销时取回的用量也是响应里 `blocked`、`bytes`、`limit` 与 `not_allowed` 判断（D4）的来源。无状态的 HMAC 令牌（沙箱的做法）做不到"注销后立即失效"和实时计数 |
| D6 | **代理（`internal/proxy`，从沙箱的 `internal/egress` 复制并改策略）：CONNECT 与明文 HTTP 转发，策略只有"只许公网"；快乐眼球；预算；审计；不缓存。** 拨号是 `dialrace.go`：沙箱和 idp-web 里已合并的 RFC 8305 实现的原样复制（250 ms 的连接尝试延迟，`IDP_BROWSER_DIAL_FAMILY` 缺省 `prefer-ipv4`，另有 `dual`、`ipv4-only`、`ipv6-only`，写错启动失败），测试一并带来，并加了通过本代理的两个测试。**预算**（每次渲染，登记时给，默认 300 个请求、总共 20 MiB、单个响应 10 MiB、渲染的时限）：请求数在每个 CONNECT 和每个明文请求上数；总字节数两个方向合计，超了就关掉该渲染的所有隧道并拒绝新的（`limit_bytes`）；单个响应：明文响应在声明的 `Content-Length` 超过时直接拒绝（502，`limit_response`），没声明的流到超过就**中断连接**（让浏览器看到一个坏响应，而不是一个看似完整的短响应）；隧道里一条连接从源站来的字节超过它就关（TLS 里分不出响应的边界，所以按"每条隧道"算）；时限到了，该渲染的所有隧道被关，令牌失效。**审计**：一个请求一行，字段只有渲染 id、主机、端口、决定、原因、字节、毫秒（`Entry` 类型没有别的字段，所以不会不小心记下路径、查询串或请求体）。 | 计划第 2 节"浏览器出网代理"。**代理看不见 TLS 里面**：它数的"请求"是 CONNECT 隧道和明文请求；一条 HTTP/2 连接里的上千个请求它数不到。所以渲染器也用 CDP 的 Fetch 域数页面自己的请求（超过 `maxRequests` 就在浏览器里拒绝，`limit: requests`），字节预算兜底。这是对计划的修正，见第 4 节 |
| D7 | **渲染器 API 的认证：idp-web 对每个请求签 ES256 的调用者断言，格式同平台的调用者断言（idp-mcp D44、idp-web `internal/mcp/assertion.go`）。** 紧凑 JWS，`typ: idp-caller+jwt`，`kid` 是公钥的 RFC 7638 指纹；声明 `aud`（渲染器的端点，逐字相同）、`sub`（只接受 `idp-web`）、`iat`、`exp`（不超过两分钟，idp-web 签 30 秒）、`jti`（缓存到过期加 30 秒，用过就拒；表满了拒绝，不丢旧的）、`req`（请求摘要）。**与平台不同的两点**：签名者是 idp-web 自己（这一跳不经网关）；摘要是 `sha256(METHOD "\n" PATH "\n" 请求体原样)`（不是 MCP 方法加参数），所以断言换不到别的 URL 或别的页面上。放在 `Authorization: Bearer`。公钥可以有几把（轮换：先加新公钥，再换 idp-web 的私钥）。`internal/caller/testdata/caller-assertion-v1.json` 是向量（固定时刻、固定请求的八种情形：好的、重放、过期、换了请求体、别的密钥、别的调用者、别的受众、有效期过长），idp-web 的签名器（L1-3）复制它并验证；改格式的一方测试会失败 | 任务书允许"带密钥文件的 HMAC，如果论证它够用"：不够用，也不比 ES256 省事——HMAC 的共享密钥要在两边都有，渲染器被攻破就能冒充 idp-web 调用自己和别的实例；ES256 下渲染器只有公钥。ES256 的验证代码本来就在三个仓库里，向量机制也已有。**单一身份**：验证器只有一个 `subject`，另一个主体即使密钥对也拒绝 |
| D8 | **鉴权先于一切：请求体读完（上限 16 KiB）后先验签，签名通过才解析 JSON；没签名、签错、过期、重放、受众不对、主体不对、请求体被换的请求在起任何浏览器、联系代理之前就以 401 结束，调用者只看到 `unauthorized`，原因（`why`）只进日志。** | 计划要求"NetworkPolicy 只放 idp-web 进来"，这是第二层。`tests/browser/service_test.go` 在真池上证明：被拒绝的请求之后，进程数、启动数和代理的审计都是零 |
| D9 | **Chromium 的隔离。** (a) **沙箱：在 Kubernetes 里用 gVisor 或 Kata 的 RuntimeClass，Chromium 以 `--no-sandbox` 运行；本机与测试用 Chromium 自己的沙箱。**理由：Chromium 自己的沙箱要用户命名空间，Pod 的 `seccomp: RuntimeDefault` 不给，放开 seccomp 比关掉 Chromium 沙箱更糟；RuntimeClass 把整个容器隔在另一个内核之外，保护的是同一件事（渲染器进程被页面攻破之后）。**`--no-sandbox` 是一个设置，不是默认**：`IDP_BROWSER_NO_SANDBOX=true` 必须同时有 `IDP_BROWSER_ISOLATED_BY=gvisor` 或 `kata`，否则服务退出码 2 拒绝启动。这是运维的声明，服务无法验证；清单把 RuntimeClass 与这个声明放在同一个设置（`settings.yaml`）里，`tests/deploy` 检查两者一致。(b) **每次渲染一个新的无痕浏览器上下文（`Target.createBrowserContext`），渲染完销毁；一个进程同一时刻只渲染一页**：两次渲染不共享 Cookie、缓存、存储、权限，也不共享渲染进程。(c) **上下文自己的代理**（`createBrowserContext` 的 `proxyServer`）指向这次渲染的跳点（D10），全局的 `--proxy-server` 指向一个没人监听的地址（失败即关闭），`--proxy-bypass-list=<-loopback>` 让对回环的请求也走代理（否则页面请求 127.0.0.1 会绕过代理，审计里没有）。(d) **浏览器不解析任何名字**：`--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"`（`EXCLUDE` 只放过跳点的回环字面量，没有它连代理都连不上），DNS over HTTPS 与 HTTPS 升级关闭。(e) **没有 UDP 的路**：`--disable-quic`；WebRTC 只许走代理：`--webrtc-ip-handling-policy` 与 `--force-webrtc-ip-handling-policy` 都是 `disable_non_proxied_udp`（后者**要给值**，给 `true` 不生效，测试里 STUN 金丝雀收到过 3 个包）。(f) 只许 http/https 的**文档**：Fetch 域拦截每个文档请求，scheme 不是 http/https 的拒绝；导航结束在浏览器自己的错误页（`chrome-error://`）算 `render_failed`。(g) 扩展、后台网络、同步、推送、通知（含 `--deny-permission-prompts`）、地理位置、摄像头、麦克风、剪贴板、后台同步关闭或拒绝；`Browser.setPermission` 对每个权限名再拒一遍；`navigator.serviceWorker` 在页内取消（第二层，不是边界：Service Worker 取的东西同样经代理）；下载：`Browser.setDownloadBehavior: deny`。(h) 站点隔离保持开启（chromedp 的同样决定）；**图片、媒体、字体缺省不取**（`IDP_BROWSER_BLOCK_TYPES`，Fetch 域按资源类型在浏览器里拒绝，计入 `skipped`，不占请求预算；每次渲染最多跳过 10 倍预算个，之后按普通请求计，防止页面循环重试失败的图片）。依据：国家统计局首页 442 个请求、15.9 MB，几乎都是图片和媒体，文本阅读用不到；其余类型（脚本、样式、xhr/fetch、文档、其它）照常经代理。SSRF 验收里 `<img>` 一类的向量要把这个设置清空才会到达代理（测试这样做），因为被跳过的请求根本不发出。(i) 浏览器的环境是空的（`NoInheritEnv`），HOME、XDG、TMPDIR 指向它自己的配置目录。 | 计划第 2 节"浏览器本身的加固" |
| D10 | **跳点（`internal/authhop`）：每次渲染一个只监听 127.0.0.1 随机端口的小转发器，浏览器上下文的代理是它，它给转发到代理的每个请求加 `Proxy-Authorization`。** | CDP 没有给上下文的代理带凭据的办法（`proxyServer` 不认 `user:pass@`），用 Fetch 域的 `authRequired` 要在每个目标（框架、worker）里都接钩子，漏一个就是 407 或者没带凭据的绕行。跳点让浏览器**永远拿不到令牌**，页面更读不到，任何请求都没法不带它。跳点不做决定，不是策略点：代理仍检查每个请求 |
| D11 | **池与回收。** N 个浏览器进程（缺省 2）；请求先拿一个空闲的，没有就最多等 `IDP_BROWSER_QUEUE_WAIT_MS`（2 s），然后 `render_busy`；进程在**渲染 M 次后**（缺省 50）、**一次渲染后私有内存超过阈值**（缺省 1024 MiB，按进程树的 RSS 减去共享页）、**以及任何没有正常结束的渲染之后**（超时、崩溃、内存、失败）被杀并换新，杀的是整棵进程树（页面里卡死在脚本里的渲染进程不会因为浏览器进程死了而退出），配置目录删除。**渲染期间**每 250 ms 看一次进程树的内存，超过 `IDP_BROWSER_RENDER_MEMORY_MB`（1536）就以 `render_failed` 结束（内存炸弹）；渲染的时钟是整个渲染的时限，到了就取消、杀进程（死循环：load 不来，或来了之后读 DOM 没应答，都是 `render_timeout`）。 | 计划第 3 节第 5 步"一个浏览器进程渲染够 N 次，或内存超过阈值，就回收重启" |
| D12 | **部署与网络策略**（`deploy/kubernetes`，风格同 idp-web）：命名空间 `idp-browser`（`restricted`，带配额）；两个 Deployment（非 root 10600 与 10601、只读根文件系统、丢弃全部能力、无服务账号令牌、内存与 CPU 上限，渲染器的配置目录和 `/tmp` 是内存 tmpfs），RuntimeClass 与隔离声明在 `settings.yaml` 一处，由 kustomize 的 `replacements` 写进对象。策略：默认全拒；渲染器出口**只**到本命名空间的代理 Pod 的 3128 与 3129（外加 kube-dns 的 53，服务靠它解析代理的 Service 名；Chromium 自己不解析，页面也问不到它）；渲染器入口**只**从 `idp-web` 命名空间里 `app.kubernetes.io/component: web` 的 Pod 到 8590；代理入口**只**从渲染器 Pod 到 3128 与 3129；代理出口到公网的 80 与 443，`except` 是 `addr` 表的 IPv4 部分（`tests/deploy` 逐 /24 对比），只有 IPv4。运维口 9590 与 9591 只放 `observability` 命名空间。 | 计划 D1、D4。同 idp-web 的方式：服务自己拒绝一遍，集群再拒绝一遍 |
| D13 | **测试源站的豁免：`IDP_BROWSER_TEST_ORIGINS`（`host:port`，渲染器与代理两边相同），只给验收和测试，清单里没有，`tests/deploy` 保证。** 豁免的是精确的 `host:port`，不是同主机别的端口、也不是别的主机同一端口。HTTPS 的测试源站另需 `Config.TestTrustSPKI`（Chromium 的 `--ignore-certificate-errors-spki-list`，只信这一把公钥），它没有环境变量，服务的环境里没有这个设置。 | idp-web ADR-0001 D14 |
| D14 | **日志与指标。** 渲染器每个渲染一行（状态、请求数、拒绝数、字节、毫秒，**没有 URL**），失败一行（原因码与消息）；代理每个请求一行（D6）。`/metrics` 见 RUNBOOK 第 6 节。 | 计划 D4 |

## 3. 反向验证（每个控制移除一次，看对应的测试失败，再恢复）

每一行：把这个控制去掉一次（脚本逐个改源文件、跑下表的测试、恢复），列出失败的测试。浏览器测试在镜像里跑（`make test-browser` 同一条命令行）。

| # | 去掉的控制 | 位置 | 失败的测试 |
|---|---|---|---|
| P1 | 代理：名字解析出的地址不检查是否公网 | `internal/proxy/proxy.go` `check` | `TestEveryNonPublicClassIsRefusedForConnectAndNothingIsDialed`、`…ForPlainHTTPToo`、`TestATestOriginIsExempt…` |
| P2 | 代理：多个答案只检查第一个（混合答案） | 同上 | 同上两个 |
| P3 | 地址规则：非公网的 IP 字面量被接受 | `internal/addr/target.go` | `TestTheTwentyAddressesOfTheSSRFListAreRefused`、`TestAddressesAreRefusedForTheReasonTheyAreWrong`、`FuzzTarget` 的种子等 |
| P4 | 代理：端口列表不生效（两层都去掉） | `proxy.go` 与 `target.go` | `TestPortsOtherThanTheListedAreRefused`、`TestTheListOfPortsIsConfigurable` |
| P5 | 代理：令牌不比较 | `registry.go` `Lookup` | `TestWithoutALiveCredentialNothingIsLookedAtAndNothingIsDialed` |
| P6 | 代理：渲染的时限在查找时不检查 | `registry.go` | `TestAnExpiredOrFinishedRendersTokenIsRefused`、`TestTheDeadlineEndsTheTunnelsAndThenTheToken` |
| P7 | 代理：没有请求数预算 | `registry.go` `admit` | `TestTheRequestBudgetIsCounted` |
| P8 | 代理：没有总字节预算 | `registry.go` `addBytes` | `TestTheTotalByteBudgetEndsTheTunnelsOfTheRender` |
| P9 | 代理：没有单个响应的预算（隧道、声明的、流式的） | `proxy.go` | `TestAResponseOverTheResponseBudgetIsRefusedOrCut` |
| P10 | 代理：隧道活过渲染的时限（取消钩子与连接的截止时间都去掉） | `proxy.go` `connect` | `TestTheDeadlineEndsTheTunnelsAndThenTheToken` |
| P11 | 代理：审计行带上明文请求的路径与查询串 | `proxy.go` `ServeHTTP` | `TestAuditLinesNeverHoldAPathAQueryOrABody` |
| P12 | 代理：快乐眼球缺省不优先 IPv4 | `dialrace.go` `order` | `TestEachFamilySettingGivesItsOrder`、`TestPreferIPv4NeverLetsAStallingIPv6PathWin`、`TestProxyUsesIPv4WhenIPv6ConnectsAndThenStalls` |
| P13 | 代理：转发时不去掉 Proxy-Authorization（令牌会到源站） | `proxy.go` `forward` | `TestTheCredentialIsNotForwardedToTheOrigin` |
| A1 | 断言：不比对请求摘要 | `internal/caller/caller.go` | `TestEveryWayToBeWrongIsRefused`、`TestVectors`、`TestRequestsThatAreNotIdpWebsAreRefusedBeforeAnyRender` |
| A2 | 断言：任何主体都接受（单一身份） | 同上 | 同上三个 |
| A3 | 断言：重放不拒绝 | 同上 | `TestAGoodAssertionVerifiesOnceAndOnlyOnce`、`TestVectors`、服务的同名测试 |
| A4 | 断言：不检查过期 | 同上 | 同 A1 |
| A5 | 断言：不检查受众 | 同上 | 同 A1 |
| A6 | 断言：不验签 | 同上 | `TestEveryWayToBeWrongIsRefused`（改过声明的断言） |
| A7 | 服务：不验断言就处理请求 | `internal/service/service.go` | `TestRequestsThatAreNotIdpWebsAreRefusedBeforeAnyRender` |
| A8 | 服务：`not_allowed` 的 HTTP 状态不对 | `service.go` `statusOf` | `TestReasonCodesAndStatuses` |
| R1 | `--no-sandbox` 没有隔离声明也启动 | `internal/render/config.go` `Validate` | `TestNoSandboxIsRefusedWithoutTheIsolationStatement` |
| R2 | 渲染器不对请求的 URL 用地址规则 | `render.go` `check` | `TestRequestChecks` |
| R3 | `IDP_BROWSER_NO_SANDBOX` 不进命令行 | `flags.go` | `TestNoSandboxIsRefusedWithoutTheIsolationStatement` |
| R4 | `blocked_by_site`：拒绝页的话（Akamai、FedEx）不是信号 | `detect.go` | `TestDetect` |
| R5 | `blocked_by_site`：只有 403/429 的光秃页不是信号 | `detect.go` | `TestDetect` |
| R6 | 跳点：不加凭据 | `internal/authhop/authhop.go` | `TestTheHopCarriesTheRendersCredentialForConnectAndForPlainRequests` |
| B1 | 每次渲染的浏览器上下文不带它自己的代理（浏览器落到失败即关闭的代理上） | `render.go` | `TestContextsShareNoCookieStorageOrCache`（这里被去掉的是每次渲染一个上下文与它的代理；各个页面测试也都会失败） |
| B2 | WebRTC 不限于代理（两个策略标志去掉） | `flags.go` | `TestWebRTCSendsNothingOutsideTheProxy`（STUN 金丝雀收到 UDP 包） |
| B3 | 下载允许 | `render.go` | `TestBrowserFeaturesThatReachOutOfThePageAreOff`（`/tmp/payload.bin` 出现） |
| B4 | 页面看得到 `navigator.serviceWorker` | `flags.go` `initScript` | 同上 |
| B5 | 渲染期间不看内存 | `render.go` | `TestAMemoryBombIsEndedAsRenderFailedAndThePoolStaysHealthy` |
| B6 | 渲染不正常结束后浏览器进程留着 | `pool.go` `release` | `TestAnInfiniteLoopEndsAsRenderTimeoutAndThePoolStaysHealthy`（进程没有换新） |
| B7 | 页面所在主机被代理拒绝时不报 `not_allowed` | `render.go` | `TestAPageOnAPrivateNameOrRedirectedToAPrivateAddressIsNotAllowed` |
| B8 | 渲染 M 次后不换进程 | `pool.go` | `TestABrowserIsReplacedAfterTheConfiguredNumberOfRenders` |
| B9 | 不滚动 | `render.go` | `TestALazySectionIsLoadedByOneScrollAndOnlyByIt`（它自带关掉滚动的对照） |
| B10 | 渲染器不数页面自己的请求（代理仍在数） | `render.go` | `TestAStormOverOneTLSConnectionIsCutByTheRendersOwnCount`（HTTP 的风暴测试 `TestASubresourceStormIsCutAtTheRequestBudget` 不会失败：明文请求代理数得到。这正是 D6 说的盲区） |
| B11 | HTML 不按 `maxBytes` 截（页内与服务端两处） | `render.go`、`flags.go` | `TestAHugeDOMIsCutAtMaxBytes` |
| B12 | 渲染器不拒绝非 http/https 的文档请求 | `render.go` | **没有测试失败**：Chromium 自己拒绝页面发起的 file:、chrome:、data: 顶层导航，这一条是第二层。第一层（Chromium 的拒绝）靠 `TestAPageCannotNavigateItselfToLocalSchemes` 守着：页面无论怎么导航，最终地址仍是源站页面 |
| B13 | 导航结束在浏览器的错误页也算成功 | `render.go` | `TestAPageCannotNavigateItselfToLocalSchemes` |
| B14 | 对回环的请求不走代理（全局与上下文的绕行列表都去掉） | `flags.go`、`render.go` | `TestAPageThatReachesForTheInsideOfTheNetworkGetsNothing`（金丝雀收到连接，审计里没有它） |
| B15 | 权限不拒绝（旗标与逐项覆盖都去掉） | `flags.go`、`render.go` | `TestBrowserFeaturesThatReachOutOfThePageAreOff`（`navigator.permissions` 的状态是 granted）。只去掉其中一层时没有测试失败：两层互为补充 |
| B16 | load 之后不等页面安静 | `render.go` | `TestContentThatAppearsLaterInATimerIsPresent` |
| B17 | API 对没签名的请求也起浏览器 | `service.go` | `TestTheAPIStartsNoBrowserForARequestThatIsNotSigned`（进程数、审计不是零） |
| B18 | 渲染器不跳过 image/media/font | `render.go` | `TestImagesMediaAndFontsAreSkippedAndDoNotUseTheBudget`（原来的 500 张图用光预算，源站收到图片请求，指标为 0） |
| K1 | 清单：代理出口的 `except` 少一段（169.254.0.0/16） | `deploy/kubernetes/networkpolicy.yaml` | `TestProxyEgressIsThePublicInternetOnTheListedPortsAndIPv4Only`（整个 IPv4 空间逐 /24 对比） |
| K2 | 清单：渲染器可以出公网 | 同上 | `TestNetworkPoliciesHoldTheFlowsOfTheADRAndNoOthers` |
| K3 | 清单：集群里任何 Pod 都能连代理 | 同上 | 同上 |
| K4 | 清单：任何命名空间都能连渲染器的 API | 同上 | 同上 |
| K5 | 清单：没有 RuntimeClass | `renderer.yaml` | `TestTheRendererRunsUnderARuntimeClassThatIsTheSandboxAndSaysSo` |
| K6 | 清单：`--no-sandbox` 没有隔离声明 | `settings.yaml`、`renderer.yaml` | 同上 |
| K7 | 清单：渲染器的根文件系统可写 | `renderer.yaml` | `TestBothPodsAreHardened` |
| K8 | 清单：带了测试源站设置 | `renderer.yaml` | `TestNothingTestOnlyIsShipped` |
| K9 | 清单：代理的 Service 没有 ClientIP 亲和性 | `proxy.yaml` | `TestSettingsAreKnownToTheCodeAndTheirFilesAreMounted` |
| K10 | 清单：代理的端口列表与渲染器的缺省不一致 | `proxy.yaml` | 同上 |

没有对应测试的控制（诚实地列出）：`--host-resolver-rules`（浏览器不解析名字）去掉后没有测试失败，因为有 HTTP 代理时浏览器本来就不解析目的地的名字，它是第二层；`Fetch` 域的请求数和文档 scheme 检查只在 B10、B12 的范围内被测；Chromium 沙箱本身（本机测试里开着）和 gVisor/Kata 下的运行没有测试能去掉再验证；NetworkPolicy 的实际执行要 CNI（平台的 kind）。


## 4. 计划里后来证明不对或不够的地方

1. **"每个请求（主页面、子资源……）都按地址规则检查，每次渲染限制请求数"**：代理数得到的只是它看得见的——CONNECT 隧道和明文请求。HTTPS 页面的上千个子资源经过 HTTP/2 在一两条隧道里，代理数不到。所以请求数的预算在两处执行：渲染器用 Fetch 域数页面自己的请求，代理数它看得到的；总字节与单响应预算是兜底。跨站 iframe（站点隔离下是另一个目标）里的请求只被代理的计数管。
2. **"NetworkPolicy 只放行到代理这一个出口"**：还需要 kube-dns（服务要解析代理的 Service 名）。已写进策略并有测试；要严格的话，把 `IDP_BROWSER_PROXY` 与 `_PROXY_ADMIN` 写成 ClusterIP，就可以去掉渲染器的 DNS 出口（`allow-dns` 按 Pod 选择器是对全命名空间的，那时只需留给代理）。
3. **"代理：从沙箱代码复制一份，加'只许公网'模式"**：沙箱的凭据是无状态的 HMAC。第一层要的"每次渲染的上限、渲染结束就失效、取回用量"需要有状态的登记表，因此有了管理口（D5），代理不能多副本地随便扩（亲和性）。多副本的代价写在 RUNBOOK 里；要真正的横向扩展，登记表要放到共享存储里，这不是第一层的事。
4. **"等网络空闲或页面稳定"不够读 `setTimeout` 的内容**：网络空闲的 500 ms 窗口在页面用 800 ms 的定时器填内容时就会提前结束。DOM 要静止 1 s（用页内的 MutationObserver 计数），整个等待最多 5 s。1 s 以上没有任何网络或 DOM 动静之后才出现的内容读不到，这是已知的限制。
5. **"WebRTC 只允许经代理"**：`--webrtc-ip-handling-policy` 单独不够；要 `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`（带值）。这是在测试里发现的：STUN 金丝雀收到过 3 个 UDP 包。
6. **"不用本机 DNS，主机名交给代理解析"**：`--host-resolver-rules="MAP * ~NOTFOUND"` 也会让浏览器解析**代理自己的地址**失败（`ERR_PROXY_CONNECTION_FAILED`），要 `EXCLUDE 127.0.0.1`。另：Chromium 默认不对回环走代理，页面请求 127.0.0.1 会绕过代理，要 `--proxy-bypass-list=<-loopback>`，否则 SSRF 页面里最典型的那个目标不经过代理、审计里也没有。
7. **`blocked_by_site` 不只是验证码**：Akamai 的"无权限"页以 200 返回（FedEx，2026-11-23），用状态码和验证码关键词都抓不到；加了 S4（拒绝页的话）。
8. **计划写"idp-web 渲染后正文仍然太少 → 报 `needs_script`，原因另记 `render_failed`"**：渲染成功但内容仍少是 idp-web 的判断（L1-3）；本服务只在渲染本身失败时给 `render_failed`。
9. **chromedp 的新版 API**（v0.24：泛型 `Action[T]`、`chromedp.Call`、`cdp.Call`、管道传输是缺省）与旧文档里的 `chromedp.Run(ctx, chromedp.ActionFunc(...))` 不同；第一次 `Run` 的上下文不能带超时（超时会停掉整个浏览器），所以渲染的时钟是自己的 `AfterFunc`，不是 `WithTimeout`。

## 5. 没有做的

- 渲染后"正文仍然太少"的判断、租户的"总是渲染"名单、`needs_script` 的转交与 `ref`/配额/robots.txt：L1-3（idp-web）。
- compose 的服务与网络、PATH M6、BOM、镜像镜像清单的条目、升级说明：L1-4（平台）。
- 注入集（E3 方法）、真实页面集（E4）上的提取质量：计划第 3 节的验收，要 idp-web 一侧接通后做。
- 在真实集群（kind 加 Calico 加 gVisor）上验证 NetworkPolicy 与 RuntimeClass：这里只有清单与代码的一致性测试（`tests/deploy`）；Chromium 在 gVisor 下的运行（`IDP_BROWSER_TEST_NO_SANDBOX=gvisor` 加 `--runtime=runsc`）没有在本机跑过，本机 Docker 没有 runsc 运行时。
- 横向扩展代理（D5 的亲和性限制）、按租户的域名策略（计划第 2 节，第二层）。
