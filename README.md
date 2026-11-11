# dsh-clash-verge

DSH 的出口与流量看板：四种预设决定 DSH 自己的每个请求走哪条链路，本地代理按字节记账。

## 它管什么

DSH 向外发的每一个请求，都从这条链路出去：`web_fetch`、`web_search`、bash 里的 `curl` 和 `nmap`、以及任何走 Node `fetch` 的插件。插件在 DSH 和外部世界之间插一个本地代理，于是「这条请求走哪条线、一共搬了多少字节」从一件靠手工 `export https_proxy=…` 维持的事，变成面板上的一个开关加一张账单。

四种预设对应四类活：日常直连；拉外网资源时让公网走机场、内网仍然直连；网攻时把内网目标也一起交给代理链；以及完全不插手的原始状态。切换即时生效，只影响之后的请求，正在跑的下载保持原路由。

它计量的是真正搬动的字节，从流里累加，不按请求数估算——失败的、重试的、中途被掐断的下载都算在里面。于是「这次调研吃了多少流量、都去了哪些主机」可以事后回答，而不是只能靠猜。

作用域只有 DSH 进程和它拉起的子进程：不改系统代理、不开 TUN、不碰代理工具自己的 profile 和节点组。整台机器的网络交给系统级代理，DSH 自己的流量交给这里。

## 为 DSH 而做

不是把通用代理工具搬进编辑器，而是按 DSH 的形状重新做了一遍选路与记账：

- **按请求记账，不只按连接。** 报表以目标主机为维度聚合，回答「这次调研吃了多少流量、都去了哪台主机」；系统级代理只看得到连接，看不到是谁发起的。
- **切换不用重启，也不打断在跑的任务。** 模式是运行期状态，换链路只影响之后的请求，正在下载的文件保持原路由。
- **模型可以自己切。** `egress_mode` 工具让 agent 把「先切全局 → 打内网 → 切回外网」写成流程，不需要人守在面板前点。
- **上游故障不升级成会话事故。** 每 15 秒探活：`external` 不可达时降级直连并记账；`global` 默认**失败关闭**（拒绝发送、记 `blocked`），因为一次悄悄直连正是这个预设要防的泄露。两种行为都可在面板里看到、在配置里改。
- **不接管系统网络。** 不改系统代理、不开 TUN、不动网卡与防火墙；插件不在了，网络立刻回到启动时的样子，不会留下一个把整机留在断网状态的残留配置。
- **流式透传，不做中间加工。** 连接直接 pipe，不缓冲、不重写报文、不注入头部，本地代理只负责选路和计数。
- **零依赖、无构建。** host 半是原生 ESM，客户端半是手写 bundle，改完 `lib/*.js` 直接生效，没有 `npm install`，也没有打包步骤。

进来的路：左侧栏一个图标、一个模式切换、一张实时报表。

## 四种模式

| 模式 | 含义 | 典型场景 |
| --- | --- | --- |
| **不接管** `off` | 完全不插策略，出网与启动环境一致；不统计 | 排查问题、不想让代理介入 |
| **直连** `direct` | 全部直连，但仍经本地代理，因此照样统计 | 只想要报表、不想走上游 |
| **外网** `external` | 公网走上游，内网/回环直连（按目标分流） | 访问内网打不到的外部资源、拉 GitHub、查资料 |
| **全局** `global` | 除回环外**全部**走上游 | 网攻/红队：让内网目标也从代理侧（代理链、VPS、落地机）出去 |

模式写在 `~/.dsh/storages/clash-verge/state.json`，DSH 重启后自动恢复。

## 工作方式

```
DSH 进程 ──fetch/子进程──▶ 127.0.0.1:<临时端口> 本地统计代理 ──┬─▶ 直连目标
                                                              └─▶ 上游（http / https / socks5 / socks5h / trojan）
```

- 本地代理随插件启动，端口随机分配（只监听回环）。
- 每个连接按**目标主机名**决定路由，而不是按进程：`external` 用私网判定（10/8、172.16/12、192.168/16、169.254/16、100.64/10、fc00::/7、`.local`/`.lan`/`.internal` 等后缀、单标签主机名）决定直连还是上游。
- 回环永远直连 —— 否则 Web UI 自己的请求会被代理绕回自己，形成环路。
- 策略通过 `@deepseek-ai/dsh-http-proxy` 安装：进程内的 `fetch` 换掉 undici 全局 dispatcher，子进程在 spawn 时读到 `http_proxy/https_proxy`，所以**切换只影响之后的请求**，正在跑的下载保持原路由。
- 上游健康每 15 秒探测一次。不可达时按模式处理：`external` 降级直连（面板记「降级直连 N 次」），`global` 默认 **失败关闭** —— 请求不被发送、返回 502、报表记在 `blocked` 而不是 `direct`，可用 `globalFailClosed: false` 关掉改成降级。
- 目标地址在建连前先校验：端口超出 1–65535 或主机名为空直接 400 拒绝，不会让一个畸形 `CONNECT` 把进程带走。

## 上游：可以是任何东西

上游只是一个「下一个跳」，不绑定任何客户端。面板里填哪种都行，写进去就按那种协议说话：

| 写法 | 协议 | 典型来源 |
|---|---|---|
| `127.0.0.1:7897` | HTTP 代理（省略 scheme 时按 http 处理） | 任何客户端的混合/HTTP 入站 |
| `http://127.0.0.1:8080` | HTTP | tinyproxy、squid、企业代理 |
| `https://proxy.example:8443` | HTTPS 代理（TLS 到代理本身） | 需要加密到代理那一段 |
| `socks5://127.0.0.1:1080` | SOCKS5，**本机解析域名** | `ssh -N -D 1080 user@vps` |
| `socks5h://127.0.0.1:1080` | SOCKS5，**对端解析域名** | 对端 DNS 更干净，或本机 DNS 被污染 |
| `socks5://user:pass@host:1080` | SOCKS5 带用户名/口令 | 有认证的 SOCKS5 服务 |
| `trojan://password@vps.example:443` | trojan（TLS） | 自建 trojan 监听 |

所以不需要 Clash — 一条 `ssh -N -D 1080 you@your-vps` 就有 SOCKS5 上游了，面板里填 `socks5://127.0.0.1:1080` 即可，DSH 的出网从 VPS 出去，`global` 模式配合它做红队出口。trojan 想用自签证书就加 `?insecure=1`，证书按域名签、连接用 IP 时加 `?sni=your.domain`。

上游地址留空时自动探测本机配置（读到 `verge.yaml` 的 `verge_mixed_port` 就用它，读不到用 7897）—— 这只是「让开箱即用的用户少填一次」，不是依赖：填了别的，自动探测就不参与。

口令不会出现在面板和接口里：`state` 里的 url 渲染成 `socks5://user:***@host:1080`，密码只存在 `~/.dsh/storages/clash-verge/state.json`。

## 订阅（可选）

不想一条条填上游，就把订阅地址丢进面板：

- 三种格式都读：**Clash 配置**（`proxies:` 块、行内映射、单行列表）、**base64** 包、**一行一个 URI**（`#` 后面是名字）。
- 拉取时先直连，不通再经本机代理重试 —— 这条路径本身绕开进程级策略，否则「要连订阅得先有订阅」就死循环了。
- 每个节点会单独探活（TCP 连接，2s 超时），面板显示延迟与在线状态；`selected: "auto"` 时用**最快且在线**的那个，60 秒重测一次。没探到过延迟的节点不会被 `auto` 选中 —— 猜一个可能把第一条请进黑洞。
- 读不了的节点不装作读得了：`ss`/`vmess`/`vless`/`hysteria`/`tuic` 等会进 `skipped` 并写原因，面板底下直接列出来。
- 节点只有一个「下一个跳」的含义：`type` 与 URL 一一对应，选中哪个就等于把上游换成它；手动上游（面板第一行）随时可以切回去。

节点和订阅地址存在 `state.json` 里，重启后还在；延迟不存 —— 延迟是某一刻的事，不是配置。

## 报表

- 实时上行/下行速率（最近 5 个完整秒桶的均值）
- 累计上下行、请求数、活动连接
- 最近 120 秒吞吐折线（上行/下行分色）
- 流量去向（上游 vs 直连）与模式分布
- 目标主机 Top 20：上下行字节、请求数、实际路由、最近访问时间

所有数字都从字节流本身累加，统计的是**真正搬动的字节**，包含失败重试与被中断的下载。

## 性能

本地代理只多一跳，而且是纯粹的 pipe：不解包、不缓冲、不重写报文、不注入头部，上游到达的每个 chunk 直接写给调用方。所以它加的成本是「一条回环 TCP + 一次 HTTP 头解析」，不是「把文件下载一遍再转发一遍」。

`node tests/bench.mjs` 可复现（本机回环、多轮交错取样、取中位数）：

| 路径 | 200 次 16 KiB 请求的中位往返 |
| --- | --- |
| 直连 | 0.43 ms |
| 经代理（直连） | 0.96 ms |
| 经代理 → 上游 | 2.73 ms |

第三行里的「上游」是同进程的替身，它的解析与转发开销也计在这张表里；真实上游是另一个进程、另一台机器，那部分成本不在本插件账上。

批量传输的吞吐不做具体宣称：同一份代码在相邻几轮里能测出 168 MiB/s 到 237 MiB/s 的差别，取决于本机内存带宽与 GC 时机，而不是代理。要数字请直接跑脚本，看你自己机器上的结果，别信别人 README 里的百分比。

## 工具

模型可调用 `egress_mode` 工具切模式，返回当前上游、可达性、代理地址与累计流量。适合「先切全局再打内网」这类脚本化流程。

## HTTP 接口

`/clash-verge/api` 前缀：

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/state` | 当前模式、上游、代理状态、完整报表 |
| POST | `/mode` | `{ "mode": "off" \| "direct" \| "external" \| "global" }` |
| POST | `/config` | `{ upstream?, bypass?, intranetSuffixes?, globalFailClosed? }`（`upstream` 非法值返回 400 且不覆盖已存配置） |
| POST | `/subscription` | `{ "url": "https://…/sub" }` 拉取并替换节点列表；`url` 为空则清空 |
| POST | `/node` | `{ "id": "" \| "auto" \| <node id> }` 选节点（空串 = 用配置的上游） |
| POST | `/nodes/probe` | 给所有节点重新测速 |
| POST | `/probe` | 立即探测上游 |
| POST | `/reset` | 清零统计 |

## 安全边界

这个接口能改出口链路，所以它自己守门，不依赖上层：

- 只接受**同源**请求：`Sec-Fetch-Site` 必须是 `same-origin`/`none`，`Origin`（若有）必须等于 `Host`，`Host` 必须是回环地址或在白名单里（挡 DNS rebinding）。跨站页面发来的表单/简单请求一律 403 —— 它们既拿不到响应，也改不了模式。
- 写操作必须是 `application/json`（否则 415）并带上本进程当次启动生成的 `x-clash-verge-token`（否则 403）。token 由 `GET /state` 下发，跨源页面读不到响应，因此拿不到它；面板刷新后自动换新。
- 通过反向代理访问 Web UI 时，把对外的 `Host` 加进 `CLASH_VERGE_TRUSTED_HOSTS`（逗号分隔）即可，否则这些写操作会被判成不可信来源。

## 安装

```bash
# 直接装 GitHub 上的仓库
dsh plugin --profile web add github:dawnsss/dsh-clashVerge

# 或者先克隆，再装本地目录（改完 lib/*.js 立刻生效，适合自己动代码）
git clone https://github.com/dawnsss/dsh-clashVerge.git
dsh plugin --profile web add ./dsh-clashVerge
```

或在 GUI 插件页用「本地目录」安装。装完刷新页面，左侧栏出现「出口模式」。

## 测试

```bash
node tests/smoke.mjs    # 代理路由、CONNECT 隧道、降级与计数
node tests/upstream.mjs # 上游协议：SOCKS5（无认证/带认证/被拒）、trojan 摘要头、隧道端到端
node tests/subscription.mjs # 订阅：Clash 块/行内/单行、base64、URI 列表、拉取重定向与上限
node tests/host.mjs     # host 半契约：29 项（含鉴权、坏端口、失败关闭、订阅与选节点；需要本机装着 DSH，读它 profile 里的依赖）
node tests/client.mjs   # bundle 契约；找不到含 react 的 profile 时自动跳过
node tests/bench.mjs    # 回环性能取样，可选，默认 64 MiB × 3 轮
```

`smoke`、`upstream` 与 `bench` 自己起 origin 与上游替身（含一个带自签证书的假 trojan 监听），不联网；`host` 会在 `~/.dsh/storages/clash-verge/` 下写状态文件，跑完自行清理。

## 结构

```
lib/index.js   host 半：模式、状态、上游探测、策略安装、HTTP 接口、egress_mode 工具
lib/proxy.js   本地代理 + 计数器（无第三方依赖）
lib/upstream.js  上游协议：http/https 的 CONNECT、socks5/socks5h 握手、trojan 摘要头
lib/subscription.js 订阅：Clash 配置 / base64 / URI 列表解析，以及绕开进程策略的拉取
lib/client.js  浏览器半：手写 bundle（__ModuleLoader__.load 外壳），侧栏图标 + 面板
cordis.patch.yml  挂载行
tests/smoke.mjs   代理路由与计数（自起 origin 与上游替身）
tests/upstream.mjs 上游协议与隧道（假 SOCKS5 / 假 trojan / 端到端）
tests/subscription.mjs 订阅解析与拉取（本地 server、重定向、上限、代理回退）
tests/host.mjs    host 半契约：状态、模式、接口、工具、持久化、拆卸
tests/client.mjs  bundle 契约：模块注册、槽位、图标与首屏渲染
tests/bench.mjs   回环性能取样（小请求往返 / 批量吞吐 / CPU）
```

Host 半是原生 ESM JS，客户端半是手写 CJS bundle，因此**没有构建步骤**：

- 改 `lib/client.js`：DSH 按 mtime/size 轮询 bundle，刷新都不用，面板在页内换新（`browser_*`/浏览器里直接可见）。
- 改 `lib/index.js` 或 `lib/proxy.js`：host 半只在进程启动时加载，重启 `dsh web` 才生效。

## 注意

- 子进程的 `http_proxy` 环境变量只能写 HTTP 地址 —— 但那是**指向本插件的本地代理**，所以上游是 SOCKS5、trojan 都不影响子进程（`curl`、`git` 照样工作），协议转换在本地代理里完成。
- 不支持的 scheme（`socks4://`、`vmess://` 等）在保存时被 400 拒绝，已经存着的配置不会被覆盖。
- `external` 模式判定的是**主机名**，不做 DNS 解析后再判定 —— 一个公网域名解析到内网地址时仍会走上游，这是刻意的（否则每次请求都要多一次 DNS）。
- 需要「连内网也走代理」时用 `global`，并把 `bypass` 留空。
