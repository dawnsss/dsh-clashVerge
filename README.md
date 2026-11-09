# dsh-clash-verge

给 DSH 装一块 Clash Verge 形状的操作台：**四种出口模式** + **实时流量报表**，作用对象是 DSH 自己发出的网络请求（`web_fetch`、`web_search`、bash 里的 `curl`/`nmap`、以及所有走 Node `fetch` 的插件），不是整台机器的系统代理。

左侧栏 →「出口模式」。

## 四种模式

| 模式 | 含义 | 典型场景 |
| --- | --- | --- |
| **不接管** `off` | 完全不插策略，出网与启动环境一致；不统计 | 排查问题、不想让代理介入 |
| **直连** `direct` | 全部直连，但仍经本地代理，因此照样统计 | 只想要报表、不想走机场 |
| **外网** `external` | 公网走 Clash 上游，内网/回环直连（= Clash 规则模式） | 访问内网打不到的外部资源、拉 GitHub、查资料 |
| **全局** `global` | 除回环外**全部**走 Clash 上游 | 网攻/红队：让内网目标也从代理侧（代理链、VPS、落地机）出去 |

模式写在 `~/.dsh/storages/clash-verge/state.json`，DSH 重启后自动恢复。

## 工作方式

```
DSH 进程 ──fetch/子进程──▶ 127.0.0.1:<临时端口> 本地统计代理 ──┬─▶ 直连目标
                                                              └─▶ Clash mixed-port ──▶ 节点
```

- 本地代理随插件启动，端口随机分配（只监听回环）。
- 每个连接按**目标主机名**决定路由，而不是按进程：`external` 用私网判定（10/8、172.16/12、192.168/16、169.254/16、100.64/10、fc00::/7、`.local`/`.lan`/`.internal` 等后缀、单标签主机名）决定直连还是上游。
- 回环永远直连 —— 否则 Web UI 自己的请求会被代理绕回自己，形成环路。
- 策略通过 `@deepseek-ai/dsh-http-proxy` 安装：进程内的 `fetch` 换掉 undici 全局 dispatcher，子进程在 spawn 时读到 `http_proxy/https_proxy`，所以**切换只影响之后的请求**，正在跑的下载保持原路由。
- 上游健康每 15 秒探测一次；上游不可达时自动降级直连并在面板上记一条「降级直连 N 次」，避免 Clash 一挂就把整个会话的网络一起拖死。

上游默认从 Clash Verge 自己的 `verge.yaml` 的 `verge_mixed_port` 读（通常 7897），面板里可改成任意 `host:port` / `http(s)://host:port`。

## 报表

- 实时上行/下行速率（最近 5 个完整秒桶的均值）
- 累计上下行、请求数、活动连接
- 最近 120 秒吞吐折线（上行/下行分色）
- 流量去向（Clash 上游 vs 直连）与模式分布
- 目标主机 Top 20：上下行字节、请求数、实际路由、最近访问时间

所有数字都从字节流本身累加，统计的是**真正搬动的字节**，包含失败重试与被中断的下载。

## 工具

模型可调用 `egress_mode` 工具切模式，返回当前上游、可达性、代理地址与累计流量。适合「先切全局再打内网」这类脚本化流程。

## HTTP 接口

`/clash-verge/api` 前缀：

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/state` | 当前模式、上游、代理状态、完整报表 |
| POST | `/mode` | `{ "mode": "off" \| "direct" \| "external" \| "global" }` |
| POST | `/config` | `{ upstream?, bypass?, intranetSuffixes? }` |
| POST | `/probe` | 立即探测上游 |
| POST | `/reset` | 清零统计 |

## 安装

```bash
dsh plugin --profile web add D:\work\2026\ai\custom-plugin\dsh-clashVerge
```

或在 GUI 插件页用「本地目录」安装。装完刷新页面，左侧栏出现「出口模式」。

## 结构

```
lib/index.js   host 半：模式、状态、上游探测、策略安装、HTTP 接口、egress_mode 工具
lib/proxy.js   本地代理 + 计数器（无第三方依赖）
lib/client.js  浏览器半：手写 bundle（__ModuleLoader__.load 外壳），侧栏图标 + 面板
cordis.patch.yml  挂载行
```

Host 半是原生 ESM JS，客户端半是手写 CJS bundle，因此**没有构建步骤**，改完 `lib/*.js` 直接生效（面板 HMR 跟随 `lib/client.js` 的 mtime）。

## 注意

- 只支持 HTTP/HTTPS 上游；SOCKS 上游会被 `dsh-http-proxy` 跳过。
- `external` 模式判定的是**主机名**，不做 DNS 解析后再判定 —— 一个公网域名解析到内网地址时仍会走上游，这是刻意的（否则每次请求都要多一次 DNS）。
- 需要「连内网也走代理」时用 `global`，并把 `bypass` 留空。
