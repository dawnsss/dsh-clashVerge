/**
 * dsh-clash-verge, host half.
 *
 * A Clash Verge-shaped egress panel for the harness itself: three presets that decide how this
 * process's outbound traffic leaves the machine, one loopback proxy that measures all of it, and a
 * report the Web UI renders.
 *
 * Why a local proxy instead of talking to Clash's own API: the harness's traffic is what needs a
 * mode, not the machine's. Pointing every request at one loopback proxy puts the routing decision —
 * and therefore the byte counts — in this process, where a preset can be one callback and the
 * report can be truthful per host, per mode, and per route actually taken.
 *
 * The proxy is only half of it. Node's `fetch` ignores proxy environment variables, so a mode that
 * does not install `@deepseek-ai/dsh-http-proxy`'s policy would leave the model's own requests
 * direct while `curl` in a shell went through Clash. The policy is therefore installed from a
 * synthetic environment on every mode change and disposed back to the launcher's own policy on
 * `off`, which is also what makes switching safe at runtime: children resolve their proxy at spawn
 * time, so the change reaches the next command, not the running one.
 *
 * @module dsh-clash-verge
 */

import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

import { createProxyServer, createRecorder, isLoopbackHost, isPrivateHost, normalizeHost, parseAuthority } from './proxy.js'

/** Cordis plugin name. */
export const name = 'clash-verge'

/**
 * Services this plugin contributes to: the HTTP surface it cannot work without.
 *
 * `tools` is deliberately *not* listed. A cordis `inject` entry is a hard requirement — a plugin
 * naming a service nobody provides waits forever, printing nothing (`registry.ts:105`,
 * `fiber.ts:611-620`). The tool is an extra, so it is registered through `ctx.inject(...)` instead,
 * which activates only once the registry exists.
 */
export const inject = ['webServer']

/** The presets, in the order the panel lists them. */
export const MODES = [
  {
    id: 'off',
    title: '不接管',
    subtitle: 'Off',
    summary: '按启动环境原样出网，本插件不安装代理策略，也不统计流量。',
  },
  {
    id: 'direct',
    title: '直连',
    subtitle: 'Direct',
    summary: '全部直连；流量仍然经过本地统计代理，因此照常计数。',
  },
  {
    id: 'external',
    title: '外网',
    subtitle: 'Rule',
    summary: '公网请求走上游代理，内网与回环直连 —— 按目标分流。',
  },
  {
    id: 'global',
    title: '全局',
    subtitle: 'Global',
    summary: '除回环外的全部请求走上游代理 —— 网攻时让内网目标也从代理侧出去。',
  },
]

const MODE_IDS = new Set(MODES.map(mode => mode.id))

/** Defaults for a profile that has never opened the panel. */
const DEFAULTS = {
  mode: 'off',
  /** Empty means "detect from Clash Verge's own configuration". */
  upstream: '',
  /** Hosts or suffixes that always stay direct, whatever the mode (statistics still count them). */
  bypass: [],
  /** Extra intranet suffixes for the `external` preset, on top of the built-in list. */
  intranetSuffixes: [],
  /**
   * Whether `global` refuses a request instead of degrading to a direct connection when the upstream
   * is unreachable. On by default: a silently direct request defeats the point of that preset.
   */
  globalFailClosed: true,
}

/** Where Clash Verge keeps its configuration and where its mixed port is recorded. */
const VERGE_DIRS = [
  path.join(process.env.APPDATA ?? path.join(os.homedir(), 'AppData', 'Roaming'), 'io.github.clash-verge-rev.clash-verge-rev'),
  path.join(os.homedir(), '.config', 'io.github.clash-verge-rev.clash-verge-rev'),
]

/** Clash's default mixed port, used when no configuration can be read. */
const DEFAULT_MIXED_PORT = 7897

/**
 * Read a `key: value` scalar out of a YAML file without pulling in a parser.
 * @param file - absolute path of the YAML file.
 * @param key - the top-level key to find.
 * @returns the trimmed scalar, or undefined when the file or key is absent.
 */
function readYamlScalar(file, key) {
  if (!existsSync(file)) return undefined
  try {
    const text = readFileSync(file, 'utf8')
    const match = new RegExp(`^${key}:\\s*(.+)$`, 'm').exec(text)
    if (match === null) return undefined
    return match[1].trim().replace(/^['"]|['"]$/g, '')
  } catch {
    return undefined
  }
}

/**
 * Find out what Clash Verge on this machine would use as its mixed port.
 *
 * The running GUI writes `verge_mixed_port` in `verge.yaml`; the generated core config carries
 * `mixed-port`. When neither is readable the Clash default is the best guess there is.
 * @returns the detected port, the file it came from, and whether the configuration exists at all.
 */
function detectClash() {
  for (const dir of VERGE_DIRS) {
    const verge = path.join(dir, 'verge.yaml')
    const generated = path.join(dir, 'clash-verge.yaml')
    if (!existsSync(verge) && !existsSync(generated)) continue
    const configured = readYamlScalar(verge, 'verge_mixed_port')
    const generatedPort = readYamlScalar(generated, 'mixed-port')
    const port = Number(configured ?? generatedPort ?? DEFAULT_MIXED_PORT)
    const mode = readYamlScalar(generated, 'mode')
    return {
      configDir: dir,
      mixedPort: Number.isFinite(port) && port > 0 ? port : DEFAULT_MIXED_PORT,
      source: configured !== undefined ? 'verge.yaml' : generatedPort !== undefined ? 'clash-verge.yaml' : 'default',
      profileMode: mode ?? '',
      tun: readYamlScalar(generated, 'tun') !== undefined,
    }
  }
  return { configDir: '', mixedPort: DEFAULT_MIXED_PORT, source: 'default', profileMode: '', tun: false }
}

/**
 * Turn a configured or detected upstream into a URL and its parts.
 * @param value - `host:port`, `http://host:port` or `https://host:port`.
 * @returns the parsed descriptor, or undefined when nothing usable is configured.
 */
function parseUpstream(value) {
  const text = String(value ?? '').trim()
  if (text === '') return undefined
  // The scheme pattern must accept digits: `[a-z]+` misses `socks5://`, which then got an `http://`
  // prefix and parsed into the nonsense host `socks5`.
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`
  try {
    const url = new URL(withScheme)
    // Only HTTP CONNECT and absolute-URI forwarding are implemented: a `socks5://` value would be
    // spoken to as if it were an HTTP proxy and produce garbled failures far from the cause.
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined
    const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80))
    if (url.hostname === '' || !Number.isFinite(port) || port < 1 || port > 65_535) return undefined
    return { protocol: url.protocol, host: normalizeHost(url.hostname), port, url: `${url.protocol}//${url.hostname}:${port}` }
  } catch {
    return undefined
  }
}

/**
 * Open a TCP connection and report whether it succeeded, without keeping it.
 * @param host - target host.
 * @param port - target port.
 * @param timeoutMs - how long to wait.
 * @returns latency in milliseconds, or the failure reason.
 */
async function probeTcp(host, port, timeoutMs = 1500) {
  const started = Date.now()
  return await new Promise((resolve) => {
    const socket = net.connect({ host, port })
    let settled = false
    const finish = (result) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(result)
    }
    socket.setTimeout(timeoutMs, () => finish({ ok: false, error: 'timeout', ms: timeoutMs }))
    socket.once('connect', () => finish({ ok: true, ms: Date.now() - started }))
    socket.once('error', error => finish({ ok: false, error: error.code ?? error.message, ms: Date.now() - started }))
  })
}

/**
 * Human-readable byte size.
 * @param bytes - count of bytes.
 * @returns a short label such as `1.4 MB`.
 */
export function formatBytes(bytes) {
  const value = Number(bytes) || 0
  if (value < 1024) return `${value} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let size = value / 1024
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size.toFixed(size >= 100 ? 0 : size >= 10 ? 1 : 2)} ${units[unit]}`
}

/**
 * Whether a host is named by one bypass entry.
 * @param host - the target host.
 * @param entry - an exact host, a bare suffix, or a `.suffix` / `*.suffix` pattern.
 * @returns true when the entry claims the host.
 */
function matchesBypass(host, entry) {
  const raw = String(entry ?? '').trim().toLowerCase()
  if (raw === '') return false
  const wildcard = raw.replace(/^\*\./, '.').replace(/^\*/, '')
  const bare = normalizeHost(wildcard)
  if (bare === '') return false
  if (wildcard.startsWith('.') || raw.startsWith('*')) {
    return host === bare || host.endsWith(`.${bare}`)
  }
  return host === bare || host.endsWith(`.${bare}`)
}

/**
 * Resolve one module from the profile that loaded this plugin.
 *
 * A plugin installed as a link inside the profile resolves its own bare imports from its source
 * directory, which is not where the harness's packages live. Resolving from the loader's base
 * directory instead finds the profile's `node_modules` and, one level up, the hoisted harness
 * packages — the same files the running process already loaded.
 * @param baseDir - the cordis loader's base directory.
 * @param specifier - the bare specifier to resolve.
 * @returns the imported namespace, or undefined when it cannot be resolved.
 */
async function importFromProfile(baseDir, specifier) {
  const candidates = [baseDir, path.join(os.homedir(), '.dsh', 'profiles')].filter(candidate => typeof candidate === 'string' && candidate !== '')
  for (const dir of candidates) {
    try {
      const require = createRequire(path.join(dir, 'noop.cjs'))
      const resolved = require.resolve(specifier)
      return await import(pathToFileURL(resolved).href)
    } catch {
      // Try the next candidate: a profile directory that does not hoist this package is normal.
    }
  }
  return undefined
}

/**
 * Mount the plugin.
 * @param ctx - the cordis context.
 * @param config - optional row configuration from `cordis.patch.yml`.
 */
export async function apply(ctx, config = {}) {
  const log = (message) => {
    try {
      ctx.logger?.info?.(`[clash-verge] ${message}`)
    } catch {
      // A logger that throws must not break routing.
    }
  }
  const warn = (message) => {
    try {
      ctx.logger?.warn?.(`[clash-verge] ${message}`)
    } catch {
      // Same.
    }
  }

  // `baseDir` is a cordis service, not a plain field: reading it without
  // `inject` throws. It only seeds module resolution, and `importFromProfile`
  // carries its own fallbacks, so a guarded read plus cwd is enough here.
  let baseDir = process.cwd()
  try {
    const candidate = ctx.baseDir
    if (typeof candidate === 'string' && candidate !== '') baseDir = candidate
  } catch {
    // Not injected: fall back to cwd, then to the profile-level resolution base.
  }
  const storageDir = path.join(os.homedir(), '.dsh', 'storages', 'clash-verge')
  const stateFile = path.join(storageDir, 'state.json')

  const loadState = () => {
    let stored = {}
    try {
      if (existsSync(stateFile)) stored = JSON.parse(readFileSync(stateFile, 'utf8'))
    } catch (error) {
      warn(`ignoring unreadable state file: ${error.message}`)
    }
    const merged = { ...DEFAULTS, ...config, ...stored }
    if (!MODE_IDS.has(merged.mode)) merged.mode = 'off'
    merged.bypass = Array.isArray(merged.bypass) ? merged.bypass.filter(entry => typeof entry === 'string' && entry.trim() !== '') : []
    merged.intranetSuffixes = Array.isArray(merged.intranetSuffixes) ? merged.intranetSuffixes.filter(entry => typeof entry === 'string' && entry.trim() !== '') : []
    merged.globalFailClosed = merged.globalFailClosed !== false
    return merged
  }

  const state = loadState()
  const persist = () => {
    try {
      mkdirSync(storageDir, { recursive: true })
      const temporary = `${stateFile}.${process.pid}.tmp`
      writeFileSync(temporary, `${JSON.stringify({
        mode: state.mode,
        upstream: state.upstream,
        bypass: state.bypass,
        intranetSuffixes: state.intranetSuffixes,
        globalFailClosed: state.globalFailClosed,
      }, null, 2)}\n`)
      renameSync(temporary, stateFile)
    } catch (error) {
      warn(`cannot persist state: ${error.message}`)
    }
  }

  const clash = detectClash()
  const recorder = createRecorder()
  const health = { ok: false, checkedAt: 0, latencyMs: 0, error: 'not probed yet' }
  const fallback = { count: 0, lastAt: 0, lastHost: '' }
  const blocked = { count: 0, lastAt: 0, lastHost: '' }
  /**
   * Per-process secret the panel echoes back on every mutation.
   *
   * `ctx.webServer` adds no authentication of its own (`packages/host/webserver/README.md:130`:
   * "No server-wide authentication or origin policy"), so this route has to guard itself. The token
   * is the second half of that: without CORS headers a cross-site page can *send* a request but
   * cannot *read* a response, so it can never learn the token it would need to mutate anything.
   */
  const apiToken = randomUUID()
  /** Extra hosts, besides loopback, allowed to talk to this API (see `CLASH_VERGE_TRUSTED_HOSTS`). */
  const trustedHosts = new Set(
    String(process.env.CLASH_VERGE_TRUSTED_HOSTS ?? '')
      .split(',')
      .map(entry => normalizeHost(entry))
      .filter(entry => entry !== ''),
  )
  let proxyPort = 0
  let disposedPolicy = undefined
  let policyModule = undefined
  let policyFallbackEnv = undefined

  /** The upstream this profile currently uses — configured, or Clash Verge's own port. */
  const currentUpstream = () => {
    const configured = String(state.upstream ?? '').trim() !== '' ? String(state.upstream).trim() : `http://127.0.0.1:${clash.mixedPort}`
    return parseUpstream(configured)
  }

  /**
   * Decide how one connection leaves this process.
   * @param host - target host.
   * @returns the route actually taken, never a route that will fail.
   */
  const routeFor = (host) => {
    const mode = state.mode
    if (mode === 'off' || mode === 'direct') return 'direct'
    if (isLoopbackHost(host)) return 'direct'
    if (state.bypass.some(entry => matchesBypass(host, entry))) return 'direct'
    const wantsUpstream = mode === 'global'
      ? true
      : !isPrivateHost(host, state.intranetSuffixes)
    if (!wantsUpstream) return 'direct'
    if (health.ok) return 'upstream'
    if (mode === 'global' && state.globalFailClosed) {
      // Fail closed. `external` may degrade (the alternative is having no network at all), but a
      // request that quietly went direct under `global` is exactly the leak that preset exists to
      // prevent — so it is refused, and the report says `blocked` rather than `direct`.
      blocked.count += 1
      blocked.lastAt = Date.now()
      blocked.lastHost = host
      return 'blocked'
    }
    // The safety valve: a dead upstream must not take the session's network down with it. The
    // request goes direct, the report says direct, and the panel says the route was degraded.
    fallback.count += 1
    fallback.lastAt = Date.now()
    fallback.lastHost = host
    return 'direct'
  }

  const server = createProxyServer({
    recorder,
    route: routeFor,
    mode: () => state.mode,
    upstream: () => (health.ok ? currentUpstream() : undefined),
    onUpstreamFailure: (reason) => {
      health.ok = false
      health.error = reason
      warn(`upstream marked unreachable: ${reason}`)
    },
    log: warn,
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject)
      resolve()
    })
  })
  proxyPort = server.address().port
  log(`local proxy listening on 127.0.0.1:${proxyPort}`)

  const probe = async () => {
    const upstream = currentUpstream()
    if (upstream === undefined) {
      health.ok = false
      health.error = 'no upstream configured'
      health.checkedAt = Date.now()
      return health
    }
    const result = await probeTcp(upstream.host, upstream.port, 1500)
    health.ok = result.ok
    health.checkedAt = Date.now()
    health.latencyMs = result.ms
    health.error = result.ok ? '' : String(result.error ?? 'unreachable')
    return health
  }

  policyModule = await importFromProfile(baseDir, '@deepseek-ai/dsh-http-proxy')
  if (policyModule === undefined) {
    warn('@deepseek-ai/dsh-http-proxy is not resolvable from this profile: only spawned children will follow the mode')
  }

  /** The environment a policy install reads: everything proxied, loopback left to the package. */
  const policyEnv = (proxyUrl) => ({
    get: (variable) => {
      const key = String(variable).toLowerCase()
      if (key === 'http_proxy' || key === 'https_proxy') return { value: proxyUrl }
      if (key === 'no_proxy') return { value: '' }
      return undefined
    },
  })

  /**
   * Install this profile's mode as the process's transport policy.
   *
   * `off` disposes back to whatever the launcher installed, which is the only way to make "do not
   * take over" true rather than a label.
   */
  const syncPolicy = async () => {
    if (disposedPolicy !== undefined) {
      const dispose = disposedPolicy
      disposedPolicy = undefined
      // A graceful drain waits for idle keep-alive sockets, and an idle socket must never hold a
      // preset switch open: drop this proxy's idle connections, then bound the wait.
      server.closeIdleConnections?.()
      await Promise.race([
        dispose().catch((error) => warn(`disposing the previous policy failed: ${error.message}`)),
        new Promise((resolve) => setTimeout(resolve, 2_000)),
      ])
    }
    if (policyFallbackEnv !== undefined) {
      policyFallbackEnv()
      policyFallbackEnv = undefined
    }
    if (state.mode === 'off') return
    const proxyUrl = `http://127.0.0.1:${proxyPort}`
    if (policyModule?.installProxyFromEnvironment !== undefined) {
      disposedPolicy = await policyModule.installProxyFromEnvironment(policyEnv(proxyUrl), warn)
      return
    }
    // Without the policy package the in-process `fetch` cannot be routed, but children can: publish
    // the variables for them and put the environment back on `off`.
    const names = ['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'no_proxy', 'NO_PROXY']
    const previous = Object.fromEntries(names.map(name => [name, process.env[name]]))
    process.env.http_proxy = proxyUrl
    process.env.HTTP_PROXY = proxyUrl
    process.env.https_proxy = proxyUrl
    process.env.HTTPS_PROXY = proxyUrl
    process.env.no_proxy = ''
    process.env.NO_PROXY = ''
    policyFallbackEnv = () => {
      for (const [name, value] of Object.entries(previous)) {
        if (value === undefined) Reflect.deleteProperty(process.env, name)
        else process.env[name] = value
      }
    }
  }

  let switching = Promise.resolve()

  /**
   * Switch preset, then publish the change and its consequences.
   * @param next - one of {@link MODES}' ids.
   */
  const setMode = (next) => {
    if (!MODE_IDS.has(next)) throw new Error(`unknown egress mode: ${next}`)
    const run = switching.then(async () => {
      state.mode = next
      persist()
      await syncPolicy()
      if (next !== 'off' && next !== 'direct') await probe()
    })
    // Keep the chain alive across a failed switch. Awaiting `switching` directly would leave it
    // rejected forever, and every later `.then` would be skipped — one bad switch would freeze the
    // preset for the life of the process.
    switching = run.catch(() => {})
    return run
  }

  const snapshot = () => {
    const upstream = currentUpstream()
    return {
      ok: true,
      mode: state.mode,
      modes: MODES,
      upstream: {
        url: upstream?.url ?? '',
        configured: state.upstream,
        detectedPort: clash.mixedPort,
        detectedSource: clash.source,
        reachable: health.ok,
        latencyMs: health.latencyMs,
        checkedAt: health.checkedAt,
        error: health.error,
      },
      clash: {
        configDir: clash.configDir,
        profileMode: clash.profileMode,
      },
      proxy: {
        url: `http://127.0.0.1:${proxyPort}`,
        port: proxyPort,
        // What this profile is *able* to do, not what it currently does.
        policy: policyModule === undefined ? (policyFallbackEnv !== undefined ? 'environment-only' : 'unavailable') : 'installed',
        // "Taken over" must mean the process's own `fetch` is routed as well, not just children.
        installed: state.mode !== 'off' && policyModule !== undefined,
        envOnly: state.mode !== 'off' && policyModule === undefined,
      },
      bypass: state.bypass,
      intranetSuffixes: state.intranetSuffixes,
      globalFailClosed: state.globalFailClosed,
      fallback,
      blocked,
      token: apiToken,
      stats: recorder.snapshot({ history: 120, top: 20 }),
      serverTime: Date.now(),
    }
  }

  const json = (res, status, body) => {
    const text = JSON.stringify(body)
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
    res.end(text)
  }

  const readBody = async (req, limit = 64 * 1024) => {
    const chunks = []
    let size = 0
    for await (const chunk of req) {
      size += chunk.length
      if (size > limit) throw new Error('request body too large')
      chunks.push(chunk)
    }
    if (size === 0) return {}
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  }

  /**
   * Whether a request may touch this API at all.
   *
   * Three facts, each of which a cross-site page cannot fake:
   * - `sec-fetch-site` is set by the browser itself; anything but same-origin is refused.
   * - `host` must name this machine (loopback) or a host listed in `CLASH_VERGE_TRUSTED_HOSTS`.
   *   This is what stops DNS rebinding: `evil.example` resolving to 127.0.0.1 still sends
   *   `Host: evil.example`, so every "same-origin" test downstream would otherwise pass.
   * - `origin`, when present, must be the origin the request is addressed to.
   * @param req - the incoming request.
   * @returns true when the request may be answered.
   */
  const isTrustedRequest = (req) => {
    const site = String(req.headers['sec-fetch-site'] ?? '').toLowerCase()
    if (site !== '' && site !== 'same-origin' && site !== 'none') return false
    const hostHeader = String(req.headers.host ?? '')
    const host = parseAuthority(hostHeader, 80).host
    if (host === '') return false
    if (!isLoopbackHost(host) && !trustedHosts.has(host)) return false
    const origin = String(req.headers.origin ?? '')
    if (origin !== '') {
      try {
        if (new URL(origin).host.toLowerCase() !== hostHeader.toLowerCase()) return false
      } catch {
        return false
      }
    }
    return true
  }

  /**
   * The panel's API: one prefix, four verbs, no session state.
   * @param req - the incoming request.
   * @param res - the response to fill.
   */
  const handleApi = async (req, res) => {
    const pathname = new URL(req.url ?? '/', 'http://x').pathname
    const action = pathname.slice('/clash-verge/api'.length).replace(/^\/+/, '').replace(/\/+$/, '')
    if (!isTrustedRequest(req)) {
      json(res, 403, { ok: false, error: 'this API only answers same-origin requests from this machine' })
      return
    }
    try {
      if (req.method === 'POST') {
        // A cross-site HTML form can only produce a "simple" content type, and any other type from a
        // cross-site page needs a preflight this route never grants. The token then closes the rest.
        const type = String(req.headers['content-type'] ?? '').toLowerCase()
        if (!type.startsWith('application/json')) {
          json(res, 415, { ok: false, error: 'content-type must be application/json' })
          return
        }
        if (String(req.headers['x-clash-verge-token'] ?? '') !== apiToken) {
          json(res, 403, { ok: false, error: 'missing or stale panel token; reload the panel' })
          return
        }
      }
      if (req.method === 'GET' && (action === 'state' || action === '')) {
        json(res, 200, snapshot())
        return
      }
      if (req.method === 'POST' && action === 'mode') {
        const body = await readBody(req)
        if (typeof body.mode !== 'string') {
          json(res, 400, { ok: false, error: 'mode is required' })
          return
        }
        if (!MODE_IDS.has(body.mode)) {
          json(res, 400, { ok: false, error: `mode must be one of ${[...MODE_IDS].join(', ')}` })
          return
        }
        await setMode(body.mode)
        json(res, 200, snapshot())
        return
      }
      if (req.method === 'POST' && action === 'config') {
        const body = await readBody(req)
        // Validate before assigning: a rejected value must leave the working configuration intact.
        if (body.upstream !== undefined && String(body.upstream).trim() !== '' && parseUpstream(body.upstream) === undefined) {
          json(res, 400, { ok: false, error: 'upstream must be http://host:port or host:port' })
          return
        }
        if (typeof body.upstream === 'string') state.upstream = body.upstream.trim()
        if (Array.isArray(body.bypass)) {
          state.bypass = body.bypass.filter(entry => typeof entry === 'string' && entry.trim() !== '').map(entry => entry.trim())
        }
        if (Array.isArray(body.intranetSuffixes)) {
          state.intranetSuffixes = body.intranetSuffixes.filter(entry => typeof entry === 'string' && entry.trim() !== '').map(entry => entry.trim())
        }
        if (typeof body.globalFailClosed === 'boolean') state.globalFailClosed = body.globalFailClosed
        persist()
        await probe()
        await syncPolicy()
        json(res, 200, snapshot())
        return
      }
      if (req.method === 'POST' && action === 'reset') {
        recorder.reset()
        fallback.count = 0
        fallback.lastAt = 0
        fallback.lastHost = ''
        blocked.count = 0
        blocked.lastAt = 0
        blocked.lastHost = ''
        json(res, 200, snapshot())
        return
      }
      if (req.method === 'POST' && action === 'probe') {
        await probe()
        json(res, 200, snapshot())
        return
      }
      json(res, 404, { ok: false, error: `unknown endpoint: ${req.method} ${pathname}` })
    } catch (error) {
      warn(`api ${req.method} ${pathname} failed: ${error.message}`)
      json(res, 500, { ok: false, error: error.message })
    }
  }

  ctx.effect(() => ctx.webServer.register({ kind: 'prefix', path: '/clash-verge/api', handler: handleApi }), 'clash-verge: api route')

  const tool = {
    name: 'egress_mode',
    description:
      'Switch this harness session\'s outbound network mode and read its traffic report. '
      + 'Modes: "off" (leave the launch environment alone), "direct" (everything direct, still counted), '
      + '"external" (public hosts through the upstream proxy, intranet and loopback direct), '
      + '"global" (everything except loopback through the upstream proxy — use when an intranet target must be '
      + 'reached from the proxy side). Switching affects requests made after the call, including spawned '
      + 'shells; a running download keeps its route.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        mode: {
          type: 'string',
          enum: MODES.map(entry => entry.id),
          description: 'The egress mode to apply.',
        },
      },
      required: ['mode'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          mode: { type: 'string' },
          summary: { type: 'string' },
          upstream: { type: 'string' },
          upstreamReachable: { type: 'boolean' },
          proxy: { type: 'string' },
          total: { type: 'string' },
        },
        required: ['mode', 'summary', 'upstream', 'upstreamReachable', 'proxy', 'total'],
      },
      render: (_args, value) => [{ type: 'text', text: value.summary }],
    },
    async execute(args) {
      const next = typeof args?.mode === 'string' ? args.mode : ''
      if (!MODE_IDS.has(next)) throw new Error(`mode must be one of ${[...MODE_IDS].join(', ')}`)
      await setMode(next)
      const view = snapshot()
      const totals = view.stats.totals
      const label = MODES.find(entry => entry.id === next)
      const healthText = view.upstream.reachable
        ? `可达（${view.upstream.latencyMs} ms）`
        : next === 'global' && view.globalFailClosed
          ? '不可达，全局模式按失败关闭处理（请求被拒绝，不会直连）'
          : '不可达，已降级直连'
      return {
        mode: next,
        summary: [
          `出口模式：${label?.title ?? next}（${label?.subtitle ?? ''}）`,
          `上游：${view.upstream.url || '未配置'} ${healthText}`,
          `本地代理：${view.proxy.url}，策略：${view.proxy.installed ? '已安装' : view.proxy.envOnly ? '仅环境变量（子进程）' : '未接管'}`,
          `累计：↓ ${formatBytes(totals.down)} ↑ ${formatBytes(totals.up)}，${totals.req} 个请求`,
        ].join('\n'),
        upstream: view.upstream.url,
        upstreamReachable: view.upstream.reachable,
        proxy: view.proxy.url,
        total: `${formatBytes(totals.down)}↓ / ${formatBytes(totals.up)}↑`,
      }
    },
  }
  // `tools` is deliberately absent from `inject` (see its comment): registering through the dynamic
  // form waits for the registry instead of holding the panel itself in PENDING on a profile that
  // has none.
  if (typeof ctx.inject === 'function') {
    ctx.inject(['tools'], (scoped) => {
      scoped.effect(() => scoped.tools.register(tool), 'clash-verge: egress_mode tool')
    })
  } else {
    warn('this context has no inject(): the egress_mode tool is not registered')
  }

  const timer = setInterval(() => {
    void probe()
  }, 15_000)
  timer.unref?.()

  // Returned as an async disposer so the loader awaits it: cordis awaits async disposers
  // (`fiber.ts:69-73`, `:675-686`), and returning `undefined` around a floating promise would let
  // unloading finish before the policy is restored and the listener is closed.
  ctx.effect(() => async () => {
    clearInterval(timer)
    try {
      if (disposedPolicy !== undefined) await disposedPolicy()
    } catch (error) {
      warn(`disposing the proxy policy failed: ${error.message}`)
    }
    policyFallbackEnv?.()
    await new Promise(resolve => server.close(() => resolve(undefined)))
  }, 'clash-verge: teardown')

  // Restoring a persisted mode is the point of persisting it, but a mode whose upstream is down at
  // boot must not take the session's own transport with it: probe first, then install.
  if (state.mode !== 'off') {
    await probe()
    if (state.mode !== 'direct' && !health.ok) {
      warn(`upstream unreachable at startup (${health.error}); routing direct until it answers`)
    }
    await syncPolicy()
  }
}
