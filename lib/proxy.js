/**
 * The transport and measurement half of dsh-clash-verge.
 *
 * One loopback HTTP proxy that every harness request can be pointed at, plus the recorder that
 * turns what flows through it into a report. Routing is decided here — per connection, on the
 * resolved target host — so the same proxy serves every preset: `external` sends public hosts to
 * the Clash upstream and everything else direct, `global` sends everything but loopback upstream.
 *
 * The proxy is deliberately dumb about policy: the host plugin owns the mode, the upstream and the
 * health of that upstream, and hands this module a `route(host, port)` callback. Everything the
 * recorder publishes therefore describes traffic that actually moved, not traffic that was planned:
 * when the upstream is down the route says `direct` and the report says `direct`.
 *
 * @module dsh-clash-verge/proxy
 */

import http from 'node:http'
import net from 'node:net'
import tls from 'node:tls'

import { openTunnel } from './upstream.js'

/** How many one-second buckets the live chart keeps (three minutes of history). */
export const BUCKET_LIMIT = 180

/** How many distinct hosts the per-host table keeps before the least recently seen is dropped. */
export const HOST_LIMIT = 400

/** Suffixes that name a host inside someone's own network, never a public one. */
export const INTRANET_SUFFIXES = [
  '.local',
  '.lan',
  '.internal',
  '.intranet',
  '.corp',
  '.home.arpa',
  '.localdomain',
]

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/
const LOOPBACK_NAMES = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback'])

/**
 * Strip the brackets and the trailing dot an authority or a URL may carry.
 * @param host - hostname as read from a CONNECT authority, a URL, or a Host header.
 * @returns the lowercased bare host.
 */
export function normalizeHost(host) {
  return String(host ?? '')
    .trim()
    .toLowerCase()
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.$/, '')
}

/**
 * Whether a host can only ever mean this machine.
 *
 * Loopback never goes upstream whatever the mode: a proxy that also forwards the harness's own
 * Web UI, Connection transport or test servers is a routing loop, not a preset.
 * @param host - hostname to test.
 * @returns true for loopback names and loopback literals.
 */
export function isLoopbackHost(host) {
  const bare = normalizeHost(host)
  if (bare === '' || LOOPBACK_NAMES.has(bare)) return true
  if (bare === '::1' || bare === '::' || bare === '0:0:0:0:0:0:0:1') return true
  if (bare === '0.0.0.0') return true
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(bare)
  if (mapped !== null) return isLoopbackHost(mapped[1])
  const octets = parseIpv4(bare)
  return octets !== null && octets[0] === 127
}

/**
 * Parse a dotted-quad IPv4 literal.
 * @param host - candidate literal.
 * @returns its four octets, or null when it is not a well-formed address.
 */
function parseIpv4(host) {
  if (!IPV4.test(host)) return null
  const octets = host.split('.').map(Number)
  return octets.every(octet => octet >= 0 && octet <= 255) ? octets : null
}

/**
 * Whether a host names a machine inside a private network rather than a public one.
 *
 * This is the whole difference between the `external` and the `global` preset: `external` keeps
 * these hosts direct because the Clash upstream cannot reach an intranet address, while `global`
 * deliberately sends them upstream as well (an engagement host reached through a tunnel, say).
 * @param host - hostname to classify.
 * @param extraSuffixes - deployment-specific intranet suffixes, matched as suffixes.
 * @returns true for private literals, intranet suffixes, and single-label intranet names.
 */
export function isPrivateHost(host, extraSuffixes = []) {
  const bare = normalizeHost(host)
  if (bare === '') return true
  if (isLoopbackHost(bare)) return true
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(bare)
  if (mapped !== null) return isPrivateHost(mapped[1], extraSuffixes)
  if (bare.includes(':')) {
    // fc00::/7 unique-local and fe80::/10 link-local.
    if (/^f[cd][0-9a-f]{2}:/.test(bare)) return true
    if (/^fe[89ab][0-9a-f]:/.test(bare)) return true
    return false
  }
  const octets = parseIpv4(bare)
  if (octets !== null) {
    const [a, b] = octets
    if (a === 10) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a === 169 && b === 254) return true
    // Carrier-grade NAT, where a lot of consumer routers actually live.
    if (a === 100 && b >= 64 && b <= 127) return true
    if (a === 0) return true
    return false
  }
  const suffixes = INTRANET_SUFFIXES.concat(extraSuffixes.map(suffix => normalizeHost(suffix.startsWith('.') ? suffix : `.${suffix}`)))
  if (suffixes.some(suffix => bare.endsWith(suffix))) return true
  // A single-label name ("gitea", "router") is always resolved by a local resolver.
  return !bare.includes('.')
}

/** Highest port number a socket can be asked for. */
const MAX_PORT = 65_535

/**
 * Whether a parsed target can be attempted at all.
 *
 * `net.connect` and `http.request` throw *synchronously* on an out-of-range port, and both are
 * called from callbacks here — an unguarded throw there is an uncaught exception that takes the
 * whole harness down. A CONNECT naming `host:99999` is therefore refused, not attempted.
 * @param host - target host.
 * @param port - target port.
 * @returns true when the pair is a legal socket target.
 */
export function isValidTarget(host, port) {
  return typeof host === 'string' && host !== '' && Number.isInteger(port) && port >= 1 && port <= MAX_PORT
}

/**
 * Split a CONNECT authority ("host:port", "[::1]:443") into its parts.
 * @param authority - the request target of a CONNECT.
 * @param fallbackPort - port used when the authority names none.
 * @returns the bare host and the numeric port.
 */
export function parseAuthority(authority, fallbackPort = 443) {
  const raw = String(authority ?? '')
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw)
  if (bracketed !== null) {
    return { host: normalizeHost(bracketed[1]), port: Number(bracketed[2] ?? fallbackPort) || fallbackPort }
  }
  const at = raw.lastIndexOf(':')
  const colons = raw.split(':').length - 1
  if (at !== -1 && colons === 1) {
    return { host: normalizeHost(raw.slice(0, at)), port: Number(raw.slice(at + 1)) || fallbackPort }
  }
  return { host: normalizeHost(raw), port: fallbackPort }
}

/**
 * Create the traffic recorder: one-second buckets for the live chart, running totals for the
 * report, and a bounded per-host table for the "where did it go" list.
 *
 * Every counter is updated from the byte streams themselves, so the numbers are what actually moved
 * through the proxy — including retries, aborted downloads and the upstream's own failures.
 * @param now - clock, injectable for tests.
 * @returns the recorder.
 */
export function createRecorder(now = () => Date.now()) {
  const startedAt = now()
  /** @type {{ t: number, up: number, down: number, req: number }[]} */
  const buckets = []
  /** @type {Map<string, { host: string, up: number, down: number, req: number, last: number, route: string, mode: string }>} */
  const hosts = new Map()
  const totals = { up: 0, down: 0, req: 0 }
  const byMode = new Map()
  const byRoute = new Map()
  let connections = 0
  let liveConnections = 0

  const modeRow = (mode) => {
    let row = byMode.get(mode)
    if (row === undefined) {
      row = { up: 0, down: 0, req: 0 }
      byMode.set(mode, row)
    }
    return row
  }
  const routeRow = (route) => {
    let row = byRoute.get(route)
    if (row === undefined) {
      row = { up: 0, down: 0, req: 0 }
      byRoute.set(route, row)
    }
    return row
  }
  const currentBucket = () => {
    const t = Math.floor(now() / 1000)
    const tail = buckets[buckets.length - 1]
    if (tail !== undefined && tail.t === t) return tail
    if (tail !== undefined && t > tail.t) {
      // A gap (idle seconds, a suspended laptop) becomes explicit empty buckets so the chart keeps
      // an honest time axis instead of pretending the traffic happened in one second.
      const gap = Math.min(t - tail.t - 1, BUCKET_LIMIT)
      for (let i = 1; i <= gap; i += 1) buckets.push({ t: tail.t + i, up: 0, down: 0, req: 0 })
      const bucket = { t, up: 0, down: 0, req: 0 }
      buckets.push(bucket)
      if (buckets.length > BUCKET_LIMIT) buckets.splice(0, buckets.length - BUCKET_LIMIT)
      return bucket
    }
    const bucket = { t, up: 0, down: 0, req: 0 }
    buckets.push(bucket)
    if (buckets.length > BUCKET_LIMIT) buckets.splice(0, buckets.length - BUCKET_LIMIT)
    return bucket
  }

  const touchHost = (host, route, mode) => {
    let row = hosts.get(host)
    if (row === undefined) {
      row = { host, up: 0, down: 0, req: 0, last: now(), route, mode }
      hosts.set(host, row)
      if (hosts.size > HOST_LIMIT) {
        let oldestKey
        let oldest = Infinity
        for (const [key, candidate] of hosts) {
          if (candidate.last < oldest) {
            oldest = candidate.last
            oldestKey = key
          }
        }
        if (oldestKey !== undefined) hosts.delete(oldestKey)
      }
    }
    row.last = now()
    row.route = route
    row.mode = mode
    return row
  }

  return {
    /**
     * Count one request (one CONNECT tunnel or one absolute-URL request).
     * @param host - target host.
     * @param route - route actually taken.
     * @param mode - mode in force when it was taken.
     */
    request(host, route, mode) {
      const bucket = currentBucket()
      bucket.req += 1
      totals.req += 1
      modeRow(mode).req += 1
      const routeCount = routeRow(route)
      if (routeCount !== undefined) routeCount.req += 1
      touchHost(host, route, mode).req += 1
    },
    /**
     * Count bytes that moved.
     * @param host - target host.
     * @param route - route actually taken.
     * @param mode - mode in force when the bytes moved.
     * @param up - bytes sent by this process.
     * @param down - bytes received by this process.
     */
    traffic(host, route, mode, up = 0, down = 0) {
      if (up === 0 && down === 0) return
      const bucket = currentBucket()
      bucket.up += up
      bucket.down += down
      totals.up += up
      totals.down += down
      const byModeRow = modeRow(mode)
      byModeRow.up += up
      byModeRow.down += down
      const byRouteRow = routeRow(route)
      if (byRouteRow !== undefined) {
        byRouteRow.up += up
        byRouteRow.down += down
      }
      const row = touchHost(host, route, mode)
      row.up += up
      row.down += down
    },
    /** @param delta - +1 when a tunnel or request opens, -1 when it closes. */
    connection(delta) {
      connections += delta
      liveConnections = Math.max(0, liveConnections + delta)
    },
    /**
     * Read the report.
     * @param options - `history` trims the bucket list, `top` trims the host table.
     * @returns a plain JSON snapshot; it carries no live handles.
     */
    snapshot(options = {}) {
      const history = Math.min(options.history ?? BUCKET_LIMIT, BUCKET_LIMIT)
      const top = Math.min(options.top ?? 24, HOST_LIMIT)
      const recent = buckets.slice(-history)
      // The newest bucket is the one still filling; a rate over it would read as a cliff.
      const complete = recent.slice(0, -1)
      const window = complete.slice(-5)
      const rate = { up: 0, down: 0 }
      if (window.length > 0) {
        rate.up = Math.round(window.reduce((sum, bucket) => sum + bucket.up, 0) / window.length)
        rate.down = Math.round(window.reduce((sum, bucket) => sum + bucket.down, 0) / window.length)
      }
      const listed = [...hosts.values()]
        .sort((left, right) => (right.up + right.down) - (left.up + left.down))
        .slice(0, top)
        .map(row => ({ ...row }))
      return {
        startedAt,
        now: now(),
        totals: { ...totals },
        rate,
        connections: { total: connections, live: liveConnections },
        byMode: Object.fromEntries([...byMode].map(([mode, row]) => [mode, { ...row }])),
        byRoute: Object.fromEntries([...byRoute].map(([route, row]) => [route, { ...row }])),
        buckets: recent.map(bucket => ({ ...bucket })),
        hosts: listed,
      }
    },
    /** Forget every counter but keep the start time of the current reporting window. */
    reset() {
      buckets.length = 0
      hosts.clear()
      totals.up = 0
      totals.down = 0
      totals.req = 0
      byMode.clear()
      byRoute.clear()
      connections = 0
    },
  }
}

/** Headers that belong to one hop and must not be forwarded by a proxy. */
const HOP_BY_HOP = new Set([
  'connection',
  'proxy-connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/**
 * Copy request headers without the hop-by-hop ones, overriding whatever the caller must not set.
 * @param headers - the inbound headers.
 * @param override - headers to force.
 * @returns a plain object safe to hand to a new request.
 */
function forwardableHeaders(headers, override = {}) {
  const out = {}
  for (const [name, value] of Object.entries(headers)) {
    const key = name.toLowerCase()
    if (HOP_BY_HOP.has(key)) continue
    out[name] = value
  }
  return { ...out, ...override }
}

/**
 * Open a socket to the upstream, plain or TLS.
 * @param upstream - resolved upstream descriptor.
 * @returns the connected socket.
 */
function connectUpstream(upstream) {
  if (upstream.protocol === 'https') {
    // A local hop to Clash's own https listener; the certificate there is generated per install and
    // is not verifiable, and this connection never crosses a network boundary.
    return tls.connect({ host: upstream.host, port: upstream.port, servername: upstream.host, rejectUnauthorized: false })
  }
  return net.connect({ host: upstream.host, port: upstream.port })
}

/**
 * Pump bytes both ways between the client and the target, counting as they move.
 * @param client - the socket facing the caller.
 * @param target - the socket facing the origin (or the upstream tunnel).
 * @param onUp - called with every byte count sent by the caller.
 * @param onDown - called with every byte count sent to the caller.
 * @param onError - called once when the pair tears down.
 */
function pump(client, target, onUp, onDown, onError) {
  let closed = false
  const teardown = () => {
    if (closed) return
    closed = true
    client.destroy()
    target.destroy()
    onError()
  }
  client.setTimeout(10 * 60 * 1000, teardown)
  target.setTimeout(10 * 60 * 1000, teardown)
  // Counting rides along on the same chunks `pipe` forwards: the listener sees every chunk once,
  // and backpressure still belongs to `pipe`, so a slow reader slows the sender instead of growing
  // a buffer here. Writing the chunks by hand instead measured about twice the overhead on bulk
  // transfers (see tests/bench.mjs).
  client.on('data', chunk => onUp(chunk.length))
  target.on('data', chunk => onDown(chunk.length))
  client.pipe(target)
  target.pipe(client)
  client.on('error', teardown)
  target.on('error', teardown)
  client.on('close', teardown)
  target.on('close', teardown)
}

/**
 * Answer a CONNECT with a failure, then close.
 * @param socket - the client socket.
 * @param status - HTTP status to report.
 * @param detail - one-line reason shown to the caller.
 */
function refuse(socket, status, detail) {
  if (socket.destroyed) return
  const body = `${detail}\n`
  const label = status === 502 ? 'Bad Gateway' : status === 400 ? 'Bad Request' : 'Forbidden'
  socket.end(
    `HTTP/1.1 ${status} ${label}\r\n`
    + 'Content-Type: text/plain; charset=utf-8\r\n'
    + `Content-Length: ${Buffer.byteLength(body)}\r\n`
    + 'Connection: close\r\n\r\n'
    + body,
  )
}

/**
 * Build the proxy server.
 * @param options - recorder, route callback, mode reader, upstream reader and a logger.
 * @returns the unlistened `http.Server`.
 */
export function createProxyServer(options) {
  const {
    recorder,
    route,
    mode = () => 'external',
    upstream = () => undefined,
    onUpstreamFailure = () => {},
    log = () => {},
  } = options

  const server = http.createServer()

  server.on('connect', (req, clientSocket, head) => {
    const { host, port } = parseAuthority(req.url, 443)
    clientSocket.on('error', () => {})
    if (!isValidTarget(host, port)) {
      // Before any counting: a target this proxy cannot even attempt is not traffic of ours.
      refuse(clientSocket, 400, `dsh-clash-verge: cannot CONNECT to ${JSON.stringify(req.url ?? '')}`)
      return
    }
    const chosen = route(host, port)
    const currentMode = mode()
    recorder.request(host, chosen, currentMode)
    recorder.connection(1)
    let counted = false
    const done = () => {
      if (counted) return
      counted = true
      recorder.connection(-1)
    }

    if (chosen === 'blocked') {
      refuse(clientSocket, 502, `dsh-clash-verge: ${host}:${port} was not sent — this preset fails closed while the upstream is unreachable`)
      done()
      return
    }

    if (chosen === 'direct') {
      let target
      try {
        target = net.connect({ host, port })
      } catch (error) {
        refuse(clientSocket, 502, `dsh-clash-verge: cannot reach ${host}:${port} (${error.message})`)
        done()
        return
      }
      target.once('connect', () => {
        target.setNoDelay(true)
        clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: dsh-clash-verge\r\n\r\n')
        if (head !== undefined && head.length > 0) {
          recorder.traffic(host, chosen, currentMode, head.length, 0)
          target.write(head)
        }
        pump(
          clientSocket,
          target,
          up => recorder.traffic(host, chosen, currentMode, up, 0),
          down => recorder.traffic(host, chosen, currentMode, 0, down),
          done,
        )
      })
      target.once('error', (error) => {
        log(`direct connect ${host}:${port} failed: ${error.message}`)
        refuse(clientSocket, 502, `dsh-clash-verge: cannot reach ${host}:${port} (${error.message})`)
        done()
      })
      return
    }

    const up = upstream()
    if (up === undefined) {
      refuse(clientSocket, 502, 'dsh-clash-verge: no upstream is configured for this mode')
      done()
      return
    }

    if (up.tunnel === 'native') {
      // SOCKS5 and trojan cannot be asked for a tunnel with CONNECT framing: the dialer opens one
      // itself, and from then on the two sockets are the same kind of thing.
      openTunnel(up, host, port).then((socket) => {
        if (clientSocket.destroyed) {
          socket.destroy()
          done()
          return
        }
        clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: dsh-clash-verge\r\n\r\n')
        if (head !== undefined && head.length > 0) {
          recorder.traffic(host, chosen, currentMode, head.length, 0)
          socket.write(head)
        }
        pump(
          clientSocket,
          socket,
          upBytes => recorder.traffic(host, chosen, currentMode, upBytes, 0),
          downBytes => recorder.traffic(host, chosen, currentMode, 0, downBytes),
          done,
        )
      }, (error) => {
        log(`tunnel ${host}:${port} via ${up.protocol}://${up.host}:${up.port} failed: ${error.message}`)
        refuse(clientSocket, 502, `dsh-clash-verge: upstream ${up.host}:${up.port} ${error.message}`)
        onUpstreamFailure(error.message)
        done()
      })
      return
    }

    let tunnel
    try {
      tunnel = connectUpstream(up)
    } catch (error) {
      refuse(clientSocket, 502, `dsh-clash-verge: cannot reach upstream ${up.host}:${up.port} (${error.message})`)
      onUpstreamFailure(error.message)
      done()
      return
    }
    let buffered = Buffer.alloc(0)
    let settled = false
    const giveUp = (reason) => {
      if (settled) return
      settled = true
      tunnel.destroy()
      refuse(clientSocket, 502, `dsh-clash-verge: upstream ${up.host}:${up.port} ${reason}`)
      onUpstreamFailure(reason)
      done()
    }
    tunnel.once('connect', () => {
      tunnel.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\nProxy-Connection: keep-alive\r\n\r\n`)
    })
    tunnel.once('error', error => giveUp(`failed (${error.message})`))
    tunnel.setTimeout(8000, () => giveUp('timed out while opening the tunnel'))
    tunnel.on('data', function onHandshake(chunk) {
      buffered = Buffer.concat([buffered, chunk])
      const end = buffered.indexOf('\r\n\r\n')
      if (end === -1) {
        if (buffered.length > 64 * 1024) giveUp('answered with an oversized response header')
        return
      }
      tunnel.removeListener('data', onHandshake)
      tunnel.setTimeout(10 * 60 * 1000, () => {})
      const statusLine = buffered.subarray(0, buffered.indexOf('\r\n')).toString('latin1')
      const status = Number(statusLine.split(' ')[1])
      const rest = buffered.subarray(end + 4)
      if (status !== 200) {
        settled = true
        tunnel.destroy()
        refuse(clientSocket, 502, `dsh-clash-verge: upstream refused ${host}:${port} (${statusLine.trim()})`)
        done()
        return
      }
      settled = true
      clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: dsh-clash-verge\r\n\r\n')
      if (rest.length > 0) {
        recorder.traffic(host, chosen, currentMode, 0, rest.length)
        clientSocket.write(rest)
      }
      if (head !== undefined && head.length > 0) {
        recorder.traffic(host, chosen, currentMode, head.length, 0)
        tunnel.write(head)
      }
      pump(
        clientSocket,
        tunnel,
        upBytes => recorder.traffic(host, chosen, currentMode, upBytes, 0),
        downBytes => recorder.traffic(host, chosen, currentMode, 0, downBytes),
        done,
      )
    })
  })

  // A WebSocket (or any HTTP upgrade) is not a request: Node emits it separately, and a server with
  // no `upgrade` listener simply drops the socket. Without this block every ws:// connection dies the
  // moment a mode other than `off` installs the policy, which is exactly when a tool needs it.
  const upgraded = new Set()
  const closeServer = server.close.bind(server)
  // A socket that was handed to an `upgrade` handler leaves the server's own connection list, so
  // neither `closeAllConnections()` nor `close()` ever waits on it — a live WebSocket would keep the
  // plugin's teardown pending forever. Ending them here is what makes `close()` a close.
  server.close = (callback) => {
    for (const socket of upgraded) socket.destroy()
    upgraded.clear()
    return closeServer(callback)
  }

  server.on('upgrade', (req, clientSocket, head) => {
    upgraded.add(clientSocket)
    clientSocket.on('close', () => upgraded.delete(clientSocket))
    clientSocket.on('error', () => clientSocket.destroy())
    let url
    try {
      const raw = req.url ?? '/'
      url = raw.startsWith('http://') || raw.startsWith('https://')
        ? new URL(raw)
        : new URL(`http://${req.headers.host ?? 'unknown'}${raw.startsWith('/') ? raw : `/${raw}`}`)
    } catch {
      clientSocket.destroy()
      return
    }
    const host = normalizeHost(url.hostname)
    const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80))
    if (!isValidTarget(host, port)) {
      clientSocket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')
      return
    }
    const chosen = route(host, port)
    const currentMode = mode()
    if (chosen === 'blocked') {
      clientSocket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n')
      return
    }
    const up = chosen === 'direct' ? undefined : upstream()
    if (chosen === 'upstream' && up === undefined) {
      clientSocket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n')
      return
    }
    recorder.request(host, chosen, currentMode)
    recorder.connection(1)
    let closed = false
    const done = () => {
      if (closed) return
      closed = true
      recorder.connection(-1)
    }
    const meter = (upBytes, downBytes) => recorder.traffic(host, chosen, currentMode, upBytes, downBytes)
    const fail = (detail) => {
      log(`upgrade ${host}:${port} failed: ${detail}`)
      if (!clientSocket.destroyed) clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n`)
      if (chosen === 'upstream') onUpstreamFailure(detail)
      done()
    }

    // `upgrade` and `connection` are hop-by-hop and were dropped from `forwardableHeaders`; this is
    // the one place where they are the whole request, so put them back explicitly.
    const headers = forwardableHeaders(req.headers, {
      host: url.host,
      connection: 'Upgrade',
      upgrade: req.headers.upgrade ?? 'websocket',
    })

    if (up !== undefined && up.tunnel === 'native') {
      openTunnel(up, host, port).then((socket) => {
        if (clientSocket.destroyed) {
          socket.destroy()
          done()
          return
        }
        socket.resume()
        // The hop speaks a raw tunnel, so the request is written as origin-form by hand.
        const lines = [`GET ${url.pathname}${url.search} HTTP/1.1`]
        for (const [name, value] of Object.entries(headers)) {
          lines.push(`${name}: ${Array.isArray(value) ? value.join(', ') : value}`)
        }
        const request = `${lines.join('\r\n')}\r\n\r\n`
        recorder.traffic(host, chosen, currentMode, Buffer.byteLength(request), 0)
        socket.write(request)
        if (head !== undefined && head.length > 0) {
          recorder.traffic(host, chosen, currentMode, head.length, 0)
          socket.write(head)
        }
        pump(clientSocket, socket, upBytes => meter(upBytes, 0), downBytes => meter(0, downBytes), done)
      }, (error) => fail(`upstream ${up.host}:${up.port} ${error.message}`))
      return
    }

    // Direct, or through an HTTP proxy: Node's own client can carry the upgrade for us.
    const requestOptions = {
      host: up === undefined ? host : up.host,
      port: up === undefined ? port : up.port,
      method: req.method,
      path: up === undefined ? `${url.pathname}${url.search}` : url.href,
      headers,
      setHost: false,
    }
    let outbound
    try {
      outbound = http.request(requestOptions)
    } catch (error) {
      fail(error.message)
      return
    }
    outbound.on('upgrade', (answer, socket, leftover) => {
      const lines = [`HTTP/1.1 ${answer.statusCode} ${answer.statusMessage ?? 'Switching Protocols'}`]
      for (let index = 0; index < answer.rawHeaders.length; index += 2) {
        lines.push(`${answer.rawHeaders[index]}: ${answer.rawHeaders[index + 1]}`)
      }
      const headText = `${lines.join('\r\n')}\r\n\r\n`
      clientSocket.write(headText)
      recorder.traffic(host, chosen, currentMode, 0, Buffer.byteLength(headText))
      if (leftover !== undefined && leftover.length > 0) {
        recorder.traffic(host, chosen, currentMode, 0, leftover.length)
        clientSocket.write(leftover)
      }
      if (head !== undefined && head.length > 0) {
        recorder.traffic(host, chosen, currentMode, head.length, 0)
        socket.write(head)
      }
      pump(clientSocket, socket, upBytes => meter(upBytes, 0), downBytes => meter(0, downBytes), done)
    })
    outbound.on('response', (answer) => {
      // The far side refused the upgrade: relay its answer verbatim and close.
      const lines = [`HTTP/1.1 ${answer.statusCode} ${answer.statusMessage ?? ''}`]
      for (let index = 0; index < answer.rawHeaders.length; index += 2) {
        lines.push(`${answer.rawHeaders[index]}: ${answer.rawHeaders[index + 1]}`)
      }
      clientSocket.write(`${lines.join('\r\n')}\r\n\r\n`)
      answer.on('data', chunk => recorder.traffic(host, chosen, currentMode, 0, chunk.length))
      answer.pipe(clientSocket)
      answer.on('end', done)
      answer.on('error', done)
    })
    outbound.on('error', (error) => fail(error.message))
    outbound.end(head !== undefined && head.length > 0 ? head : undefined)
  })

  server.on('request', (req, res) => {
    let url
    try {
      const raw = req.url ?? '/'
      url = raw.startsWith('http://') || raw.startsWith('https://')
        ? new URL(raw)
        : new URL(`http://${req.headers.host ?? 'unknown'}${raw.startsWith('/') ? raw : `/${raw}`}`)
    } catch {
      res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('dsh-clash-verge: cannot parse the request target\n')
      return
    }
    const host = normalizeHost(url.hostname)
    const defaultPort = url.protocol === 'https:' ? 443 : 80
    const port = Number(url.port || defaultPort)
    if (!isValidTarget(host, port)) {
      res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`dsh-clash-verge: cannot reach ${JSON.stringify(url.host)}\n`)
      return
    }
    const chosen = route(host, port)
    const currentMode = mode()
    recorder.request(host, chosen, currentMode)
    recorder.connection(1)
    let closed = false
    const done = () => {
      if (closed) return
      closed = true
      recorder.connection(-1)
    }

    if (chosen === 'blocked') {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`dsh-clash-verge: ${host}:${port} was not sent — this preset fails closed while the upstream is unreachable\n`)
      done()
      return
    }

    if (url.protocol === 'https:') {
      // A browser tunnels https with CONNECT before it ever writes a request line; a caller that
      // sends an absolute https URI over a plain connection is asking this proxy to terminate TLS,
      // which it does not do.
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('dsh-clash-verge: absolute-form https requests are not supported, use CONNECT\n')
      done()
      return
    }

    const up = chosen === 'direct' ? undefined : upstream()
    if (chosen === 'upstream' && up === undefined) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('dsh-clash-verge: no upstream is configured for this mode\n')
      done()
      return
    }

    const native = up !== undefined && up.tunnel === 'native'
    // A tunnelled hop carries an origin-form request to the target itself; only a real HTTP proxy is
    // given the absolute URI. Either way the caller's host survives as the Host header.
    const target = up === undefined || native
      ? { host, port, method: req.method, path: `${url.pathname}${url.search}`, headers: forwardableHeaders(req.headers, { host: url.host }) }
      : { host: up.host, port: up.port, method: req.method, path: url.href, headers: forwardableHeaders(req.headers, { host: url.host }) }

    const requestOptions = { ...target, setHost: false }
    if (native) {
      // Overriding `createConnection` on a one-shot agent is the only way to hand Node a socket it
      // did not open itself; its own request writer then does the framing, so this module needs no
      // HTTP parser for the tunnelled case.
      const agent = new http.Agent({ keepAlive: false })
      agent.createConnection = (_options, callback) => {
        // `openTunnel` hands back a paused socket so that nothing the target says between the
        // handshake and the first consumer is lost. Node's HTTP client attaches its own `data`
        // listener, and attaching one does not resume an explicitly paused stream, so resume here:
        // no request has been written yet, so there is nothing on this socket to lose.
        openTunnel(up, host, port).then(socket => {
          socket.resume()
          callback(null, socket)
        }, error => callback(error))
      }
      requestOptions.agent = agent
    }

    let outbound
    try {
      outbound = http.request(requestOptions, (answer) => {
        const headers = forwardableHeaders(answer.headers)
        res.writeHead(answer.statusCode ?? 502, answer.statusMessage, headers)
        answer.on('data', (chunk) => {
          recorder.traffic(host, chosen, currentMode, 0, chunk.length)
        })
        answer.pipe(res)
        answer.on('end', done)
        answer.on('error', done)
      })
    } catch (error) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`dsh-clash-verge: cannot reach ${host}:${port} (${error.message})\n`)
      if (chosen === 'upstream') onUpstreamFailure(error.message)
      done()
      return
    }
    req.on('data', (chunk) => {
      recorder.traffic(host, chosen, currentMode, chunk.length, 0)
    })
    req.pipe(outbound)
    outbound.on('error', (error) => {
      log(`request ${host}:${port} failed: ${error.message}`)
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
        res.end(`dsh-clash-verge: ${error.message}\n`)
      } else {
        res.destroy()
      }
      if (chosen === 'upstream') onUpstreamFailure(error.message)
      done()
    })
    res.on('close', () => {
      // The one-shot agent exists only to hand Node the tunnelled socket; nothing else holds a
      // reference to it, so it has to be told to let go of its sockets here.
      if (native) requestOptions.agent.destroy()
      done()
    })
  })

  server.on('clientError', (error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
    log(`proxy client error: ${error.message}`)
  })

  return server
}
