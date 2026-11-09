/**
 * Measures what the local proxy costs on the wire.
 *
 * Three paths over the same servers: straight to the origin, through the proxy with the `direct`
 * preset, and through the proxy with an upstream in front (the `external` / `global` shape).
 *
 * Two scenarios, because they answer different questions:
 *   - bulk: one 64 MiB transfer, where an extra copy or a JS loop per chunk shows up as throughput;
 *   - small: 200 sequential 16 KiB requests on one kept-alive connection, which is what harness
 *     traffic actually looks like.
 *
 * Runs are interleaved (direct, proxy, upstream, repeat) so a machine that slows down halfway
 * through penalises every path equally instead of the last one measured.
 *
 *   node tests/bench.mjs [payloadMiB] [rounds]
 *
 * Loopback only, no external traffic, no third-party code.
 */

import http from 'node:http'
import { createProxyServer, createRecorder } from '../lib/proxy.js'

const SIZE = Math.max(1, Number(process.argv[2] ?? 64)) * 1024 * 1024
const ROUNDS = Math.max(1, Number(process.argv[3] ?? 3))
const SMALL = 16 * 1024
const SMALL_COUNT = 200

const bulkPayload = Buffer.alloc(SIZE, 0x61)
const smallPayload = Buffer.alloc(SMALL, 0x62)

/** Bind a server to a random loopback port and resolve with that port. */
function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve(server.address().port))
  })
}

/**
 * Read one whole body, timing the first byte and the last.
 * @param options - request options handed to `http.request`.
 * @returns bytes received, milliseconds to first byte, milliseconds to completion, CPU milliseconds.
 */
function transfer(options) {
  return new Promise((resolve, reject) => {
    const started = process.hrtime.bigint()
    const cpuStarted = process.cpuUsage()
    let firstByte = 0
    let bytes = 0
    const request = http.request(options, (response) => {
      if (response.statusCode !== 200) {
        response.resume()
        reject(new Error(`unexpected status ${response.statusCode}`))
        return
      }
      response.on('data', (chunk) => {
        if (firstByte === 0) firstByte = Number(process.hrtime.bigint() - started) / 1e6
        bytes += chunk.length
      })
      response.on('end', () => {
        const cpu = process.cpuUsage(cpuStarted)
        resolve({
          bytes,
          ttfb: firstByte,
          total: Number(process.hrtime.bigint() - started) / 1e6,
          cpuMs: (cpu.user + cpu.system) / 1000,
        })
      })
      response.on('error', reject)
    })
    request.on('error', reject)
    request.end()
  })
}

/** Median of a list of numbers; empty input yields 0. */
function median(values) {
  if (values.length === 0) return 0
  const sorted = [...values].sort((left, right) => left - right)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle]
}

const origin = http.createServer((req, res) => {
  const body = req.url.startsWith('/small') ? smallPayload : bulkPayload
  res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': body.length })
  res.end(body)
})
const originPort = await listen(origin)

// A stand-in for an HTTP proxy upstream: absolute-URI requests forwarded as-is, nothing else.
const upstream = http.createServer((req, res) => {
  const target = new URL(req.url)
  const outbound = http.request(
    {
      host: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method: req.method,
      headers: { ...req.headers, host: target.host },
      agent: false,
    },
    (answer) => {
      res.writeHead(answer.statusCode ?? 502, answer.headers)
      answer.pipe(res)
    },
  )
  outbound.on('error', () => {
    if (!res.headersSent) res.writeHead(502)
    res.end()
  })
  req.pipe(outbound)
})
const upstreamPort = await listen(upstream)

const recorderDirect = createRecorder()
const proxyDirect = createProxyServer({ recorder: recorderDirect, route: () => 'direct', mode: () => 'direct' })
const proxyDirectPort = await listen(proxyDirect)

const recorderUpstream = createRecorder()
const proxyUpstream = createProxyServer({
  recorder: recorderUpstream,
  route: () => 'upstream',
  mode: () => 'external',
  upstream: () => ({ host: '127.0.0.1', port: upstreamPort, protocol: 'http:' }),
})
const proxyUpstreamPort = await listen(proxyUpstream)

const paths = [
  { label: '直连', port: originPort },
  { label: '经代理（直连）', port: proxyDirectPort },
  { label: '经代理 → 上游', port: proxyUpstreamPort },
]

/**
 * Build request options for one path and one payload size.
 * @param path - entry from `paths`.
 * @param kind - 'bulk' or 'small'.
 * @param agent - connection pool to reuse, or false for a fresh connection.
 */
function optionsFor(path, kind, agent) {
  const tail = kind === 'bulk' ? '/blob' : '/small'
  const absolute = `http://127.0.0.1:${originPort}${tail}`
  if (path.port === originPort) {
    return { host: '127.0.0.1', port: originPort, path: tail, method: 'GET', agent }
  }
  return {
    host: '127.0.0.1',
    port: path.port,
    path: absolute,
    method: 'GET',
    headers: { host: `127.0.0.1:${originPort}` },
    agent,
  }
}

// One warm-up transfer per path per scenario, so the first run does not carry socket and JIT cost.
for (const path of paths) {
  await transfer(optionsFor(path, 'bulk', false))
  await transfer(optionsFor(path, 'small', false))
}

/** Every path once, in the same order, so machine drift is spread across all of them. */
async function round() {
  const rows = []
  for (const path of paths) {
    const one = await transfer(optionsFor(path, 'bulk', false))
    rows.push({ path, mbps: (one.bytes / 1024 / 1024) / (one.total / 1000), ttfb: one.ttfb, cpuMs: one.cpuMs })
  }
  return rows
}

/** The small-request scenario: one kept-alive connection, counted requests, no pipelining. */
async function smallRound() {
  const rows = []
  for (const path of paths) {
    const agent = new http.Agent({ keepAlive: true, maxSockets: 1 })
    const latencies = []
    let bytes = 0
    const cpuStarted = process.cpuUsage()
    const started = process.hrtime.bigint()
    for (let i = 0; i < SMALL_COUNT; i += 1) {
      const one = await transfer(optionsFor(path, 'small', agent))
      latencies.push(one.ttfb)
      bytes += one.bytes
    }
    const cpu = process.cpuUsage(cpuStarted)
    const wall = Number(process.hrtime.bigint() - started) / 1e6
    agent.destroy()
    rows.push({
      path,
      latency: median(latencies),
      perSecond: SMALL_COUNT / (wall / 1000),
      mbps: (bytes / 1024 / 1024) / (wall / 1000),
      cpuMs: (cpu.user + cpu.system) / 1000,
    })
  }
  return rows
}

const bulkRounds = []
const smallRounds = []
for (let i = 0; i < ROUNDS; i += 1) {
  bulkRounds.push(await round())
  smallRounds.push(await smallRound())
}

/** Collapse rounds into one row per path. */
function collapse(rounds, pick) {
  return paths.map(path => {
    const values = rounds.map(rows => rows.find(row => row.path.label === path.label))
    return {
      label: path.label,
      mbps: median(values.map(row => row.mbps)),
      latency: median(values.map(row => row.latency ?? 0)),
      ttfb: median(values.map(row => row.ttfb ?? 0)),
      perSecond: median(values.map(row => row.perSecond ?? 0)),
      cpuMs: median(values.map(row => row.cpuMs)),
    }
  })
}

const bulk = collapse(bulkRounds)
const small = collapse(smallRounds)
const cpuPerGiB = (row) => {
  const gib = row.mbps * 1024 / 1024
  return `${((row.cpuMs / 1000) / (gib / 1000) * 1000).toFixed(0)} ms/GiB`
}

console.log(`\n回环实测 · ${ROUNDS} 轮交错取样取中位数 · Node ${process.versions.node}\n`)
console.log(`### 批量传输（单次 ${(SIZE / 1024 / 1024).toFixed(0)} MiB）\n`)
console.log('| 路径 | 吞吐 | 首字节 | 搬运 1 GiB 的 CPU |')
console.log('| --- | --- | --- | --- |')
for (const row of bulk) {
  console.log(`| ${row.label} | ${row.mbps.toFixed(0)} MiB/s | ${row.ttfb.toFixed(1)} ms | ${cpuPerGiB(row)} |`)
}

const baselineLatency = small[0].latency
console.log(`\n### 小请求（${SMALL_COUNT} 次 ${(SMALL / 1024).toFixed(0)} KiB，keep-alive 单连接）\n`)
console.log('| 路径 | 中位往返 | 请求/秒 | 相对直连 |')
console.log('| --- | --- | --- | --- |')
for (const row of small) {
  const delta = row === small[0] ? '—' : `+${(row.latency - baselineLatency).toFixed(2)} ms`
  console.log(`| ${row.label} | ${row.latency.toFixed(2)} ms | ${row.perSecond.toFixed(0)} | ${delta} |`)
}

const expectMiB = (SIZE / 1024 / 1024) * (ROUNDS + 1)
const directMiB = recorderDirect.snapshot({ history: 1 }).totals.down / 1024 / 1024
const upstreamMiB = recorderUpstream.snapshot({ history: 1 }).totals.down / 1024 / 1024
console.log(`\n计数核对：批量直连路径记 ${directMiB.toFixed(0)} MiB、上游路径 ${upstreamMiB.toFixed(0)} MiB，`
  + `期望各 ≥ ${expectMiB.toFixed(0)} MiB（另含小请求）`)

for (const server of [proxyDirect, proxyUpstream, origin, upstream]) server.closeAllConnections?.()
await Promise.all([
  new Promise(resolve => proxyDirect.close(resolve)),
  new Promise(resolve => proxyUpstream.close(resolve)),
  new Promise(resolve => origin.close(resolve)),
  new Promise(resolve => upstream.close(resolve)),
])
