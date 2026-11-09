/**
 * Smoke test for the transport and the recorder, with no harness involved.
 *
 * Two stand-in origins: a plain HTTP origin, and a minimal "Clash" upstream proxy (absolute-form
 * GET plus CONNECT). The plugin's proxy is then driven through every path it has: upstream request,
 * direct request, upstream tunnel, and a tunnel whose upstream is gone.
 */

import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'

import { createProxyServer, createRecorder, isLoopbackHost, isPrivateHost, parseAuthority } from '../lib/proxy.js'

const listen = (server) => new Promise((resolve, reject) => {
  server.once('error', reject)
  server.listen(0, '127.0.0.1', () => {
    server.removeListener('error', reject)
    resolve(server.address().port)
  })
})

const close = (server) => new Promise((resolve) => server.close(() => resolve()))

const readAll = (socket, limit = 64 * 1024) => new Promise((resolve, reject) => {
  const chunks = []
  let size = 0
  socket.on('data', (chunk) => {
    chunks.push(chunk)
    size += chunk.length
    if (size > limit) socket.destroy()
  })
  socket.once('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
  socket.once('error', reject)
})

const readHeadAndBody = (socket) => new Promise((resolve, reject) => {
  let buffer = ''
  const onData = (chunk) => {
    buffer += chunk.toString('utf8')
    const end = buffer.indexOf('\r\n\r\n')
    if (end === -1) return
    const head = buffer.slice(0, end)
    const rest = buffer.slice(end + 4)
    const length = Number(/content-length:\s*(\d+)/i.exec(head)?.[1] ?? 0)
    if (Buffer.byteLength(rest) < length) return
    socket.removeListener('data', onData)
    resolve({ head, body: rest })
  }
  socket.on('data', onData)
  socket.once('error', reject)
})

// ---- origins ---------------------------------------------------------------------------------

let originHits = 0
const origin = http.createServer((req, res) => {
  originHits += 1
  const body = 'y'.repeat(2048)
  res.writeHead(200, { 'content-type': 'text/plain', 'content-length': String(body.length) })
  res.end(body)
})
const originPort = await listen(origin)

let upstreamHits = 0
const upstream = http.createServer((req, res) => {
  upstreamHits += 1
  // Absolute-form: forward the target and echo how big the answer was.
  const target = new URL(req.url)
  const out = http.request({ host: target.hostname, port: target.port || 80, path: target.pathname + target.search, method: req.method, headers: req.headers }, (answer) => {
    res.writeHead(answer.statusCode ?? 502, answer.headers)
    answer.pipe(res)
  })
  out.on('error', () => {
    res.writeHead(502)
    res.end('upstream could not reach the target')
  })
  req.pipe(out)
})
upstream.on('connect', (req, socket, head) => {
  upstreamHits += 1
  const { host, port } = parseAuthority(req.url, 80)
  const target = net.connect({ host, port }, () => {
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    if (head?.length) target.write(head)
    socket.pipe(target)
    target.pipe(socket)
  })
  target.on('error', () => socket.destroy())
  socket.on('error', () => target.destroy())
})
const upstreamPort = await listen(upstream)

// A port that is closed, to test the fail-closed path.
const deadServer = net.createServer()
const deadPort = await listen(deadServer)
await close(deadServer)

// ---- the plugin's proxy ---------------------------------------------------------------------

const recorder = createRecorder()
let routeDecision = () => 'direct'
let upstreamSpec = { protocol: 'http:', host: '127.0.0.1', port: upstreamPort, url: `http://127.0.0.1:${upstreamPort}` }
let failures = 0

const proxy = createProxyServer({
  recorder,
  route: () => routeDecision(),
  mode: () => 'global',
  upstream: () => upstreamSpec,
  onUpstreamFailure: () => { failures += 1 },
})
const proxyPort = await listen(proxy)

const throughProxy = (options = {}) => new Promise((resolve, reject) => {
  const req = http.request({
    host: '127.0.0.1',
    port: proxyPort,
    method: 'GET',
    path: `http://127.0.0.1:${originPort}/hello`,
    headers: { host: `127.0.0.1:${originPort}`, connection: 'close' },
    ...options,
  }, (res) => {
    const chunks = []
    res.on('data', (chunk) => chunks.push(chunk))
    res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }))
  })
  req.on('error', reject)
  req.end()
})

// 1. absolute-form request through the upstream
routeDecision = () => 'upstream'
const viaUpstream = await throughProxy()
assert.equal(viaUpstream.status, 200)
assert.equal(viaUpstream.body.length, 2048)
assert.equal(upstreamHits, 1, 'the request should have gone through the upstream')

// 2. absolute-form request direct
routeDecision = () => 'direct'
const before = originHits
const viaDirect = await throughProxy()
assert.equal(viaDirect.status, 200)
assert.equal(originHits, before + 1, 'direct route should reach the origin itself')
assert.equal(upstreamHits, 1, 'direct route must not touch the upstream')

// 3. CONNECT tunnel through the upstream
routeDecision = () => 'upstream'
const tunnel = net.connect({ host: '127.0.0.1', port: proxyPort })
await new Promise((resolve, reject) => { tunnel.once('connect', resolve); tunnel.once('error', reject) })
tunnel.write(`CONNECT 127.0.0.1:${originPort} HTTP/1.1\r\nHost: 127.0.0.1:${originPort}\r\n\r\n`)
const established = await readHeadAndBody(tunnel)
assert.match(established.head, /^HTTP\/1\.1 200/)
tunnel.write(`GET /tunnel HTTP/1.1\r\nHost: 127.0.0.1:${originPort}\r\nConnection: close\r\n\r\n`)
const tunneled = await readHeadAndBody(tunnel)
assert.match(tunneled.head, /^HTTP\/1\.1 200/)
assert.equal(tunneled.body.length, 2048)
tunnel.destroy()

// 4. CONNECT whose upstream is dead must fail closed with 502
const deadUpstream = { ...upstreamSpec, port: deadPort }
upstreamSpec = deadUpstream
const broken = net.connect({ host: '127.0.0.1', port: proxyPort })
await new Promise((resolve, reject) => { broken.once('connect', resolve); broken.once('error', reject) })
broken.write(`CONNECT 127.0.0.1:${originPort} HTTP/1.1\r\nHost: 127.0.0.1:${originPort}\r\n\r\n`)
const refusal = await readAll(broken)
assert.match(refusal, /^HTTP\/1\.1 502/)
assert.equal(failures, 1, 'a dead upstream should be reported once')
broken.destroy()

// 5. the report
const report = recorder.snapshot({ history: 120, top: 20 })
assert.ok(report.totals.down >= 2048 * 3, `expected at least three payloads, got ${report.totals.down}`)
assert.ok(report.totals.up > 0, 'requests should count as upstream bytes')
assert.equal(report.totals.req, 4, 'four requests were made')
assert.deepEqual(Object.keys(report.byRoute).sort(), ['direct', 'upstream'])
assert.ok(report.hosts.length >= 1)
assert.ok(report.buckets.length >= 1 && report.buckets.length <= 120)
assert.equal(report.connections.live, 0, 'every connection should be closed again')

// 6. classification helpers
assert.equal(isLoopbackHost('127.0.0.1'), true)
assert.equal(isLoopbackHost('localhost'), true)
assert.equal(isLoopbackHost('example.com'), false)
assert.equal(isPrivateHost('10.1.2.3'), true)
assert.equal(isPrivateHost('172.20.9.9'), true)
assert.equal(isPrivateHost('172.32.0.1'), false)
assert.equal(isPrivateHost('192.168.3.3'), true)
assert.equal(isPrivateHost('gitea'), true)
assert.equal(isPrivateHost('intra.corp'), true)
assert.equal(isPrivateHost('intra.example.com'), false)
assert.equal(isPrivateHost('::1'), true)
assert.equal(isPrivateHost('fd00::5'), true)

// 7. reset empties the report but keeps the recorder usable
recorder.reset()
const cleared = recorder.snapshot()
assert.equal(cleared.totals.req, 0)
assert.equal(cleared.hosts.length, 0)

await close(proxy)
await close(origin)
await close(upstream)
console.log('smoke: ok')
