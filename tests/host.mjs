/**
 * Host-half integration test: mount the plugin on a stub cordis context and drive it the way the
 * browser panel does — over HTTP, through the local proxy, and through the `egress_mode` tool.
 *
 * Run: node tests/host.mjs
 */
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { readFileSync, rmSync } from 'node:fs'

const { apply, formatBytes, inject, MODES } = await import('../lib/index.js')

const stateFile = path.join(os.homedir(), '.dsh', 'storages', 'clash-verge', 'state.json')
rmSync(stateFile, { force: true })

const logs = []
const disposers = []
let route
let tool

const ctx = {
  // The real loader resolves `baseDir` as a service: reading it without the
  // matching `inject` throws, which is how the first boot of this plugin died.
  get baseDir() {
    throw new Error('cannot get property "baseDir" without inject')
  },
  logger: { info: (line) => logs.push(line), warn: (line) => logs.push(line) },
  effect(factory) {
    const dispose = factory()
    disposers.push(dispose)
    return dispose
  },
  webServer: {
    register(definition) {
      route = definition
      return () => {}
    },
  },
  tools: {
    register(definition) {
      tool = definition
      return () => {}
    },
  },
  // `inject` is a hard requirement list, and `tools` is not on it: the plugin asks for the registry
  // through the dynamic form instead, so that a profile without tools still gets the panel.
  inject(dependencies, callback) {
    assert.deepEqual(dependencies, ['tools'])
    callback({ effect: ctx.effect, tools: ctx.tools, inject: ctx.inject })
    return () => {}
  },
}

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))

// The stand-in for Clash: answers absolute-URL requests so a routed request is visible here.
const upstreamSeen = []
const upstream = http.createServer((req, res) => {
  upstreamSeen.push(req.headers.host)
  res.writeHead(200, { 'content-type': 'text/plain' })
  res.end('via-clash')
})
upstream.on('connect', (req, socket) => {
  upstreamSeen.push(req.url)
  socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
})
const upstreamPort = await listen(upstream)

const origin = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' })
  res.end('direct-origin')
})
const originPort = await listen(origin)

// A private-but-reachable target: the intranet branch is only observable if something answers.
const lanIp = Object.values(os.networkInterfaces()).flat()
  .find((entry) => entry && entry.family === 'IPv4' && !entry.internal && !entry.address.startsWith('169.254.'))?.address
const intranet = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' })
  res.end('intranet-origin')
})
const intranetPort = await new Promise((resolve) => intranet.listen(0, lanIp ?? '127.0.0.1', () => resolve(intranet.address().port)))

await apply(ctx)
assert.equal(route?.kind, 'prefix')
assert.equal(route.path, '/clash-verge/api')
assert.equal(tool?.name, 'egress_mode')
assert.deepEqual(MODES.map((entry) => entry.id), ['off', 'direct', 'external', 'global'])
assert.deepEqual(inject, ['webServer'], 'tools must not be a hard requirement: a profile without it would lose the panel')

const bridge = http.createServer((req, res) => {
  route.handler(req, res).catch((error) => {
    res.statusCode = 500
    res.end(String(error))
  })
})
const bridgePort = await listen(bridge)

// `node:http` rather than `fetch`: the plugin replaces the process-wide undici dispatcher, and a
// pooled fetch socket would be torn down mid-response by the very switch it is asking for.
//
// The token is what the panel echoes back: the host half mints one per process and refuses any
// mutation that does not carry it, so a cross-site page (which cannot read a cross-origin response)
// can never learn it.
let apiToken = ''
const call = (action, body, extraHeaders = {}) => new Promise((resolve, reject) => {
  const payload = body === undefined ? undefined : JSON.stringify(body)
  const request = http.request({
    host: '127.0.0.1',
    port: bridgePort,
    method: body === undefined ? 'GET' : 'POST',
    path: `/clash-verge/api/${action}`,
    agent: false,
    headers: {
      accept: 'application/json',
      connection: 'close',
      ...(payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }),
      ...(payload === undefined || apiToken === '' ? {} : { 'x-clash-verge-token': apiToken }),
      ...extraHeaders,
    },
  }, (response) => {
    const chunks = []
    response.on('data', (chunk) => chunks.push(chunk))
    response.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8')
      const parsed = text === '' ? {} : JSON.parse(text)
      if (typeof parsed.token === 'string' && parsed.token !== '') apiToken = parsed.token
      resolve({ status: response.statusCode, payload: parsed })
    })
  })
  request.on('error', reject)
  request.setTimeout(8000, () => request.destroy(new Error(`api ${action} timed out`)))
  request.end(payload)
})

/** A raw CONNECT, so an impossible authority reaches the proxy unchanged. */
const connectTo = (proxyPort, authority) => new Promise((resolve) => {
  const socket = net.connect(proxyPort, '127.0.0.1', () => {
    socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`)
  })
  let text = ''
  const finish = () => { socket.destroy(); resolve(text) }
  socket.on('data', (chunk) => { text += chunk.toString('latin1') })
  socket.on('close', finish)
  socket.on('error', finish)
  socket.setTimeout(4000, finish)
})

/** One request sent to the plugin's own proxy in absolute-URL form. */
const through = (proxyPort, target) => new Promise((resolve, reject) => {
  const url = new URL(target)
  const request = http.request({
    host: '127.0.0.1',
    port: proxyPort,
    method: 'GET',
    path: target,
    headers: { host: url.host, connection: 'close' },
  }, (response) => {
    const chunks = []
    response.on('data', (chunk) => chunks.push(chunk))
    response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }))
  })
  request.on('error', reject)
  request.setTimeout(5000, () => request.destroy(new Error('proxy request timed out')))
  request.end()
})

const results = []
const check = async (name, run) => {
  try {
    await run()
    results.push(`ok    ${name}`)
    console.log(`ok    ${name}`)
  } catch (error) {
    results.push(`FAIL  ${name}: ${error.message}`)
    console.log(`FAIL  ${name}: ${error.message}`)
    process.exitCode = 1
  }
}

let proxyPort = 0

await check('state: untouched start', async () => {
  const { status, payload } = await call('state')
  assert.equal(status, 200)
  assert.equal(payload.ok, true)
  assert.equal(payload.mode, 'off')
  assert.equal(payload.modes.length, 4)
  assert.equal(payload.proxy.policy, 'installed', 'the transport policy package must resolve from the profile')
  assert.ok(payload.proxy.port > 0)
  proxyPort = payload.proxy.port
})

await check('mode: unknown preset is rejected', async () => {
  const { status, payload } = await call('mode', { mode: 'teleport' })
  assert.equal(status, 400)
  assert.equal(payload.ok, false)
})

await check('mode: direct keeps loopback direct and counts it', async () => {
  const { payload } = await call('mode', { mode: 'direct' })
  assert.equal(payload.mode, 'direct')
  const answer = await through(proxyPort, `http://127.0.0.1:${originPort}/hello`)
  assert.equal(answer.body, 'direct-origin')
  const state = (await call('state')).payload
  assert.equal(state.stats.totals.req, 1)
  assert.equal(state.stats.byRoute.direct.req, 1)
})

await check('config: upstream is adopted and probed', async () => {
  const { payload } = await call('config', { upstream: `http://127.0.0.1:${upstreamPort}` })
  assert.equal(payload.upstream.url, `http://127.0.0.1:${upstreamPort}`)
  assert.equal(payload.upstream.reachable, true)
})

await check('external: a public host rides the upstream', async () => {
  const { payload } = await call('mode', { mode: 'external' })
  assert.equal(payload.mode, 'external')
  const answer = await through(proxyPort, 'http://public.example/hello')
  assert.equal(answer.body, 'via-clash')
  assert.ok(upstreamSeen.includes('public.example'))
})

await check('external: a private host never reaches the upstream', async () => {
  assert.ok(lanIp !== undefined, 'no LAN address to observe the intranet branch')
  const before = upstreamSeen.length
  const answer = await through(proxyPort, `http://${lanIp}:${intranetPort}/secret`)
  assert.equal(answer.body, 'intranet-origin')
  assert.equal(upstreamSeen.length, before)
  const state = (await call('state')).payload
  assert.ok(state.stats.byRoute.direct.req >= 2)
})

await check('global + bypass: the bypass list wins over the preset', async () => {
  await call('config', { bypass: [String(lanIp)] })
  const before = upstreamSeen.length
  const { payload } = await call('mode', { mode: 'global' })
  assert.equal(payload.mode, 'global')
  const answer = await through(proxyPort, `http://${lanIp}:${intranetPort}/x`)
  assert.equal(answer.body, 'intranet-origin')
  assert.equal(upstreamSeen.length, before)
})

await check('global: everything else rides the upstream and is reported', async () => {
  const answer = await through(proxyPort, 'http://other.example/y')
  assert.equal(answer.body, 'via-clash')
  const state = (await call('state')).payload
  assert.equal(state.stats.totals.req, 5)
  assert.ok(state.stats.byRoute.upstream.req >= 2)
  assert.ok(state.stats.byMode.global.req >= 2)
  const host = state.stats.hosts.find((row) => row.host === 'other.example')
  assert.equal(host?.route, 'upstream')
  assert.ok(state.stats.buckets.length > 0)
  assert.equal(typeof state.stats.buckets.at(-1).down, 'number')
  assert.equal(typeof state.stats.rate.down, 'number')
})

await check('config: bypass is cleared before the next preset', async () => {
  const { payload } = await call('config', { bypass: [] })
  assert.deepEqual(payload.bypass, [])
})

await check('tool: egress_mode switches and reports', async () => {
  const value = await tool.execute({ mode: 'external' })
  assert.deepEqual(Object.keys(value).sort(), ['mode', 'proxy', 'summary', 'total', 'upstream', 'upstreamReachable'])
  assert.equal(value.mode, 'external')
  assert.equal(value.upstreamReachable, true)
  assert.match(value.summary, /外网/)
  assert.match(value.total, /↓/)
  const rendered = tool.output.render({ mode: 'external' }, value)
  assert.deepEqual(rendered, [{ type: 'text', text: value.summary }])
  await assert.rejects(() => tool.execute({ mode: 'nope' }), /mode must be one of/)
})

await check('state: the chosen mode is persisted', async () => {
  const stored = JSON.parse(readFileSync(stateFile, 'utf8'))
  assert.equal(stored.mode, 'external')
  assert.equal(stored.upstream, `http://127.0.0.1:${upstreamPort}`)
})

await check('reset: counters drop to zero', async () => {
  const { payload } = await call('reset', {})
  assert.equal(payload.stats.totals.req, 0)
  assert.deepEqual(payload.stats.hosts, [])
})

await check('probe: reports the upstream again', async () => {
  const { payload } = await call('probe', {})
  assert.equal(payload.upstream.reachable, true)
  assert.ok(payload.upstream.checkedAt > 0)
})

await check('api: a cross-site POST cannot change the mode', async () => {
  const before = (await call('state')).payload.mode
  const { status } = await call('mode', { mode: 'global' }, {
    origin: 'https://evil.example',
    'sec-fetch-site': 'cross-site',
    'content-type': 'text/plain',
  })
  assert.equal(status, 403, 'a cross-site simple request must be refused')
  assert.equal((await call('state')).payload.mode, before)
})

await check('api: a same-origin POST with a wrong token is refused', async () => {
  const { status } = await call('mode', { mode: 'direct' }, { 'x-clash-verge-token': 'not-the-panel-token' })
  assert.equal(status, 403)
})

await check('api: a POST with a non-JSON content type is refused', async () => {
  const { status } = await call('mode', { mode: 'direct' }, { 'content-type': 'text/plain' })
  assert.equal(status, 415)
})

await check('proxy: an impossible CONNECT port is refused, and the process survives it', async () => {
  const text = await connectTo(proxyPort, '127.0.0.1:99999')
  assert.match(text, /^HTTP\/1\.1 400/, `expected a 400 for host:99999, got ${JSON.stringify(text.slice(0, 40))}`)
  const alive = await call('state')
  assert.equal(alive.status, 200, 'an out-of-range port must never become an uncaught exception')
})

await check('global: an unreachable upstream fails closed instead of going direct', async () => {
  await call('config', { upstream: 'http://127.0.0.1:9' })
  const { payload } = await call('mode', { mode: 'global' })
  assert.equal(payload.upstream.reachable, false)
  const answer = await through(proxyPort, 'http://blocked.example/x')
  assert.equal(answer.status, 502, 'global must not answer a request it could not route through the upstream')
  assert.match(answer.body, /was not sent/)
  const state = (await call('state')).payload
  assert.ok(state.blocked.count >= 1)
  assert.ok(state.stats.byRoute.blocked.req >= 1, 'the report must say blocked, not direct')
})

await check('global: with fail-closed off, the same situation degrades to direct', async () => {
  const { payload } = await call('config', { globalFailClosed: false })
  assert.equal(payload.globalFailClosed, false)
  assert.ok(lanIp !== undefined, 'no LAN address to observe the direct branch')
  const answer = await through(proxyPort, `http://${lanIp}:${intranetPort}/degraded`)
  assert.equal(answer.body, 'intranet-origin')
  assert.ok((await call('state')).payload.fallback.count >= 1)
})

await check('config: an unusable upstream is rejected without replacing the stored one', async () => {
  const before = (await call('state')).payload.upstream.configured
  const { status, payload } = await call('config', { upstream: 'socks5://127.0.0.1:7890' })
  assert.equal(status, 400)
  assert.match(payload.error, /http:\/\/host:port/)
  assert.equal((await call('state')).payload.upstream.configured, before)
})

await check('teardown: the policy is undone and the proxy stops listening', async () => {
  for (const dispose of disposers) if (typeof dispose === 'function') await dispose()
  await new Promise((resolve) => setTimeout(resolve, 250))
  assert.equal(process.env.http_proxy, undefined)
  assert.equal(process.env.HTTP_PROXY, undefined)
  const refused = await new Promise((resolve) => {
    const socket = net.connect(proxyPort, '127.0.0.1')
    socket.once('connect', () => { socket.destroy(); resolve(false) })
    socket.once('error', () => resolve(true))
  })
  assert.equal(refused, true)
})

for (const server of [bridge, upstream, origin, intranet]) {
  server.closeAllConnections?.()
  await new Promise((resolve) => server.close(resolve))
}
// The test drove the real state file; leaving a dead upstream port in it would poison the next boot.
rmSync(stateFile, { force: true })

console.log(`formatBytes: ${formatBytes(1536)} / ${formatBytes(5 * 1024 * 1024)}`)
console.log(process.exitCode === 1 ? 'host: FAILED' : 'host: ok')
