/**
 * Subscription coverage: the three shapes a provider answers with, and the fetch that gets them.
 *
 * The point of these tests is the boundary the plugin promises — a Clash document's `proxies:` block,
 * a base64 blob of URIs, or a plain URI list all end up as the same list of hops, and everything the
 * plugin cannot speak is counted rather than dropped in silence.
 */

import assert from 'node:assert/strict'
import http from 'node:http'

import { fetchSubscription, parseSubscription } from '../lib/subscription.js'

const failures = []
const ok = (label) => process.stdout.write(`ok  ${label}\n`)
async function check(label, run) {
  try {
    await run()
    ok(label)
  } catch (error) {
    failures.push(`${label}: ${error.message}`)
    process.stdout.write(`FAIL ${label}: ${error.message}\n`)
  }
}

const CLASH = `port: 7890
mode: rule
proxies:
  - name: "HK trojan"
    type: trojan
    server: hk.example.com
    port: 443
    password: "p@ss word"
    sni: edge.example.com
    skip-cert-verify: true
  - name: "SG socks"
    type: socks5
    server: sg.example.com
    port: 1080
    username: alice
    password: s3cret
  - name: "JP shadowsocks"
    type: ss
    server: jp.example.com
    port: 8388
    cipher: aes-256-gcm
    password: hunter2
  - name: "US http"
    type: http
    server: 10.1.2.3
    port: 8080
    username: bob
    password: bobpass
proxy-groups:
  - name: Proxy
    type: select
    proxies: ["HK trojan", "SG socks"]
rules:
  - MATCH,Proxy
`

await check('clash: block-form proxies become hops, unsupported types are counted', () => {
  const { nodes, skipped, format } = parseSubscription(CLASH)
  assert.equal(format, 'clash')
  assert.equal(nodes.length, 3)
  assert.deepEqual(nodes.map(node => node.type), ['trojan', 'socks5', 'http'])
  assert.equal(nodes[0].name, 'HK trojan')
  assert.equal(nodes[0].url, 'trojan://p%40ss%20word@hk.example.com:443?sni=edge.example.com&insecure=1')
  assert.equal(nodes[1].url, 'socks5://alice:s3cret@sg.example.com:1080')
  assert.equal(nodes[2].url, 'http://bob:bobpass@10.1.2.3:8080')
  assert.equal(skipped.length, 1)
  assert.match(skipped[0].reason, /shadowsocks is not implemented/)
  assert.equal(skipped[0].name, 'JP shadowsocks')
  // Stable ids: the same subscription parsed twice selects the same node.
  const again = parseSubscription(CLASH)
  assert.deepEqual(again.nodes.map(node => node.id), nodes.map(node => node.id))
})

await check('clash: inline maps and a single-line list are read too', () => {
  const inline = `proxies:\n  - {name: A, type: trojan, server: a.example.com, port: 443, password: pw}\n`
  const one = parseSubscription(inline)
  assert.equal(one.nodes.length, 1)
  assert.equal(one.nodes[0].url, 'trojan://pw@a.example.com:443')

  const single = `proxies: [{name: B, type: socks5, server: 1.2.3.4, port: 1080}, {name: C, type: http, server: 5.6.7.8, port: 3128}]\n`
  const many = parseSubscription(single)
  assert.equal(many.nodes.length, 2)
  assert.deepEqual(many.nodes.map(node => node.type), ['socks5', 'http'])
})

await check('clash: a trojan node without a password is refused, not guessed', () => {
  const broken = `proxies:\n  - name: Broken\n    type: trojan\n    server: b.example.com\n    port: 443\n`
  const { nodes, skipped } = parseSubscription(broken)
  assert.equal(nodes.length, 0)
  assert.match(skipped[0].reason, /trojan needs a password/)
})

await check('uris: a plain list keeps its fragments as names and skips foreign schemes', () => {
  const list = [
    '# my subscription',
    'trojan://secret@vps.example:443?sni=vps.example#VPS trojan',
    'socks5://127.0.0.1:1080#local socks',
    'vmess://eyJhZGQiOiJ4In0=',
    'ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#ss node',
    'https://proxy.example:8443#https hop',
  ].join('\n')
  const { nodes, skipped, format } = parseSubscription(list)
  assert.equal(format, 'uris')
  assert.deepEqual(nodes.map(node => node.name), ['VPS trojan', 'local socks', 'https hop'])
  assert.equal(nodes[0].url, 'trojan://secret@vps.example:443?sni=vps.example')
  assert.equal(nodes[1].url, 'socks5://127.0.0.1:1080')
  assert.equal(skipped.length, 2)
  assert.match(skipped[0].reason, /vmess is not implemented/)
  assert.match(skipped[1].reason, /shadowsocks is not implemented/)
})

await check('uris: a base64 blob is decoded first', () => {
  const plain = 'trojan://pw@a.example:443#A\nsocks5://b.example:1080#B\n'
  const encoded = Buffer.from(plain, 'utf8').toString('base64')
  const { nodes, format } = parseSubscription(encoded)
  assert.equal(format, 'base64')
  assert.deepEqual(nodes.map(node => node.name), ['A', 'B'])
})

await check('parse: junk answers nothing at all, without throwing', () => {
  for (const value of ['', '   ', 'not a subscription at all', '{"proxies":[]}', '<html>404</html>']) {
    const { nodes } = parseSubscription(value)
    assert.equal(nodes.length, 0, `no nodes for ${JSON.stringify(value.slice(0, 20))}`)
  }
})

/** A one-shot HTTP server that answers the given handler. */
async function startServer(handler) {
  const server = http.createServer(handler)
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    port: server.address().port,
    close: () => new Promise((resolve) => {
      server.closeAllConnections?.()
      server.close(() => resolve(undefined))
    }),
  }
}

await check('fetch: a plain answer is returned, and the body is the subscription', async () => {
  const server = await startServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/yaml' })
    res.end(CLASH)
  })
  try {
    const body = await fetchSubscription(`http://127.0.0.1:${server.port}/sub`)
    const { nodes } = parseSubscription(body)
    assert.equal(nodes.length, 3)
  } finally {
    await server.close()
  }
})

await check('fetch: redirects are followed', async () => {
  const server = await startServer((req, res) => {
    if (req.url === '/sub') {
      res.writeHead(302, { location: '/real' })
      res.end()
      return
    }
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('trojan://pw@a.example:443#A')
  })
  try {
    const body = await fetchSubscription(`http://127.0.0.1:${server.port}/sub`)
    assert.match(body, /trojan:\/\/pw@a\.example:443/)
  } finally {
    await server.close()
  }
})

await check('fetch: an error status is reported with the code', async () => {
  const server = await startServer((_req, res) => {
    res.writeHead(403)
    res.end('nope')
  })
  try {
    await assert.rejects(() => fetchSubscription(`http://127.0.0.1:${server.port}/sub`), /HTTP 403/)
  } finally {
    await server.close()
  }
})

await check('fetch: an oversized answer is cut off instead of buffered forever', async () => {
  const server = await startServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.write('x'.repeat(64 * 1024))
    res.end()
  })
  try {
    await assert.rejects(
      () => fetchSubscription(`http://127.0.0.1:${server.port}/sub`, { maxBytes: 4096 }),
      /larger than 4096 bytes/,
    )
  } finally {
    await server.close()
  }
})

await check('fetch: the direct route is tried first, then the local proxy', async () => {
  // Behaves like the plugin's own proxy: the request line is an absolute URL.
  let proxied = 0
  const proxy = await startServer((req, res) => {
    assert.match(req.url, /^http:\/\/sub\.invalid\//, 'the proxy is asked for the absolute URL')
    proxied += 1
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('socks5://127.0.0.1:1080#via-proxy')
  })
  try {
    const body = await fetchSubscription('http://sub.invalid/sub', {
      timeoutMs: 3000,
      via: { host: '127.0.0.1', port: proxy.port },
    })
    assert.match(body, /via-proxy/)
    assert.equal(proxied, 1)
  } finally {
    await proxy.close()
  }
})

if (failures.length > 0) {
  process.stdout.write(`\nsubscription: ${failures.length} failure(s)\n`)
  process.exit(1)
}
process.stdout.write('subscription: ok\n')
