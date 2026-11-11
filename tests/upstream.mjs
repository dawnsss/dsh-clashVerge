/**
 * Upstream protocol coverage: SOCKS5 (with and without authentication) and trojan.
 *
 * Everything here runs against fake servers on loopback, so the test proves the plugin's own wire
 * format — greeting, auth subnegotiation, address encoding, reply draining, trojan's digest header —
 * and not somebody else's implementation. The last block drives the same code through
 * `createProxyServer`, so the two paths a request can take (absolute-form HTTP and CONNECT) are both
 * covered with a real tunnel under them.
 */

import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import net from 'node:net'
import tls from 'node:tls'
import http from 'node:http'

import { createProxyServer, createRecorder } from '../lib/proxy.js'
import { buildTrojanHeader, openTunnel, parseUpstream } from '../lib/upstream.js'

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

/** A self-signed certificate for the fake trojan listener (throwaway, test-only). */
const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIBPDCB5KADAgECAhQFhi+5uIlOoEdAsPorHEdixgmHaTAKBggqhkjOPQQDAjAf
MR0wGwYDVQQDDBRkc2gtY2xhc2gtdmVyZ2UgdGVzdDAeFw0yNjExMDkwOTIxMDZa
Fw0zNjExMDcwOTIxMDZaMB8xHTAbBgNVBAMMFGRzaC1jbGFzaC12ZXJnZSB0ZXN0
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENroyB/KU9cW2zV4qKM/ibkjN3Thg
fbSQ9k5UyRN9KAHGF+nF2EOdJSSNviwFca4emRp6tTkdvE+yVCgWGIvV+jAKBggq
hkjOPQQDAgNHADBEAiAfjIYy430UyQ22BWp5efDjmAKgFucZhmNg98Wd2YQadwIg
MPOO+f/vXTFvzBPuH8av+rqBZ4MmDEToWwgpsWf9uYk=
-----END CERTIFICATE-----
`
const TEST_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIO3f2MuTlZBgn96aHR9PR08o7rM5w0RHvA3exWm1myqdoAoGCCqGSM49
AwEHoUQDQgAENroyB/KU9cW2zV4qKM/ibkjN3ThgfbSQ9k5UyRN9KAHGF+nF2EOd
JSSNviwFca4emRp6tTkdvE+yVCgWGIvV+g==
-----END EC PRIVATE KEY-----
`

/**
 * A pull reader over a socket, for servers whose handshakes arrive in pieces.
 * @param socket - the socket to read.
 * @returns reader with `read(n)`.
 */
function reader(socket) {
  let buffer = Buffer.alloc(0)
  let wake
  let ended = false
  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk])
    if (wake !== undefined) wake()
  })
  socket.on('close', () => {
    ended = true
    if (wake !== undefined) wake()
  })
  return {
    async read(count) {
      while (buffer.length < count) {
        if (ended) throw new Error('socket closed')
        await new Promise((resolve) => {
          wake = () => {
            wake = undefined
            resolve(undefined)
          }
        })
      }
      const out = buffer.subarray(0, count)
      buffer = buffer.subarray(count)
      return out
    },
    /** everything buffered so far, then stop counting on this reader */
    drain() {
      const out = buffer
      buffer = Buffer.alloc(0)
      socket.removeAllListeners('data')
      return out
    },
  }
}

/**
 * Read a SOCKS5-style address (atyp + address + port) from a stream.
 * @param read - pull function.
 * @returns the target as `host:port`.
 */
async function readTarget(read) {
  const atyp = (await read(1))[0]
  let host
  if (atyp === 0x01) host = Array.from(await read(4)).join('.')
  else if (atyp === 0x04) {
    const bytes = await read(16)
    const groups = []
    for (let i = 0; i < 16; i += 2) groups.push(bytes.readUInt16BE(i).toString(16))
    host = groups.join(':')
  } else if (atyp === 0x03) {
    const length = (await read(1))[0]
    host = (await read(length)).toString('utf8')
  } else throw new Error(`unknown address type ${atyp}`)
  const port = (await read(2)).readUInt16BE(0)
  return { host, port }
}

/**
 * Start a fake SOCKS5 server that tunnels to whatever the client asks for.
 * @param options - `auth` (user:pass) makes the server demand username/password.
 * @returns the listening port, a close function and the targets it was asked for.
 */
async function startSocks5(options = {}) {
  const seen = []
  const server = net.createServer(async (socket) => {
    socket.on('error', () => {})
    const read = async (n) => (await reader(socket).read(n))
    const stream = reader(socket)
    try {
      const greeting = await stream.read(2)
      assert.equal(greeting[0], 0x05, 'client spoke SOCKS5')
      const methods = Array.from(await stream.read(greeting[1]))
      if (options.auth === undefined) {
        assert.deepEqual(methods.includes(0x00), true, 'client offered no-auth')
        socket.write(Buffer.from([0x05, 0x00]))
      } else {
        assert.deepEqual(methods.includes(0x02), true, 'client offered username/password')
        socket.write(Buffer.from([0x05, 0x02]))
        const version = (await stream.read(1))[0]
        assert.equal(version, 0x01, 'auth subnegotiation version')
        const userLength = (await stream.read(1))[0]
        const user = (await stream.read(userLength)).toString('utf8')
        const passLength = (await stream.read(1))[0]
        const pass = (await stream.read(passLength)).toString('utf8')
        if (`${user}:${pass}` !== options.auth) {
          socket.write(Buffer.from([0x01, 0x01]))
          socket.destroy()
          return
        }
        socket.write(Buffer.from([0x01, 0x00]))
      }
      const command = await stream.read(3)
      assert.equal(command[0], 0x05, 'request version')
      assert.equal(command[1], 0x01, 'CONNECT command')
      const target = await readTarget(stream.read)
      seen.push(`${target.host}:${target.port}`)
      const upstream = net.connect({ host: target.host, port: target.port }, () => {
        socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        const leftover = stream.drain()
        if (leftover.length > 0) upstream.write(leftover)
        socket.pipe(upstream)
        upstream.pipe(socket)
      })
      upstream.on('error', () => socket.destroy())
    } catch (error) {
      process.stderr.write(`fake socks5: ${error.message}\n`)
      socket.destroy()
    }
    void read
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    port: server.address().port,
    seen,
    close: () => new Promise((resolve) => server.close(() => resolve(undefined))),
  }
}

/**
 * Start a fake trojan listener: TLS, then digest header, then tunnel.
 * @param password - the shared secret the client must present.
 * @returns the listening port, a close function and the targets it was asked for.
 */
async function startTrojan(password) {
  const seen = []
  const expected = crypto.createHash('sha224').update(password, 'utf8').digest('hex')
  const server = tls.createServer({ cert: TEST_CERT, key: TEST_KEY }, async (socket) => {
    socket.on('error', () => {})
    const stream = reader(socket)
    try {
      const digest = (await stream.read(expected.length)).toString('latin1')
      assert.equal(digest, expected, 'trojan digest')
      await stream.read(2) // \r\n
      const command = (await stream.read(1))[0]
      assert.equal(command, 0x01, 'CONNECT command')
      const target = await readTarget(stream.read)
      await stream.read(2) // \r\n
      seen.push(`${target.host}:${target.port}`)
      const upstream = net.connect({ host: target.host, port: target.port }, () => {
        const leftover = stream.drain()
        if (leftover.length > 0) upstream.write(leftover)
        socket.pipe(upstream)
        upstream.pipe(socket)
      })
      upstream.on('error', () => socket.destroy())
    } catch (error) {
      process.stderr.write(`fake trojan: ${error.message}\n`)
      socket.destroy()
    }
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    port: server.address().port,
    seen,
    close: () => new Promise((resolve) => server.close(() => resolve(undefined))),
  }
}

/**
 * Start an origin server that answers every request with a fixed body.
 * @param body - the reply body.
 * @returns the listening port and a close function.
 */
async function startOrigin(body) {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(body)
  })
  // An upgraded socket drops out of the server's connection list, so it has to be tracked and
  // destroyed by hand or `close()` waits on it forever.
  const upgraded = new Set()
  server.on('upgrade', (_req, socket) => {
    upgraded.add(socket)
    socket.on('close', () => upgraded.delete(socket))
    socket.on('error', () => socket.destroy())
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n')
    socket.on('data', chunk => socket.write(chunk))
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    port: server.address().port,
    close: () => new Promise((resolve) => {
      for (const socket of upgraded) socket.destroy()
      upgraded.clear()
      server.closeAllConnections?.()
      server.close(() => resolve(undefined))
    }),
  }
}

/**
 * Start the proxy under test over a given upstream descriptor.
 * @param upstreamValue - what the panel would hold.
 * @returns the proxy port, the recorder and a close function.
 */
async function startProxy(upstreamValue) {
  const recorder = createRecorder()
  const server = createProxyServer({
    recorder,
    route: () => 'upstream',
    mode: () => 'external',
    upstream: () => parseUpstream(upstreamValue),
    onUpstreamFailure: () => {},
    log: () => {},
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    port: server.address().port,
    recorder,
    close: () => new Promise((resolve) => {
      server.closeAllConnections?.()
      server.close(() => resolve(undefined))
    }),
  }
}

/**
 * GET an absolute URL through a proxy.
 * @param proxyPort - the proxy to use.
 * @param target - the absolute URL.
 * @returns the body.
 */
function proxyGet(proxyPort, target) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port: proxyPort,
      method: 'GET',
      path: target,
      headers: { host: new URL(target).host },
      agent: false,
    }, (response) => {
      const chunks = []
      response.on('data', chunk => chunks.push(chunk))
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    })
    request.on('error', reject)
    request.end()
  })
}

/** Parse the upstream descriptor forms the panel accepts. */
await check('parseUpstream accepts the five schemes and keeps bare host:port as http', () => {
  const plain = parseUpstream('127.0.0.1:7897')
  assert.equal(plain.protocol, 'http')
  assert.equal(plain.tunnel, 'http')
  assert.equal(plain.url, 'http://127.0.0.1:7897')

  const socks = parseUpstream('socks5://127.0.0.1:1080')
  assert.equal(socks.protocol, 'socks5')
  assert.equal(socks.tunnel, 'native')
  assert.equal(socks.remoteDns, false)

  assert.equal(parseUpstream('socks5h://10.0.0.5').remoteDns, true)
  assert.equal(parseUpstream('socks5h://10.0.0.5').port, 1080, 'socks default port')
  assert.equal(parseUpstream('trojan://secret@example.com').port, 443, 'trojan default port')

  const authed = parseUpstream('socks5://user:pass@127.0.0.1:1080')
  assert.equal(authed.username, 'user')
  assert.equal(authed.password, 'pass')
  assert.equal(authed.url, 'socks5://user:***@127.0.0.1:1080', 'the published url hides the password')

  const trojan = parseUpstream('trojan://secret@vps.example:8443?insecure=1&sni=edge.example')
  assert.equal(trojan.insecure, true)
  assert.equal(trojan.sni, 'edge.example')
})

await check('parseUpstream rejects what it cannot speak', () => {
  for (const value of ['', '   ', 'socks4://127.0.0.1:1080', 'ftp://x:21', 'http://host:0', 'http://host:70000', 'vmess://abc']) {
    assert.equal(parseUpstream(value), undefined, `rejected: ${JSON.stringify(value)}`)
  }
})

await check('parseUpstream refuses a trojan hop with no shared secret', () => {
  // Trojan cannot report a bad secret — the header is fire-and-forget — so a secret-less descriptor
  // would connect, greet, and tunnel nothing at all. It has to die at parse time.
  assert.equal(parseUpstream('trojan://vps.example:443'), undefined)
  assert.equal(parseUpstream('trojan://@vps.example:443'), undefined)
  assert.notEqual(parseUpstream('trojan://secret@vps.example:443'), undefined)
})

await check('buildTrojanHeader writes digest, command and target', async () => {
  const digest = crypto.createHash('sha224').update('secret').digest('hex')
  assert.equal(digest.length, 56, 'sha224 renders as 56 hex characters')
  const header = await buildTrojanHeader('secret', 'example.com', 443)
  assert.equal(header.subarray(0, 56).toString('latin1'), digest)
  assert.equal(header.subarray(56, 58).toString('latin1'), '\r\n')
  assert.equal(header[58], 0x01)
  assert.equal(header[59], 0x03, 'domain address form')
  assert.equal(header[60], 'example.com'.length)
  assert.equal(header.subarray(61, 72).toString('latin1'), 'example.com')
  assert.equal(header.readUInt16BE(72), 443)
  assert.equal(header.subarray(74).toString('latin1'), '\r\n')
  assert.equal(header.length, 76)
})

const origin = await startOrigin('through-the-tunnel')
const socksPlain = await startSocks5()
const socksAuthed = await startSocks5({ auth: 'alice:s3cret' })
const nogood = await startSocks5({ auth: 'alice:s3cret' })
const trojan = await startTrojan('hunter2')

await check('SOCKS5: openTunnel reaches the target and carries bytes both ways', async () => {
  const socket = await openTunnel(parseUpstream(`socks5://127.0.0.1:${socksPlain.port}`), '127.0.0.1', origin.port)
  const answer = await new Promise((resolve, reject) => {
    // openTunnel hands back a paused socket: the consumer resumes it, which is what pump() does in
    // production via pipe().
    socket.write(`GET /hi HTTP/1.1\r\nHost: 127.0.0.1:${origin.port}\r\nConnection: close\r\n\r\n`)
    let text = ''
    socket.on('data', (chunk) => { text += chunk.toString('utf8') })
    socket.resume()
    socket.on('close', () => resolve(text))
    socket.on('error', reject)
  })
  socket.destroy()
  assert.match(answer, /200 OK/)
  assert.match(answer, /through-the-tunnel/)
  assert.deepEqual(socksPlain.seen, [`127.0.0.1:${origin.port}`])
})

await check('SOCKS5: username/password authentication', async () => {
  const url = `socks5://alice:s3cret@127.0.0.1:${socksAuthed.port}`
  const socket = await openTunnel(parseUpstream(url), '127.0.0.1', origin.port)
  socket.destroy()
  assert.deepEqual(socksAuthed.seen, [`127.0.0.1:${origin.port}`])
})

await check('SOCKS5: a rejected password surfaces as a failure, not a hang', async () => {
  const url = `socks5://alice:wrong@127.0.0.1:${nogood.port}`
  await assert.rejects(() => openTunnel(parseUpstream(url), '127.0.0.1', origin.port), /rejected the username and password/)
})

await check('SOCKS5: a refused target is reported with the SOCKS5 reason', async () => {
  const socket = await new Promise((resolve, reject) => {
    const server = net.createServer((client) => {
      client.on('error', () => {})
      client.once('data', () => {
        client.write(Buffer.from([0x05, 0x00]))
        client.once('data', () => {
          // ver, rep=5 (connection refused), rsv, atyp=ipv4, address, port
          client.write(Buffer.from([0x05, 0x05, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]))
        })
      })
    })
    server.listen(0, '127.0.0.1', () => resolve(server))
    server.on('error', reject)
  })
  const { port } = socket.address()
  try {
    await assert.rejects(
      () => openTunnel(parseUpstream(`socks5://127.0.0.1:${port}`), 'example.com', 80),
      /connection refused/,
    )
  } finally {
    await new Promise((resolve) => socket.close(() => resolve(undefined)))
  }
})

await check('SOCKS5: bytes that arrive before the tunnel consumer attaches are kept', async () => {
  // SSH, SMTP and MySQL all speak first. The handshake happens on the same socket the tunnel then
  // uses, so anything the target sends in the gap belongs to the tunnel and must still be there.
  const banner = 'SSH-2.0-dsh-clash-verge-test\r\n'
  const sockets = new Set()
  const server = net.createServer((client) => {
    sockets.add(client)
    client.on('error', () => {})
    setTimeout(() => { if (!client.destroyed) client.write(banner) }, 30)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()
  const socket = await openTunnel(parseUpstream(`socks5://127.0.0.1:${socksPlain.port}`), '127.0.0.1', port)
  try {
    assert.equal(socket.isPaused(), true, 'the tunnel socket comes back paused, so nothing is emitted into the void')
    // A real caller has a promise chain to walk before it attaches; reproduce that gap.
    await new Promise((resolve) => setTimeout(resolve, 120))
    const first = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('the banner was dropped during the handshake gap')), 600)
      socket.once('data', (chunk) => { clearTimeout(timer); resolve(chunk.toString('utf8')) })
      socket.resume()
    })
    assert.equal(first, banner)
  } finally {
    socket.destroy()
    for (const client of sockets) client.destroy()
    await new Promise((resolve) => server.close(() => resolve(undefined)))
  }
})

await check('trojan: openTunnel presents the digest and tunnels', async () => {
  const url = `trojan://hunter2@127.0.0.1:${trojan.port}?insecure=1`
  const socket = await openTunnel(parseUpstream(url), '127.0.0.1', origin.port)
  const answer = await new Promise((resolve, reject) => {
    socket.write(`GET /hi HTTP/1.1\r\nHost: 127.0.0.1:${origin.port}\r\nConnection: close\r\n\r\n`)
    let text = ''
    socket.on('data', (chunk) => { text += chunk.toString('utf8') })
    socket.on('close', () => resolve(text))
    socket.on('error', reject)
    socket.resume()
  })
  socket.destroy()
  assert.match(answer, /through-the-tunnel/)
  assert.deepEqual(trojan.seen, [`127.0.0.1:${origin.port}`])
})

await check('proxy: absolute-form HTTP goes through a SOCKS5 upstream', async () => {
  const proxy = await startProxy(`socks5://127.0.0.1:${socksPlain.port}`)
  try {
    const body = await proxyGet(proxy.port, `http://127.0.0.1:${origin.port}/abs`)
    assert.equal(body, 'through-the-tunnel')
    const snapshot = proxy.recorder.snapshot()
    assert.equal(snapshot.byRoute.upstream.req, 1, 'the request is reported as upstream traffic')
    assert.equal((snapshot.byRoute.direct ?? { req: 0 }).req, 0, 'nothing was reported as direct')
  } finally {
    await proxy.close()
  }
})

/** Drive one HTTP upgrade through the proxy and echo a payload over the resulting socket. */
function upgradeThrough(proxyPort, targetPort) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port: proxyPort }, () => {
      socket.write(
        `GET http://127.0.0.1:${targetPort}/ws HTTP/1.1\r\n`
        + `Host: 127.0.0.1:${targetPort}\r\n`
        + 'Connection: Upgrade\r\nUpgrade: echo\r\n\r\n',
      )
    })
    let text = ''
    let upgraded = false
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error(`no upgrade arrived, saw: ${JSON.stringify(text.slice(0, 200))}`))
    }, 4000)
    socket.on('data', (chunk) => {
      const piece = chunk.toString('utf8')
      text += piece
      if (!upgraded && text.includes('\r\n\r\n')) {
        upgraded = true
        socket.write('ping-through-the-upgrade')
      } else if (upgraded && text.includes('ping-through-the-upgrade')) {
        clearTimeout(timer)
        socket.destroy()
        resolve(text)
      }
    })
    socket.on('error', (error) => { clearTimeout(timer); reject(error) })
    socket.on('close', () => { clearTimeout(timer); if (!upgraded) reject(new Error('closed before the upgrade')) })
  })
}

await check('proxy: an HTTP upgrade is carried when the hop is direct', async () => {
  const proxy = await startProxy(`socks5://127.0.0.1:${socksPlain.port}`)
  const directProxy = createProxyServer({
    recorder: createRecorder(),
    route: () => 'direct',
    mode: () => 'direct',
    upstream: () => undefined,
    onUpstreamFailure: () => {},
    log: () => {},
  })
  await new Promise((resolve) => directProxy.listen(0, '127.0.0.1', resolve))
  try {
    const answer = await upgradeThrough(directProxy.address().port, origin.port)
    assert.match(answer, /101/)
    assert.match(answer, /ping-through-the-upgrade/)
  } finally {
    directProxy.closeAllConnections?.()
    await new Promise((resolve) => directProxy.close(() => resolve(undefined)))
    await proxy.close()
  }
})

await check('proxy: an HTTP upgrade is tunnelled through a SOCKS5 upstream', async () => {
  const before = socksPlain.seen.length
  const proxy = await startProxy(`socks5://127.0.0.1:${socksPlain.port}`)
  try {
    const answer = await upgradeThrough(proxy.port, origin.port)
    assert.match(answer, /101/)
    assert.match(answer, /ping-through-the-upgrade/)
    assert.equal(socksPlain.seen.length, before + 1, 'the upgrade target reached the SOCKS5 server')
  } finally {
    await proxy.close()
  }
})

await check('proxy: CONNECT is tunnelled through a SOCKS5 upstream', async () => {
  const before = socksPlain.seen.length
  const proxy = await startProxy(`socks5://127.0.0.1:${socksPlain.port}`)
  try {
    const answer = await new Promise((resolve, reject) => {
      const socket = net.connect({ host: '127.0.0.1', port: proxy.port }, () => {
        socket.write(`CONNECT 127.0.0.1:${origin.port} HTTP/1.1\r\nHost: 127.0.0.1:${origin.port}\r\n\r\n`)
      })
      let text = ''
      let established = false
      socket.on('data', (chunk) => {
        text += chunk.toString('utf8')
        if (!established && text.includes('\r\n\r\n')) {
          established = true
          socket.write(`GET /tunnel HTTP/1.1\r\nHost: 127.0.0.1:${origin.port}\r\nConnection: close\r\n\r\n`)
        }
      })
      socket.on('close', () => resolve(text))
      socket.on('error', reject)
    })
    assert.match(answer, /HTTP\/1.1 200 Connection Established/)
    assert.match(answer, /through-the-tunnel/)
    assert.equal(socksPlain.seen.length, before + 1, 'the CONNECT target reached the SOCKS5 server')
  } finally {
    await proxy.close()
  }
})

await check('proxy: a dead SOCKS5 upstream fails the request and marks it unreachable', async () => {
  let failed = 0
  const recorder = createRecorder()
  const server = createProxyServer({
    recorder,
    route: () => 'upstream',
    mode: () => 'external',
    upstream: () => parseUpstream('socks5://127.0.0.1:9'),
    onUpstreamFailure: () => { failed += 1 },
    log: () => {},
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  try {
    const { port } = server.address()
    const answer = await new Promise((resolve, reject) => {
      const socket = net.connect({ host: '127.0.0.1', port }, () => {
        socket.write(`CONNECT 127.0.0.1:${origin.port} HTTP/1.1\r\nHost: x\r\n\r\n`)
      })
      let text = ''
      socket.on('data', (chunk) => { text += chunk.toString('utf8') })
      socket.on('close', () => resolve(text))
      socket.on('error', reject)
    })
    assert.match(answer, /HTTP\/1.1 502/)
    assert.equal(failed, 1, 'the failure was reported to the host half')
  } finally {
    await new Promise((resolve) => {
      server.closeAllConnections?.()
      server.close(() => resolve(undefined))
    })
  }
})

await origin.close()
await socksPlain.close()
await socksAuthed.close()
await nogood.close()
await trojan.close()

if (failures.length > 0) {
  process.stdout.write(`\nupstream: ${failures.length} failure(s)\n`)
  process.exit(1)
}
process.stdout.write('upstream: ok\n')
