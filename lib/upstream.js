/**
 * Upstream dialers: how a request that has to leave through somewhere else actually leaves.
 *
 * The proxy itself only ever speaks one thing on its loopback side (HTTP absolute-form and
 * CONNECT). Everything past that point is a question of *which* hop the bytes go through, and a
 * hop is not always an HTTP proxy: a laptop with only `ssh -D` has SOCKS5, a VPS may run a trojan
 * listener, and neither of those is reachable through `CONNECT` framing. This module turns an
 * upstream string into a descriptor and, for the non-HTTP schemes, into a socket that already
 * reaches the target — so `lib/proxy.js` can tunnel through any of them without knowing the wire
 * format.
 *
 * Supported: `http`, `https`, `socks5`, `socks5h`, `trojan`.
 *
 * @module dsh-clash-verge/upstream
 */

import crypto from 'node:crypto'
import dns from 'node:dns/promises'
import net from 'node:net'
import tls from 'node:tls'

/** Schemes a configured upstream may name. */
export const UPSTREAM_SCHEMES = ['http:', 'https:', 'socks5:', 'socks5h:', 'trojan:']

/** Default ports, used when the value names none. */
const DEFAULT_PORTS = { 'http:': 80, 'https:': 443, 'socks5:': 1080, 'socks5h:': 1080, 'trojan:': 443 }

/** How long a handshake may take before the upstream is declared unusable. */
const HANDSHAKE_TIMEOUT = 8000

/** SOCKS5 reply codes, for messages someone can act on. */
const SOCKS_REPLIES = {
  1: 'general SOCKS server failure',
  2: 'connection not allowed by ruleset',
  3: 'network unreachable',
  4: 'host unreachable',
  5: 'connection refused',
  6: 'TTL expired',
  7: 'command not supported',
  8: 'address type not supported',
}

/**
 * Strip the brackets and trailing dot an authority may carry.
 * @param host - hostname as written in a config value.
 * @returns the lowercased bare host.
 */
function bare(host) {
  return String(host ?? '')
    .trim()
    .toLowerCase()
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.$/, '')
}

/**
 * Parse an upstream value into a descriptor.
 *
 * A bare `host:port` is read as an HTTP proxy, because that is what people paste when they point at
 * their own client's mixed or http port.
 * @param value - `host:port`, `http://…`, `https://…`, `socks5://…`, `socks5h://…` or `trojan://password@…`.
 * @returns the descriptor, or undefined when nothing usable is configured.
 */
export function parseUpstream(value) {
  const text = String(value ?? '').trim()
  if (text === '') return undefined
  // A scheme may contain digits (`socks5://`), so `[a-z]+` is wrong: it would see no scheme at all,
  // prepend `http://`, and parse `socks5` as a host name.
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`
  let url
  try {
    url = new URL(withScheme)
  } catch {
    return undefined
  }
  if (!UPSTREAM_SCHEMES.includes(url.protocol)) return undefined
  const port = Number(url.port || DEFAULT_PORTS[url.protocol])
  if (url.hostname === '' || !Number.isInteger(port) || port < 1 || port > 65_535) return undefined

  const protocol = url.protocol.slice(0, -1)
  const host = bare(url.hostname)
  let username = url.username === '' ? undefined : decodeURIComponent(url.username)
  let password = url.password === '' ? undefined : decodeURIComponent(url.password)
  if (protocol === 'trojan') {
    // Trojan puts the shared secret in the userinfo slot: `trojan://secret@host:port`. There is no
    // user name in that protocol, so whatever is written there is the password.
    if (password === undefined && username !== undefined) {
      password = username
      username = undefined
    } else if (password !== undefined) {
      username = undefined
    }
  }
  const flag = (name) => ['1', 'true', 'yes'].includes(String(url.searchParams.get(name) ?? '').toLowerCase())
  // Credentials are masked in the published url: the panel renders that string, and a SOCKS5 or
  // trojan password has no business being on screen (or in a screenshot of the panel).
  const credited = username === undefined ? '' : `${username}${password === undefined ? '' : ':***'}@`

  return {
    protocol,
    host,
    port,
    url: `${protocol}://${credited}${url.hostname}:${port}`,
    username,
    password,
    /** hostname supplied in the TLS handshake, for a trojan server behind a certificate by name */
    sni: url.searchParams.get('sni') ?? undefined,
    /** accept a self-signed certificate: common for a trojan listener on your own VPS */
    insecure: flag('insecure'),
    /** whether this hop understands absolute-form HTTP requests and CONNECT framing */
    tunnel: protocol === 'http' || protocol === 'https' ? 'http' : 'native',
    /** ask the far side to resolve the name (`socks5h`), rather than resolving it here */
    remoteDns: protocol === 'socks5h',
  }
}

/**
 * Connect a plain TCP socket.
 * @param upstream - the parsed upstream.
 * @param timeoutMs - handshake budget.
 * @returns the connected socket.
 */
function connectTcp(upstream, timeoutMs = HANDSHAKE_TIMEOUT) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: upstream.host, port: upstream.port })
    const fail = (error) => {
      socket.destroy()
      reject(error)
    }
    socket.once('connect', () => {
      socket.setNoDelay(true)
      socket.setTimeout(0)
      resolve(socket)
    })
    socket.once('error', fail)
    socket.setTimeout(timeoutMs, () => fail(new Error(`timed out after ${timeoutMs}ms`)))
  })
}

/**
 * A pull-based reader over a socket, for handshakes whose replies arrive in pieces.
 *
 * Whatever is left over after the last read belongs to the tunnel, so `release()` hands it back to
 * the socket with `unshift`: a server that answers the handshake and immediately sends payload in
 * the same packet must not lose that payload.
 * @param socket - the socket being handshaken.
 * @returns `read(n)` and `release()`.
 */
function createReader(socket) {
  let buffered = Buffer.alloc(0)
  let wake
  let failure
  let ended = false
  const onData = (chunk) => {
    buffered = buffered.length === 0 ? chunk : Buffer.concat([buffered, chunk])
    if (wake !== undefined) wake()
  }
  const onError = (error) => {
    failure = error
    if (wake !== undefined) wake()
  }
  const onEnd = () => {
    ended = true
    if (wake !== undefined) wake()
  }
  socket.on('data', onData)
  socket.once('error', onError)
  socket.once('end', onEnd)
  socket.once('close', onEnd)

  return {
    async read(count) {
      while (buffered.length < count) {
        if (failure !== undefined) throw failure
        if (ended) throw new Error('the upstream closed the connection during the handshake')
        await new Promise((resolve) => {
          wake = () => {
            wake = undefined
            resolve(undefined)
          }
        })
      }
      const out = buffered.subarray(0, count)
      buffered = buffered.subarray(count)
      return out
    },
    release() {
      socket.removeListener('data', onData)
      socket.removeListener('error', onError)
      socket.removeListener('end', onEnd)
      socket.removeListener('close', onEnd)
      if (buffered.length > 0) socket.unshift(buffered)
      buffered = Buffer.alloc(0)
    },
  }
}

/**
 * Encode an IPv6 address as sixteen bytes.
 * @param address - textual IPv6, with or without a `::` run and a trailing dotted quad.
 * @returns the address bytes.
 */
function ipv6Bytes(address) {
  const text = address.replace(/%.*$/, '')
  const [head, tail] = text.includes('::') ? text.split('::') : [text, undefined]
  const headParts = head === '' ? [] : head.split(':')
  const tailParts = tail === undefined || tail === '' ? [] : tail.split(':')
  const groups = headParts.concat(new Array(Math.max(0, 8 - headParts.length - tailParts.length)).fill('0'), tailParts)
  const buffer = Buffer.alloc(16)
  const last = groups[groups.length - 1] ?? ''
  if (last.includes('.')) {
    const quad = last.split('.').map(Number)
    groups.pop()
    groups.push(((quad[0] << 8) | quad[1]).toString(16), ((quad[2] << 8) | quad[3]).toString(16))
  }
  for (let i = 0; i < 8; i += 1) buffer.writeUInt16BE(Number.parseInt(groups[i] ?? '0', 16) || 0, i * 2)
  return buffer
}

/**
 * Encode a target the way SOCKS5 (and trojan, which copied it) wants it.
 * @param upstream - the parsed upstream, for the local/remote DNS decision.
 * @param host - target host.
 * @param port - target port.
 * @returns CONNECT request bytes: atyp, address, port.
 */
async function encodeTarget(upstream, host, port) {
  const portBytes = Buffer.from([(port >> 8) & 0xff, port & 0xff])
  const family = net.isIP(host)
  if (family === 4) {
    return Buffer.concat([Buffer.from([0x01]), Buffer.from(host.split('.').map(Number)), portBytes])
  }
  if (family === 6) {
    return Buffer.concat([Buffer.from([0x04]), ipv6Bytes(host), portBytes])
  }
  if (upstream.remoteDns) return Buffer.concat([domainForm(host), portBytes])
  // `socks5` resolves here, which keeps the name out of the far side's logs and works with servers
  // that cannot resolve. A name that does not resolve locally still goes out as a domain rather than
  // failing: a split-DNS setup is the far side's business, not ours.
  try {
    const answer = await dns.lookup(host, { family: 4 })
    return Buffer.concat([Buffer.from([0x01]), Buffer.from(answer.address.split('.').map(Number)), portBytes])
  } catch {
    return Buffer.concat([domainForm(host), portBytes])
  }
}

/**
 * Encode a hostname in the domain address form.
 * @param host - hostname.
 * @returns atyp byte plus length plus the name.
 */
function domainForm(host) {
  const name = Buffer.from(host, 'utf8')
  if (name.length > 255) throw new Error(`host name is too long for a domain-form address: ${host}`)
  return Buffer.concat([Buffer.from([0x03, name.length]), name])
}

/**
 * Establish a SOCKS5 tunnel to a target.
 * @param upstream - the parsed upstream.
 * @param host - target host.
 * @param port - target port.
 * @returns a socket carrying bytes to the target.
 */
async function socks5Connect(upstream, host, port) {
  const socket = await connectTcp(upstream)
  const reader = createReader(socket)
  try {
    const wantsAuth = upstream.username !== undefined
    socket.write(Buffer.from(wantsAuth ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00]))
    const greeting = await reader.read(2)
    if (greeting[0] !== 0x05) throw new Error(`not a SOCKS5 proxy (version ${greeting[0]})`)
    if (greeting[1] === 0xff) throw new Error('the SOCKS5 proxy accepts none of the offered authentication methods')
    if (greeting[1] === 0x02) {
      if (upstream.username === undefined) throw new Error('the SOCKS5 proxy requires a username and password')
      const user = Buffer.from(upstream.username, 'utf8')
      const pass = Buffer.from(upstream.password ?? '', 'utf8')
      socket.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]))
      const answer = await reader.read(2)
      if (answer[1] !== 0x00) throw new Error('the SOCKS5 proxy rejected the username and password')
    }

    socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), await encodeTarget(upstream, host, port)]))
    const head = await reader.read(4)
    if (head[0] !== 0x05) throw new Error(`not a SOCKS5 reply (version ${head[0]})`)
    if (head[1] !== 0x00) throw new Error(`SOCKS5 refused ${host}:${port}: ${SOCKS_REPLIES[head[1]] ?? `code ${head[1]}`}`)
    // Drain the bound address so the next bytes on the wire are the target's.
    if (head[3] === 0x01) await reader.read(4 + 2)
    else if (head[3] === 0x04) await reader.read(16 + 2)
    else if (head[3] === 0x03) {
      const length = (await reader.read(1))[0]
      await reader.read(length + 2)
    } else throw new Error(`SOCKS5 answered with an unknown address type ${head[3]}`)

    reader.release()
    socket.setTimeout(0)
    return socket
  } catch (error) {
    reader.release()
    socket.destroy()
    throw error
  }
}

/**
 * Build the trojan request header for a target.
 * @param password - the shared secret.
 * @param host - target host.
 * @param port - target port.
 * @returns the bytes to send before any payload.
 */
export async function buildTrojanHeader(password, host, port) {
  const digest = crypto.createHash('sha224').update(password ?? '', 'utf8').digest('hex')
  return Buffer.concat([
    Buffer.from(`${digest}\r\n`, 'latin1'),
    Buffer.from([0x01]),
    await encodeTarget({ remoteDns: true }, host, port),
    Buffer.from('\r\n', 'latin1'),
  ])
}

/**
 * Establish a trojan tunnel to a target.
 * @param upstream - the parsed upstream.
 * @param host - target host.
 * @param port - target port.
 * @returns a TLS socket carrying bytes to the target.
 */
async function trojanConnect(upstream, host, port) {
  const socket = await new Promise((resolve, reject) => {
    const tlsSocket = tls.connect({
      host: upstream.host,
      port: upstream.port,
      servername: net.isIP(upstream.host) === 0 ? (upstream.sni ?? upstream.host) : undefined,
      rejectUnauthorized: !upstream.insecure,
    })
    const fail = (error) => {
      tlsSocket.destroy()
      reject(error)
    }
    tlsSocket.once('secureConnect', () => {
      tlsSocket.setNoDelay(true)
      tlsSocket.setTimeout(0)
      resolve(tlsSocket)
    })
    tlsSocket.once('error', fail)
    tlsSocket.setTimeout(HANDSHAKE_TIMEOUT, () => fail(new Error(`timed out after ${HANDSHAKE_TIMEOUT}ms`)))
  })
  socket.write(await buildTrojanHeader(upstream.password ?? '', host, port))
  return socket
}

/**
 * Open a tunnel to a target through an upstream that is not an HTTP proxy.
 * @param upstream - the parsed upstream.
 * @param host - target host.
 * @param port - target port.
 * @returns a socket already carrying bytes to the target.
 */
export async function openTunnel(upstream, host, port) {
  if (upstream.protocol === 'socks5' || upstream.protocol === 'socks5h') {
    return await socks5Connect(upstream, host, port)
  }
  if (upstream.protocol === 'trojan') return await trojanConnect(upstream, host, port)
  throw new Error(`upstream ${upstream.protocol}:// speaks HTTP, not a tunnel protocol`)
}
