/**
 * Subscriptions: one URL that answers with a list of hops.
 *
 * A subscription is not a protocol, it is a shopping list. What arrives is either a Clash-style
 * document (`proxies:` and a YAML-ish body), a base64 blob of `scheme://` URIs, or a plain list of
 * `scheme://` URIs. All three are turned into the same thing here: the hops this plugin can actually
 * speak — http, https, socks5, socks5h, trojan — plus a count of what was left behind, because
 * silently dropping a `vmess://` node would look like the subscription failed.
 *
 * Zero dependencies: the YAML subset Clash uses for `proxies:` is a list of flat maps, which is
 * exactly what a two-level indentation scan can read.
 */

import crypto from 'node:crypto'
import http from 'node:http'
import https from 'node:https'

import { parseUpstream } from './upstream.js'

/** Clash `type:` values this plugin can speak, and the scheme each one becomes. */
const SPEAKABLE = new Map([
  ['trojan', 'trojan'],
  ['socks5', 'socks5'],
  ['socks', 'socks5'],
  ['http', 'http'],
  ['https', 'https'],
])

/** Values that are real nodes but not in this plugin's vocabulary, with the reason to report. */
const UNSUPPORTED = new Map([
  ['ss', 'shadowsocks is not implemented'],
  ['ssr', 'shadowsocks-r is not implemented'],
  ['vmess', 'vmess is not implemented'],
  ['vless', 'vless is not implemented'],
  ['hysteria', 'hysteria is not implemented'],
  ['hysteria2', 'hysteria2 is not implemented'],
  ['hy2', 'hysteria2 is not implemented'],
  ['tuic', 'tuic is not implemented'],
  ['anytls', 'anytls is not implemented'],
  ['wireguard', 'wireguard is not implemented'],
  ['snell', 'snell is not implemented'],
  ['mieru', 'mieru is not implemented'],
])

/** Schemes accepted in a URI list, mapped to themselves. */
const URI_SCHEMES = new Set(['http', 'https', 'socks5', 'socks5h', 'trojan'])

/** Prefixes recognised as "a real node, but not one this plugin speaks". */
const FOREIGN_SCHEMES = new Set([
  'ss', 'ssr', 'vmess', 'vless', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'anytls', 'wireguard',
  'snell', 'mieru', 'juicity', 'naive+https', 'naive+quic',
])

const MAX_NODES = 500

/**
 * A stable id for a node: the same hop keeps its id across refreshes, so a selection survives.
 * @param value - the node's url.
 * @returns eight hex characters.
 */
function nodeId(value) {
  return crypto.createHash('sha1').update(value, 'utf8').digest('hex').slice(0, 8)
}

/** Strip a YAML scalar of its quotes, comments and stray whitespace. */
function scalar(raw) {
  let text = String(raw ?? '').trim()
  const hash = text.search(/\s#/)
  if (hash !== -1 && !/^["']/.test(text)) text = text.slice(0, hash).trim()
  if (text.length >= 2 && ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'")))) {
    text = text.slice(1, -1)
  }
  return text
}

/**
 * Split `key: value` pairs out of an inline map (`{name: a, type: trojan}`) or a `key: value` line.
 * @param text - the map body, braces optional.
 * @returns a plain object of scalars.
 */
function inlineMap(text) {
  const out = {}
  const body = text.trim().replace(/^\{/, '').replace(/\}$/, '')
  // Values may contain commas inside quotes; walk the string instead of splitting blindly.
  let depth = 0
  let quote = ''
  let current = ''
  const pieces = []
  for (const character of body) {
    if (quote !== '') {
      current += character
      if (character === quote) quote = ''
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      current += character
      continue
    }
    if (character === '{' || character === '[') depth += 1
    if (character === '}' || character === ']') depth -= 1
    if (character === ',' && depth === 0) {
      pieces.push(current)
      current = ''
      continue
    }
    current += character
  }
  if (current.trim() !== '') pieces.push(current)
  for (const piece of pieces) {
    const index = piece.indexOf(':')
    if (index === -1) continue
    out[scalar(piece.slice(0, index))] = scalar(piece.slice(index + 1))
  }
  return out
}

/**
 * Turn one Clash proxy map into the url this plugin stores, or a reason it cannot be used.
 * @param proxy - the parsed map.
 * @returns `{url}` or `{reason}`.
 */
function fromClash(proxy) {
  const type = String(proxy.type ?? '').toLowerCase()
  if (UNSUPPORTED.has(type)) return { reason: UNSUPPORTED.get(type) }
  const scheme = SPEAKABLE.get(type)
  if (scheme === undefined) return { reason: `unknown proxy type "${type}"` }
  const server = String(proxy.server ?? '')
  const port = Number(proxy.port ?? 0)
  if (server === '' || !Number.isInteger(port) || port < 1 || port > 65_535) {
    return { reason: 'missing or invalid server/port' }
  }
  // `tls: true` on a socks5 or http hop means TLS to the proxy itself, which is a different thing
  // from the plain CONNECT framing this plugin sends. Report it rather than bending it.
  if (scheme !== 'https' && scheme !== 'trojan' && String(proxy.tls ?? '').toLowerCase() === 'true') {
    return { reason: `${type} over TLS is not implemented` }
  }

  const host = server.includes(':') && !server.startsWith('[') ? `[${server}]` : server
  const address = `${host}:${port}`
  let url
  if (scheme === 'trojan') {
    const password = proxy.password ?? ''
    if (password === '') return { reason: 'trojan needs a password' }
    const query = new URLSearchParams()
    const sni = proxy.sni ?? proxy.servername
    if (sni !== undefined && sni !== '') query.set('sni', String(sni))
    if (String(proxy['skip-cert-verify'] ?? '').toLowerCase() === 'true') query.set('insecure', '1')
    const search = query.toString() === '' ? '' : `?${query.toString()}`
    url = `trojan://${encodeURIComponent(String(password))}@${address}${search}`
  } else {
    const user = proxy.username
    const credentials = user === undefined || user === ''
      ? ''
      : `${encodeURIComponent(String(user))}:${encodeURIComponent(String(proxy.password ?? ''))}@`
    url = `${scheme}://${credentials}${address}`
  }
  if (parseUpstream(url) === undefined) return { reason: 'cannot be expressed as an upstream here' }
  return { url }
}

/**
 * Read the `proxies:` block of a Clash-style document.
 * @param text - the document.
 * @returns the proxy maps, in order.
 */
function clashProxies(text) {
  const lines = text.split(/\r?\n/)
  const proxies = []
  let inside = false
  let current
  const flush = () => {
    if (current !== undefined) proxies.push(current)
    current = undefined
  }
  for (const line of lines) {
    if (/^proxies\s*:/.test(line)) {
      inside = true
      const rest = line.replace(/^proxies\s*:\s*/, '').trim()
      if (rest.startsWith('[')) {
        // `proxies: [ {..}, {..} ]` on one line.
        const body = rest.replace(/^\[/, '').replace(/\]$/, '')
        for (const piece of body.split(/\}\s*,\s*\{/)) proxies.push(inlineMap(piece))
        return proxies
      }
      continue
    }
    if (!inside) continue
    if (/^\S/.test(line)) {
      // A new top-level key ends the block.
      flush()
      inside = false
      continue
    }
    const item = line.match(/^\s*-\s*(.*)$/)
    if (item !== null) {
      flush()
      const rest = item[1].trim()
      if (rest.startsWith('{')) {
        current = inlineMap(rest)
        // An inline map is complete in itself.
        flush()
      } else {
        current = {}
        const pair = rest.match(/^([^:]+):\s*(.*)$/)
        if (pair !== null) current[scalar(pair[1])] = scalar(pair[2])
      }
      continue
    }
    const pair = line.match(/^\s+([A-Za-z0-9_-]+)\s*:\s*(.*)$/)
    if (pair !== null && current !== undefined) {
      current[scalar(pair[1])] = scalar(pair[2])
    }
  }
  flush()
  return proxies
}

/**
 * Parse a subscription body.
 * @param text - whatever the URL answered with.
 * @returns `{nodes, skipped, format}`, where a node is `{id, name, type, url}`.
 */
export function parseSubscription(text) {
  const input = String(text ?? '')
  const nodes = []
  const skipped = []

  const add = (name, url) => {
    if (nodes.length >= MAX_NODES) return false
    const descriptor = parseUpstream(url)
    if (descriptor === undefined) return false
    const id = nodeId(url)
    if (nodes.some(node => node.id === id)) return false
    nodes.push({
      id,
      name: String(name ?? '').trim() || `${descriptor.protocol}://${descriptor.host}:${descriptor.port}`,
      type: descriptor.protocol,
      url,
    })
    return true
  }

  if (/^proxies\s*:/m.test(input) || /^\s*proxy-groups\s*:/m.test(input)) {
    for (const proxy of clashProxies(input)) {
      const converted = fromClash(proxy)
      if (converted.reason !== undefined) {
        skipped.push({ name: String(proxy.name ?? ''), reason: converted.reason })
        continue
      }
      if (!add(proxy.name, converted.url)) {
        skipped.push({ name: String(proxy.name ?? ''), reason: 'duplicate' })
      }
    }
    return { nodes, skipped, format: 'clash' }
  }

  // A provider that answers with a base64 blob is the other half of the ecosystem.
  let list = input
  let format = 'uris'
  const compact = input.replace(/\s+/g, '')
  if (/^[A-Za-z0-9+/=_-]+$/.test(compact) && compact.length > 24) {
    try {
      const decoded = Buffer.from(compact, 'base64').toString('utf8')
      if (decoded.includes('://')) {
        list = decoded
        format = 'base64'
      }
    } catch {
      // Not base64 after all; the plain pass below decides.
    }
  }

  for (const raw of list.split(/\r?\n/)) {
    const line = raw.trim()
    if (line === '' || line.startsWith('#') || line.startsWith('//')) continue
    const match = line.match(/^([a-z0-9+.-]+):\/\/(.*)$/i)
    if (match === null) continue
    const scheme = match[1].toLowerCase()
    if (FOREIGN_SCHEMES.has(scheme)) {
      skipped.push({ name: line.slice(0, 24), reason: UNSUPPORTED.get(scheme) ?? `${scheme} is not implemented` })
      continue
    }
    if (!URI_SCHEMES.has(scheme)) {
      skipped.push({ name: line.slice(0, 24), reason: `unknown scheme "${scheme}"` })
      continue
    }
    const hash = line.indexOf('#')
    const target = hash === -1 ? line : line.slice(0, hash)
    const label = hash === -1 ? '' : decodeURIComponent(line.slice(hash + 1))
    if (!add(label, target)) skipped.push({ name: label || line.slice(0, 24), reason: 'incomplete or duplicate' })
  }
  return { nodes, skipped, format }
}

/**
 * Fetch a subscription, falling back to the plugin's own proxy when the direct route fails.
 * @param url - the subscription URL.
 * @param options - `{timeoutMs, maxBytes, via}` where `via` is `{host, port}` of a local proxy.
 * @returns the body text.
 */
export async function fetchSubscription(url, options = {}) {
  const timeoutMs = options.timeoutMs ?? 15_000
  const maxBytes = options.maxBytes ?? 4 * 1024 * 1024
  const via = options.via

  const once = (target, proxy) => new Promise((resolve, reject) => {
    const secure = target.protocol === 'https:'
    const requestOptions = proxy === undefined
      ? {
        protocol: target.protocol,
        host: target.hostname,
        port: target.port === '' ? (secure ? 443 : 80) : Number(target.port),
        path: `${target.pathname}${target.search}`,
        method: 'GET',
        headers: { accept: '*/*', 'user-agent': 'dsh-clash-verge/0.1', connection: 'close' },
        servername: secure ? target.hostname : undefined,
      }
      : {
        protocol: 'http:',
        host: proxy.host,
        port: proxy.port,
        method: 'GET',
        path: target.href,
        headers: {
          accept: '*/*',
          'user-agent': 'dsh-clash-verge/0.1',
          host: target.host,
          connection: 'close',
        },
      }
    const transport = proxy !== undefined ? http : (secure ? https : http)
    const request = transport.request(requestOptions, (response) => {
      const status = response.statusCode ?? 0
      if (status >= 300 && status < 400 && typeof response.headers.location === 'string') {
        response.resume()
        try {
          resolve({ redirect: new URL(response.headers.location, target).href })
        } catch (error) {
          reject(new Error(`the subscription redirected to something unparsable: ${error.message}`))
        }
        return
      }
      if (status !== 200) {
        response.resume()
        reject(new Error(`the subscription answered HTTP ${status}`))
        return
      }
      const chunks = []
      let size = 0
      response.on('data', (chunk) => {
        size += chunk.length
        if (size > maxBytes) {
          request.destroy()
          reject(new Error(`the subscription is larger than ${maxBytes} bytes`))
          return
        }
        chunks.push(chunk)
      })
      response.on('end', () => resolve({ body: Buffer.concat(chunks).toString('utf8') }))
      response.on('error', reject)
    })
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error(`the subscription did not answer within ${timeoutMs}ms`))
    })
    request.on('error', reject)
    request.end()
  })

  const walk = async (proxy) => {
    let current = url
    for (let hop = 0; hop < 5; hop += 1) {
      const answer = await once(new URL(current), proxy)
      if (answer.redirect !== undefined) {
        current = answer.redirect
        continue
      }
      return answer.body
    }
    throw new Error('the subscription redirected too many times')
  }

  try {
    return await walk(undefined)
  } catch (error) {
    if (via === undefined) throw error
    try {
      return await walk(via)
    } catch (retry) {
      throw new Error(`${error.message} (and through ${via.host}:${via.port}: ${retry.message})`)
    }
  }
}
