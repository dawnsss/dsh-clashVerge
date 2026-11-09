/**
 * Browser-half test: load the hand-written bundle the way the client module loader does, check the
 * module contract, and render both registered components so a broken element tree fails here
 * instead of in the panel.
 *
 * Run: node tests/client.mjs
 */
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'

/**
 * Locate a React to render with. The bundle ships no copy of its own — it borrows the host's — so
 * the test needs a DSH profile that has one installed. `DSH_PROFILE_DIR` wins; otherwise every
 * profile under `~/.dsh/profiles` is tried in turn.
 * @returns a `require` rooted in that profile, or undefined when there is no such profile.
 */
function resolveProfileRequire() {
  const candidates = []
  if (process.env.DSH_PROFILE_DIR) candidates.push(path.resolve(process.env.DSH_PROFILE_DIR))
  try {
    const root = path.join(os.homedir(), '.dsh', 'profiles')
    for (const name of fs.readdirSync(root)) candidates.push(path.join(root, name))
  } catch {
    // No profiles yet: the skip below says what to do about it.
  }
  for (const dir of candidates) {
    // Resolve rather than stat a path: pnpm hoists react to a shared node_modules above the
    // profile, so `dir/node_modules/react` usually does not exist even when requiring it works.
    const require = createRequire(path.join(dir, 'noop.cjs'))
    try {
      require.resolve('react')
      require.resolve('react-dom/server')
      return require
    } catch {
      // This profile has no renderer; try the next one.
    }
  }
  return undefined
}

const profileRequire = resolveProfileRequire()
if (profileRequire === undefined) {
  console.log('skip  no DSH profile with react found (set DSH_PROFILE_DIR, or install the plugin into a profile)')
  process.exit(0)
}

const React = profileRequire('react')
const { renderToStaticMarkup } = profileRequire('react-dom/server')

const loaded = []
globalThis.window = {
  __ModuleLoader__: {
    load: (entry) => loaded.push(entry),
  },
}

await import('../lib/client.js')

assert.equal(loaded.length, 1, 'the bundle must register exactly one module')
const entry = loaded[0]
assert.equal(entry.id, 'dsh-clash-verge')
assert.equal(typeof entry.factory, 'function')

const module_ = entry.factory((specifier) => {
  if (specifier === 'react') return React
  throw new Error(`the bundle may only require platform modules, got "${specifier}"`)
})

assert.equal(module_.name, 'clash-verge')
assert.deepEqual(module_.inject, ['slots'])
assert.equal(typeof module_.apply, 'function')

// `slots.inject(name, factory)` runs the factory; a generator registers later, a plain call now.
const injected = []
const registered = []
const ctx = {
  slots: {
    inject(name, factory) {
      injected.push(name)
      const produced = factory()
      if (produced !== null && typeof produced === 'object' && typeof produced[Symbol.iterator] === 'function') {
        for (const _ of produced) { /* the registration already happened inside the yield */ }
      }
    },
    register(options, component) {
      registered.push({ options, component })
      return () => {}
    },
  },
}

module_.apply(ctx)

assert.deepEqual(injected, ['main', 'sidebar.panellist'])
assert.equal(registered.length, 2)

const [panel, icon] = registered
assert.equal(panel.options.name, 'main')
assert.equal(panel.options.key, 'clash-verge', 'the panel key is what the sidebar row addresses')
assert.equal(typeof panel.component, 'function')

assert.equal(icon.options.name, 'sidebar.panellist')
assert.equal(icon.options.id, 'clash-verge')
assert.equal(icon.options.order, 30)
assert.equal(typeof icon.options.label, 'function')
assert.equal(typeof icon.options.label(), 'string')

// The icon is rendered by the sidebar with `{ size, active }`.
const iconMarkup = renderToStaticMarkup(React.createElement(icon.component, { size: 16, active: true }))
assert.match(iconMarkup, /^<svg/)
assert.match(iconMarkup, /width="16"/)

// Before its first poll returns, the panel renders a placeholder; that path must not throw.
const panelMarkup = renderToStaticMarkup(React.createElement(panel.component, {}))
assert.ok(panelMarkup.length > 0)
assert.match(panelMarkup, /正在连接出口代理/)

console.log('ok    bundle contract')
console.log('ok    slot registrations: main + sidebar.panellist')
console.log('ok    icon renders')
console.log('ok    panel renders before its first poll')
console.log('client: ok')
