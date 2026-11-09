/**
 * Browser-half test: load the hand-written bundle the way the client module loader does, check the
 * module contract, and render both registered components so a broken element tree fails here
 * instead of in the panel.
 *
 * Run: node tests/client.mjs
 */
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

const profileRequire = createRequire('C:/Users/Laptop/.dsh/profiles/web/noop.cjs')
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
