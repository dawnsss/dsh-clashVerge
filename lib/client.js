/**
 * dsh-clash-verge, browser half.
 *
 * A left-sidebar panel shaped like Clash Verge's own: the presets on top, live throughput in the
 * middle, and the traffic report underneath. It holds no state of its own — every number comes from
 * the host's `/clash-verge/api/state`, which is the process that actually routes and counts.
 *
 * Delivered as a hand-written bundle (the loader contract is the `__ModuleLoader__.load` wrapper and
 * a CommonJS `module.exports`), so the package needs no client build step.
 *
 * @module dsh-clash-verge/client
 */

window.__ModuleLoader__.load({
  id: 'dsh-clash-verge',
  factory: (require) => {
    const module = { exports: {} }
    const exports = module.exports

    const React = require('react')
    const h = React.createElement
    const PANEL_ID = 'clash-verge'

    const C = {
      text: 'var(--dsw-alias-label-primary, #e6e6e6)',
      text2: 'var(--dsw-alias-label-secondary, #a8a8a8)',
      text3: 'var(--dsw-alias-label-tertiary, #7a7a7a)',
      border: 'var(--dsw-alias-border-l2, #2f2f2f)',
      borderStrong: 'var(--dsw-alias-border-l3, #3d3d3d)',
      bg: 'var(--dsw-alias-bg-base, transparent)',
      card: 'var(--dsw-alias-bg-layer-1, rgba(255,255,255,0.03))',
      card2: 'var(--dsw-alias-bg-layer-2, rgba(255,255,255,0.06))',
      brand: 'var(--dsw-alias-state-business-primary, #4f8cff)',
      up: 'var(--dsw-alias-state-warn-primary, #f0a92b)',
      down: 'var(--dsw-alias-state-success-primary, #35c78a)',
      bad: 'var(--dsw-alias-state-error-primary, #ef5b5b)',
    }

    function formatBytes(bytes) {
      const value = Number(bytes) || 0
      if (value < 1024) return value + ' B'
      const units = ['KB', 'MB', 'GB', 'TB']
      let size = value / 1024
      let unit = 0
      while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1 }
      return size.toFixed(size >= 100 ? 0 : size >= 10 ? 1 : 2) + ' ' + units[unit]
    }

    function formatRate(bytesPerSecond) {
      const value = Number(bytesPerSecond) || 0
      return value < 1024 ? value + ' B/s' : formatBytes(value) + '/s'
    }

    function ago(timestamp) {
      if (!timestamp) return '—'
      const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000))
      if (seconds < 1) return '刚刚'
      if (seconds < 60) return seconds + ' 秒前'
      if (seconds < 3600) return Math.round(seconds / 60) + ' 分钟前'
      return Math.round(seconds / 3600) + ' 小时前'
    }

    const CARD = {
      border: '1px solid ' + C.border,
      borderRadius: 10,
      background: C.card,
      padding: '12px 14px',
    }

    const CARD_TITLE = { fontSize: 12, color: C.text3, letterSpacing: '0.04em', marginBottom: 10 }

    function Stat(props) {
      return h('div', { style: { ...CARD, flex: '1 1 0', minWidth: 132 } },
        h('div', { style: { fontSize: 11, color: C.text3, marginBottom: 6 } }, props.label),
        h('div', { style: { fontSize: 19, fontWeight: 600, fontVariantNumeric: 'tabular-nums' } }, props.value),
        props.hint ? h('div', { style: { fontSize: 11, color: C.text3, marginTop: 4 } }, props.hint) : null,
      )
    }

    function ModeCard(props) {
      const active = props.active
      return h('button', {
        type: 'button',
        onClick: props.onClick,
        disabled: props.busy,
        title: props.mode.summary,
        style: {
          flex: '1 1 0',
          minWidth: 150,
          textAlign: 'left',
          cursor: props.busy ? 'progress' : 'pointer',
          border: '1px solid ' + (active ? C.brand : C.border),
          background: active ? 'var(--dsw-alias-interactive-bg-hover, rgba(79,140,255,0.12))' : C.card,
          borderRadius: 10,
          padding: '12px 14px',
          color: C.text,
          outline: 'none',
          transition: 'border-color 120ms ease, background 120ms ease',
        },
      },
      h('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 } },
        h('span', { style: { fontSize: 14, fontWeight: 600 } }, props.mode.title),
        h('span', { style: { fontSize: 10, color: active ? C.brand : C.text3, letterSpacing: '0.06em' } }, props.mode.subtitle),
      ),
      h('div', { style: { fontSize: 11, lineHeight: 1.5, color: C.text3, marginTop: 6 } }, props.mode.summary),
      )
    }

    function Sparkline(props) {
      const buckets = props.buckets || []
      const width = 600
      const height = 84
      const pad = 2
      const values = buckets.map(bucket => (bucket.up || 0) + (bucket.down || 0))
      const peak = Math.max(1, ...values)
      const step = values.length > 1 ? (width - pad * 2) / (values.length - 1) : 0
      const pointsFor = (pick) => buckets.map((bucket, index) => {
        const value = pick(bucket)
        const x = pad + index * step
        const y = height - pad - (value / peak) * (height - pad * 2)
        return x.toFixed(2) + ',' + y.toFixed(2)
      }).join(' ')
      const down = pointsFor(bucket => bucket.down || 0)
      const up = pointsFor(bucket => bucket.up || 0)
      const area = down === ''
        ? ''
        : pad.toFixed(2) + ',' + (height - pad) + ' ' + down + ' ' + (pad + (buckets.length - 1) * step).toFixed(2) + ',' + (height - pad)
      return h('div', null,
        h('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: 11, color: C.text3, marginBottom: 8 } },
          h('span', { style: CARD_TITLE }, '最近 ' + buckets.length + ' 秒吞吐'),
          h('span', null,
            h('span', { style: { color: C.down } }, '■ 下行 '),
            h('span', { style: { color: C.up, marginLeft: 10 } }, '■ 上行 '),
            h('span', { style: { marginLeft: 10 } }, '峰值 ' + formatRate(peak) + '/s'),
          ),
        ),
        h('svg', { viewBox: '0 0 ' + width + ' ' + height, preserveAspectRatio: 'none', style: { width: '100%', height: 84, display: 'block' } },
          h('line', { x1: 0, y1: height - pad, x2: width, y2: height - pad, stroke: C.border, strokeWidth: 1 }),
          area === '' ? null : h('polygon', { points: area, fill: C.down, opacity: 0.14 }),
          h('polyline', { points: down, fill: 'none', stroke: C.down, strokeWidth: 1.5, vectorEffect: 'non-scaling-stroke' }),
          h('polyline', { points: up, fill: 'none', stroke: C.up, strokeWidth: 1.5, vectorEffect: 'non-scaling-stroke' }),
        ),
      )
    }

    function SplitBar(props) {
      const rows = props.rows || []
      const total = rows.reduce((sum, row) => sum + row.value, 0)
      return h('div', { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
        rows.map(row => {
          const share = total > 0 ? row.value / total : 0
          return h('div', { key: row.label },
            h('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: 11, color: C.text2, marginBottom: 4 } },
              h('span', null, row.label),
              h('span', { style: { fontVariantNumeric: 'tabular-nums' } }, formatBytes(row.value) + ' · ' + Math.round(share * 100) + '%'),
            ),
            h('div', { style: { height: 6, borderRadius: 3, background: C.card2, overflow: 'hidden' } },
              h('div', { style: { width: Math.max(share * 100, share > 0 ? 2 : 0) + '%', height: '100%', background: row.color || C.brand, borderRadius: 3 } }),
            ),
          )
        }),
      )
    }

    function HostTable(props) {
      const hosts = props.hosts || []
      const headStyle = { fontSize: 11, color: C.text3, textAlign: 'left', padding: '4px 8px', fontWeight: 500 }
      const cellStyle = { fontSize: 12, padding: '6px 8px', borderTop: '1px solid ' + C.border, fontVariantNumeric: 'tabular-nums' }
      if (hosts.length === 0) {
        return h('div', { style: { fontSize: 12, color: C.text3, padding: '10px 0' } }, '还没有流量经过本地代理。')
      }
      return h('table', { style: { width: '100%', borderCollapse: 'collapse' } },
        h('thead', null,
          h('tr', null,
            h('th', { style: headStyle }, '目标'),
            h('th', { style: { ...headStyle, textAlign: 'right' } }, '下行'),
            h('th', { style: { ...headStyle, textAlign: 'right' } }, '上行'),
            h('th', { style: { ...headStyle, textAlign: 'right' } }, '请求'),
            h('th', { style: headStyle }, '路由'),
            h('th', { style: { ...headStyle, textAlign: 'right' } }, '最近'),
          ),
        ),
        h('tbody', null,
          hosts.map(host => h('tr', { key: host.host },
            h('td', { style: { ...cellStyle, maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }, title: host.host }, host.host),
            h('td', { style: { ...cellStyle, textAlign: 'right', color: C.down } }, formatBytes(host.down)),
            h('td', { style: { ...cellStyle, textAlign: 'right', color: C.up } }, formatBytes(host.up)),
            h('td', { style: { ...cellStyle, textAlign: 'right', color: C.text2 } }, String(host.req)),
            h('td', { style: cellStyle },
              h('span', {
                style: {
                  fontSize: 10,
                  padding: '1px 6px',
                  borderRadius: 999,
                  border: '1px solid ' + (host.route === 'upstream' ? C.brand : C.border),
                  color: host.route === 'upstream' ? C.brand : C.text3,
                },
              }, host.route === 'upstream' ? '上游' : host.route === 'blocked' ? '失败关闭' : '直连'),
            ),
            h('td', { style: { ...cellStyle, textAlign: 'right', color: C.text3 } }, ago(host.last)),
          )),
        ),
      )
    }

    function Pill(props) {
      return h('span', {
        style: {
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          fontSize: 11,
          padding: '3px 9px',
          borderRadius: 999,
          border: '1px solid ' + (props.bad ? C.bad : props.accent ? C.brand : C.border),
          color: props.bad ? C.bad : props.accent ? C.brand : C.text2,
          background: C.card,
        },
      },
      h('span', { style: { width: 6, height: 6, borderRadius: 3, background: props.bad ? C.bad : props.accent ? C.brand : C.text3 } }),
      props.children,
      )
    }

    function NodeTable(props) {
      if (props.nodes.length === 0) {
        return h('div', { style: { fontSize: 12, color: C.text3, padding: '6px 0' } },
          '还没有节点。填一个订阅地址，Clash 配置、base64、或一行一个的 URI 都能读。')
      }
      const rowStyle = { display: 'grid', gridTemplateColumns: '18px minmax(0, 1fr) 62px 74px 58px', gap: 8, alignItems: 'center', fontSize: 12, padding: '5px 6px', borderRadius: 6 }
      const healthy = (node) => node.ok ? { color: C.down } : { color: C.bad }
      const line = (key, active, onClick, name, type, latency, ok) => h('div', {
        key,
        onClick,
        style: {
          ...rowStyle,
          cursor: onClick === undefined ? 'default' : 'pointer',
          background: active ? C.card2 : 'transparent',
          outline: active ? '1px solid ' + C.brand : 'none',
        },
      },
        h('div', { style: { color: active ? C.brand : C.text3 } }, active ? '●' : '○'),
        h('div', { style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }, title: name }, name),
        h('div', { style: { color: C.text3 } }, type),
        h('div', { style: { ...healthy({ ok }), textAlign: 'right', fontVariantNumeric: 'tabular-nums' } }, ok ? latency + ' ms' : '—'),
        h('div', { style: { color: C.text3, textAlign: 'right' } }, ok ? '在线' : '不可达'),
      )
      return h('div', { style: { display: 'flex', flexDirection: 'column', gap: 2 } },
        line('manual', props.selected === '', props.onSelect === undefined ? undefined : () => props.onSelect(''),
          '手动上游（用下面填的地址）', '—', 0, true),
        line('auto', props.selected === 'auto', props.onSelect === undefined ? undefined : () => props.onSelect('auto'),
          '自动：最快的在线节点', 'auto', 0, true),
        props.nodes.map(node => line(node.id, props.selected === node.id,
          props.onSelect === undefined ? undefined : () => props.onSelect(node.id),
          node.name, node.type, node.latencyMs, node.ok)),
      )
    }

    function EgressPanel() {
      const [view, setView] = React.useState(null)
      const [error, setError] = React.useState('')
      const [busy, setBusy] = React.useState('')
      const [upstreamDraft, setUpstreamDraft] = React.useState('')
      const [draftTouched, setDraftTouched] = React.useState(false)
      const [subDraft, setSubDraft] = React.useState('')
      const [subTouched, setSubTouched] = React.useState(false)
      // The host half mints a token per process and only answers same-origin reads, so a cross-site
      // page can never learn it. Every mutation echoes it back.
      const tokenRef = React.useRef('')

      const call = React.useCallback(async (action, body) => {
        const headers = body === undefined
          ? { accept: 'application/json' }
          : { 'content-type': 'application/json', 'x-clash-verge-token': tokenRef.current }
        const response = await fetch('/clash-verge/api/' + action, body === undefined
          ? { method: 'GET', headers }
          : { method: 'POST', headers, body: JSON.stringify(body) })
        const payload = await response.json().catch(() => ({ ok: false, error: 'invalid response' }))
        if (typeof payload.token === 'string' && payload.token !== '') tokenRef.current = payload.token
        if (!response.ok || payload.ok === false) throw new Error(payload.error || ('HTTP ' + response.status))
        return payload
      }, [])

      React.useEffect(() => {
        let alive = true
        const load = async () => {
          try {
            const payload = await call('state')
            if (!alive) return
            setView(payload)
            setError('')
            if (!draftTouched) setUpstreamDraft(payload.upstream.configured || '')
            if (!subTouched) setSubDraft((payload.subscription || {}).url || '')
          } catch (cause) {
            if (alive) setError(String(cause.message || cause))
          }
        }
        void load()
        const timer = setInterval(load, 1500)
        return () => { alive = false; clearInterval(timer) }
      }, [call, draftTouched, subTouched])

      const run = async (tag, action, body) => {
        setBusy(tag)
        try {
          const payload = await call(action, body)
          setView(payload)
          setError('')
        } catch (cause) {
          setError(String(cause.message || cause))
        } finally {
          setBusy('')
        }
      }

      if (view === null) {
        return h('div', { style: { padding: 24, color: C.text3, fontSize: 13 } }, error || '正在连接出口代理…')
      }

      const stats = view.stats
      const totals = stats.totals
      const modeRows = [
        { label: '上游代理', value: (stats.byRoute.upstream || {}).down + (stats.byRoute.upstream || {}).up || 0, color: C.brand },
        { label: '直连', value: (stats.byRoute.direct || {}).down + (stats.byRoute.direct || {}).up || 0, color: C.down },
      ]
      const activeMode = view.modes.find(mode => mode.id === view.mode) || view.modes[0]

      return h('div', { style: { height: '100%', overflowY: 'auto', background: C.bg, color: C.text, padding: '20px 24px 32px', fontFamily: 'var(--dsw-font-family, system-ui)', display: 'flex', flexDirection: 'column', gap: 16 } },
        // Header
        h('div', { style: { display: 'flex', flexWrap: 'wrap', alignItems: 'flex-end', gap: 12, justifyContent: 'space-between' } },
          h('div', null,
            h('div', { style: { fontSize: 17, fontWeight: 600, letterSpacing: '0.01em' } }, '出口模式'),
            h('div', { style: { fontSize: 12, color: C.text3, marginTop: 4 } }, '本机回环统计代理 · DSH 自身出网路由'),
          ),
          h('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 8 } },
            h(Pill, { accent: view.proxy.installed, bad: view.proxy.envOnly }, view.proxy.installed
              ? '已接管 ' + view.proxy.url
              : view.proxy.envOnly ? '仅子进程 ' + view.proxy.url : '未接管'),
            h(Pill, { bad: !view.upstream.reachable, accent: view.upstream.reachable }, view.upstream.url || '无上游'),
            view.fallback.count > 0
              ? h(Pill, { bad: false }, '降级直连 ' + view.fallback.count + ' 次')
              : null,
            view.blocked && view.blocked.count > 0
              ? h(Pill, { bad: true }, '失败关闭 ' + view.blocked.count + ' 次')
              : null,
          ),
        ),

        error === ''
          ? null
          : h('div', { style: { ...CARD, borderColor: C.bad, color: C.bad, fontSize: 12 } }, error),

        // Presets
        h('div', { style: { display: 'flex', gap: 10, flexWrap: 'wrap' } },
          view.modes.map(mode => h(ModeCard, {
            key: mode.id,
            mode,
            active: mode.id === view.mode,
            busy: busy === 'mode',
            onClick: () => { if (mode.id !== view.mode) void run('mode', 'mode', { mode: mode.id }) },
          })),
        ),

        // Live numbers
        h('div', { style: { display: 'flex', gap: 10, flexWrap: 'wrap' } },
          h(Stat, { label: '实时下行', value: formatRate(stats.rate.down), hint: '近 5 秒均值' }),
          h(Stat, { label: '实时上行', value: formatRate(stats.rate.up), hint: '近 5 秒均值' }),
          h(Stat, { label: '累计下行', value: formatBytes(totals.down), hint: '自 ' + ago(stats.startedAt) + ' 起' }),
          h(Stat, { label: '累计上行', value: formatBytes(totals.up), hint: totals.req + ' 个请求' }),
          h(Stat, {
            label: '活动连接',
            value: String(stats.connections.live),
            hint: '累计 ' + stats.connections.total + ' 条',
          }),
        ),

        // Chart
        h('div', CARD, h(Sparkline, { buckets: stats.buckets })),

        // Split + routes
        h('div', { style: { display: 'flex', gap: 10, flexWrap: 'wrap' } },
          h('div', { style: { ...CARD, flex: '2 1 320px' } },
            h('div', { style: CARD_TITLE }, '流量去向'),
            h(SplitBar, { rows: modeRows }),
          ),
          h('div', { style: { ...CARD, flex: '1 1 220px' } },
            h('div', { style: CARD_TITLE }, '模式分布'),
            h(SplitBar, {
              rows: view.modes.map((mode, index) => ({
                label: mode.title,
                value: ((stats.byMode[mode.id] || {}).down || 0) + ((stats.byMode[mode.id] || {}).up || 0),
                color: [C.text3, C.text2, C.brand, C.up][index] || C.brand,
              })),
            }),
          ),
        ),

        // Hosts
        h('div', CARD,
          h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 } },
            h('div', { style: CARD_TITLE }, '目标主机 Top 20'),
            h('button', {
              type: 'button',
              onClick: () => void run('reset', 'reset', {}),
              disabled: busy !== '',
              style: { fontSize: 11, color: C.text2, background: 'transparent', border: '1px solid ' + C.border, borderRadius: 6, padding: '3px 9px', cursor: 'pointer' },
            }, busy === 'reset' ? '清零中…' : '清零统计'),
          ),
          h(HostTable, { hosts: stats.hosts }),
        ),

        // Nodes and subscription
        h('div', CARD,
          h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8, flexWrap: 'wrap', gap: 8 } },
            h('div', { style: CARD_TITLE }, '节点与订阅'),
            h('div', { style: { display: 'flex', gap: 8 } },
              h('button', {
                type: 'button',
                disabled: busy !== '' || view.nodes.length === 0,
                onClick: () => void run('nodes', 'nodes/probe', {}),
                style: { fontSize: 11, color: C.text2, background: 'transparent', border: '1px solid ' + C.border, borderRadius: 6, padding: '3px 9px', cursor: 'pointer' },
              }, busy === 'nodes' ? '测速中…' : '节点测速'),
              h('button', {
                type: 'button',
                disabled: busy !== '' || view.nodes.length === 0 || view.selected === 'auto',
                onClick: () => void run('auto', 'node', { id: 'auto' }),
                style: { fontSize: 11, color: C.text2, background: 'transparent', border: '1px solid ' + C.border, borderRadius: 6, padding: '3px 9px', cursor: 'pointer' },
              }, '自动选最快'),
            ),
          ),
          h('div', { style: { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10, flexWrap: 'wrap' } },
            h('input', {
              value: subDraft,
              placeholder: '订阅地址：https://…/sub（Clash 配置 / base64 / URI 列表）',
              onChange: (event) => { setSubTouched(true); setSubDraft(event.target.value) },
              style: {
                flex: '1 1 260px',
                minWidth: 200,
                background: C.card2,
                color: C.text,
                border: '1px solid ' + C.border,
                borderRadius: 6,
                padding: '6px 9px',
                fontSize: 12,
                outline: 'none',
              },
            }),
            h('button', {
              type: 'button',
              disabled: busy !== '',
              onClick: () => void run('sub', 'subscription', { url: subDraft }).then(() => setSubTouched(false)),
              style: { fontSize: 12, color: '#fff', background: C.brand, border: 'none', borderRadius: 6, padding: '6px 12px', cursor: 'pointer' },
            }, busy === 'sub' ? '拉取中…' : '拉取订阅'),
            view.subscription.url === ''
              ? null
              : h('button', {
                type: 'button',
                disabled: busy !== '',
                onClick: () => void run('clear', 'subscription', { url: '' }).then(() => { setSubDraft(''); setSubTouched(false) }),
                style: { fontSize: 12, color: C.text2, background: 'transparent', border: '1px solid ' + C.border, borderRadius: 6, padding: '6px 12px', cursor: 'pointer' },
              }, '清除节点'),
          ),
          h(NodeTable, {
            nodes: view.nodes,
            selected: view.selected,
            onSelect: busy === '' ? (id) => void run('node', 'node', { id }) : undefined,
          }),
          h('div', { style: { fontSize: 11, color: C.text3, marginTop: 8, lineHeight: 1.6 } },
            view.subscription.url === ''
              ? '订阅是可选的：不填就用手动上游。拉取会先直连，不通再经本机代理重试。'
              : view.subscription.count + ' 个可用节点 · ' + ago(view.subscription.updatedAt) + ' 拉取'
                + (view.subscription.skipped.length > 0
                  ? ' · ' + view.subscription.skipped.length + ' 个读不了（' + view.subscription.skipped.slice(0, 3).map(entry => entry.reason).join('；') + '）'
                  : ''),
          ),
        ),

        // Footer: upstream + probe
        h('div', { style: { ...CARD, display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' } },
          h('div', { style: { fontSize: 12, color: C.text2 } }, '上游代理'),
          h('input', {
            value: upstreamDraft,
            placeholder: 'http://127.0.0.1:' + view.upstream.detectedPort + ' 或 socks5://127.0.0.1:1080',
            onChange: (event) => { setDraftTouched(true); setUpstreamDraft(event.target.value) },
            style: {
              flex: '1 1 220px',
              minWidth: 180,
              background: C.card2,
              color: C.text,
              border: '1px solid ' + C.border,
              borderRadius: 6,
              padding: '6px 9px',
              fontSize: 12,
              outline: 'none',
            },
          }),
          h('button', {
            type: 'button',
            disabled: busy !== '',
            onClick: () => void run('config', 'config', { upstream: upstreamDraft }).then(() => setDraftTouched(false)),
            style: { fontSize: 12, color: '#fff', background: C.brand, border: 'none', borderRadius: 6, padding: '6px 12px', cursor: 'pointer' },
          }, busy === 'config' ? '保存中…' : '保存'),
          h('button', {
            type: 'button',
            disabled: busy !== '',
            onClick: () => void run('probe', 'probe', {}),
            style: { fontSize: 12, color: C.text2, background: 'transparent', border: '1px solid ' + C.border, borderRadius: 6, padding: '6px 12px', cursor: 'pointer' },
          }, busy === 'probe' ? '探测中…' : '探测上游'),
          h('div', { style: { flexBasis: '100%', fontSize: 11, color: C.text3 } },
            (view.upstream.configured === ''
              ? '自动探测本机代理端口 ' + view.upstream.detectedPort + '（来自 ' + view.upstream.detectedSource + '）'
              : (view.upstream.protocol || 'http') + ' 上游 · 探测端口 ' + view.upstream.detectedPort)
            + ' · 探测于 ' + ago(view.upstream.checkedAt)
            + (view.upstream.error ? ' · ' + view.upstream.error : ''),
          ),
        ),
      )
    }

    const PanelIcon = (props) => h('svg', {
      width: props.size || 18,
      height: props.size || 18,
      viewBox: '0 0 24 24',
      fill: 'none',
      stroke: 'currentColor',
      strokeWidth: 1.6,
      strokeLinecap: 'round',
      strokeLinejoin: 'round',
      style: { opacity: props.active ? 1 : 0.82 },
    },
    h('rect', { x: 2.5, y: 4.5, width: 19, height: 15, rx: 2.5 }),
    h('path', { d: 'M6 15.5l3.2-3.6 2.6 2.3 3-4.2 3.2 4.4' }),
    )

    function apply(ctx) {
      // The sidebar entry and the panel it opens are one registration each: `main` is the page
      // (keyed by the same id the sidebar list addresses), `sidebar.panellist` is the row that
      // selects it.
      ctx.slots.inject('main', function* () {
        yield ctx.slots.register({ name: 'main', key: PANEL_ID }, EgressPanel)
      })
      ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({
        name: 'sidebar.panellist',
        id: PANEL_ID,
        order: 30,
        label: () => '出口模式',
      }, PanelIcon))
    }

    exports.name = 'clash-verge'
    exports.inject = ['slots']
    exports.apply = apply
    return module.exports
  },
})
