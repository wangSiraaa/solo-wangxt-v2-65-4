import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'

// lifecycle -> label / tone
const STATUS = {
  draft: ['草稿', ''], pending: ['待批准', 'warn'],
  scheduled: ['已计划', ''], active: ['已生效', 'ok'],
  expired: ['已过期', 'muted'], revoked: ['已撤销', 'bad'],
}

function fmt(iso) {
  if (!iso) return '—'
  return iso.replace('+00:00', 'Z').slice(0, 19)
}

function Tag({ s }) {
  const [label, tone] = STATUS[s] || [s, '']
  return <span className={`tag ${tone}`}>{label}</span>
}

const EMPTY_FORM = {
  name: '', action: 'permit', priority: 100,
  start_at: '', end_at: '', reason: '',
  matchesText: '192.168.100.0/24',
}

export default function ExceptionsLab({ policy, onChange }) {
  const [baseline, setBaseline] = useState(null)
  const [exceptions, setExceptions] = useState([])
  const [timeline, setTimeline] = useState(null)
  const [effective, setEffective] = useState(null)
  const [selected, setSelected] = useState(null)
  const [history, setHistory] = useState([])
  const [preview, setPreview] = useState(null)
  const [form, setForm] = useState(EMPTY_FORM)
  const [probe, setProbe] = useState('192.168.100.0/24')
  const [hit, setHit] = useState(null)
  const [cv, setCv] = useState(null)
  const [node, setNode] = useState('a')
  const [clockState, setClockState] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function refresh(keepSelected = true) {
    setErr('')
    try {
      const [b, xs2, tl, eff, clk] = await Promise.all([
        api.getBaseline(policy.id),
        api.listExceptions(policy.id),
        api.timeline(policy.id),
        api.effective(policy.id),
        api.clock(),
      ])
      setBaseline(b)
      setExceptions(xs2)
      setTimeline(tl)
      setEffective(eff)
      setClockState(clk)
      if (keepSelected && selected) {
        const fresh = xs2.find((x) => x.id === selected.id)
        if (fresh) await selectException(fresh)
      }
    } catch (e) { setErr(e.message) }
  }

  useEffect(() => { refresh(false) }, [policy.id])

  async function selectException(ex) {
    setSelected(ex)
    setPreview(null); setHit(null)
    try {
      const [h, pv] = await Promise.all([
        api.exHistory(ex.id),
        api.exPreview(ex.id).catch(() => null),
      ])
      setHistory(h); setPreview(pv)
    } catch (e) { setErr(e.message) }
  }

  async function createException() {
    setErr('')
    const matches = form.matchesText.split(/[\n,;\s]+/).filter(Boolean)
      .map((p) => ({ prefix: p }))
    try {
      const ex = await api.createException(policy.id, {
        name: form.name || `window-${Date.now()}`,
        action: form.action, priority: Number(form.priority) || 100,
        start_at: new Date(form.start_at).toISOString(),
        end_at: new Date(form.end_at).toISOString(),
        reason: form.reason, matches, requested_by: 'web',
      })
      setForm(EMPTY_FORM)
      await refresh(false)
      selectException(ex)
    } catch (e) { setErr(e.message) }
  }

  async function act(ex, action, body = {}) {
    setErr(''); setBusy(true)
    try {
      const fresh = await api.exAction(ex.id, action, body)
      await refresh()
      return fresh
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  async function publishBaseline() {
    setErr('')
    if (!confirm('冻结当前规则为新基线？所有未生效例外将进入“待复核”。')) return
    try {
      await api.publishBaseline(policy.id, `v${(baseline?.version || 0) + 1}`, 'web')
      await refresh()
      onChange?.()
    } catch (e) { setErr(e.message) }
  }

  async function classifyProbe() {
    setErr(''); setHit(null)
    try { setHit(await api.effectiveClassify(policy.id, probe)) }
    catch (e) { setErr(e.message) }
  }

  async function crossValidate() {
    setErr(''); setCv(null)
    const probes = effective?.witnesses?.map((w) => w.prefix) || []
    try {
      setCv(await api.effectiveCrossValidate(policy.id, probes, node))
    } catch (e) { setErr(e.message) }
  }

  async function advance(seconds) {
    setErr('')
    try {
      await api.clockAdvance(seconds)
      await refresh()
    } catch (e) { setErr(e.message) }
  }
  async function freezeHere() {
    try { await api.clockFreeze(); await refresh() } catch (e) { setErr(e.message) }
  }
  async function resetClock() {
    try { await api.clockReset(); await refresh() } catch (e) { setErr(e.message) }
  }

  const hasBaseline = baseline && baseline.id
  const now = clockState?.now

  return (
    <div className="exceptions">
      <div className="bar">
        <strong>时效策略例外</strong>
        <span className="muted">
          当前基线：{hasBaseline
            ? <>快照 <code>v{baseline.version} ({baseline.label}) #{baseline.id}</code></>
            : <span className="error">未发布</span>}
        </span>
        <button className="small primary" onClick={publishBaseline}>
          📌 发布当前规则为新基线
        </button>
        <span className="muted">|</span>
        <span className="muted">时钟：{clockState?.mode === 'fixed' ? '固定（实验室）' : '系统'} {now ? fmt(now) : ''}</span>
        <button className="mini" onClick={freezeHere}>冻结到现在</button>
        <button className="mini" onClick={() => advance(3600)}>前进 1h</button>
        <button className="mini" onClick={() => advance(-3600)}>后退 1h</button>
        <button className="mini" onClick={resetClock}>恢复系统时钟</button>
        {err && <span className="error">{err}</span>}
      </div>

      <div className="cols">
        {/* left: create + list */}
        <div style={{ minWidth: 380, maxWidth: 430 }}>
          <div className="analysis">
            <h4>新建例外（草稿）</h4>
            <table className="rules">
              <tbody>
                <tr><td>名称</td><td><input value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="维护窗口-A" /></td></tr>
                <tr><td>动作</td><td>
                  <select value={form.action}
                    onChange={(e) => setForm({ ...form, action: e.target.value })}>
                    <option value="permit">临时放行 permit</option>
                    <option value="deny">临时拒绝 deny</option>
                  </select>
                </td></tr>
                <tr><td>优先级</td><td><input type="number" value={form.priority}
                  onChange={(e) => setForm({ ...form, priority: e.target.value })} />
                  <span className="muted"> 数字小者优先</span></td></tr>
                <tr><td>开始(UTC)</td><td><input type="datetime-local"
                  value={form.start_at}
                  onChange={(e) => setForm({ ...form, start_at: e.target.value })} /></td></tr>
                <tr><td>结束(UTC)</td><td><input type="datetime-local"
                  value={form.end_at}
                  onChange={(e) => setForm({ ...form, end_at: e.target.value })} /></td></tr>
                <tr><td>匹配范围</td><td>
                  <textarea rows={3} value={form.matchesText}
                    onChange={(e) => setForm({ ...form, matchesText: e.target.value })} />
                  <span className="muted">每行一个前缀，可含 ge/le（如 10/8 le 24）</span>
                </td></tr>
                <tr><td>理由</td><td><input value={form.reason}
                  onChange={(e) => setForm({ ...form, reason: e.target.value })} /></td></tr>
              </tbody>
            </table>
            <button className="primary" onClick={createException} disabled={!hasBaseline || busy}>
              创建草稿
            </button>
          </div>

          <h4>例外列表（{exceptions.length}）</h4>
          <table className="cv">
            <thead><tr><th></th><th>名称</th><th>动作</th><th>状态</th><th>窗口(UTC)</th></tr></thead>
            <tbody>
              {exceptions.map((x) => (
                <tr key={x.id}
                  className={selected?.id === x.id ? 'okrow' : ''}
                  style={{ cursor: 'pointer' }}
                  onClick={() => selectException(x)}>
                  <td>#{x.id}{x.needs_review && <span className="tag warn" title="基线已更新，需重新复核">待复核</span>}</td>
                  <td>{x.name}<div className="muted">p{x.priority} · 快照#{x.snapshot_id}</div></td>
                  <td className={x.action}>{x.action}</td>
                  <td><Tag s={x.status} />
                    {x.projected_status !== x.status &&
                      <div className="muted">（按时钟将为 {STATUS[x.projected_status]?.[0]}）</div>}
                  </td>
                  <td className="muted" style={{ fontSize: 11 }}>
                    {fmt(x.start_at)}<br />→ {fmt(x.end_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* middle: timeline + selected detail */}
        <div style={{ flex: 1, minWidth: 420 }}>
          {timeline && <Timeline tl={timeline} />}

          {selected ? (
            <div className="analysis">
              <h4>例外 #{selected.id} {selected.name}
                {' '}<Tag s={selected.status} />
                {selected.needs_review && <span className="tag warn">基线已更新 · 待复核</span>}
              </h4>
              <p className="muted" style={{ margin: '4px 0' }}>
                绑定不可变基线快照 <code>#{selected.snapshot_id}</code>
                {!selected.baseline_is_current &&
                  <>；策略当前基线为 <code>#{selected.current_baseline_snapshot_id}</code></>}
                {' '}· IPv{selected.family} · 优先级 {selected.priority}
              </p>
              <p style={{ margin: '4px 0' }}>
                {selected.matches.map((m, i) => (
                  <code key={i} className="chip">{m.prefix}
                    {m.ge ? ` ge ${m.ge}` : ''}{m.le ? ` le ${m.le}` : ''}
                  </code>
                ))}
                <span className={selected.action}> → {selected.action}</span>
              </p>
              <p className="muted" style={{ margin: '4px 0' }}>理由：{selected.reason || '—'} · 申请人 {selected.requested_by}</p>

              <div className="bar">
                {selected.status === 'draft' &&
                  <button onClick={() => act(selected, 'submit', { actor: 'web' })}>提交批准</button>}
                {selected.status === 'pending' && !selected.needs_review &&
                  <button className="primary"
                    onClick={() => act(selected, 'approve', { approver: 'web-approver' })}>
                    批准
                  </button>}
                {selected.needs_review &&
                    (selected.status === 'pending' || selected.status === 'scheduled') &&
                  <button className="primary"
                    title="按当前基线重新预览并确认，旧基线快照不被修改"
                    onClick={() => act(selected, 'review', { reviewer: 'web-reviewer' })}>
                    🔍 按当前基线重新预览并确认
                  </button>}
                {!['expired', 'revoked'].includes(selected.status) &&
                  <button className="mini danger"
                    onClick={() => act(selected, 'revoke', { actor: 'web', reason: 'UI 撤销' })}>
                    撤销
                  </button>}
                {selected.status === 'scheduled' &&
                  <button className="mini" onClick={() => act(selected, 'activate')}>立即激活（补跑）</button>}
                {['scheduled', 'active'].includes(selected.status) &&
                  <button className="mini" onClick={() => act(selected, 'expire')}>立即过期（补跑）</button>}
              </div>

              {preview && <Preview pv={preview} />}

              <h4>状态历史（{history.length}）</h4>
              <table className="cv">
                <thead><tr><th>#</th><th>事件</th><th>操作者</th><th>发生时刻(UTC)</th><th>记录时刻</th><th>详情</th></tr></thead>
                <tbody>
                  {history.map((h) => (
                    <tr key={h.id}>
                      <td>{h.id}</td>
                      <td><code>{h.event_type}</code></td>
                      <td>{h.actor}</td>
                      <td>{fmt(h.occurred_at)}</td>
                      <td className="muted">{fmt(h.recorded_at)}</td>
                      <td className="muted" style={{ fontSize: 11 }}>
                        {Object.entries(h.detail || {}).map(([k, v]) => `${k}=${v}`).join(' ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="muted">← 选择一个例外查看语义预览、审批操作与完整状态历史</p>}
        </div>

        {/* right: current synthesized policy */}
        <div style={{ minWidth: 380, maxWidth: 480 }}>
          <div className="analysis">
            <h4>当前合成配置（基线 + 生效中例外）</h4>
            <p className="muted">
              {effective?.active_exceptions?.length
                ? <>生效例外：{effective.active_exceptions
                    .map((x) => `#${x.id} ${x.name}`).join('，')}</>
                : '当前无生效例外，行为等于基线'}
            </p>
            <pre style={{ fontSize: 11, maxHeight: 220, overflow: 'auto' }}>
              {effective?.frr_config || '（无基线）'}
            </pre>

            <h4>语义影响（最小见证前缀，非文本 diff）</h4>
            {effective?.witnesses?.length ? (
              <table className="cv">
                <thead><tr><th>见证前缀</th><th>基线→合成</th></tr></thead>
                <tbody>
                  {effective.witnesses.map((w, i) => (
                    <tr key={i}><td><code>{w.prefix}</code></td>
                      <td className={w.new_action}>{w.change}</td></tr>
                  ))}
                </tbody>
              </table>
            ) : <p className="muted">无行为差异（合成结果与基线完全等价）</p>}

            <h4>最终命中链查询</h4>
            <div className="bar">
              <input value={probe} onChange={(e) => setProbe(e.target.value)}
                style={{ minWidth: 200 }} />
              <button className="small" onClick={classifyProbe}>推演</button>
            </div>
            {hit && <HitChain hit={hit} />}

            <h4>仅在本地隔离 FRR 验证当前合成配置</h4>
            <div className="bar">
              <select value={node} onChange={(e) => setNode(e.target.value)}>
                <option value="a">router-a</option>
                <option value="b">router-b</option>
              </select>
              <button className="small primary"
                disabled={!effective?.witnesses?.length}
                title="把合成配置渲染成临时 prefix-list 下发到本地容器，探针比对后删除"
                onClick={crossValidate}>推送 FRR 并比对（见证集）</button>
            </div>
            {cv && (
              <div className={`cvbox ${cv.status}`}>
                {cv.status === 'match'
                  ? <span className="ok">✓ 与 FRR 判定一致（run #{cv.run_id}，验证后已删除临时列表）</span>
                  : <span className="error">
                      {cv.setup_error || `✗ ${cv.mismatch_count} 处不一致`}</span>}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
function Timeline({ tl }) {
  // horizontal band: exceptions as bars across window positions in a
  // [minStart, maxEnd] time scale; boundaries marked.
  const [lo, hi] = useMemo(() => {
    const starts = tl.exceptions.map((x) => new Date(x.start_at).getTime())
    const ends = tl.exceptions.map((x) => new Date(x.end_at).getTime())
    if (!starts.length) return [0, 1]
    return [Math.min(...starts), Math.max(...ends)]
  }, [tl])
  const span = Math.max(1, hi - lo)
  const pos = (iso) => `${((new Date(iso).getTime() - lo) / span) * 100}%`
  const nowPct = tl.now ? ((new Date(tl.now).getTime() - lo) / span) * 100 : null

  return (
    <div className="analysis">
      <h4>时间线 · 边界时刻的最终命中集合（时钟 now：{fmt(tl.now)}）</h4>
      <div style={{ position: 'relative', height: 26 * Math.max(1, tl.exceptions.length) + 24 }}>
        {tl.exceptions.map((x, i) => {
          const left = pos(x.start_at)
          const width = `calc(${pos(x.end_at)} - ${left})`
          const tone = x.status === 'active' ? '#2f6d4a'
            : x.status === 'expired' ? '#444'
            : x.status === 'revoked' ? '#6d2f2f'
            : x.needs_review ? '#7a6320' : '#2c4a7a'
          return (
            <div key={x.id} style={{
              position: 'absolute', left, width, top: 26 * i + 4,
              height: 18, background: tone, borderRadius: 4,
              opacity: ['draft'].includes(x.status) ? 0.55 : 0.95,
              fontSize: 11, padding: '0 6px', whiteSpace: 'nowrap',
              overflow: 'hidden', color: '#e8f0ff',
              borderLeft: '2px solid #9ec1ff', borderRight: '2px solid #ffb0b0',
            }} title={`${x.name} ${x.start_at} → ${x.end_at} [${x.status}]`}>
              #{x.id} {x.name} · {STATUS[x.status]?.[0]}
              {x.needs_review ? ' · 待复核' : ''}
            </div>
          )
        })}
        {nowPct !== null && nowPct >= 0 && nowPct <= 100 && (
          <div style={{ position: 'absolute', left: `${nowPct}%`, top: 0, bottom: 0,
            borderLeft: '2px solid var(--accent)', zIndex: 5 }}
            title="时钟 now" />
        )}
      </div>
      <table className="cv" style={{ marginTop: 8 }}>
        <thead><tr><th>边界时刻(UTC)</th><th>该时刻生效例外（按优先级顺序）</th></tr></thead>
        <tbody>
          {tl.boundaries.map((b, i) => (
            <tr key={i}>
              <td><code>{fmt(b.at)}</code>{b.at === tl.now && <span className="tag"> now</span>}</td>
              <td>{b.active_exception_ids.length
                ? b.active_exception_ids.map((id) => {
                    const x = tl.exceptions.find((e) => e.id === id)
                    return <span key={id} className={`chip tag ${x.action}`}>
                      #{id} {x.name}</span>
                  })
                : <span className="muted">（仅基线）</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Preview({ pv }) {
  return (
    <div style={{ marginTop: 8 }}>
      <h4>语义影响预览（相对{pv.baseline_is_current ? '当前' : '绑定的旧'}基线 #{pv.baseline_snapshot_id}）</h4>
      {pv.witness_count === 0
        ? <p className="muted">该例外在其范围内不改变最终动作（如基线已 deny 再 deny）；仍是可审计的临时规则。</p>
        : (
          <table className="cv">
            <thead><tr><th>最小见证前缀</th><th>变化</th></tr></thead>
            <tbody>
              {pv.witnesses.map((w, i) => (
                <tr key={i}><td><code>{w.prefix}</code></td>
                  <td className={w.new_action}>{w.change}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      <details>
        <summary className="muted">将下发的合成 FRR 配置（预览，不修改基线）</summary>
        <pre style={{ fontSize: 11 }}>{pv.composed_frr_config}</pre>
      </details>
    </div>
  )
}

function HitChain({ hit }) {
  return (
    <div className={`hitbox ${hit.final_action}`}>
      <div className="hit-head">
        <code>{hit.prefix}</code> → <strong className={hit.final_action}>
          {hit.final_action}</strong>
        <span className="muted"> · 命中层：
          {hit.matched_layer === 'exception' ? '例外'
            : hit.matched_layer === 'baseline' ? '基线' : '隐式默认'}</span>
      </div>
      <table className="chain cv">
        <thead><tr><th>层</th><th>seq</th><th>前缀</th><th>动作</th><th>包含</th><th>窗口</th><th>命中</th></tr></thead>
        <tbody>
          {hit.chain.map((c, i) => (
            <tr key={i} className={c.matched ? 'matched' : c.contained ? 'contained' : ''}>
              <td>{c.layer === 'exception'
                ? <span className="tag ok">例外#{c.owner?.exception_id}</span>
                : c.layer === 'baseline' ? <span className="tag">基线</span>
                  : <span className="tag">默认</span>}</td>
              <td>{c.seq ?? '—'}</td>
              <td><code>{c.prefix}</code></td>
              <td className={c.action}>{c.action}</td>
              <td>{c.contained ? '✓' : '—'}</td>
              <td>{c.length_ok ? '✓' : '—'}</td>
              <td>{c.matched ? '▶' : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
