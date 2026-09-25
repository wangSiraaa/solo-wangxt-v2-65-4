import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'

const STATES = ['draft', 'pending', 'planned', 'active', 'expired', 'revoked', 'rejected']
const STATE_CN = {
  draft: '草稿', pending: '待批准', planned: '已计划', active: '已生效',
  expired: '已过期', revoked: '已撤销', rejected: '已驳回',
}
const STATE_ORDER = { draft: 0, pending: 1, planned: 2, active: 3, expired: 4, revoked: 4, rejected: 1 }

// local datetime <input> value (no tz) -> UTC ISO
function localInputToIso(local) {
  if (!local) return null
  const d = new Date(local)
  return d.toISOString()
}
function isoToLocalInput(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function StatePill({ status, needsReview }) {
  const cls = ['active'].includes(status) ? 'st-active'
    : ['expired', 'revoked'].includes(status) ? 'st-terminal'
    : ['rejected'].includes(status) ? 'st-reject' : 'st-normal'
  return (
    <span className={`statepill ${cls}`}>
      {STATE_CN[status] || status}
      {needsReview && <em className="reviewflag"> · 待复核</em>}
    </span>
  )
}

function Timeline({ events }) {
  const evs = [...(events || [])].sort((a, b) =>
    new Date(a.at_time) - new Date(b.at_time) || a.id - b.id)
  return (
    <div className="timeline">
      {evs.map((e, i) => (
        <div className="tl-item" key={e.id}>
          <div className="tl-dot" />
          {i < evs.length - 1 && <div className="tl-line" />}
          <div className="tl-body">
            <b>{e.event_type}</b>
            {e.from_status && <span className="muted"> {STATE_CN[e.from_status] || e.from_status} → </span>}
            {e.to_status && <b>{STATE_CN[e.to_status] || e.to_status}</b>}
            <div className="muted tl-time">{new Date(e.at_time).toLocaleString()}</div>
            {e.detail && Object.keys(e.detail).length > 0 && (
              <div className="tl-detail">{JSON.stringify(e.detail)}</div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

function WitnessTable({ witnesses }) {
  if (!witnesses || !witnesses.length)
    return <p className="muted">无行为变化区域（例外不改变最终转发结果，或与基线一致）。</p>
  return (
    <table className="cv">
      <thead><tr><th>最小见证前缀</th><th>变化</th><th>旧来源</th><th>新来源</th></tr></thead>
      <tbody>
        {witnesses.map((w, i) => (
          <tr key={i} className={w.change === 'permit->deny' ? 'deny' : 'permit'}>
            <td><code>{w.prefix}</code></td>
            <td>{w.change}</td>
            <td>{sourceLabel(w.old_source, w.old_seq)}</td>
            <td>{sourceLabel(w.new_source, w.new_seq)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function sourceLabel(src, seq) {
  if (!src) return <span className="muted">隐式默认</span>
  if (src.layer === 'exception')
    return <span className="excsrc">例外 {src.name} (P{src.priority})</span>
  return <span className="basesrc">基线 seq {src.seq}</span>
}

function OverlapList({ overlaps }) {
  if (!overlaps || !overlaps.length)
    return <p className="muted">该时间窗内无重叠例外。</p>
  return (
    <table className="cv">
      <thead><tr><th>见证前缀</th><th>胜者</th><th>败者</th><th>冲突</th><th>判定依据</th></tr></thead>
      <tbody>
        {overlaps.map((o, i) => (
          <tr key={i} className={o.conflicting ? 'badrow' : ''}>
            <td><code>{o.prefix}</code></td>
            <td className={o.winner_action}>{o.winner_name} ({o.winner_action})</td>
            <td className={o.loser_action}>{o.loser_name} ({o.loser_action})</td>
            <td>{o.conflicting ? '⚠ 动作冲突' : '动作一致'}</td>
            <td className="muted">{o.resolution}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function HitChain({ hit }) {
  if (!hit) return null
  return (
    <div className={`hitbox ${hit.final_action}`}>
      <div className="hit-head">
        <code>{hit.prefix}</code> → <b className={hit.final_action}>{hit.final_action}</b>
        <span className="muted"> （终局：{hit.terminal === 'exception' ? '例外' : hit.terminal === 'rule' ? '基线规则' : '隐式默认'}）</span>
        {hit.overridden && <span className="tag warn"> 覆盖了基线 {hit.baseline_action}</span>}
      </div>
      <h5>例外层（按显式优先级，首条匹配即终止）</h5>
      <table className="cv chain">
        <thead><tr><th>#</th><th>例外</th><th>范围</th><th>动作</th><th>包含</th><th>窗口</th><th>命中</th></tr></thead>
        <tbody>
          {hit.exception_chain.map((c) => (
            <tr key={c.exception_id ?? c.rank} className={c.matched ? 'matched' : c.contained ? 'contained' : ''}>
              <td>{c.rank + 1}</td>
              <td>{c.name} <span className="muted">P{c.priority}</span></td>
              <td><code>{c.prefix}{c.ge ? ` ge ${c.ge}` : ''}{c.le ? ` le ${c.le}` : ''}</code></td>
              <td className={c.action}>{c.action}</td>
              <td>{c.contained ? '✓' : '—'}</td>
              <td>{c.length_ok ? '✓' : '✗'}</td>
              <td>{c.matched ? '★' : ''}</td>
            </tr>
          ))}
          {!hit.exception_chain.length && <tr><td colSpan="7" className="muted">当前时刻无生效例外</td></tr>}
        </tbody>
      </table>
      <h5>基线层（完整命中链，始终评估以供对比）</h5>
      <table className="cv chain">
        <thead><tr><th>seq</th><th>前缀</th><th>动作</th><th>包含</th><th>窗口</th><th>命中</th></tr></thead>
        <tbody>
          {hit.baseline_chain.map((c, i) => (
            <tr key={i} className={c.seq === null ? 'defaultrow' : c.matched ? 'matched' : c.contained ? 'contained' : ''}>
              <td>{c.seq ?? '默认'}</td><td><code>{c.prefix}</code></td>
              <td className={c.action}>{c.action}</td>
              <td>{c.contained ? '✓' : '—'}</td><td>{c.length_ok ? '✓' : '✗'}</td>
              <td>{c.matched ? '★' : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const EMPTY_FORM = {
  name: '', prefix: '', action: 'deny', ge: '', le: '', priority: 100,
  starts_at: '', ends_at: '', reason: '',
}

export default function Exceptions({ policy, onChange }) {
  const [rows, setRows] = useState([])
  const [snaps, setSnaps] = useState([])
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [form, setForm] = useState(EMPTY_FORM)
  const [preview, setPreview] = useState(null)
  const [probe, setProbe] = useState('192.168.100.0/24')
  const [probeAt, setProbeAt] = useState('')
  const [hit, setHit] = useState(null)
  const [effective, setEffective] = useState(null)
  const [cv, setCv] = useState(null)
  const [clockNow, setClockNow] = useState(null)
  const [clockInput, setClockInput] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')

  async function refresh() {
    try {
      const [es, ss, ck] = await Promise.all([
        api.listExceptions(policy.id), api.snapshots(policy.id), api.clock()])
      setRows(es); setSnaps(ss); setClockNow(ck)
      if (selected) {
        const d = await api.getException(selected)
        setDetail(d)
      }
      setErr('')
    } catch (e) { setErr(e.message) }
  }

  useEffect(() => { setSelected(null); setDetail(null); setHit(null); setPreview(null); setCv(null) },
    [policy.id])
  useEffect(() => { refresh() }, [policy.id])

  const latestSnap = useMemo(
    () => [...snaps].sort((a, b) => b.version - a.version)[0] || null, [snaps])

  function field(k, v) { setForm((f) => ({ ...f, [k]: v })) }

  async function guard(label, fn) {
    setBusy(label); setErr('')
    try { await fn(); await refresh(); }
    catch (e) { setErr(e.message) }
    finally { setBusy('') }
  }

  async function createDraft() {
    const body = {
      ...form,
      ge: form.ge === '' ? null : Number(form.ge),
      le: form.le === '' ? null : Number(form.le),
      priority: Number(form.priority),
      starts_at: localInputToIso(form.starts_at),
      ends_at: localInputToIso(form.ends_at),
      baseline_snapshot_id: latestSnap?.id ?? null,
    }
    await guard('create', async () => {
      const e = await api.createException(policy.id, body)
      setSelected(e.id)
      setForm(EMPTY_FORM)
    })
  }

  async function previewCandidate() {
    setPreview(null)
    await guard('preview', async () => {
      const b = {
        name: form.name || 'candidate', prefix: form.prefix, action: form.action,
        ge: form.ge === '' ? null : Number(form.ge),
        le: form.le === '' ? null : Number(form.le),
        priority: Number(form.priority),
        starts_at: localInputToIso(form.starts_at),
        ends_at: localInputToIso(form.ends_at),
      }
      setPreview(await api.previewCandidate(policy.id, { candidate: b }))
    })
  }

  async function open(id) {
    setSelected(id); setPreview(null); setHit(null); setCv(null)
    try { setDetail(await api.getException(id)) } catch (e) { setErr(e.message) }
  }

  async function previewExisting(snapshotId) {
    setPreview(null)
    await guard('preview', async () =>
      setPreview(await api.previewException(selected, snapshotId)))
  }

  async function doAction(action, body) {
    await guard(action, async () => { await api.exceptionAction(selected, action, body) })
  }

  async function reconfirm() {
    if (!preview) return
    await guard('reconfirm', async () => {
      await api.reconfirmException(selected, preview.baseline_snapshot_id,
        preview.signature, preview.witnesses.length)
      setPreview(null)
    })
  }

  async function runProbe() {
    setHit(null); setErr('')
    try {
      const at = probeAt ? localInputToIso(probeAt) : null
      setHit(await api.effectiveClassify(policy.id, probe, at))
    } catch (e) { setErr(e.message) }
  }

  async function showEffective() {
    setEffective(null); setErr('')
    try {
      const at = probeAt ? localInputToIso(probeAt) : null
      setEffective(await api.effective(policy.id, at))
    } catch (e) { setErr(e.message) }
  }

  async function cvFRR() {
    setCv(null); setErr('')
    try {
      const at = probeAt ? localInputToIso(probeAt) : null
      setCv(await api.effectiveCrossValidate(policy.id, [probe], at, 'a'))
    } catch (e) { setErr(e.message) }
  }

  async function applyClock(local) {
    await guard('clock', async () => {
      if (!local) { await api.setClock(null, true); setClockInput('') }
      else await api.setClock(localInputToIso(local))
    })
  }
  async function doSweep() {
    await guard('sweep', async () => {
      const at = clockInput ? localInputToIso(clockInput) : null
      await api.sweep(at)
    })
  }

  return (
    <div className="exc">
      {/* injectable clock control */}
      <div className="bar clockbar">
        <span>🕒 可注入时钟：</span>
        <b className={clockNow?.real ? '' : 'warn'}>
          {clockNow ? new Date(clockNow.now).toLocaleString() : '…'}
          {clockNow?.real ? '（真实时间）' : '（已冻结/模拟）'}
        </b>
        <input type="datetime-local" value={clockInput} onChange={(e) => setClockInput(e.target.value)} />
        <button className="small" disabled={busy === 'clock'} onClick={() => applyClock(clockInput)}>冻结到</button>
        <button className="small" disabled={busy === 'clock'} onClick={() => applyClock('')}>恢复真实</button>
        <button className="small primary" disabled={busy === 'sweep'} onClick={doSweep}>立即扫描定时事件</button>
        {err && <span className="error">{err}</span>}
      </div>

      <div className="cols exc-cols">
        {/* left: list + create */}
        <div className="exc-left">
          <h4>例外列表（策略 {policy.name}，基线快照 v{latestSnap?.version ?? '—'}）</h4>
          <table className="cv">
            <thead><tr><th>状态</th><th>名称</th><th>范围/动作</th><th>窗口 (UTC)</th><th>P</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}
                  className={`${selected === r.id ? 'selrow' : ''} ${r.needs_review ? 'reviewrow' : ''}`}
                  style={{ cursor: 'pointer' }} onClick={() => open(r.id)}>
                  <td><StatePill status={r.status} needsReview={r.needs_review} /></td>
                  <td>{r.name}</td>
                  <td className={r.action}>
                    <code>{r.prefix}{r.ge ? ` ge${r.ge}` : ''}{r.le ? ` le${r.le}` : ''}</code>
                    {' '}{r.action}
                  </td>
                  <td className="muted">
                    {new Date(r.starts_at).toLocaleString()} →<br />
                    {new Date(r.ends_at).toLocaleString()}
                  </td>
                  <td>{r.priority}</td>
                </tr>
              ))}
              {!rows.length && <tr><td colSpan="5" className="muted">尚无例外</td></tr>}
            </tbody>
          </table>

          <details className="createbox">
            <summary><b>＋ 新建有时效例外（草稿）</b></summary>
            <div className="formgrid">
              <label>名称 <input value={form.name} onChange={(e) => field('name', e.target.value)} /></label>
              <label>前缀 <input placeholder="192.168.100.0/24" value={form.prefix}
                onChange={(e) => field('prefix', e.target.value)} /></label>
              <label>动作
                <select value={form.action} onChange={(e) => field('action', e.target.value)}>
                  <option value="deny">deny（临时拒绝）</option>
                  <option value="permit">permit（临时放行）</option>
                </select>
              </label>
              <label>优先级 <input type="number" value={form.priority}
                onChange={(e) => field('priority', e.target.value)} /></label>
              <label>ge（可选）<input type="number" value={form.ge}
                onChange={(e) => field('ge', e.target.value)} /></label>
              <label>le（可选）<input type="number" value={form.le}
                onChange={(e) => field('le', e.target.value)} /></label>
              <label>生效起 <input type="datetime-local" value={form.starts_at}
                onChange={(e) => field('starts_at', e.target.value)} /></label>
              <label>生效止 <input type="datetime-local" value={form.ends_at}
                onChange={(e) => field('ends_at', e.target.value)} /></label>
              <label className="span2">理由 <input value={form.reason}
                onChange={(e) => field('reason', e.target.value)} /></label>
            </div>
            <p className="muted">
              例外绑定创建时的<strong>不可变基线快照 v{latestSnap?.version}</strong>与地址族 IPv{policy.family}；
              窗口为半开区间 [起, 止)，边界时刻自动生效/恢复。
            </p>
            <button disabled={busy === 'create'} onClick={createDraft}>存为草稿</button>
            <button className="primary" disabled={busy === 'preview'} onClick={previewCandidate}>
              预览语义影响（不落库）
            </button>
          </details>
        </div>

        {/* right: detail */}
        <div className="exc-right">
          {!detail && <p className="muted">选择左侧例外查看时间线、审批操作与语义影响；或在下方推演当前合成配置。</p>}
          {detail && (
            <div className="detailbox">
              <div className="bar">
                <b>{detail.name}</b>
                <StatePill status={detail.status} needsReview={detail.needs_review} />
                <span className="muted">绑定快照 #{detail.baseline_snapshot_id} · IPv{detail.family} ·
                  {' '}P{detail.priority}</span>
              </div>
              <p>
                <code>{detail.prefix}{detail.ge ? ` ge ${detail.ge}` : ''}{detail.le ? ` le ${detail.le}` : ''}</code>{' '}
                → <b className={detail.action}>{detail.action}</b>
                <span className="muted">；{detail.reason}（{detail.requested_by}
                  {detail.approved_by ? ` / 批准人 ${detail.approved_by}` : ''}）</span>
              </p>

              {detail.needs_review && (
                <div className="reviewbox">
                  ⚠ {detail.review_reason}
                  <div className="muted">旧基线 #{detail.baseline_snapshot_id} 未被修改；
                    请对当前最新快照 v{latestSnap?.version} 重新预览并确认后才会生效。</div>
                  <button disabled={busy === 'preview'}
                    onClick={() => previewExisting(latestSnap?.id)}>对新基线重新预览</button>
                  {preview && preview.baseline_snapshot_id === latestSnap?.id && (
                    <button className="primary" disabled={busy === 'reconfirm'} onClick={reconfirm}>
                      我已确认上述影响，重新绑定到 v{latestSnap?.version}
                    </button>
                  )}
                </div>
              )}

              {/* lifecycle operations */}
              <div className="actions">
                {detail.status === 'draft' &&
                  <button disabled={busy} onClick={() => doAction('submit')}>提交待批准</button>}
                {detail.status === 'rejected' &&
                  <button disabled={busy} onClick={() => doAction('revise')}>修订回草稿</button>}
                {detail.status === 'pending' && <>
                  <button className="primary" disabled={busy}
                    onClick={() => doAction('approve', { approver: 'ops-lead' })}>批准（进入已计划）</button>
                  <button className="danger" disabled={busy}
                    onClick={() => doAction('reject', { note: '不符合窗口要求' })}>驳回</button>
                </>}
                {detail.status === 'planned' && <>
                  <button disabled={busy} onClick={() => doAction('activate')}>手动激活（幂等）</button>
                  <button className="danger" disabled={busy}
                    onClick={() => doAction('revoke', { note: '人工撤销' })}>撤销</button>
                </>}
                {detail.status === 'active' &&
                  <button className="danger" disabled={busy}
                    onClick={() => doAction('revoke', { note: '提前终止' })}>撤销（立即恢复基线）</button>}
                {['expired', 'revoked'].includes(detail.status) &&
                  <span className="muted">终态：重复/迟到的定时事件不会改变此状态。</span>}
                <button className="small" disabled={busy === 'preview'}
                  onClick={() => previewExisting()}>预览语义影响</button>
              </div>

              <h5>状态时间线（append-only 历史）</h5>
              <Timeline events={detail.events} />
            </div>
          )}

          {preview && (
            <div className="analysis">
              <h4>语义影响预览（基线快照 #{preview.baseline_snapshot_id} v{preview.baseline_version} @ {new Date(preview.at).toLocaleString()}）</h4>
              <h5>最小见证前缀集（相对基线的行为变化，非文本 diff）</h5>
              <WitnessTable witnesses={preview.witnesses} />
              <h5>重叠例外的确定优先级与最小见证</h5>
              <OverlapList overlaps={preview.overlaps} />
              <p className="muted">预览签名 <code>{preview.signature}</code>（复核确认时校验，防止看后即变）</p>
            </div>
          )}

          {/* effective-policy workbench */}
          <div className="analysis">
            <h4>当前合成配置（不改原规则；基线 + 生效例外）</h4>
            <div className="bar">
              <input placeholder="探针前缀" value={probe} onChange={(e) => setProbe(e.target.value)} />
              <input type="datetime-local" value={probeAt} onChange={(e) => setProbeAt(e.target.value)} />
              <button className="small" onClick={runProbe}>推演命中链</button>
              <button className="small" onClick={showEffective}>查看合成 FRR 配置</button>
              <button className="small primary" onClick={cvFRR}>仅本地隔离 FRR 验证</button>
            </div>
            {cv && (
              <div className={`cvbox ${cv.status}`}>
                FRR 交叉验证：<b>{cv.status}</b>，不一致 {cv.mismatch_count} 处
                {cv.setup_error && <div className="error">{cv.setup_error}</div>}
              </div>
            )}
            <HitChain hit={hit} />
            {effective && (
              <details>
                <summary>下发到隔离 FRR 的合成 prefix-list（结束即删除）</summary>
                <pre>{effective.frr_config || '# 无规则（空策略：FRR 视为 permit，拒绝比对）'}</pre>
                <p className="muted">
                  例外占用低 seq 带（{10},{20},…），基线规则在高 seq 带（1,000,000+原seq）；
                  FRR 首条匹配天然实现显式优先级，原基线规则内容与快照均不被修改。
                </p>
              </details>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
