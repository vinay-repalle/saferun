import { useMemo, useState } from 'react'
import { SeverityTally } from '../SeverityTally/SeverityTally'
import { SEVERITIES, location, sortedFindings, txt } from '../../utils/report'
import './FindingsTable.css'

const PAGE = 100

const HASH = /^[0-9a-f]{40}$/i

/** Real release numbers only: OSV also lists git commit hashes as "fixed in", which are noise for a reader. */
function releases(f) {
  return f.fixed_versions.filter((v) => !HASH.test(v)).slice(0, 4)
}

function FindingRow({ f }) {
  const [open, setOpen] = useState(false)
  const msg = txt(f.message)
  const long = msg.length > 160
  const fixes = releases(f)
  const ids = f.vulnerability_ids.map((v) => txt(v, 60))
  return (
    <tr>
      <td><span className={`badge sev-${txt(f.severity, 12).replace(/[^a-z]/g, '')}`}>{txt(f.severity, 12)}</span></td>
      <td className="rule-cell">
        {f.package
          ? <><strong>{txt(f.package.name, 100)} {txt(f.package.version, 60)}</strong><div className="muted small">{ids[0] ?? txt(f.rule_id, 200)}</div></>
          : <><code>{txt(f.rule_id, 200)}</code><div className="muted small">{txt(f.check, 100)}</div></>}
      </td>
      <td><code className="path">{location(f)}</code></td>
      <td>
        <div className={long && !open ? 'msg clamp' : 'msg'}>{msg}</div>
        {long && <button className="link small" onClick={() => setOpen(!open)}>{open ? 'Show less' : 'Show more'}</button>}
        {f.package && <div className="muted small">package: {txt(f.package.name, 100)} {txt(f.package.version, 60)} ({txt(f.package.ecosystem, 40)})</div>}
        {f.package && fixes.length > 0 && <div className="fix">Fix: upgrade {txt(f.package.name, 100)} - fixed in: {fixes.join(', ')}</div>}
        {f.package && fixes.length === 0 && <div className="fix">Fix: upgrade {txt(f.package.name, 100)} to a patched release</div>}
        {ids.length > 0 && <div className="muted small">{ids.join(' · ')}</div>}
        {f.cwe.length > 0 && <div className="muted small">{f.cwe.map((v) => txt(v, 40)).join(', ')}</div>}
      </td>
    </tr>
  )
}

export function FindingsTable({ report }) {
  const all = useMemo(() => sortedFindings(report), [report])
  const [sev, setSev] = useState('all')
  const [q, setQ] = useState('')
  const [shown, setShown] = useState(PAGE)
  const rows = all.filter((f) => (sev === 'all' || f.severity === sev) &&
    (!q || `${f.rule_id} ${f.path ?? ''} ${f.message} ${f.check}`.toLowerCase().includes(q.toLowerCase())))
  return (
    <section className="card" aria-label="Findings">
      <div className="card-head">
        <h2>Findings <span className="muted">({all.length})</span></h2>
        <div className="filters">
          <label>Severity
            <select value={sev} onChange={(e) => { setSev(e.target.value); setShown(PAGE) }}>
              <option value="all">All</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label>Search <input type="search" value={q} onChange={(e) => { setQ(e.target.value); setShown(PAGE) }} placeholder="rule, path, message" /></label>
        </div>
      </div>
      <SeverityTally report={report} />
      {all.length === 0 ? <p className="empty">No findings were reported. See check coverage above for what was and was not analysed.</p> : (
        <div className="scroll">
          <table>
            <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Details</th></tr></thead>
            <tbody>{rows.slice(0, shown).map((f, i) => <FindingRow key={i} f={f} />)}</tbody>
          </table>
          {rows.length === 0 && <p className="empty">No findings match the filter.</p>}
          {rows.length > shown && <button className="link" onClick={() => setShown((n) => n + PAGE)}>Show {Math.min(PAGE, rows.length - shown)} more of {rows.length - shown} remaining</button>}
        </div>
      )}
    </section>
  )
}
