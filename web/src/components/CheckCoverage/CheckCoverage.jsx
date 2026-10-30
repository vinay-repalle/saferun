import { StatusBadge } from '../StatusBadge/StatusBadge'
import { txt } from '../../utils/report'

function CheckRow({ c }) {
  const extra = c.errors.length + c.notes.length > 0
  return (
    <tr>
      <td><strong>{txt(c.name, 100)}</strong>{c.tool && <div className="muted small">{txt(c.tool, 100)}</div>}</td>
      <td><StatusBadge status={c.status} /></td>
      <td className="num">{c.findings.length}{c.truncated_findings ? <span className="muted"> (+{c.truncated_findings})</span> : null}</td>
      <td className="num">{c.duration_s ? `${c.duration_s.toFixed(1)} s` : '–'}</td>
      <td>
        {c.detail && <div>{txt(c.detail, 300)}</div>}
        {extra && (
          <details><summary>{[c.errors.length && `${c.errors.length} error(s)`, c.notes.length && `${c.notes.length} note(s)`].filter(Boolean).join(', ')}</summary>
            <ul className="small">{c.errors.map((e, i) => <li key={`e${i}`}>error: {txt(e, 300)}</li>)}{c.notes.map((n, i) => <li key={`n${i}`}>{txt(n, 300)}</li>)}</ul>
          </details>
        )}
      </td>
    </tr>
  )
}

export function CheckCoverage({ report }) {
  return (
    <section className="card" aria-label="Check coverage">
      <h2>Check coverage</h2>
      <div className="scroll">
        <table>
          <thead><tr><th>Check</th><th>Status</th><th className="num">Findings</th><th className="num">Time</th><th>Detail</th></tr></thead>
          <tbody>{report.checks.map((c) => <CheckRow key={c.name} c={c} />)}</tbody>
        </table>
      </div>
    </section>
  )
}
