import { gaps } from '../../utils/report'
import './GapsPanel.css'

export function GapsPanel({ report }) {
  const g = gaps(report)
  if (!g.length) return null
  return (
    <section className="card gaps" aria-label="Coverage gaps and operational problems">
      <h2>Coverage gaps and operational problems</h2>
      <p className="muted">These parts of the project were not (fully) checked. A gap is never reported as clean.</p>
      <ul>{g.map((x, i) => <li key={i}>{x.head}{x.lines.length > 0 && <ul className="small">{x.lines.map((l, j) => <li key={j}>{l}</li>)}</ul>}</li>)}</ul>
    </section>
  )
}
