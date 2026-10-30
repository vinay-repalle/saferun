import { SEVERITIES, tally } from '../../utils/report'
import './SeverityTally.css'

export function SeverityTally({ report }) {
  const t = tally(report)
  return (
    <ul className="tally" aria-label="Findings by severity">
      {SEVERITIES.map((s) => (
        <li key={s} className={`sev sev-${s}`}><span className="n">{t[s] ?? 0}</span><span>{s}</span></li>
      ))}
    </ul>
  )
}
