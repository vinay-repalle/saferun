import { useMemo } from 'react'
import { txt, upgradePlan } from '../../utils/report'
import './UpgradePlan.css'

/** The few upgrades that clear every dependency finding: one row per package instead of one per advisory. */
export function UpgradePlan({ report }) {
  const plan = useMemo(() => upgradePlan(report), [report])
  if (plan.length === 0) return null
  return (
    <section className="card" aria-label="Upgrade plan">
      <div className="card-head"><h2>Upgrade plan <span className="muted">({plan.length} {plan.length === 1 ? 'package' : 'packages'})</span></h2></div>
      <div className="scroll">
        <table>
          <thead><tr><th>Package</th><th>Installed</th><th>Upgrade to</th><th className="num">Findings</th><th>Worst</th></tr></thead>
          <tbody>
            {plan.map((r) => (
              <tr key={`${r.ecosystem}/${r.name}/${r.version}`}>
                <td><strong>{txt(r.name, 100)}</strong> <span className="muted small">{txt(r.ecosystem, 40)}</span></td>
                <td>{txt(r.version, 60)}</td>
                <td>{r.upgradeTo ? <span className="fix">≥ {txt(r.upgradeTo, 60)}</span> : <span className="muted">no fix listed</span>}</td>
                <td className="num">{r.findings}</td>
                <td><span className={`badge sev-${txt(r.severity, 12).replace(/[^a-z]/g, '')}`}>{txt(r.severity, 12)}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
