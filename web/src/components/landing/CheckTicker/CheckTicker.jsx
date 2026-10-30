import './CheckTicker.css'

// The checks SafeRun really runs (see the engine docs); nothing here is a statistic.
const CHECKS = ['workspace-sensitive-files', 'python-syntax', 'javascript-syntax', 'python-static-analysis', 'dependency-vulnerabilities']

/** A slow marquee under the hero. The second copy is hidden from assistive tech; with reduced motion it stops and wraps. */
export function CheckTicker() {
  const row = (hidden) => (
    <ul className="tick-row" aria-hidden={hidden || undefined}>
      {CHECKS.map((c) => <li key={c}><span className="tick-ok" aria-hidden="true">✓</span>{c}</li>)}
    </ul>
  )
  return (
    <div className="tick" role="region" aria-label="Checks SafeRun runs">
      <div className="tick-track">{row(false)}{row(true)}{row(true)}</div>
    </div>
  )
}
