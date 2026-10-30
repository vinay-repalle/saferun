import { completedChecks, txt } from '../../utils/report'
import './VerdictCard.css'

const VERDICT_NOTE = {
  PASS: 'The implemented checks completed and found nothing above informational.',
  WARNING: 'Lower-severity findings, or the project was not fully checked.',
  FAIL: 'At least one high or critical finding.',
}
const VERDICT_ADVICE = {
  PASS: 'What to do: nothing was flagged, so it looks fine to go ahead. This is not a guarantee, so still review the code yourself.',
  WARNING: 'What to do: review the items below before running this project. Often it is a minor finding, or a check that could not run (see "Coverage gaps") - fix or install that and scan again.',
  FAIL: 'What to do: do not run this project yet. Fix the high/critical findings listed below (or confirm each is a false alarm), then scan again.',
}
const VERDICT_ICON = { PASS: '✓', WARNING: '!', FAIL: '✕' }

/** Shows the engine's verdict verbatim; it never derives or adjusts one. */
export function VerdictCard({ report }) {
  const v = report.verdict
  const cls = ['PASS', 'WARNING', 'FAIL'].includes(v) ? v.toLowerCase() : 'unknown'
  const { done, total } = completedChecks(report.checks)
  return (
    <section className={`card verdict verdict-${cls}`} aria-label="Verdict">
      <div className="verdict-main">
        <span className="verdict-icon" aria-hidden="true">{VERDICT_ICON[v] ?? '?'}</span>
        <div>
          <div className="eyebrow">Verdict</div>
          <div className="verdict-word" data-testid="verdict">{txt(v, 20)}</div>
          <p className="muted">{VERDICT_NOTE[v] ?? ''}</p>
          {VERDICT_ADVICE[v] && <p className="verdict-advice" data-testid="verdict-advice">{VERDICT_ADVICE[v]}</p>}
        </div>
      </div>
      <dl className="kpis">
        <div><dt>Scan complete</dt><dd className={report.complete ? 'ok' : 'bad'} data-testid="complete">{report.complete ? 'Yes' : 'No – see coverage gaps'}</dd></div>
        <div><dt>Checks completed</dt><dd>{done} of {total}</dd></div>
        <div><dt>Findings</dt><dd>{report.checks.reduce((n, c) => n + c.findings.length, 0)}</dd></div>
      </dl>
      <h3>Why this verdict</h3>
      <ul className="reasons">{report.reasons.map((r, i) => <li key={i}>{txt(r)}</li>)}</ul>
      <p className="fine">PASS means the existing checks found nothing; it is not a proof that the code is safe.</p>
    </section>
  )
}
