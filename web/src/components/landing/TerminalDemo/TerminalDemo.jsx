import './TerminalDemo.css'

// Illustrative output; the title bar says so. Each line fades in one after the other (CSS delays), so the session "types" itself.
const LINES = [
  <><span className="t-p">$ </span>saferun status</>,
  <><span className="t-ok">✓</span> python  <span className="t-dim">image pinned by digest</span></>,
  <><span className="t-ok">✓</span> node    <span className="t-dim">image pinned by digest</span></>,
  <><span className="t-ok">✓</span> analyzer  <span className="t-dim">locked, labels verified</span></>,
  <><span className="t-ok">✓</span> osv-db  <span className="t-dim">integrity manifest ok</span></>,
  ' ',
  <><span className="t-p">$ </span>saferun scan ./my-project</>,
  <><span className="t-bad">Verdict: FAIL</span>    Scan complete: yes</>,
  'Checks:',
  '  passed    python-syntax',
  '  passed    javascript-syntax',
  '  findings  dependency-vulnerabilities',
  'Findings:',
  <>{'  '}<span className="t-bad">[HIGH]</span> <span className="t-dim">demo-advisory</span>  package-lock.json</>,
  <><span className="t-p">$ </span>echo $?</>,
  <>1<span className="caret" /></>,
]

export function TerminalDemo() {
  return (
    <div className="term" role="figure" aria-label="Sample SafeRun terminal session">
      <div className="term-bar"><i /><i /><i /><span>terminal · sample output</span></div>
      <pre className="term-body"><code>{LINES.map((l, i) => <span className="ln" key={i}>{l}</span>)}</code></pre>
    </div>
  )
}
