import { Section, SectionHead } from '../../Section/Section'
import './Features.css'

const FEATURES = [
  ['Python syntax check', 'Parses every .py file and reports syntax errors with file and line.'],
  ['JavaScript syntax check', 'Runs node --check inside the Node.js sandbox.'],
  ['Static analysis', 'Semgrep with SafeRun’s bundled rules, for Python. JavaScript rules are not implemented yet.'],
  ['Dependency scanning', 'OSV-Scanner against local data for lockfiles. Transitive resolution and some lockfile formats are not covered.'],
  ['CLI first', 'saferun scan with text or JSON output and deterministic exit codes: 0 PASS, 1 FAIL, 2 WARNING.'],
]

export function Features() {
  return (
    <Section id="features" alt>
      <SectionHead n="04" title="What it" accent="checks." />
      <div className="feat stag">{FEATURES.map(([t, d]) => <div key={t}><h3>{t}</h3><p>{d}</p></div>)}</div>
      <p className="sec-link"><a href="#/guide">Read the setup guide →</a></p>
    </Section>
  )
}
