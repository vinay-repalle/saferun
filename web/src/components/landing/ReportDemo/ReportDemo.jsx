import { useState } from 'react'
import { VERDICTS } from '../../../content/site'
import { Section, SectionHead } from '../../Section/Section'
import './ReportDemo.css'

const note = (key) => VERDICTS.find(([k]) => k === key)[3]
const OK = [['passed', 'python-syntax', 'No findings'], ['passed', 'javascript-syntax', 'No findings'], ['passed', 'python-static-analysis', 'No findings']]

// Invented sample rows. Verdict wording comes from the shared VERDICTS so it matches the guide.
const DEMO = [
  { id: 'pass', label: 'PASS', note: note('pass'), rows: [...OK, ['passed', 'dependency-vulnerabilities', 'No findings']] },
  { id: 'warn', label: 'WARNING', note: note('warn'), rows: [...OK, ['unavailable', 'dependency-vulnerabilities', 'OSV data is missing: run saferun osv-db update']] },
  { id: 'fail', label: 'FAIL', note: note('fail'), rows: [['findings', 'python-syntax', '[HIGH] syntax-error  app.py:12'], OK[1], ['findings', 'dependency-vulnerabilities', '[HIGH] example-advisory  package-lock.json'], OK[2]] },
]

export function ReportDemo() {
  const [sel, setSel] = useState('warn')
  const d = DEMO.find((x) => x.id === sel)
  return (
    <Section id="demo">
      <SectionHead n="05" title="Read a report" accent="at a glance." sub="Pick a verdict to see how a report looks." />
      <div className="demo">
        <div className="demo-bar">
          <span className="demo-tag">Demonstration only · no scan was run</span>
          <div className="demo-tabs" role="tablist" aria-label="Sample verdict">
            {DEMO.map((x) => <button key={x.id} type="button" role="tab" aria-selected={sel === x.id} className={'demo-tab v-' + x.id} onClick={() => setSel(x.id)}>{x.label}</button>)}
          </div>
        </div>
        <div className={'report v-' + d.id} role="tabpanel">
          <p className="verdict">Verdict: {d.label}</p>
          <p className="report-note">{d.note}</p>
          <table>
            <thead><tr><th>Status</th><th>Check</th><th>Result</th></tr></thead>
            <tbody>{d.rows.map(([s, c, r]) => <tr key={c}><td className={'s-' + s}>{s}</td><td><code>{c}</code></td><td>{r}</td></tr>)}</tbody>
          </table>
          <p className="fine">Sample data. Real reports come from <code>saferun scan</code>.</p>
        </div>
      </div>
    </Section>
  )
}
