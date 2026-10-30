import { Section, SectionHead } from '../../Section/Section'
import './HowItWorks.css'

const PIPELINE = [
  ['Project', 'A folder on your machine, or a ZIP uploaded to the local dashboard.'],
  ['Validation', 'The project is copied read-only; sensitive files are withheld; limits are enforced.'],
  ['Isolated analyzer', 'Checks run in a verified container with no network. Nothing from the project is executed.'],
  ['Security report', 'Each check is reported as passed, findings, or a coverage gap. Incomplete scans never report PASS.'],
]

export function HowItWorks() {
  return (
    <Section id="how" alt>
      <SectionHead n="02" title="From folder to" accent="verdict." sub="A fixed pipeline, the same for the CLI and the dashboard." />
      <ol className="pipe stag">
        {PIPELINE.map(([t, d], i) => <li key={t}><span className="pipe-n">{String(i + 1).padStart(2, '0')}</span><h3>{t}</h3><p>{d}</p></li>)}
      </ol>
    </Section>
  )
}
