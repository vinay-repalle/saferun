import { Section, SectionHead } from '../../Section/Section'
import './Features.css'

const FEATURES = [
  ['Python only', 'SafeRun checks Python code and Python dependencies. JavaScript and npm files are not checked, and a note in the report says so.'],
  ['Can the scanner read it?', 'The syntax check parses every .py file without running it. A file that fails to parse is reported, because the other checks cannot analyse it.'],
  ['Static analysis', 'Semgrep with SafeRun’s bundled Python rules, including rules for credential-file reads, persistence setup and hidden function lookups.'],
  ['Hardcoded secrets', 'gitleaks inside the offline analyzer container. Secret values are never printed or logged: only the rule, file and line.'],
  ['Dependency scanning', 'OSV-Scanner against local data. Each finding says whether the nearest fix is a patch, minor or major upgrade, and you can record an accepted risk with a reason and expiry date.'],
  ['Plain-English findings', 'Each finding in the report has an “In plain words” line: what it is, why it matters and how to fix it.'],
  ['Package-name check', 'saferun check-names flags dependency names that resemble popular PyPI packages (reqeusts for requests). It is a separate command; scan is unchanged.'],
  ['CLI first', 'saferun scan only reads files; saferun run scans a script and runs it in the sandbox only if the verdict allows. Text or JSON output, exit codes 0 PASS, 1 FAIL, 2 WARNING.'],
]

export function Features() {
  return (
    <Section id="features" alt>
      <SectionHead n="04" title="What it" accent="checks." />
      <div className="feat stag">{FEATURES.map(([t, d]) => <div key={t}><h3>{t}</h3><p>{d}</p></div>)}</div>
      <p className="sec-link"><a href="#/guide">Read the setup guide →</a> · <a href="#/benchmarks">See the benchmark →</a></p>
    </Section>
  )
}
