import { ALPHA_NOTICE, HONEST_LIMITS, requirement } from '../../../content/site'
import { Section, SectionHead } from '../../Section/Section'
import './Faq.css'

// Answers about requirements reuse the guide's own wording (content/site.js); the guide has the full troubleshooting list.
const FAQ = [
  ['How do I install it?', 'Run pip install saferun-cli (version 0.0.2 is on PyPI; pipx and uv tool work too), then saferun init and saferun doctor. The setup guide has every command, with copy buttons.'],
  ['Is it production-ready?', ALPHA_NOTICE],
  ['Which platforms are supported?', 'Ubuntu/Linux is fully tested. Native Windows and macOS are supported but only partly verified: their non-Docker tests pass in CI, while Docker Desktop integration has not yet been manually verified. The guide has a section for each.'],
  ['Why does it need Docker?', requirement('Docker')],
  ['Do I need Cosign?', requirement('Cosign')],
  ['Does it need internet access?', requirement('Internet')],
  ['Which languages are supported?', 'Python only: the syntax check, Semgrep rules, the secrets scan and the dependency scan for Python projects. JavaScript and npm files are not checked; a note in the report says so, and it does not change the verdict.'],
  ['What is the difference between scan and run?', 'saferun scan only reads the files and reports; no project code is run. saferun run scans a Python script first and runs it, inside the sandbox only, when the verdict allows it.'],
  ['Does it look for hardcoded secrets?', 'Yes. gitleaks runs inside the offline analyzer container. Secret values are never printed, logged or put in the JSON report: only the rule, file and line. You can turn it off with --no-secrets-check, which limits the verdict to WARNING at best.'],
  ['Does a PASS mean the code is safe?', HONEST_LIMITS],
]

export function Faq() {
  return (
    <Section id="faq" alt>
      <div className="faq-wrap">
        <SectionHead n="07" title="Questions," accent="answered." />
        <div className="faq stag">{FAQ.map(([q, a]) => <details key={q}><summary>{q}</summary><p>{a}</p></details>)}</div>
        <p className="sec-link"><a href="#/guide">More help in the setup guide →</a></p>
      </div>
    </Section>
  )
}
