import { HONEST_LIMITS, requirement } from '../../../content/site'
import { Section, SectionHead } from '../../Section/Section'
import './Faq.css'

// Answers about requirements reuse the guide's own wording (content/site.js); the guide has the full troubleshooting list.
const FAQ = [
  ['How do I install it?', 'Clone the repository, create a virtualenv, install with pip, then run saferun init. The setup guide has every command, with copy buttons.'],
  ['Which platforms are supported?', 'Ubuntu/Linux is fully tested. Native Windows and macOS are supported but only partly verified: their non-Docker tests pass in CI, while Docker Desktop integration has not yet been manually verified. The guide has a section for each.'],
  ['Why does it need Docker?', requirement('Docker')],
  ['Do I need Cosign?', requirement('Cosign')],
  ['Does it need internet access?', requirement('Internet')],
  ['Which languages are supported?', 'Python (syntax, Semgrep) and JavaScript / Node.js (node --check and npm lockfile scan). JavaScript dependency installation, test runners and JavaScript Semgrep rules are not implemented.'],
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
