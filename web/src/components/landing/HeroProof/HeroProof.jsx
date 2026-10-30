import { TRUST } from '../../../content/site'
import { Section } from '../../Section/Section'
import { FlowDiagram } from '../FlowDiagram/FlowDiagram'
import { TerminalDemo } from '../TerminalDemo/TerminalDemo'
import './HeroProof.css'

/** Right after the opening: what you get, shown as the pipeline and a sample terminal session. */
export function HeroProof() {
  return (
    <Section id="overview">
      <div className="proof">
        <div>
          <h2>One verdict, <em>no execution.</em></h2>
          <p className="sec-sub">Code goes in, passes through an isolated analyzer, and a report comes out. Your project is read, never run.</p>
          <ul className="trust stag">
            {TRUST.map(([t, d]) => <li key={t}><strong>{t}</strong><span>{d}</span></li>)}
          </ul>
        </div>
        <div className="proof-art stag"><FlowDiagram /><TerminalDemo /></div>
      </div>
    </Section>
  )
}
