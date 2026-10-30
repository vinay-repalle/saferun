import { HONEST_LIMITS, SAFETY } from '../../../content/site'
import { Section, SectionHead } from '../../Section/Section'
import './SecuritySection.css'

/** The controls and the limits come from content/site.js, the same text the setup guide shows. */
export function SecuritySection() {
  return (
    <Section id="security">
      <SectionHead n="03" title="Security you can" accent="inspect." sub="Each control below is implemented in the repository and documented with its limits." />
      <div className="sec-grid">
        <dl className="defs stag">{SAFETY.map(([t, d]) => <div key={t}><dt>{t}</dt><dd>{d}</dd></div>)}</dl>
        <aside className="limits">
          <h3>Known limits</h3>
          <p>{HONEST_LIMITS}</p>
          <a href="#/guide">How SafeRun stays safe, in the guide →</a>
        </aside>
      </div>
    </Section>
  )
}
