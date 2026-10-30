import { STEPS } from '../../../content/site'
import { CommandBlock } from '../../CommandBlock/CommandBlock'
import { Section, SectionHead } from '../../Section/Section'
import './QuickStart.css'

/** The three steps are the guide's own (content/site.js). Docker and everything else live in the guide, not here. */
export function QuickStart() {
  return (
    <Section id="quick-start" alt>
      <SectionHead n="06" title="Up and running in" accent="three commands." sub="Install SafeRun from a checkout first (Linux, Python 3.12+, a local Docker Engine), then:" />
      <ol className="qs stag">
        {STEPS.map(([title, text, cmd]) => <li key={title}><h3>{title}</h3><CommandBlock command={cmd} /><p>{text}</p></li>)}
      </ol>
      <p className="sec-link"><a href="#/guide">Read the full setup guide: Docker and troubleshooting →</a></p>
    </Section>
  )
}
