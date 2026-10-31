import { PLATFORMS, STEPS } from '../../../content/site'
import { CommandBlock } from '../../CommandBlock/CommandBlock'
import { Section, SectionHead } from '../../Section/Section'
import './QuickStart.css'

/** The three steps are the guide's own (content/site.js). Docker and everything else live in the guide, not here. */
export function QuickStart() {
  return (
    <Section id="quick-start" alt>
      <SectionHead n="06" title="Up and running in" accent="three commands." sub="Install SafeRun from a checkout first (Ubuntu/Linux, Windows or macOS, Python 3.12+, a local Docker that runs Linux containers), then:" />
      <ul className="qs-plat" aria-label="Supported platforms">
        {PLATFORMS.map(([name, status, note]) => <li key={name}><strong>{name}</strong><span>{status}</span><p>{note}</p></li>)}
      </ul>
      <ol className="qs stag">
        {STEPS.map(([title, text, cmd]) => <li key={title}><h3>{title}</h3><CommandBlock command={cmd} /><p>{text}</p></li>)}
      </ol>
      <p className="sec-link"><a href="#/guide">Platform-specific setup for Ubuntu/Linux, Windows and macOS →</a></p>
    </Section>
  )
}
