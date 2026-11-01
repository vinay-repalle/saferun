import { ALPHA_NOTICE, GITHUB, INSTALL, PLATFORMS, PYPI, PYPI_VERSION, RELEASES, STEPS, VERSION } from '../../../content/site'
import { CommandBlock } from '../../CommandBlock/CommandBlock'
import { Section, SectionHead } from '../../Section/Section'
import './QuickStart.css'

/** The three steps are the guide's own (content/site.js). Docker and everything else live in the guide, not here. */
export function QuickStart() {
  return (
    <Section id="quick-start" alt>
      <SectionHead n="06" title="Install from PyPI," accent="then three commands." sub={`SafeRun ${VERSION} is published on PyPI as saferun-cli (it installs the saferun command). Needs Python 3.12+ and Docker running Linux containers; works on Linux, Windows and macOS.`} />
      <div className="qs-install">
        <CommandBlock command={INSTALL} />
        <p>Also works with <code>pipx install saferun-cli</code> and <code>uv tool install saferun-cli</code>. To upgrade later: <code>pip install --upgrade saferun-cli</code>, then run <code>saferun init</code> again (it skips what is already valid).</p>
        <ul className="qs-links" aria-label="Release links">
          <li><a href={PYPI} target="_blank" rel="noreferrer noopener">PyPI package ↗</a></li>
          <li><a href={PYPI_VERSION} target="_blank" rel="noreferrer noopener">Version {VERSION} on PyPI ↗</a></li>
          <li><a href={RELEASES} target="_blank" rel="noreferrer noopener">GitHub Releases ↗</a></li>
          <li><a href={GITHUB} target="_blank" rel="noreferrer noopener">Source on GitHub ↗</a></li>
        </ul>
      </div>
      <ul className="qs-plat" aria-label="Supported platforms">
        {PLATFORMS.map(([name, status, note]) => <li key={name}><strong>{name}</strong><span>{status}</span><p>{note}</p></li>)}
      </ul>
      <ol className="qs stag">
        {STEPS.map(([title, text, cmd]) => <li key={title}><h3>{title}</h3><CommandBlock command={cmd} /><p>{text}</p></li>)}
      </ol>
      <p className="notice qs-alpha"><strong>Alpha release.</strong> {ALPHA_NOTICE}</p>
      <p className="sec-link"><a href="#/guide">Platform-specific setup for Ubuntu/Linux, Windows and macOS →</a></p>
    </Section>
  )
}
