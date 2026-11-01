import { GITHUB, PYPI, RELEASES, VERSION } from '../../../content/site'
import { Section } from '../../Section/Section'
import './GithubCta.css'

/** Links to the repository, the PyPI package and the releases; no star counts, downloads or other numbers that have not been verified. */
export function GithubCta() {
  return (
    <Section id="github">
      <div className="gh">
        <div>
          <h2>Open source, <em>on GitHub.</em></h2>
          <p className="sec-sub">Read the code, the threat model and the documented limits. Issues and feedback are welcome.</p>
        </div>
        <div className="gh-card">
          <code>vinay-repalle/saferun</code>
          <a className="btn btn-primary" href={GITHUB} target="_blank" rel="noreferrer noopener">View on GitHub ↗</a>
          <a className="btn btn-ghost" href={PYPI} target="_blank" rel="noreferrer noopener">PyPI ↗</a>
          <a className="btn btn-ghost" href={RELEASES} target="_blank" rel="noreferrer noopener">Releases ({'v' + VERSION}) ↗</a>
        </div>
      </div>
    </Section>
  )
}
