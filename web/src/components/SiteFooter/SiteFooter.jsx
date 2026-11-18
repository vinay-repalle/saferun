import { DOCS, GITHUB, PYPI, RELEASES, SECURITY_POLICY, VERSION } from '../../content/site'
import { Mark } from '../Mark/Mark'
import { toggleShortcuts, useShortcutsEnabled } from '../SiteNav/shortcuts'
import './SiteFooter.css'

const EXT = { target: '_blank', rel: 'noreferrer noopener' }

/** The one footer for every page. */
export function SiteFooter() {
  const keys = useShortcutsEnabled()
  return (
    <footer className="foot">
      <div className="wrap foot-row">
        <div>
          <a className="brand" href="#/"><Mark size={22} /> <span>SafeRun</span></a>
          <p className="fine">SafeRun checks what it can check. It never claims the code is secure.</p>
          <p className="fine">v{VERSION} · alpha · MIT license · not independently certified</p>
          <button type="button" className="foot-keys" data-key="?" aria-pressed={keys} onClick={toggleShortcuts}>Keyboard shortcuts: {keys ? 'on' : 'off'}</button>
        </div>
        <nav aria-label="Footer">
          <a href="#/guide">Setup guide</a>
          <a href={DOCS + 'cli.md'} {...EXT}>CLI docs</a>
          <a href={DOCS + 'engine.md'} {...EXT}>Engine docs</a>
          <a href={DOCS + 'release-images.md'} {...EXT}>Release images</a>
          <a href={GITHUB} {...EXT}>GitHub</a>
          <a href={PYPI} {...EXT}>PyPI</a>
          <a href={RELEASES} {...EXT}>Releases</a>
          <a href={SECURITY_POLICY} {...EXT}>Security policy</a>
        </nav>
      </div>
    </footer>
  )
}
