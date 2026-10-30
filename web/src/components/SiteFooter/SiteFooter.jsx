import { DOCS, GITHUB } from '../../content/site'
import { Mark } from '../Mark/Mark'
import './SiteFooter.css'

const EXT = { target: '_blank', rel: 'noreferrer noopener' }

/** The one footer for every page. */
export function SiteFooter() {
  return (
    <footer className="foot">
      <div className="wrap foot-row">
        <div>
          <a className="brand" href="#/"><Mark size={22} /> <span>SafeRun</span></a>
          <p className="fine">SafeRun checks what it can check. It never claims the code is secure.</p>
        </div>
        <nav aria-label="Footer">
          <a href="#/guide">Setup guide</a>
          <a href={DOCS + 'cli.md'} {...EXT}>CLI docs</a>
          <a href={DOCS + 'engine.md'} {...EXT}>Engine docs</a>
          <a href={DOCS + 'release-images.md'} {...EXT}>Release images</a>
          <a href={GITHUB} {...EXT}>GitHub</a>
        </nav>
      </div>
    </footer>
  )
}
