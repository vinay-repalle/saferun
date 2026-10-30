import { useState } from 'react'
import { GITHUB } from '../../content/site'
import { Mark } from '../Mark/Mark'
import './SiteNav.css'

// Every link is a real hash link, so the same navbar works on the website, the dashboard and the guide.
const LINKS = [['#/product', 'Product'], ['#/security', 'Security'], ['#/how', 'How it works'], ['#/guide', 'Documentation'], ['#/dashboard', 'Dashboard']]

/** The one navbar for every page. `current` is the active hash route (e.g. '#/guide'), if any. */
export function SiteNav({ current = '' }) {
  const [open, setOpen] = useState(false)
  const close = () => setOpen(false)
  return (
    <header className="nav">
      <div className="wrap nav-row">
        <a className="brand" href="#/" aria-label="SafeRun home" onClick={close}><Mark /> <span>SafeRun</span></a>
        <button type="button" className="nav-burger" aria-expanded={open} aria-controls="site-menu" onClick={() => setOpen(!open)}>
          <span className="sr-only">{open ? 'Close menu' : 'Open menu'}</span><i aria-hidden="true" />
        </button>
        <nav id="site-menu" className={'nav-menu' + (open ? ' open' : '')} aria-label="Main">
          {LINKS.map(([href, label]) => <a key={href} className="nav-link" href={href} aria-current={current === href ? 'page' : undefined} onClick={close}>{label}</a>)}
          <a className="nav-link" href={GITHUB} target="_blank" rel="noreferrer noopener">GitHub</a>
          <a className="btn btn-primary nav-cta" href="#/quick-start" onClick={close}>Get Started</a>
        </nav>
      </div>
    </header>
  )
}
