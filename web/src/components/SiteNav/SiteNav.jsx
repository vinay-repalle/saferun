import { useState } from 'react'
import { GITHUB } from '../../content/site'
import { Mark } from '../Mark/Mark'
import './SiteNav.css'

// Every link is a real hash link, so the same navbar works on the website and the guide.
const LINKS = [['#/product', 'Product'], ['#/security', 'Security'], ['#/how', 'How it works'], ['#/guide', 'Docs']]

// The GitHub mark (Octicons "mark-github", MIT). Decorative: the link carries the accessible name.
function GithubMark() {
  return (
    <svg viewBox="0 0 16 16" width="22" height="22" aria-hidden="true" focusable="false">
      <path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  )
}

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
          <a className="nav-link nav-gh" href={GITHUB} target="_blank" rel="noreferrer noopener" aria-label="SafeRun on GitHub (opens in a new tab)" title="GitHub"><GithubMark /><span className="nav-gh-text">GitHub</span></a>
          <a className="btn btn-primary nav-cta" href="#/quick-start" onClick={close}>Get Started</a>
        </nav>
      </div>
    </header>
  )
}
