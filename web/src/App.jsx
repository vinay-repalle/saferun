import { useEffect, useLayoutEffect, useState } from 'react'
import { ToTop } from './components/ToTop/ToTop'
import { BenchmarksPage } from './pages/BenchmarksPage/BenchmarksPage'
import { GuidePage } from './pages/GuidePage/GuidePage'
import { LandingPage } from './pages/LandingPage/LandingPage'
import { NotFoundPage } from './pages/NotFoundPage/NotFoundPage'
import { NAV_EVENT, onLinkClick, readLocation, upgradeLegacyHash } from './router'
import { applyHead } from './seo'

const where = (push) => { upgradeLegacyHash(); return { ...readLocation(), push } }

/** Pages have real URLs (see router.js): / the website and /#<section> its parts, /guide the setup guide, /benchmarks the benchmark results.
 *  `url` is given only when pre-rendering on the server; in the browser the address bar decides. Clicks on our own links navigate in place. */
export function App({ url }) {
  const [at, setAt] = useState(() => (url ? readLocation(url) : where(false)))
  useEffect(() => {
    const pushed = () => setAt(where(true))
    const popped = () => setAt(where(false))
    window.addEventListener(NAV_EVENT, pushed)
    window.addEventListener('popstate', popped)
    document.addEventListener('click', onLinkClick)
    return () => { window.removeEventListener(NAV_EVENT, pushed); window.removeEventListener('popstate', popped); document.removeEventListener('click', onLinkClick) }
  }, [])
  useEffect(() => { applyHead(at.page) }, [at.page])
  // A link to another page opens it at the top (the website scrolls itself, to its section or the top).
  useLayoutEffect(() => { if (at.push && at.page !== 'home') window.scrollTo?.(0, 0) }, [at])
  const page = at.page === 'guide' ? <GuidePage /> : at.page === 'benchmarks' ? <BenchmarksPage /> : at.page === 'notfound' ? <NotFoundPage /> : <LandingPage section={at.section} visit={at} />
  return <>{page}<ToTop /></>
}
