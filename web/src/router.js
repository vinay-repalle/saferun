import { useSyncExternalStore } from 'react'

// Real URLs, so search engines and AI tools see one page per address: / (the website, with #<section> for its parts), /guide and /benchmarks.
// `npm run build` pre-renders each of them to its own HTML file (scripts/prerender.js). Any other path is the not-found page.
export const PATHS = { home: '/', guide: '/guide', benchmarks: '/benchmarks' }
export const LANDING_SECTIONS = ['product', 'security', 'how', 'features', 'demo', 'quick-start', 'github', 'faq']
export const NAV_EVENT = 'saferun:navigate'

/** The page a path shows: 'home', 'guide', 'benchmarks' or 'notfound'. '/guide/', '/guide.html' and '/index.html' count as the clean path. */
export function pageFor(pathname) {
  const p = pathname.replace(/\.html$/, '').replace(/\/index$/, '/').replace(/(.)\/+$/, '$1') || '/'
  return Object.keys(PATHS).find((k) => PATHS[k] === p) ?? 'notfound'
}

/** Links from before real URLs used hash routes (#/guide, #/security). Returns the real URL such a hash means, or null for an ordinary hash. */
export function fromLegacyHash(hash) {
  const m = /^#\/(.*)$/.exec(hash)
  if (!m) return null
  const r = m[1].replace(/\/+$/, '')
  if (r === 'guide' || r === 'benchmarks') return PATHS[r]
  return LANDING_SECTIONS.includes(r) ? '/#' + r : '/' // anything else (e.g. the removed #/dashboard) opens the website
}

/** Rewrites an old hash-route address in place (no new history entry), so shared links keep working. */
export function upgradeLegacyHash() {
  const to = fromLegacyHash(window.location.hash)
  if (to) window.history.replaceState(null, '', to)
}

/** Where the browser is now, as { page, section }. `section` is a website section named by the hash (#security), else ''. */
export function readLocation(url) {
  const { pathname, hash } = url ? new URL(url, 'http://x') : window.location
  const page = pageFor(pathname)
  const s = hash.replace(/^#/, '')
  return { page, section: page === 'home' && LANDING_SECTIONS.includes(s) ? s : '' }
}

/** Goes to an internal URL without reloading the page. */
export function navigate(to) {
  if (to !== window.location.pathname + window.location.hash) window.history.pushState(null, '', to)
  window.dispatchEvent(new Event(NAV_EVENT))
}

/** Document click handler: plain left clicks on links to our own pages navigate in place. New-tab clicks, other sites and files
 *  (robots.txt, llms.txt) are left to the browser. */
export function onLinkClick(e) {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
  const a = e.target instanceof Element ? e.target.closest('a[href]') : null
  if (!a || (a.target && a.target !== '_self') || a.hasAttribute('download')) return
  const url = new URL(a.getAttribute('href'), window.location.href)
  if (url.origin !== window.location.origin || pageFor(url.pathname) === 'notfound') return
  e.preventDefault()
  navigate(url.pathname + url.hash)
}

const never = () => () => {}
/** False on the server and while the pre-rendered HTML is being hydrated, true afterwards (and from the start in a plain client render).
 *  Browser-only choices (animation, the active section) wait for it, so the first client render matches the server HTML exactly. */
export const useIsClient = () => useSyncExternalStore(never, () => true, () => false)
