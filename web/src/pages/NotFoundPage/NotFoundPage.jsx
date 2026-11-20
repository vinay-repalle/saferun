import { SiteFooter } from '../../components/SiteFooter/SiteFooter'
import { SiteNav } from '../../components/SiteNav/SiteNav'
import './NotFoundPage.css'

/** Any address that is not a page. Pre-rendered as 404.html, which the host serves with a 404 status; it is marked noindex. */
export function NotFoundPage() {
  return (
    <div className="shell">
      <SiteNav />
      <main className="wrap nf">
        <p className="sec-num">404</p>
        <h1>Page not found</h1>
        <p className="nf-lead">There is no page at this address. It may have moved when the site switched to real page addresses.</p>
        <ul className="nf-links">
          <li><a href="/">SafeRun home</a></li>
          <li><a href="/guide">Setup guide</a></li>
          <li><a href="/benchmarks">Benchmark</a></li>
        </ul>
      </main>
      <SiteFooter />
    </div>
  )
}
