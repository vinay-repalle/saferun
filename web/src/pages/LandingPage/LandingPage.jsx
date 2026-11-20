import { useEffect } from 'react'
import { LANDING_SECTIONS, useIsClient } from '../../router'
import { SiteFooter } from '../../components/SiteFooter/SiteFooter'
import { SiteNav } from '../../components/SiteNav/SiteNav'
import { CheckTicker } from '../../components/landing/CheckTicker/CheckTicker'
import { Faq } from '../../components/landing/Faq/Faq'
import { Features } from '../../components/landing/Features/Features'
import { GithubCta } from '../../components/landing/GithubCta/GithubCta'
import { HeroProof } from '../../components/landing/HeroProof/HeroProof'
import { HowItWorks } from '../../components/landing/HowItWorks/HowItWorks'
import { ProblemSolution } from '../../components/landing/ProblemSolution/ProblemSolution'
import { QuickStart } from '../../components/landing/QuickStart/QuickStart'
import { ReportDemo } from '../../components/landing/ReportDemo/ReportDemo'
import { ScrollHero } from '../../components/landing/ScrollHero/ScrollHero'
import { SecuritySection } from '../../components/landing/SecuritySection/SecuritySection'

export { LANDING_SECTIONS }

/** The website. `section` (from the hash, e.g. /#security) is scrolled into view; without it the page starts at the top. `visit` changes on
 *  every navigation, so clicking a section link again scrolls back to it. */
export function LandingPage({ section = '', visit }) {
  const client = useIsClient()
  useEffect(() => {
    const el = section && document.getElementById(section)
    if (el?.scrollIntoView) el.scrollIntoView({ block: 'start' })
    else window.scrollTo?.(0, 0)
  }, [section, visit])
  return (
    <div className="shell">
      {/* The pre-rendered page has no section; the highlight waits for the browser so the first render matches it. */}
      <SiteNav current={client && section ? '/#' + section : ''} />
      <main>
        <ScrollHero /><CheckTicker /><HeroProof /><ProblemSolution /><HowItWorks /><SecuritySection /><Features /><ReportDemo /><QuickStart /><GithubCta /><Faq />
      </main>
      <SiteFooter />
    </div>
  )
}
