import { useEffect } from 'react'
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

export const LANDING_SECTIONS = ['product', 'security', 'how', 'features', 'demo', 'quick-start', 'github', 'faq']

/** The website. `section` (from the hash, e.g. #/security) is scrolled into view; without it the page starts at the top. */
export function LandingPage({ section = '' }) {
  useEffect(() => {
    const el = section && document.getElementById(section)
    if (el?.scrollIntoView) el.scrollIntoView({ block: 'start' })
    else window.scrollTo?.(0, 0)
  }, [section])
  return (
    <div className="shell">
      <SiteNav current={section ? '#/' + section : ''} />
      <main>
        <ScrollHero /><CheckTicker /><HeroProof /><ProblemSolution /><HowItWorks /><SecuritySection /><Features /><ReportDemo /><QuickStart /><GithubCta /><Faq />
      </main>
      <SiteFooter />
    </div>
  )
}
