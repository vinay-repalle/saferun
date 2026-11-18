import { useEffect, useState } from 'react'
import { ToTop } from './components/ToTop/ToTop'
import { BenchmarksPage } from './pages/BenchmarksPage/BenchmarksPage'
import { GuidePage } from './pages/GuidePage/GuidePage'
import { LANDING_SECTIONS, LandingPage } from './pages/LandingPage/LandingPage'

/** Pages are switched by the URL hash, no router needed: #/ and #/<section> the website, #/guide the setup guide, #/benchmarks the benchmark results. */
export function App() {
  const [hash, setHash] = useState(window.location.hash)
  useEffect(() => {
    const on = () => setHash(window.location.hash)
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  const route = hash.replace(/^#\/?/, '')
  const page = route === 'guide' ? <GuidePage /> : route === 'benchmarks' ? <BenchmarksPage /> : <LandingPage section={LANDING_SECTIONS.includes(route) ? route : ''} />
  return <>{page}<ToTop /></>
}
