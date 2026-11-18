import { useEffect, useRef, useState } from 'react'
import './ToTop.css'

const SHOW_AFTER = 480 // px scrolled before the arrow appears on pages without the scroll-driven hero
const NAV = 64 // height of the sticky navbar
const reduced = () => typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

// On the website the opening hero is a tall pinned stage; the arrow waits until that whole stage is behind you. Other pages have no hero.
const passedHero = () => {
  const hero = document.querySelector('.sh')
  return hero ? hero.getBoundingClientRect().bottom <= NAV : window.scrollY > SHOW_AFTER
}

/** A small "back to top" arrow, fixed in the corner once you have scrolled past the hero (or the first screen on other pages). Key T does the same. It bobs while idle, and on click it flies off the
 *  top of its box while the page scrolls up. With reduced motion it only jumps, with no bobbing or flight. Works on every page. */
export function ToTop() {
  const [shown, setShown] = useState(false)
  const [flying, setFlying] = useState(false)
  const timer = useRef(0)
  useEffect(() => {
    const on = () => setShown(passedHero())
    const route = () => setTimeout(on, 60) // the new page renders just after the hash changes
    on()
    window.addEventListener('scroll', on, { passive: true })
    window.addEventListener('resize', on)
    window.addEventListener('hashchange', route)
    return () => { window.removeEventListener('scroll', on); window.removeEventListener('resize', on); window.removeEventListener('hashchange', route); clearTimeout(timer.current) }
  }, [])
  const go = () => {
    const calm = reduced()
    window.scrollTo({ top: 0, behavior: calm ? 'auto' : 'smooth' })
    if (!calm) { setFlying(true); clearTimeout(timer.current); timer.current = setTimeout(() => setFlying(false), 700) }
  }
  return (
    <button type="button" className={'totop' + (shown ? ' on' : '') + (flying ? ' fly' : '')} onClick={go} aria-label="Back to top" title="Back to top" data-key={shown ? 'T' : undefined}>
      <svg viewBox="0 0 20 24" width="18" height="22" aria-hidden="true" focusable="false">
        <path className="totop-trail" d="M6 20v3M10 18v5M14 20v3" />
        <path className="totop-arrow" d="M10 15V3M4 9l6-6 6 6" />
      </svg>
    </button>
  )
}
