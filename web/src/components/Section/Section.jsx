import { useEffect, useRef, useState } from 'react'
import './Section.css'

const canAnimate = () => typeof IntersectionObserver !== 'undefined' && !(typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches)

/** A full-width page band. `alt` gives it the raised background. It fades up once when scrolled into view; without
 *  IntersectionObserver or with reduced motion it is simply shown (no hidden state is ever applied). */
export function Section({ id, alt = false, children }) {
  const ref = useRef(null)
  const [phase, setPhase] = useState(() => (canAnimate() ? 'armed' : 'off'))
  useEffect(() => {
    if (phase !== 'armed') return undefined
    const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setPhase('in'); io.disconnect() } }, { threshold: 0.1 })
    io.observe(ref.current)
    return () => io.disconnect()
  }, [phase])
  const cls = 'sec' + (alt ? ' sec-alt' : '') + (phase === 'off' ? '' : phase === 'in' ? ' reveal in' : ' reveal')
  return <section className={cls} id={id} ref={ref}><div className="wrap">{children}</div></section>
}

/** Numbered section heading; `accent` is the italic blue tail of the title. */
export function SectionHead({ n, title, accent, sub }) {
  return (
    <div className="sec-head">
      <p className="sec-num">{n}</p>
      <h2>{title} {accent && <em>{accent}</em>}</h2>
      {sub && <p className="sec-sub">{sub}</p>}
    </div>
  )
}
