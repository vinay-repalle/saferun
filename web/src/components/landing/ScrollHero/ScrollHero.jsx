import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { GITHUB, INSTALL, PYPI_VERSION, VERSION } from '../../../content/site'
import { CommandBlock } from '../../CommandBlock/CommandBlock'
import { Emblem } from '../../Emblem/Emblem'
import './ScrollHero.css'

const NAV = 64 // height of the sticky navbar: the stage pins just below it

// A decorative 6 x 10 grid of "files". The same positions are flagged on the left and judged on the right. No real data.
const COLS = 6
const CELLS = Array.from({ length: 60 }, (_, i) => ({ i, row: Math.floor(i / COLS), kind: i % 11 === 3 ? 'fail' : i % 7 === 2 ? 'warn' : 'ok' }))

const clamp = (n) => Math.min(1, Math.max(0, n))
const seg = (p, a, b) => clamp((p - a) / (b - a)) // progress of p between a and b

const canAnimate = () => typeof window.matchMedia === 'function' && !window.matchMedia('(prefers-reduced-motion: reduce)').matches

function Card({ side, title, status }) {
  return (
    <div className={'sh-card sh-' + side} aria-hidden="true">
      <div className="sh-tilt">
        <div className="sh-head"><span>{title}</span><b>{status}</b></div>
        <div className="sh-gridwrap">
          <div className="sh-grid">{CELLS.map((c) => <i key={c.i} className={`c ${c.kind} row-${c.row}`} />)}</div>
          {side === 'r' && <div className="sh-beam" />}
        </div>
      </div>
    </div>
  )
}

/**
 * The opening of the website. A tall "stage" keeps the hero pinned while you scroll through it: the logo is alone, two cards slide in from the
 * sides, a scan lights up the report, then the headline takes over. Scrolling back up plays it in reverse. Scroll position is written to CSS
 * variables (--p1 cards in, --p2 scan, --p3 headline) and the cursor to --mx/--my (tilt). Without animation (reduced motion, no matchMedia)
 * the stage is not tall or pinned and simply shows its finished state.
 */
export function ScrollHero() {
  const stage = useRef(null)
  const [live] = useState(canAnimate)

  useLayoutEffect(() => {
    if (!live) return undefined
    const el = stage.current
    const pin = el.firstElementChild
    let raf = 0
    const update = () => {
      raf = 0
      const range = el.offsetHeight - pin.offsetHeight
      const p = range > 0 ? clamp((NAV - el.getBoundingClientRect().top) / range) : 0
      const p3 = seg(p, 0.7, 0.95)
      el.style.setProperty('--p1', seg(p, 0.05, 0.35))
      el.style.setProperty('--p2', seg(p, 0.3, 0.7))
      el.style.setProperty('--p3', p3)
      el.classList.toggle('sh-copy-on', p3 > 0.5)
    }
    const schedule = () => { if (!raf) raf = requestAnimationFrame(update) }
    update()
    window.addEventListener('scroll', schedule, { passive: true })
    window.addEventListener('resize', schedule)

    // Mouse tilt and spotlight: fine pointers only.
    const hover = window.matchMedia('(hover: hover) and (pointer: fine)').matches
    const move = (e) => {
      const r = pin.getBoundingClientRect()
      el.style.setProperty('--mx', clamp((e.clientX - r.left) / r.width) * 2 - 1)
      el.style.setProperty('--my', clamp((e.clientY - r.top) / r.height) * 2 - 1)
    }
    const leave = () => { el.style.setProperty('--mx', 0); el.style.setProperty('--my', 0) }
    if (hover) { pin.addEventListener('pointermove', move); pin.addEventListener('pointerleave', leave) }
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('scroll', schedule); window.removeEventListener('resize', schedule)
      pin.removeEventListener('pointermove', move); pin.removeEventListener('pointerleave', leave)
    }
  }, [live])

  return (
    <section className={'sh' + (live ? ' sh-live' : '')} ref={stage}>
      <div className="sh-pin">
        <div className="wrap sh-stage">
          <Card side="l" title="Submitted project" status="not run" />
          <div className="sh-center">
            <div className="sh-intro" aria-hidden="true">
              <Emblem className="sh-logo" />
              <p className="sh-word">SafeRun</p>
              <p className="sh-cue"><span aria-hidden="true">↓</span> Scroll to see how it works</p>
            </div>
            <div className="sh-copy">
              <p className="eyebrow"><span className="dot" /> Pre-run verification for untrusted code</p>
              <a className="sh-release" href={PYPI_VERSION} target="_blank" rel="noreferrer noopener">v{VERSION} · alpha · available on PyPI <span aria-hidden="true">↗</span></a>
              <h1>Check the code <em>before</em> you run it.</h1>
              <p className="lede">SafeRun inspects AI-generated and downloaded projects inside a locked-down, offline container, and gives you a PASS, WARNING or FAIL verdict, without executing the program you submitted.</p>
              <div className="sh-cta">
                <a className="btn btn-primary" href="#/quick-start">Get Started</a>
                <a className="btn btn-ghost" href={GITHUB} target="_blank" rel="noreferrer noopener">View on GitHub <span aria-hidden="true">↗</span></a>
              </div>
              <div className="sh-install"><CommandBlock command={INSTALL} /></div>
            </div>
          </div>
          <Card side="r" title="Verified report" status="sample" />
        </div>
      </div>
    </section>
  )
}
