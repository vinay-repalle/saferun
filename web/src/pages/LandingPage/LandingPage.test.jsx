// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { App } from '../../App'
import { GITHUB } from '../../content/site'
import { LandingPage } from './LandingPage'

afterEach(() => { vi.restoreAllMocks(); window.location.hash = '' })

describe('Landing page', () => {
  it('has the navbar, hero CTAs and trust indicators', () => {
    const { container } = render(<LandingPage />)
    const nav = screen.getByRole('navigation', { name: 'Main' })
    for (const n of ['Product', 'Security', 'How it works', 'Documentation', 'GitHub', 'Get Started']) expect(nav.textContent).toContain(n)
    expect(container.querySelector('h1').textContent).toMatch(/before/)
    expect(screen.getAllByRole('link', { name: /View on GitHub/ })[0].getAttribute('href')).toBe(GITHUB)
    for (const t of ['Scans work offline', 'Locked-down containers', 'Pinned analyzer image']) expect(container.textContent).toContain(t)
  })

  it('links to the dashboard, the guide and the real repository only', () => {
    const { container } = render(<LandingPage />)
    const hrefs = [...container.querySelectorAll('a')].map((a) => a.getAttribute('href'))
    expect(hrefs).toContain('#/dashboard'); expect(hrefs).toContain('#/guide')
    for (const h of hrefs.filter((x) => x.startsWith('http'))) expect(h.startsWith('https://github.com/vinay-repalle/saferun')).toBe(true)
    for (const a of container.querySelectorAll('a[target=_blank]')) expect(a.getAttribute('rel')).toMatch(/noopener/)
  })

  it('every nav link and CTA is a real link; section links target sections that exist', () => {
    const { container } = render(<LandingPage />)
    for (const id of ['product', 'security', 'how', 'features', 'demo', 'quick-start', 'github', 'faq']) expect(container.querySelector('#' + id)).not.toBeNull()
    const nav = screen.getByRole('navigation', { name: 'Main' })
    const hrefs = Object.fromEntries([...nav.querySelectorAll('a')].map((a) => [a.textContent, a.getAttribute('href')]))
    expect(hrefs).toMatchObject({ Product: '#/product', Security: '#/security', 'How it works': '#/how', Documentation: '#/guide', Dashboard: '#/dashboard', 'Get Started': '#/quick-start', GitHub: GITHUB })
  })

  it('scrolls to the section named by the route', () => {
    const scroll = vi.fn(); window.HTMLElement.prototype.scrollIntoView = scroll
    render(<LandingPage section="security" />)
    expect(scroll).toHaveBeenCalledTimes(1)
  })

  it('mobile menu toggles', () => {
    render(<LandingPage />)
    const b = screen.getByRole('button', { name: 'Open menu' })
    fireEvent.click(b)
    expect(b.getAttribute('aria-expanded')).toBe('true')
  })

  it('demo is labelled as a demonstration and switches between PASS, WARNING and FAIL', () => {
    const { container } = render(<LandingPage />)
    expect(container.querySelector('#demo').textContent).toMatch(/Demonstration only · no scan was run/)
    for (const v of ['PASS', 'WARNING', 'FAIL']) {
      fireEvent.click(screen.getByRole('tab', { name: v }))
      expect(container.querySelector('.verdict').textContent).toBe('Verdict: ' + v)
    }
  })

  it('quick start shows the real commands and copy puts only the command on the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue()
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    const { container } = render(<LandingPage />)
    const qs = container.querySelector('#quick-start').textContent
    for (const c of ['saferun init', 'saferun status', 'saferun scan ./my-project']) expect(qs).toContain(c)
    fireEvent.click(screen.getByRole('button', { name: 'Copy command: saferun scan ./my-project' }))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('saferun scan ./my-project'))
  })

  it('invents no statistics and uses no inline styles or scripts (CSP)', () => {
    const { container } = render(<LandingPage />)
    expect(container.textContent).not.toMatch(/stars|downloads|\d+\s*(users|developers)/i)
    expect(container.querySelectorAll('[style]')).toHaveLength(0)
    expect(container.querySelectorAll('script')).toHaveLength(0)
  })

  it('FAQ covers installation, Docker, Cosign, offline, languages and limits', () => {
    const t = render(<LandingPage />).container.querySelector('#faq').textContent
    for (const k of ['install', 'Docker', 'Cosign', 'internet', 'languages', 'safe']) expect(t).toContain(k)
  })
})

describe('Scroll hero', () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

  it('shows its finished state, not pinned, when animation is unavailable', () => {
    const { container } = render(<LandingPage />)
    expect(container.querySelector('.sh').className).not.toContain('sh-live')
    expect(container.querySelector('h1').textContent).toMatch(/before/)
    expect(container.querySelectorAll('.sh-card[aria-hidden=true]')).toHaveLength(2)
  })

  it('is not animated with reduced motion', () => {
    vi.stubGlobal('matchMedia', () => ({ matches: true }))
    expect(render(<LandingPage />).container.querySelector('.sh').className).not.toContain('sh-live')
  })

  it('scroll position drives it: headline takes over late in the scroll, and reverses', () => {
    vi.stubGlobal('matchMedia', (q) => ({ matches: q.includes('hover') ? false : false }))
    vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockImplementation(function () { return this.classList.contains('sh-pin') ? 400 : 1000 })
    let top = 64
    vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function () { return this.classList.contains('sh') ? { top, left: 0, width: 100, height: 1000 } : { top: 0, left: 0, width: 100, height: 100 } })
    let queued = null
    vi.stubGlobal('requestAnimationFrame', (f) => { queued = f; return 1 })
    const flush = () => { const f = queued; queued = null; f?.() }
    const { container } = render(<LandingPage />)
    const sh = container.querySelector('.sh')
    expect(sh.className).toContain('sh-live')
    expect(sh.className).not.toContain('sh-copy-on')
    top = 64 - 540 // 90% through the 600px of scroll range
    fireEvent.scroll(window); flush()
    expect(sh.className).toContain('sh-copy-on')
    top = 64
    fireEvent.scroll(window); flush()
    expect(sh.className).not.toContain('sh-copy-on')
  })
})

describe('Cursor tilt', () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

  it('follows the cursor on fine pointers and resets when it leaves', () => {
    vi.stubGlobal('matchMedia', (q) => ({ matches: q.includes('hover') }))
    vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({ top: 0, left: 0, width: 1000, height: 500 })
    const { container } = render(<LandingPage />)
    const sh = container.querySelector('.sh'); const pin = container.querySelector('.sh-pin')
    fireEvent.pointerMove(pin, { clientX: 1000, clientY: 0 })
    expect(sh.style.getPropertyValue('--mx')).toBe('1')
    expect(sh.style.getPropertyValue('--my')).toBe('-1')
    fireEvent.pointerLeave(pin)
    expect(sh.style.getPropertyValue('--mx')).toBe('0')
  })

  it('does not listen for the cursor on touch devices', () => {
    vi.stubGlobal('matchMedia', () => ({ matches: false }))
    const { container } = render(<LandingPage />)
    fireEvent.pointerMove(container.querySelector('.sh-pin'), { clientX: 500, clientY: 200 })
    expect(container.querySelector('.sh').style.getPropertyValue('--mx')).toBe('')
  })
})

describe('Routing', () => {
  it('serves the website by default and keeps the dashboard and guide reachable', () => {
    window.location.hash = ''
    const a = render(<App />); expect(a.container.querySelector('#product')).not.toBeNull(); a.unmount()
    window.location.hash = '#/dashboard'
    const b = render(<App />); expect(b.container.querySelector('.layout')).not.toBeNull(); b.unmount()
    window.location.hash = '#/guide'
    const c = render(<App />); expect(c.container.querySelector('.guide')).not.toBeNull(); c.unmount()
  })

  it('all three pages share the same navbar and footer, with working links between them', () => {
    for (const h of ['', '#/dashboard', '#/guide']) {
      window.location.hash = h
      const { container, unmount } = render(<App />)
      expect(container.querySelectorAll('header.nav')).toHaveLength(1)
      expect(container.querySelectorAll('footer.foot')).toHaveLength(1)
      const hrefs = [...container.querySelectorAll('nav[aria-label=Main] a')].map((a) => a.getAttribute('href'))
      expect(hrefs).toEqual(expect.arrayContaining(['#/guide', '#/dashboard', '#/product', '#/quick-start']))
      unmount()
    }
  })

  it('the landing page reuses the guide text instead of duplicating it', async () => {
    const { SAFETY, HONEST_LIMITS, STEPS } = await import('../../content/site')
    const text = render(<LandingPage />).container.textContent
    for (const [t, d] of SAFETY) { expect(text).toContain(t); expect(text).toContain(d) }
    expect(text).toContain(HONEST_LIMITS)
    for (const [, , cmd] of STEPS) expect(text).toContain(cmd)
  })
})
