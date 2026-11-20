// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { FILES, render } from './entry-server'

// Pre-rendering runs in Node at build time: no window, no document.
describe('Pre-rendered pages', () => {
  it('render on the server with their real text, so tools that do not run JavaScript can read them', () => {
    expect(typeof window).toBe('undefined')
    const html = Object.fromEntries(FILES.map(([page]) => [page, render(page).html]))
    expect(html.home).toContain('Check the code <em>before</em> you run it.')
    for (const k of ['pip install saferun-cli', 'id="faq"', 'id="security"', 'Which platforms are supported?']) expect(html.home).toContain(k)
    for (const k of ['Set up SafeRun in three steps', 'id="commands"', 'saferun doctor']) expect(html.guide).toContain(k)
    expect(html.benchmarks).toContain('Benchmark: SafeRun vs Bandit')
    expect(html.notfound).toContain('Page not found')
  })

  it('links between pages use real addresses', () => {
    const { html } = render('guide')
    for (const href of ['href="/"', 'href="/guide"', 'href="/benchmarks"', 'href="/#security"', 'href="/#quick-start"']) expect(html).toContain(href)
    expect(html).not.toContain('href="#/')
  })

  it('assumes the animated hero and sections, as most visitors get them', () => {
    const { html } = render('home')
    expect(html).toContain('class="sh sh-live"')
    expect(html).toMatch(/class="sec[^"]* reveal"/)
  })

  it('gives each page its own title', () => {
    expect(render('guide').head).toContain('<title>Setup guide · SafeRun</title>')
    expect(render('notfound').head).toContain('name="robots" content="noindex"')
  })
})
