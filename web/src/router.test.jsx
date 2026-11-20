// @vitest-environment jsdom
import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { App } from './App'
import { setShortcuts } from './components/SiteNav/shortcuts'
import { fromLegacyHash, pageFor } from './router'

afterEach(() => { vi.restoreAllMocks(); window.history.replaceState(null, '', '/'); setShortcuts(true) })
const go = (path) => window.history.replaceState(null, '', path)
const canonical = () => document.head.querySelector('link[rel=canonical]')?.getAttribute('href')

describe('Addresses', () => {
  it('maps paths to pages, with or without a trailing slash or .html', () => {
    for (const p of ['/', '/index.html']) expect(pageFor(p)).toBe('home')
    for (const p of ['/guide', '/guide/', '/guide.html']) expect(pageFor(p)).toBe('guide')
    expect(pageFor('/benchmarks')).toBe('benchmarks')
    for (const p of ['/nope', '/robots.txt', '/guide/x']) expect(pageFor(p)).toBe('notfound')
  })

  it('turns old hash-route links into real addresses', () => {
    expect(fromLegacyHash('#/guide')).toBe('/guide')
    expect(fromLegacyHash('#/benchmarks/')).toBe('/benchmarks')
    expect(fromLegacyHash('#/security')).toBe('/#security')
    expect(fromLegacyHash('#/')).toBe('/')
    expect(fromLegacyHash('#/dashboard')).toBe('/')
    expect(fromLegacyHash('#security')).toBeNull()
    expect(fromLegacyHash('')).toBeNull()
  })

  it('an old #/guide link opens the guide at /guide, without adding a history entry', () => {
    go('/#/guide')
    const before = window.history.length
    const { container } = render(<App />)
    expect(window.location.pathname).toBe('/guide')
    expect(window.location.hash).toBe('')
    expect(window.history.length).toBe(before)
    expect(container.querySelector('.guide')).not.toBeNull()
  })

  it('an old #/security link opens the website at that section', () => {
    window.HTMLElement.prototype.scrollIntoView = vi.fn()
    go('/#/security')
    render(<App />)
    expect(window.location.pathname + window.location.hash).toBe('/#security')
    expect(window.HTMLElement.prototype.scrollIntoView).toHaveBeenCalled()
  })

  it('an unknown address shows the not-found page, marked noindex', () => {
    go('/no-such-page')
    const { container } = render(<App />)
    expect(container.querySelector('h1').textContent).toBe('Page not found')
    expect(document.head.querySelector('meta[name=robots]').getAttribute('content')).toBe('noindex')
    expect(canonical()).toBeUndefined()
  })
})

describe('Navigation in place', () => {
  it('clicking Docs opens /guide without a reload, with its own title and canonical link; Back returns', () => {
    window.scrollTo = vi.fn()
    const { container } = render(<App />)
    expect(document.title).toBe('SafeRun: check code before you run it')
    expect(canonical()).toBe('https://safe-run.netlify.app/')
    const click = fireEvent.click(screen.getByRole('link', { name: 'Docs' }))
    expect(click).toBe(false) // default prevented: no page load
    expect(window.location.pathname).toBe('/guide')
    expect(container.querySelector('.guide')).not.toBeNull()
    expect(document.title).toBe('Setup guide · SafeRun')
    expect(canonical()).toBe('https://safe-run.netlify.app/guide')
    expect(window.scrollTo).toHaveBeenCalledWith(0, 0)
    act(() => { window.history.replaceState(null, '', '/'); window.dispatchEvent(new PopStateEvent('popstate')) })
    expect(container.querySelector('#product')).not.toBeNull()
    expect(document.title).toBe('SafeRun: check code before you run it')
  })

  it('a section link from another page opens the website at that section and marks it current', () => {
    const scroll = vi.fn(); window.HTMLElement.prototype.scrollIntoView = scroll
    go('/benchmarks')
    render(<App />)
    fireEvent.click(screen.getByRole('link', { name: 'Security' }))
    expect(window.location.pathname + window.location.hash).toBe('/#security')
    expect(scroll).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('link', { name: 'Security' }).getAttribute('aria-current')).toBe('page')
    fireEvent.click(screen.getByRole('link', { name: 'Security' })) // again: scrolls back to it
    expect(scroll).toHaveBeenCalledTimes(2)
  })

  it('keyboard shortcuts still work: D opens the guide', () => {
    const { container } = render(<App />)
    fireEvent.keyDown(document.body, { key: 'd' })
    expect(window.location.pathname).toBe('/guide')
    expect(container.querySelector('.guide')).not.toBeNull()
  })

  it('leaves new-tab clicks and external links to the browser', () => {
    render(<App />)
    expect(fireEvent.click(screen.getByRole('link', { name: 'Docs' }), { ctrlKey: true })).toBe(true)
    expect(fireEvent.click(screen.getByRole('link', { name: 'Docs' }), { button: 1 })).toBe(true)
    expect(fireEvent.click(screen.getByRole('link', { name: /SafeRun on GitHub/ }))).toBe(true)
    expect(window.location.pathname).toBe('/')
  })
})
