// @vitest-environment jsdom
import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SiteNav } from '../SiteNav/SiteNav'
import { setShortcuts } from '../SiteNav/shortcuts'
import { ToTop } from './ToTop'

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); window.scrollY = 0; setShortcuts(true); document.body.innerHTML = '' })
const scrollTo = (y) => act(() => { window.scrollY = y; window.dispatchEvent(new Event('scroll')) })
const btn = (opts) => screen.getByRole('button', { name: 'Back to top', ...opts })

describe('Back to top (pages without the hero)', () => {
  it('appears only after scrolling past the first screen', () => {
    render(<ToTop />)
    expect(btn({ hidden: true }).className).not.toContain('on')
    scrollTo(900); expect(btn().className).toContain('on')
    scrollTo(10); expect(btn({ hidden: true }).className).not.toContain('on')
  })

  it('scrolls smoothly to the top and plays the flight', () => {
    const spy = vi.spyOn(window, 'scrollTo').mockImplementation(() => {})
    vi.stubGlobal('matchMedia', () => ({ matches: false }))
    render(<ToTop />); scrollTo(900)
    fireEvent.click(btn())
    expect(spy).toHaveBeenCalledWith({ top: 0, behavior: 'smooth' })
    expect(btn().className).toContain('fly')
  })

  it('only jumps, with no flight, when reduced motion is requested', () => {
    const spy = vi.spyOn(window, 'scrollTo').mockImplementation(() => {})
    vi.stubGlobal('matchMedia', () => ({ matches: true }))
    render(<ToTop />); scrollTo(900)
    fireEvent.click(btn())
    expect(spy).toHaveBeenCalledWith({ top: 0, behavior: 'auto' })
    expect(btn().className).not.toContain('fly')
  })
})

describe('Back to top (website with the scroll-driven hero)', () => {
  const withHero = (bottom) => {
    const hero = document.createElement('section'); hero.className = 'sh'; document.body.append(hero)
    const rect = vi.spyOn(hero, 'getBoundingClientRect'); const set = (b) => rect.mockReturnValue({ bottom: b })
    set(bottom); return set
  }

  it('waits until the whole hero stage is behind you, however far down you have scrolled inside it', () => {
    const set = withHero(1200)
    render(<ToTop />)
    scrollTo(900); expect(btn({ hidden: true }).className).not.toContain('on') // deep inside the hero: still hidden
    set(40); scrollTo(2500); expect(btn().className).toContain('on')            // hero bottom is above the navbar
    set(300); scrollTo(2300); expect(btn({ hidden: true }).className).not.toContain('on')
  })
})

describe('Back to top shortcut', () => {
  it('"T" goes to the top, but only while the arrow is showing, and honours the shortcut switch', () => {
    const spy = vi.spyOn(window, 'scrollTo').mockImplementation(() => {})
    render(<><SiteNav /><ToTop /></>)
    fireEvent.keyDown(document.body, { key: 't' }); expect(spy).not.toHaveBeenCalled() // hidden: nothing to activate
    scrollTo(900)
    expect(btn().getAttribute('data-key')).toBe('T')
    fireEvent.keyDown(document.body, { key: 't' }); expect(spy).toHaveBeenCalledTimes(1)
    setShortcuts(false)
    fireEvent.keyDown(document.body, { key: 't' }); expect(spy).toHaveBeenCalledTimes(1)
  })
})
