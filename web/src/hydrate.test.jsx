// @vitest-environment jsdom
import { act } from 'react'
import { hydrateRoot } from 'react-dom/client'
import { renderToString } from 'react-dom/server'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { App } from './App'
import { pageFor } from './router'

// The browser must take over the pre-rendered HTML exactly as it is: any mismatch would make React log an error and leave stale markup.
// So the first render may not depend on the browser. To prove it, the "server" HTML is made under the opposite animation settings to
// the browser that takes it over: correct code gives the same markup either way.
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); window.history.replaceState(null, '', '/'); document.body.innerHTML = '' })

const bare = () => vi.unstubAllGlobals() // jsdom: no matchMedia, no IntersectionObserver, so nothing animates
const animated = () => {
  vi.stubGlobal('matchMedia', () => ({ matches: false }))
  vi.stubGlobal('requestAnimationFrame', () => 1)
  vi.stubGlobal('IntersectionObserver', class { observe() {} disconnect() {} })
}
const reducedMotion = () => { animated(); vi.stubGlobal('matchMedia', () => ({ matches: true })) }

// The server renders each page once, from its plain path (entry-server.jsx): no #section, and 404.html for every unknown address.
const served = (path) => { const { pathname } = new URL(path, 'http://x'); return pageFor(pathname) === 'notfound' ? '/404' : pathname }

function hydrate(path, serverEnv, browserEnv) {
  serverEnv()
  const html = renderToString(<App url={served(path)} />)
  browserEnv()
  window.HTMLElement.prototype.scrollIntoView = vi.fn(); window.scrollTo = vi.fn()
  window.history.replaceState(null, '', path)
  const el = document.createElement('div'); el.innerHTML = html; document.body.append(el)
  const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
  const recoverable = vi.fn()
  let root
  act(() => { root = hydrateRoot(el, <App />, { onRecoverableError: recoverable }) })
  const clean = () => { expect(recoverable).not.toHaveBeenCalled(); expect(errors).not.toHaveBeenCalled() }
  return { el, clean, unmount: () => act(() => root.unmount()) }
}

describe('Hydration', () => {
  for (const path of ['/', '/#security', '/guide', '/benchmarks', '/nope']) {
    it(`takes over ${path} without a mismatch, whatever the browser supports`, () => {
      for (const [server, browser] of [[animated, bare], [bare, animated], [animated, reducedMotion]]) {
        const { el, clean, unmount } = hydrate(path, server, browser)
        clean()
        expect(el.querySelector('h1')).not.toBeNull()
        unmount(); document.body.innerHTML = ''; vi.restoreAllMocks()
      }
    })
  }

  it('then settles into what the browser supports', () => {
    let h = hydrate('/', bare, animated)
    expect(h.el.querySelector('.sh').className).toContain('sh-live')
    expect(h.el.querySelector('#features').className).toContain('reveal')
    h.unmount(); document.body.innerHTML = ''
    h = hydrate('/', animated, reducedMotion)
    expect(h.el.querySelector('.sh').className).not.toContain('sh-live')
    expect(h.el.querySelector('#features').className).not.toContain('reveal')
    h.unmount()
  })
})
