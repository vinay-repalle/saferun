// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { GuidePage } from './GuidePage'

afterEach(() => vi.restoreAllMocks())

describe('Guide page', () => {
  it('documents the real setup commands and every component', () => {
    const text = render(<GuidePage />).container.textContent
    for (const c of ['saferun init', 'saferun init --all', '--only', '--skip', '--repair', 'saferun status', 'saferun osv-db update', 'saferun osv-db status']) {
      expect(text).toContain(c)
    }
    for (const k of ['python', 'node', 'analyzer', 'osv-db']) expect(text).toContain(k)
  })

  it('documents the signed analyzer release as the default and the local build as the alternative: cosign, --build-local and --signature', () => {
    const text = render(<GuidePage />).container.textContent
    for (const c of ['--build-local', 'saferun verify-images --signature', 'Setup cannot fetch cosign', 'The analyzer is a signed, digest-pinned image', 'analyzer-v1.0.1', 'signed download']) {
      expect(text).toContain(c)
    }
    expect(text).not.toMatch(/No signed analyzer release has been published yet/)
    expect(text).not.toMatch(/built locally for now|Not needed today/)
  })

  it('gives a complete, correct beginner setup: Docker, init, status, first scan, with cosign before init, then an optional signature check', () => {
    const { container } = render(<GuidePage />)
    const setup = container.querySelector('#setup').textContent
    for (const c of ['python3 --version', 'docker info', 'pip install saferun-cli', 'saferun init', 'saferun doctor', 'saferun status', 'saferun run my_script.py',
      'saferun verify-images --signature', 'saferun scan ./my-project']) expect(setup).toContain(c)
    expect(container.querySelectorAll('.g-walk > li')).toHaveLength(7)
    const walk = container.querySelector('.g-walk').textContent
    expect(walk).toMatch(/cosign/i)
    expect(walk.indexOf('Install SafeRun from PyPI')).toBeLessThan(walk.indexOf('Set SafeRun up'))
    expect(walk).not.toMatch(/verify-images/i)
    const future = container.querySelector('.g-future')
    expect(future.textContent).toContain('Verify the signed analyzer release')
    expect(future.querySelectorAll('li')).toHaveLength(1)
    expect(future.textContent).toContain('saferun verify-images --signature')
    expect(setup).toMatch(/You do not install cosign yourself/)
    expect(setup).not.toMatch(/git clone|pip install -e|not published on PyPI/)
    const concepts = container.querySelector('#concepts').textContent
    for (const c of ['Docker downloads', 'Cosign verifies the signed analyzer', 'pinned by digest', 'without network']) expect(concepts).toContain(c)
    expect(container.querySelector('#fix').textContent).toMatch(/command not found/)
  })

  it('explains offline operation and missing components, and no longer mentions installing host tools or online OSV', () => {
    const text = render(<GuidePage />).container.textContent
    expect(text).toMatch(/Working offline/)
    expect(text).toMatch(/If something is missing or outdated/)
    expect(text).toMatch(/never need the internet/)
    expect(text).not.toMatch(/pip install[^.]*analysis/)
    expect(text).not.toMatch(/Install osv-scanner/)
    expect(text).not.toMatch(/Online, package names/)
  })

  it('shows the three steps, the status meanings and the three verdicts', () => {
    const { container } = render(<GuidePage />)
    expect(container.querySelectorAll('.g-steps > li')).toHaveLength(3)
    for (const s of ['READY', 'MISSING', 'INVALID', 'OUTDATED']) expect(container.querySelector('.g-states').textContent).toContain(s)
    expect([...container.querySelectorAll('.g-verdict h3')].map((n) => n.textContent)).toEqual(['PASS', 'WARNING', 'FAIL'])
    expect(container.querySelectorAll('#components .g-comp')).toHaveLength(4)
  })

  it('states the honest limits next to the safety claims', () => {
    const { container } = render(<GuidePage />)
    const safety = container.querySelector('#safety').textContent
    expect(safety).toMatch(/cannot prove the original download was genuine/)
    expect(safety).toMatch(/not that the code is safe/)
  })

  it('copy buttons put only the command (no prompt) on the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue()
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    render(<GuidePage />)
    fireEvent.click(screen.getAllByRole('button', { name: 'Copy command: saferun status' })[0])
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('saferun status'))
    expect(await screen.findAllByText('Copied')).not.toHaveLength(0)
  })

  it('a failing clipboard degrades to a hint instead of an error', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: vi.fn().mockRejectedValue(new Error('denied')) }, configurable: true })
    render(<GuidePage />)
    fireEvent.click(screen.getAllByRole('button', { name: /Copy command: saferun init$/ })[0])
    expect(await screen.findAllByText('Press Ctrl+C')).not.toHaveLength(0)
  })

  it('the table of contents scrolls to real sections without changing the hash route', () => {
    const scroll = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scroll
    const before = window.location.hash
    const { container } = render(<GuidePage />)
    const ids = ['quick-start', 'platforms', 'setup', 'concepts', 'components', 'commands', 'checks', 'verdicts', 'fix', 'offline', 'safety', 'release']
    const buttons = [...container.querySelectorAll('.g-toc button')]
    expect(buttons).toHaveLength(ids.length)
    for (const id of ids) expect(container.querySelector('#' + id)).not.toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Commands' }))
    expect(scroll).toHaveBeenCalledTimes(1)
    expect(window.location.hash).toBe(before)
  })

  it('uses no inline styles or scripts (keeps the site compatible with a strict CSP)', () => {
    const { container } = render(<GuidePage />)
    expect(container.querySelectorAll('[style]')).toHaveLength(0)
    expect(container.querySelectorAll('script')).toHaveLength(0)
  })

  it('presents Ubuntu/Linux, Windows and macOS as tabs on one page, one walkthrough at a time', () => {
    const { container } = render(<GuidePage />)
    const tabs = screen.getAllByRole('tab')
    expect(tabs.map((t) => t.textContent)).toEqual(['Ubuntu / Linux', 'Windows', 'macOS'])
    expect(tabs[0].getAttribute('aria-selected')).toBe('true')
    expect(container.querySelector('#os-panel').textContent).toContain('sudo apt install')

    fireEvent.click(screen.getByRole('tab', { name: 'Windows' }))
    const win = container.querySelector('#os-panel').textContent
    for (const c of ['py -3.12 --version', 'Switch to Linux containers', 'saferun-env\\Scripts\\Activate.ps1', 'pip install saferun-cli', 'saferun init', 'UNC']) expect(win).toContain(c)
    expect(win).not.toContain('sudo apt install')
    expect(container.querySelectorAll('.g-walk > li')).toHaveLength(5)

    fireEvent.click(screen.getByRole('tab', { name: 'macOS' }))
    const mac = container.querySelector('#os-panel').textContent
    for (const c of ['brew install python@3.12', 'Docker Desktop', 'pip install saferun-cli', 'saferun scan ./my-project']) expect(mac).toContain(c)
    expect(screen.getByRole('tab', { name: 'macOS' }).getAttribute('aria-selected')).toBe('true')
  })

  it('tabs can be switched with the arrow keys', () => {
    render(<GuidePage />)
    fireEvent.keyDown(screen.getByRole('tab', { name: 'Ubuntu / Linux' }), { key: 'ArrowRight' })
    expect(screen.getByRole('tab', { name: 'Windows' }).getAttribute('aria-selected')).toBe('true')
  })

  it('states the platform status honestly: Docker Desktop unverified, and never says WSL is required', () => {
    const { container } = render(<GuidePage />)
    const text = container.textContent
    expect(container.querySelector('#platforms').textContent).toContain('Docker Desktop integration on Windows and macOS has not yet been manually verified')
    expect(text).toContain('Windows 10/11')
    expect(text).not.toMatch(/requires? WSL|WSL ?2? (is|are) required|(must|need to|have to) (have |install |enable )?WSL/i)
    for (const os of ['Windows', 'macOS']) fireEvent.click(screen.getByRole('tab', { name: os }))
    expect(container.textContent).toMatch(/not yet been manually verified/)
  })

  it('shows the installed version, the real PyPI and release links and the alpha status', () => {
    const { container } = render(<GuidePage />)
    const rel = container.querySelector('#release')
    expect(rel.textContent).toContain('0.0.2')
    expect(rel.textContent).toMatch(/alpha software/)
    expect(rel.textContent).toContain('pip install --upgrade saferun-cli')
    const hrefs = [...container.querySelectorAll('a')].map((a) => a.getAttribute('href'))
    expect(hrefs).toEqual(expect.arrayContaining(['https://pypi.org/project/saferun-cli/', 'https://github.com/vinay-repalle/saferun/releases']))
  })
})
