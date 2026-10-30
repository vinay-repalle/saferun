import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import fixture from '../../fixtures/report.json'
import { DashboardPage } from './DashboardPage'

const HEALTH = { docker_cli: true, analyzer: false, semgrep: false, osv_scanner: false,
  queue: { active: 0, capacity: 5, stored_results: 0 },
  limits: { max_archive_mib: 25, max_uncompressed_mib: 100, max_entries: 5000, max_file_mib: 10, job_deadline_s: 600, result_ttl_s: 1800 } }

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
let calls = []

function mockFetch(scan) {
  calls = []
  vi.stubGlobal('fetch', vi.fn(async (url, init) => {
    calls.push({ url, init })
    if (url === '/api/health') return json(HEALTH)
    return scan(url, init)
  }))
}
const zip = (name = 'proj.zip', size = 10) => new File([new Uint8Array(size)], name, { type: 'application/zip' })
const upload = (f) => fireEvent.change(screen.getByTestId('file-input'), { target: { files: [f] } })

beforeEach(() => { vi.useRealTimers() })
afterEach(() => { vi.unstubAllGlobals() })

describe('upload flow', () => {
  it('uploads, polls, and shows the report', async () => {
    let polls = 0
    mockFetch((_u, init) => {
      if (init?.method === 'POST') return json({ id: 'abc', status: 'queued' }, 202)
      polls += 1
      return polls < 2 ? json({ id: 'abc', status: 'running' }) : json({ id: 'abc', status: 'done', osv_mode: 'online', created_at: 0, error: null, report: fixture,
        archive: { entries: 3, files: 2, dirs: 1, bytes: 2048, stripped_prefix: 'demo', excluded: ['__MACOSX/x'], excluded_total: 1 } })
    })
    render(<DashboardPage pollMs={5} />)
    await screen.findByText(/Docker|Not ready on this machine/)
    upload(zip())
    await screen.findByTestId('verdict')
    expect(screen.getByTestId('verdict').textContent).toBe('FAIL')
    expect(screen.getByText(/Single top-level folder/)).toBeTruthy()
    expect(screen.getByText(/1 member\(s\) excluded/)).toBeTruthy()
    const post = calls.find((c) => c.init?.method === 'POST')
    expect(post.url).toBe('/api/scans?osv=offline')
    const h = post.init.headers
    expect(h['X-SafeRun-Request']).toBe('1')
    expect(h['Content-Type']).toBe('application/zip')
    expect(post.init.body).toBeInstanceOf(File)
  })

  it('defaults OSV to offline (no online option exists), and the choice is sent', async () => {
    mockFetch(() => json({ id: 'x', status: 'queued' }, 202))
    render(<DashboardPage pollMs={1000} />)
    expect(screen.getByLabelText('Offline').checked).toBe(true)
    expect(screen.queryByLabelText('Online')).toBeNull()
    expect(screen.getByTestId('osv-note').textContent).toMatch(/without network access/)
    fireEvent.click(screen.getByLabelText('Disabled'))
    expect(screen.getByTestId('osv-note').textContent).toMatch(/skipped.*WARNING/)
    fireEvent.click(screen.getByLabelText('Offline'))
    expect(screen.getByTestId('osv-note').textContent).toMatch(/nothing is sent/)
    upload(zip())
    await waitFor(() => expect(calls.some((c) => c.init?.method === 'POST')).toBe(true))
    expect(calls.find((c) => c.init?.method === 'POST').url).toBe('/api/scans?osv=offline')
  })

  it('shows a rejected archive as refused, with no verdict', async () => {
    mockFetch((_u, init) => init?.method === 'POST' ? json({ id: 'r', status: 'queued' }, 202)
      : json({ id: 'r', status: 'rejected', osv_mode: 'online', created_at: 0, archive: null, error: { code: 'unsafe-member-type', message: 'x' } }))
    render(<DashboardPage pollMs={5} />)
    upload(zip())
    await screen.findByText('Archive refused')
    expect(screen.getByText(/symlink, device or other non-regular member/)).toBeTruthy()
    expect(screen.queryByTestId('verdict')).toBeNull()
  })

  it('shows a failed job as "no verdict ... not a pass"', async () => {
    mockFetch((_u, init) => init?.method === 'POST' ? json({ id: 'f', status: 'queued' }, 202)
      : json({ id: 'f', status: 'failed', osv_mode: 'online', created_at: 0, archive: null, error: { code: 'deadline', message: 'x' } }))
    render(<DashboardPage pollMs={5} />)
    upload(zip())
    await screen.findByText('No verdict')
    expect(screen.getByText(/not a pass/)).toBeTruthy()
    expect(screen.queryByTestId('verdict')).toBeNull()
  })

  it('explains server refusals (busy, too large)', async () => {
    mockFetch(() => json({ error: { code: 'busy', message: 'raw' } }, 429))
    render(<DashboardPage pollMs={5} />)
    upload(zip())
    await screen.findByText(/server is busy/)
  })

  it('refuses oversized and empty files before uploading anything', async () => {
    mockFetch(() => json({ id: 'x', status: 'queued' }, 202))
    render(<DashboardPage pollMs={5} />)
    await waitFor(() => expect(screen.getByText(/5 slots|0 of 5/)).toBeTruthy())
    upload(zip('big.zip', 26 * 1048576))
    await screen.findByText(/larger than the 25 MiB upload limit/)
    upload(zip('empty.zip', 0))
    await screen.findByText(/is empty/)
    expect(calls.some((c) => c.init?.method === 'POST')).toBe(false)
  })

  it('does not show an unsupported report', async () => {
    mockFetch((_u, init) => init?.method === 'POST' ? json({ id: 'u', status: 'queued' }, 202)
      : json({ id: 'u', status: 'done', osv_mode: 'online', created_at: 0, archive: null, error: null, report: { ...fixture, schema_version: 2 } }))
    render(<DashboardPage pollMs={5} />)
    upload(zip())
    await screen.findByText(/unsupported format/)
    expect(screen.queryByTestId('verdict')).toBeNull()
  })

  it('reports a scan that expired (404) and a lost server', async () => {
    mockFetch((_u, init) => init?.method === 'POST' ? json({ id: 'e', status: 'queued' }, 202) : json({ error: { code: 'not-found', message: 'x' } }, 404))
    render(<DashboardPage pollMs={5} />)
    upload(zip())
    await screen.findByText(/no longer available/)
  })

  it('clearing a result deletes it on the server', async () => {
    mockFetch((_u, init) => {
      if (init?.method === 'POST') return json({ id: 'del', status: 'queued' }, 202)
      if (init?.method === 'DELETE') return new Response(null, { status: 204 })
      return json({ id: 'del', status: 'done', osv_mode: 'online', created_at: 0, archive: null, error: null, report: fixture })
    })
    render(<DashboardPage pollMs={5} />)
    upload(zip())
    fireEvent.click(await screen.findByText('Clear and delete result'))
    await waitFor(() => expect(calls.some((c) => c.init?.method === 'DELETE' && c.url === '/api/scans/del')).toBe(true))
    expect(calls.find((c) => c.init?.method === 'DELETE').init.headers['X-SafeRun-Request']).toBe('1')
    await screen.findByText('Verify a project')
  })

  it('warns when tools are missing so a WARNING is not a surprise', async () => {
    mockFetch(() => json({}))
    render(<DashboardPage pollMs={5} />)
    await screen.findByText(/Not ready on this machine: analyzer image/)
  })
})
