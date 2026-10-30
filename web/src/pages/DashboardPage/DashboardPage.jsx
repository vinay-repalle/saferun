import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, deleteScan, getHealth, getScan, startScan } from '../../api/client'
import { ResultPanel } from '../../components/ResultPanel/ResultPanel'
import { SiteFooter } from '../../components/SiteFooter/SiteFooter'
import { SiteNav } from '../../components/SiteNav/SiteNav'
import { UploadPanel } from '../../components/UploadPanel/UploadPanel'
import { describeCode } from '../../utils/errors'
import { txt } from '../../utils/report'
import './DashboardPage.css'

// phase: { kind: 'idle' } | { kind: 'uploading', name } | { kind: 'running', id, name, status }
//      | { kind: 'finished', job, name } | { kind: 'error', message }

const POLL_MS = 1000

export function DashboardPage({ pollMs = POLL_MS }) {
  const [health, setHealth] = useState(null)
  const [osv, setOsv] = useState('offline')
  const [phase, setPhase] = useState({ kind: 'idle' })
  const abort = useRef(null)

  useEffect(() => { const c = new AbortController(); getHealth(c.signal).then(setHealth); return () => c.abort() }, [])
  useEffect(() => () => abort.current?.abort(), [])

  const poll = useCallback(async (id, name, signal) => {
    let failures = 0
    for (;;) {
      await new Promise((r) => setTimeout(r, pollMs))
      if (signal.aborted) return
      try {
        const job = await getScan(id, signal)
        failures = 0
        if (job.status === 'queued' || job.status === 'running') { setPhase({ kind: 'running', id, name, status: job.status }); continue }
        setPhase({ kind: 'finished', job, name })
        return
      } catch (e) {
        if (signal.aborted) return
        if (e instanceof ApiError && e.status === 404) { setPhase({ kind: 'error', message: 'This scan is no longer available (results expire).' }); return }
        if (++failures >= 3) { setPhase({ kind: 'error', message: 'Lost contact with the SafeRun server.' }); return }
      }
    }
  }, [pollMs])

  const onFile = useCallback(async (file) => {
    abort.current?.abort()
    const ctl = new AbortController()
    abort.current = ctl
    const name = txt(file.name, 120)
    const max = health?.limits.max_archive_mib
    if (max && file.size > max * 1048576) { setPhase({ kind: 'error', message: `“${name}” is larger than the ${max} MiB upload limit.` }); return }
    if (file.size === 0) { setPhase({ kind: 'error', message: `“${name}” is empty.` }); return }
    setPhase({ kind: 'uploading', name })
    try {
      const { id } = await startScan(file, osv, ctl.signal)
      setPhase({ kind: 'running', id, name, status: 'queued' })
      await poll(id, name, ctl.signal)
    } catch (e) {
      if (ctl.signal.aborted) return
      const msg = e instanceof ApiError ? describeCode(e.code, txt(e.message, 200)) : 'Could not reach the SafeRun server.'
      setPhase({ kind: 'error', message: msg })
    }
  }, [health, osv, poll])

  const busy = phase.kind === 'uploading' || phase.kind === 'running'
  const reset = () => {
    if (phase.kind === 'finished') void deleteScan(phase.job.id)
    abort.current?.abort()
    setPhase({ kind: 'idle' })
  }

  return (
    <div className="shell">
      <SiteNav current="#/dashboard" />
      <main className="layout">
        <aside className="stack">
          <UploadPanel busy={busy} health={health} osv={osv} onOsv={setOsv} onFile={onFile} />
          {health && <p className="fine">Queue: {health.queue.active} of {health.queue.capacity} slots in use · results are kept for {Math.round(health.limits.result_ttl_s / 60)} min</p>}
        </aside>
        <section className="stack" aria-live="polite">
          {phase.kind === 'idle' && (
            <div className="card empty-state">
              <h2>Verify a project</h2>
              <p className="muted">Upload a ZIP of a project to run SafeRun’s checks: Python syntax and Semgrep analysis, JavaScript syntax, dependency vulnerabilities. Results show the verdict, per-check coverage and every finding.</p>
              <p className="fine">This dashboard does not run your code. A passing result is not proof that code is safe.</p>
            </div>
          )}
          {phase.kind === 'uploading' && <div className="card status" role="status"><span className="spin" aria-hidden="true" /> Uploading “{phase.name}”…</div>}
          {phase.kind === 'running' && (
            <div className="card status" role="status"><span className="spin" aria-hidden="true" /> {phase.status === 'queued' ? 'Waiting in the queue' : 'Validating'} “{phase.name}”… this can take a few minutes.</div>
          )}
          {phase.kind === 'error' && <div className="card error" role="alert"><h2>Could not scan</h2><p>{phase.message}</p><button onClick={reset}>Dismiss</button></div>}
          {phase.kind === 'finished' && <ResultPanel job={phase.job} name={phase.name} onReset={reset} />}
        </section>
      </main>
      <SiteFooter />
    </div>
  )
}
