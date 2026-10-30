import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import fixture from '../../fixtures/report.json'
import { gaps, isSupportedReport, sortedFindings, txt } from '../../utils/report'
import { ReportView } from './ReportView'

const report = fixture

describe('report fixture (generated from the real engine model)', () => {
  it('is a supported report', () => { expect(isSupportedReport(report)).toBe(true) })

  it('renders the engine verdict verbatim and the completeness flag', () => {
    render(<ReportView report={report} />)
    expect(screen.getByTestId('verdict').textContent).toBe('FAIL')
    expect(screen.getByTestId('complete').textContent).toMatch(/^No/)
    for (const r of report.reasons) expect(screen.getAllByText(r).length).toBeGreaterThan(0)
  })

  it('never derives a verdict: whatever the engine says is shown', () => {
    for (const v of ['PASS', 'WARNING', 'FAIL']) {
      const { unmount } = render(<ReportView report={{ ...report, verdict: v, complete: v === 'PASS' }} />)
      expect(screen.getByTestId('verdict').textContent).toBe(v)
      unmount()
    }
  })

  it('lists every check with its status, including every non-completed one', () => {
    render(<ReportView report={report} />)
    const table = within(screen.getByLabelText('Check coverage')).getByRole('table')
    expect(within(table).getAllByRole('row')).toHaveLength(report.checks.length + 1)
    for (const s of ['findings', 'incomplete', 'unavailable', 'skipped', 'timeout', 'error', 'passed', 'not applicable']) {
      expect(within(table).getAllByText(s).length).toBeGreaterThan(0)
    }
  })

  it('sorts findings like the CLI: most severe first, then check, path, line', () => {
    const order = sortedFindings(report).map((f) => f.severity)
    expect(order[0]).toBe('critical')
    expect(order.indexOf('high')).toBeLessThan(order.indexOf('medium'))
    expect(order.indexOf('low')).toBe(order.length - 1)
    render(<ReportView report={report} />)
    const rows = within(screen.getByLabelText('Findings')).getAllByRole('row')
    expect(rows).toHaveLength(report.checks.reduce((n, c) => n + c.findings.length, 0) + 1)
    expect(within(rows[1]).getByText('critical')).toBeTruthy()
    expect(within(rows[1]).getByText(/lodash 4.17.15 \(npm\)/)).toBeTruthy()
    expect(within(rows[1]).getByText(/fixed in: 4.17.21/)).toBeTruthy()
  })

  it('shows file paths with line numbers', () => {
    render(<ReportView report={report} />)
    expect(screen.getByText('src/app.py:4')).toBeTruthy()
    expect(screen.getByText('src/broken.py:1')).toBeTruthy()
    expect(screen.getByText('package-lock.json')).toBeTruthy()
  })

  it('shows coverage gaps: operational problems, skipped and withheld files, truncated findings', () => {
    const g = gaps(report).map((x) => x.head + x.lines.join(' '))
    const all = g.join('\n')
    expect(all).toMatch(/dependency-vulnerabilities: incomplete/)
    expect(all).toMatch(/3 further finding\(s\) not listed/)
    expect(all).toMatch(/javascript-syntax: unavailable/)
    expect(all).toMatch(/not analysed \(skipped\): link-to-etc \(symlink\)/)
    expect(all).toMatch(/not analysed \(withheld\): deploy\/id_rsa \(private-key\)/)
    expect(all).not.toMatch(/example-passed|example-not-applicable/)
    render(<ReportView report={report} />)
    expect(screen.getByLabelText('Coverage gaps and operational problems')).toBeTruthy()
  })

  it('treats HTML in tool output as inert text', () => {
    const { container } = render(<ReportView report={report} />)
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('[onerror]')).toBeNull()
    expect(screen.getByText(/<img src=x onerror=alert\(1\)> eval\(\)/)).toBeTruthy()
  })

  it('strips control and bidi characters from displayed text', () => {
    expect(txt('a‮b\u0007c\u001b[31m')).toBe('a?b?c?[31m')
    expect(txt('x'.repeat(600), 10)).toHaveLength(10)
  })

  it('does not render links built from report data', () => {
    const { container } = render(<ReportView report={report} />)
    expect(container.querySelector('a')).toBeNull()
  })

  it('survives unknown enum values without crashing or leaking markup', () => {
    const weird = structuredClone(report)
    weird.checks[0].status = '<b>new</b>'
    weird.checks[1].findings[0].severity = 'catastrophic'
    const { container } = render(<ReportView report={weird} />)
    expect(container.querySelector('b')).toBeNull()
  })

  it('shows a clean-but-incomplete report without implying success', () => {
    const r = { ...report, verdict: 'WARNING', complete: false, reasons: ['dependency-vulnerabilities: skipped - disabled by options'],
      checks: [{ ...report.checks[9], name: 'python-syntax', status: 'passed' }, { ...report.checks[5], name: 'dependency-vulnerabilities' }], workspace: {} }
    render(<ReportView report={r} />)
    expect(screen.getByText(/No findings were reported/)).toBeTruthy()
    expect(screen.getByTestId('complete').className).toBe('bad')
  })
})

describe('schema guard', () => {
  it('rejects other schema versions and malformed objects', () => {
    expect(isSupportedReport({ ...report, schema_version: 2 })).toBe(false)
    expect(isSupportedReport(null)).toBe(false)
    expect(isSupportedReport({})).toBe(false)
    expect(isSupportedReport({ ...report, checks: 'x' })).toBe(false)
  })
})
