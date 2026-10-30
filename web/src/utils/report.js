export const SUPPORTED_SCHEMA = 1

const RANK = { critical: 5, high: 4, medium: 3, unknown: 3, low: 2, info: 1 }
export const SEVERITIES = ['critical', 'high', 'medium', 'unknown', 'low', 'info']
export const OPERATIONAL = new Set(['incomplete', 'error', 'timeout', 'unavailable', 'skipped'])

// Report strings come from analysed projects and tools. React escapes them; this additionally drops control and
// bidi characters (the same set the engine strips) so nothing can reorder or hide text on screen.
// eslint-disable-next-line no-control-regex
const CTRL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g
export const txt = (v, max = 500) => {
  const s = String(v ?? '').replace(CTRL, '?')
  return s.length > max ? s.slice(0, max - 1) + '…' : s
}

export const rank = (s) => RANK[s] ?? 3

export function isSupportedReport(x) {
  const r = x
  return !!r && typeof r === 'object' && r.schema_version === SUPPORTED_SCHEMA && typeof r.verdict === 'string' &&
    Array.isArray(r.checks) && Array.isArray(r.reasons) && typeof r.complete === 'boolean' && typeof r.workspace === 'object'
}

/** Same ordering as the CLI text report: severity (high first), then check, path, line, rule. */
export function sortedFindings(report) {
  return report.checks.flatMap((c) => c.findings).sort((a, b) =>
    rank(b.severity) - rank(a.severity) || a.check.localeCompare(b.check) || (a.path ?? '').localeCompare(b.path ?? '') ||
    (a.line ?? 0) - (b.line ?? 0) || a.rule_id.localeCompare(b.rule_id))
}

export function tally(report) {
  const t = {}
  for (const f of report.checks.flatMap((c) => c.findings)) t[f.severity] = (t[f.severity] ?? 0) + 1
  return t
}

export const location = (f) => (f.path === null ? '–' : txt(f.path, 300) + (f.line !== null ? `:${f.line}` : ''))

/** Coverage gaps and operational problems, mirroring the CLI's "Coverage gaps" section. */
/** @returns {{head: string, lines: string[]}[]} */
export function gaps(report) {
  const out = []
  for (const c of report.checks) {
    if (OPERATIONAL.has(c.status) || c.errors.length || c.truncated_findings) {
      const lines = c.errors.map((e) => `error: ${txt(e, 300)}`)
      if (c.truncated_findings) lines.push(`${c.truncated_findings} further finding(s) not listed (cap reached)`)
      lines.push(...c.notes.map((n) => `note: ${txt(n, 300)}`))
      out.push({ head: `${txt(c.name, 100)}: ${c.status}${c.detail ? ' – ' + txt(c.detail, 300) : ''}`, lines })
    }
  }
  for (const s of report.workspace.skipped ?? []) out.push({ head: `not analysed (skipped): ${txt(s.path, 300)} (${txt(s.reason, 60)})`, lines: [] })
  for (const w of report.workspace.withheld ?? []) out.push({ head: `not analysed (withheld): ${txt(w.path, 300)} (${txt(w.reason, 60)})`, lines: [] })
  return out
}

export function completedChecks(checks) {
  const applicable = checks.filter((c) => c.status !== 'not_applicable')
  return { done: applicable.filter((c) => c.status === 'passed' || c.status === 'findings').length, total: applicable.length }
}

const HASH = /^[0-9a-f]{40}$/i
/** Sortable key for a release number ('1.26.17' -> [1, 26, 17]); null for commit hashes and anything non-numeric. */
const vkey = (v) => {
  const m = HASH.test(v) ? null : /^\d+(\.\d+)*/.exec(v)
  return m ? m[0].split('.').map(Number) : null
}
const cmp = (a, b) => {
  for (let i = 0; i < Math.max(a.length, b.length); i++) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) - (b[i] ?? 0)
  return 0
}

/**
 * One row per vulnerable package, mirroring the CLI's "Upgrade plan": finding count, worst severity and the lowest release
 * that fixes every finding (per finding the nearest fixed release above the installed one; per package the highest of those).
 * upgradeTo is null when no finding names a usable release. Worst severity first.
 * @returns {{name: string, version: string, ecosystem: string, findings: number, severity: string, upgradeTo: string|null}[]}
 */
export function upgradePlan(report) {
  const rows = new Map()
  for (const f of report.checks.flatMap((c) => c.findings)) {
    if (!f.package) continue
    const id = `${f.package.ecosystem}\u0000${f.package.name}\u0000${f.package.version}`
    const row = rows.get(id) ?? { name: f.package.name, version: f.package.version, ecosystem: f.package.ecosystem, findings: 0, severity: f.severity, upgradeTo: null, key: null }
    rows.set(id, row)
    row.findings++
    if (rank(f.severity) > rank(row.severity)) row.severity = f.severity
    const cur = vkey(String(f.package.version))
    const fixes = f.fixed_versions.map((v) => [vkey(v), v]).filter(([k]) => k)
    const above = fixes.filter(([k]) => !cur || cmp(k, cur) > 0)
    const pool = above.length ? above : fixes
    if (pool.length) {
      const [k, v] = pool.reduce((a, b) => (cmp(b[0], a[0]) < 0 ? b : a))
      if (!row.key || cmp(k, row.key) > 0) { row.key = k; row.upgradeTo = v }
    }
  }
  return [...rows.values()].sort((a, b) => rank(b.severity) - rank(a.severity) || a.name.localeCompare(b.name))
}
