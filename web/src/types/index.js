// Documentation of the report shape the website's sample report renders (JSDoc only, no runtime code).
// The report mirrors saferun/engine/model.py (schema_version 1); the golden example is fixtures/report.json,
// generated from the real engine model.
// The UI renders these fields; it never derives a verdict.

/** @typedef {'critical'|'high'|'medium'|'low'|'info'|'unknown'} Severity */
/** @typedef {'passed'|'findings'|'incomplete'|'error'|'timeout'|'unavailable'|'skipped'|'not_applicable'} CheckStatus */
/** @typedef {'PASS'|'WARNING'|'FAIL'} Verdict */

/** @typedef {{name: string, version: string, ecosystem: string}} PackageRef */
/** @typedef {{check: string, rule_id: string, severity: Severity, message: string, category: string,
 *   path: string|null, line: number|null, end_line: number|null, package: PackageRef|null,
 *   vulnerability_ids: string[], fixed_versions: string[], cwe: string[]}} Finding */
/** @typedef {{name: string, status: CheckStatus, detail: string, tool: string, duration_s: number,
 *   errors: string[], notes: string[], truncated_findings: number, findings: Finding[]}} Check */
/** @typedef {{entries_scanned?: number, copied_files?: number, copied_dirs?: number, copied_bytes?: number,
 *   skipped?: {path: string, reason: string}[], withheld?: {path: string, reason: string}[]}} Workspace */
/** @typedef {{schema_version: number, verdict: Verdict, reasons: string[], complete: boolean,
 *   workspace: Workspace, checks: Check[]}} Report */

export {}
