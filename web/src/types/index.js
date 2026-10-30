// Documentation of the data shapes the dashboard consumes (JSDoc only, no runtime code).
// The report mirrors saferun/engine/model.py (schema_version 1); the golden example is fixtures/report.json,
// generated from the real engine model and pinned by tests/test_api_schema_fixture.py.
// The UI renders these fields; it never derives a verdict.

/** @typedef {'critical'|'high'|'medium'|'low'|'info'|'unknown'} Severity */
/** @typedef {'passed'|'findings'|'incomplete'|'error'|'timeout'|'unavailable'|'skipped'|'not_applicable'} CheckStatus */
/** @typedef {'PASS'|'WARNING'|'FAIL'} Verdict */
/** @typedef {'offline'|'disabled'} OsvMode */
/** @typedef {'queued'|'running'|'done'|'failed'|'rejected'} JobStatus */

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

/** @typedef {{entries: number, files: number, dirs: number, bytes: number, stripped_prefix: string|null,
 *   excluded: string[], excluded_total: number}} ArchiveInfo */
/** @typedef {{id: string, status: JobStatus, osv_mode: OsvMode, created_at: number, archive: ArchiveInfo|null,
 *   error: {code: string, message: string}|null, report?: Report}} Job */
/** @typedef {{docker_cli: boolean, analyzer: boolean, semgrep: boolean, osv_scanner: boolean,
 *   queue: {active: number, capacity: number, stored_results: number},
 *   limits: {max_archive_mib: number, max_uncompressed_mib: number, max_entries: number, max_file_mib: number,
 *     job_deadline_s: number, result_ttl_s: number}}} Health */

export {}
