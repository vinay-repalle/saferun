# Validation engine (Phase 2) — library reference

Design and host-side analyzer risk: [PROJECT.md](../PROJECT.md#validation-engine-phase-2-saferunengine). Evidence: [IMPLEMENTATION.md](../IMPLEMENTATION.md). The command-line front end is documented in [cli.md](cli.md).

## Usage
```python
from saferun.engine import validate_project, ValidationOptions
report = validate_project("./proj", ValidationOptions(tool_timeout_s=120)   # osv_offline is kept for compatibility (scans are always offline); osv_db_max_age_days=30)
print(report.verdict.value, report.complete, report.reasons)
for c in report.checks: print(c.name, c.status.value, c.detail)
data = report.to_dict()          # stable JSON-serializable structure (schema_version 1)
```
`validate_project` copies the project with the Phase 1 sanitizer (symlinks/special files dropped, credential files withheld),
runs the checks on the **copy** (never the original directory, never project code), deletes the copy, and returns a report.

| Check | Tool | Runs where | Scope |
|---|---|---|---|
| `python-static-analysis` | Semgrep, bundled local rules ([python.yml](saferun/engine/rules/python.yml): 11 rules) | **inside the analyzer container** (`saferun-analyzer:local`, verified before every run; no host fallback), project mounted read-only, no network | `.py`/`.pyi` outside `node_modules`, `.venv`, `venv`, `site-packages` |
| `dependency-vulnerabilities` | OSV-Scanner v2 (`scan source --format json --no-resolve`; verified with 2.7.0) | **inside the analyzer container**, no network, offline OSV data mounted read-only (`saferun osv-db update`; missing, unvalidated or tampered data → `error`; data older than `osv_db_max_age_days`=30 → `incomplete`) | **Lockfiles:** `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`. **Requirements file (a manifest, not a lockfile):** `requirements.txt` only |
| `python-syntax` | `compile()` (parse only, nothing imported or run) | **inside the sandbox** (`python:3.12-slim`), one run, fixed driver script | `.py`/`.pyi` (Semgrep does *not* report syntax errors, so this is separate) |
| `javascript-syntax` | `node --check` | **inside the sandbox** (`node:22-slim`), one run, fixed driver script | `.js`/`.mjs`/`.cjs` outside `node_modules` |
| `workspace-sensitive-files` | Phase 1 copy | host (copies/inspects files; runs no analyzer) | withheld credential-like files become findings |

Semgrep and OSV-Scanner are not installed on the host any more: they live in the analyzer image (`docker/analyzer/build.sh`; pinned versions, hash-locked wheels, checksummed binary,
rules baked in). If the image is missing the check is `unavailable`; if its ID, tool versions or rules hash differ from the build lock/pins it is `error` (`AnalyzerIntegrityError`); a
failed container run is `error`. None of these is ever clean and none falls back to the host.

**Not implemented (deferred):** npm/pip dependency *installation* and test execution (needs a separate network-enabled step),
JavaScript test runners, Semgrep rules for JavaScript, transitive resolution (requirements.txt and manifests without lockfiles),
per-scan online OSV queries (removed on purpose in Phase 5B).