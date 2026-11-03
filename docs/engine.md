# Validation engine (Phase 2) — library reference

Design and analyzer isolation: [PROJECT.md](../PROJECT.md#validation-engine-phase-2-saferunengine). Evidence: [IMPLEMENTATION.md](../IMPLEMENTATION.md). The command-line front end is documented in [cli.md](cli.md).

`saferun scan` runs these checks and **executes nothing**; `saferun run` scans a script with them and then executes it only inside the sandbox if the verdict allows it ([cli.md](cli.md)).

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
| `python-static-analysis` | Semgrep, bundled local rules ([python.yml](../saferun/engine/rules/python.yml): 11 rules) | **inside the analyzer container** (`saferun-analyzer:local`, verified before every run; no host fallback), project mounted read-only, no network | `.py`/`.pyi` outside `node_modules`, `.venv`, `venv`, `site-packages` |
| `dependency-vulnerabilities` | OSV-Scanner v2 (`scan source --format json --no-resolve`; verified with 2.7.0) | **inside the analyzer container**, no network, offline OSV data mounted read-only (`saferun osv-db update`; missing, unvalidated or tampered data → `error`; data older than `osv_db_max_age_days`=30 → `incomplete`) | **Lockfiles:** `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`. **Requirements file (a manifest, not a lockfile):** `requirements.txt` only. npm files (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) are not scanned: a plain note says so and does not change the status or verdict |
| `python-syntax` | `compile()` (parse only, nothing imported or run); a "can the scanner read this file" step | **inside the sandbox** (`python:3.12-slim`), one run, fixed driver script | `.py`/`.pyi` (Semgrep does *not* report syntax errors, so this is separate) |
| `hardcoded-secrets` | gitleaks 8.30.1, SafeRun's baked configuration ([gitleaks.toml](../saferun/engine/rules/gitleaks.toml): default vendor rules, `generic-api-key` disabled), `--redact` | **inside the analyzer container**, project mounted read-only, no network, no host fallback | every file outside `node_modules`, `.venv`, `venv`, `site-packages`; binary files skipped by the tool; files over 1 MB make the check `incomplete`. Findings are always HIGH (verdict FAIL) and carry rule id, path and line only: **the secret value is discarded and never appears in any output**. No online verification. |
| `workspace-sensitive-files` | Phase 1 copy | host (copies/inspects files; runs no analyzer) | withheld credential-like files become findings |

Semgrep, OSV-Scanner and gitleaks are not installed on the host any more: they live in the analyzer image (`docker/analyzer/build.sh`; pinned versions, hash-locked wheels, checksummed binary,
rules baked in). If the image is missing the check is `unavailable`; if its ID, tool versions or rules hash differ from the build lock/pins it is `error` (`AnalyzerIntegrityError`; the gitleaks version and its configuration hash are labels checked like the others); a
failed container run is `error`. None of these is ever clean and none falls back to the host.

**Secrets scan.** `ValidationOptions(secrets_check=False)` (CLI `--no-secrets-check`) turns `hardcoded-secrets` into `skipped`, which keeps the verdict at WARNING at best. A secret finding is HIGH, so any hit is a FAIL; the verdict rules are unchanged. See [cli.md](cli.md) for coverage and limits.

**Dependency findings** also carry `fix_kind` (`patch`/`minor`/`major`, by version numbers only; absent when unknown). With `saferun scan --accept-file FILE` (`validate_project(..., ValidationOptions(accept=...))`) reviewed dependency findings move out of the verdict into `ValidationReport.accepted` until their expiry date; the file is never read from the scanned project. See [cli.md](cli.md).

**Plain-English explanations.** `Finding.explanation` (JSON key `explanation`, absent when empty) holds a one-or-two-sentence text next to the unchanged `message`. `validate_project` fills it in after the checks run, from [explain.py](../saferun/engine/explain.py): a table keyed by rule id (the 11 Semgrep rules, withheld files, Python syntax errors, one generic `secrets.*` text) plus a template for dependency findings built only from the finding's package, installed version, fixed versions and `fix_kind`. The texts live in the engine, not in the Semgrep rules file or the analyzer image. A rule id with no entry has no explanation. Findings created by hand are not changed.

**SafeRun is Python-only.** JavaScript files get no checks and npm lockfiles are not scanned; the dependency check adds the note "JavaScript/npm dependencies are not supported and were not scanned." (no effect on status or verdict; with only npm files the check is `not_applicable`).

**Not implemented (deferred):** pip dependency *installation* and test execution (needs a separate network-enabled step),
transitive resolution (requirements.txt and manifests without lockfiles),
per-scan online OSV queries (removed on purpose in Phase 5B).