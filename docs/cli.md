# Command-line reference (Phase 3)

## Install and set up
```bash
pip install saferun-cli              # installs the `saferun` command (`python -m saferun` also works); pipx, uv tool and Poetry 2.0+ work too
saferun init                         # first-run setup (interactive); `saferun doctor` / `saferun status` show the result
saferun --version                    # 0.0.2
saferun doctor                       # read-only diagnosis
```
Requirements: Python 3.12+ and Docker (Linux, Windows or macOS; see [platforms.md](platforms.md)). Upgrade: `pip install --upgrade saferun-cli`, then `saferun init`. SafeRun is alpha software; see [SECURITY.md](../SECURITY.md) for its limits and how to report vulnerabilities.
From a source checkout: `pip install -e '.[dev]'`.
Semgrep, OSV-Scanner and gitleaks are **not** installed on the host and a host copy is never used. Without the analyzer image those checks are `unavailable`; without valid OSV data the dependency check is `error`
(verdict at best WARNING). Docker is required for every sandboxed check.

### `saferun init`
Prints a two-line introduction, shows the components with their state, size and purpose, and asks what to install. Components (derived from the images and data the checks use):

| # | Component | Enables | Obtained by |
|---|---|---|---|
| 1 `python` | Python sandbox image | `python-syntax` | `docker pull python@sha256:…` (pinned digest) |
| 2 `analyzer` | Analyzer image: Semgrep, OSV-Scanner, gitleaks, rules | `python-static-analysis`, `dependency-vulnerabilities`, `hardcoded-secrets` | a cosign-verified pull of the recorded release `analyzer-v1.0.1` by digest. cosign is obtained automatically (see below); with `--build-local` a local build instead (`docker/analyzer/build.py`, source checkout only), see [release-images.md](release-images.md) |
| 3 `osv-db` | Local OSV vulnerability data | `dependency-vulnerabilities` | the `saferun osv-db update` download (PyPI advisories, about 40 MB); only missing, invalid or stale ecosystems are fetched |

**Docker first.** Before pulling anything `init` diagnoses Docker: not installed, daemon not running, permission denied, or a remote endpoint. It prints platform-specific guidance (Linux: Docker Engine and the `docker` group; macOS and Windows: Docker Desktop) and installs nothing while Docker is unusable.

**cosign is provisioned automatically.** If neither SafeRun's own copy nor a `cosign` on PATH exists, `init` downloads cosign 2.4.3 for your platform (Linux/macOS amd64+arm64, Windows amd64) over HTTPS into `<user data dir>/saferun/bin/` and keeps it only if its SHA-256 equals the pin written in `saferun/sandbox/cosign_tool.py`; otherwise it is discarded and the analyzer is not pulled. The file is re-hashed on every use and a changed file is ignored. The image signature check itself (identity, issuer, digest, repository) is unchanged.

**OSV data.** `init` checks the database like every scan does (integrity manifest, age limit 30 days). A current database is skipped (its age is shown); a missing, invalid or stale one is downloaded, per ecosystem. If the network fails, `init` reports the state of the existing data (age or problem), leaves it untouched and exits 1; scans stay INCOMPLETE (never PASS) until it is current.

Answer with numbers or names (`1,2`, `all`, `all -osv-db`, `-2`); Enter = all. **Before anything is fetched** each component is verified with the existing checks (image registry digest, analyzer lock + labels + rules hash, OSV
manifest hashes and age); a valid one is skipped and never rebuilt or re-downloaded, and a tag that merely exists locally is not trusted. Missing, invalid or outdated components are offered for install/repair/update; everything
installed is verified again afterwards, and a component that does not verify is reported as failed.

Scripts and CI (no prompts): `saferun init --all`, `--only python,analyzer` (several), `--skip osv-db` (everything except), `--yes` (confirm prompts), `--build-local` (build the analyzer locally even when a signed release exists), `--repair` (allow rebuilding an analyzer image that FAILED verification:
this replaces the image and its lock, so it is never done silently). Without a flag and without a terminal the command exits 64. Exit codes: 0 every selected component is ready · 1 at least one is not · 64 usage ·
70 reserved for fatal errors · 130 interrupted. Offline: components that need a download are listed as "no internet access" with preload instructions; valid ones are still used, and nothing else is claimed ready.

### `saferun doctor [--online] [--format json]`
Read-only diagnosis, one line per check, `PASS` / `WARNING` / `FAIL`, and a fix for every problem: SafeRun version, Python (3.12+), operating system, Docker state (as above), the python sandbox image (pinned digest), the analyzer image (lock, labels, rules hash), cosign (SafeRun's pinned copy or PATH), the OSV database (integrity and age; stale = WARNING, missing or invalid = FAIL), the data directory (writable) and `SAFERUN_*` overrides. `--online` also verifies the cosign signature of the published analyzer release. A check that cannot be carried out is never a PASS (with Docker unusable, the image checks FAIL). Exit 0 when nothing FAILED (warnings allowed), 1 otherwise. JSON: `{"schema_version": 1, "ok": bool, "checks": [{"name", "level", "detail", "fix"}]}`.

### `saferun status [--only a,b] [--format json]`
Verifies every component now and prints state (`ready`, `missing`, `invalid`, `outdated`, `unknown`), what it enables and the exact fix. Exit 0 only if all selected components are ready. JSON:
`{"schema_version": 1, "ok": bool, "components": [{"component", "title", "state", "detail", "enables"}]}`. The OSV data alone: `saferun osv-db status`.

### When a scan needs something that is not installed
The scan still runs what it can and the affected checks are `unavailable`/`error`/`incomplete` (verdict at best WARNING, exit codes unchanged); on stderr it adds one line per missing component naming the exact fix, e.g.
`setup: OSV vulnerability database is outdated: …  ->  fix: saferun init --only osv-db`. Nothing is skipped silently and nothing falls back to host tools.

## Usage
**`scan` executes nothing; `run` scans, then executes in the sandbox.** `saferun scan` reads the files and reports; no project code is run. `saferun run` (below) first performs the same scan on a script and executes it, inside the sandbox only, when the verdict allows it.
```bash
saferun scan ./my-project                 # human-readable report
saferun scan ./my-project --format json   # the Phase 2 report schema (schema_version 1), nothing else on stdout
saferun scan ./my-project --osv-offline   # accepted for compatibility; scans are always offline
saferun scan . --no-secrets-check --timeout 60
saferun --help
```
`saferun scan PATH` is a thin front end over `validate_project`: same sanitized copy, same sandbox, same checks and verdict
rules; the CLI adds no validation logic, runs no project code and installs no dependencies. Options: `--format text|json`,
`--timeout SECONDS` (per tool/sandbox run, default 120, max 3600), `--osv-offline` (no-op: always offline), `--no-python-syntax`, `--no-python-analysis`,
`--no-dependency-scan`, `--no-secrets-check`, `--accept-file FILE` (the old `--no-javascript-check` is still accepted, hidden, and does nothing). A disabled check is reported as `skipped`, which makes the verdict at best WARNING.

### Secrets scan (`hardcoded-secrets`)
Searches the project's files for hardcoded credentials with gitleaks 8.30.1, **inside the analyzer container** (no network, project mounted read-only, same limits and image verification as Semgrep and OSV-Scanner; no host fallback). `scan` still executes nothing.
- **Output.** Each hit is a finding `secrets.<gitleaks rule id>` (for example `secrets.npm-access-token`) with severity **high** (so the verdict is FAIL), category `secret`, CWE-798, the file and the line. **The secret value is never shown, logged or put in the JSON:** gitleaks is run with `--redact` and SafeRun reads only the rule id, file and line numbers from its output; its error text is not echoed either. No new JSON keys: the check is one more entry in `checks` (schema_version stays 1). Text output adds a next step (remove, rotate, read from the environment).
- **Rules.** The default vendor-specific rules compiled into gitleaks, from the configuration `saferun/engine/rules/gitleaks.toml` baked into the image (its hash is a label verified before every use). The generic entropy rule `generic-api-key` is **disabled** because it is the main source of false alarms and every finding here is HIGH. A project cannot change any of this: its own `.gitleaks.toml` is not read, `gitleaks:allow` comments are ignored, and `.gitleaksignore` files are deleted from SafeRun's private copy before the scan.
- **Coverage.** Not scanned: `node_modules`, `.venv`, `venv`, `site-packages`; binary files (skipped by the tool, not listed); files over 1 MB (listed, and the check ends `incomplete`, verdict at best WARNING). Files that match SafeRun's own credential signatures (PEM private keys, AWS, GitHub, Slack, Google, Stripe-live, PyPI, Anthropic tokens) never reach this check: they are withheld at copy time and appear under `workspace-sensitive-files` (HIGH).
- **Limits.** It finds known token formats, not every secret: plain passwords, custom internal tokens, and encoded or split values are missed; documentation examples and test keys can be false positives; it does not check whether a secret is valid or still active (that would need the network, which scans never use); it does not read git history. A clean result means "none of these patterns found", not "no secrets".
- **Status.** `--no-secrets-check` → `skipped` (verdict at best WARNING). Analyzer image missing → `unavailable`; image or labels not matching this SafeRun (for example an image built before gitleaks was added) → `error` for **all** analyzer checks until `saferun init` installs a current image. `saferun run` also performs this check on the script it is about to run.

### Dependency findings: what to upgrade to, and accepting a risk
Each dependency finding shows the fixed version(s) from the OSV data, its severity and a one-line description. New: next to the fix, a label says how big the jump is *by the version numbers only*: **patch** (`4.17.15` to `4.17.21`), **minor** (`1.2.3` to `1.3.0`) or **major** (`1.2.3` to `2.0.0`). It is computed for the nearest fixed release above the installed version, the **Upgrade plan** table shows it for the release that fixes every finding of a package, and `--format json` adds `fix_kind` to the finding (absent when unknown: no fixed version, or a version that is not a plain release number such as a commit hash). The label is a hint, not a promise: a patch can still break things and a `0.x` minor bump is often breaking, so read the changelog. Only data OSV already provides is used; nothing is looked up online.

**Accepting a risk** (`--accept-file FILE`, suggested name `.saferun-accept.toml`). When a vulnerability does not matter for your use, record why instead of ignoring the whole scan:
```toml
[[accept]]
id = "GHSA-35jh-r3h4-6jhm"      # the vulnerability id or any alias, e.g. CVE-2021-23337
package = "lodash"              # optional: only this package (names compare case-insensitively, "-", "_" and "." alike)
reason = "only used by a build script that never sees user input"
expires = 2026-12-31            # required: the last day the acceptance holds
```
```bash
saferun scan ./my-project --accept-file ~/saferun-accepts.toml
```
- **The file is never read from the scanned project.** A project is untrusted; a `.saferun-accept.toml` shipped inside it could hide its own vulnerable dependencies, so it is ignored (stderr says so) unless you pass it with `--accept-file` from a location you control.
- `id`, `reason` and `expires` are required; unknown keys, a missing or non-date `expires`, an unreadable or invalid file are a usage error (exit 64) and **nothing is scanned**, so a broken file never turns into "accept everything".
- Only dependency findings can be accepted (code, syntax and workspace findings never).
- An accepted finding is **not counted in the verdict** (the scan can become PASS) but is listed under **Accepted risks** with its reason and expiry, the verdict reasons say how many were accepted, and the JSON report gets `accepted` (finding, `accepted_id`, `reason`, `expires`) and `accept_notes`. Reports of scans without an accept file are unchanged.
- **After the `expires` date the entry stops applying**: the finding counts again and a note says it expired. A note also lists entries that matched nothing in this scan (they can be removed). Only dependency findings the scan actually reported can be accepted; if the report was capped (`further finding(s) not listed`) the hidden ones still count.
- `saferun run` does not take an accept file.

`python-syntax` answers one question: *can the scanner read this file?* It parses each file (`compile()`) and runs none of it; a file that fails to parse is reported because the other checks cannot analyse it. SafeRun is Python-only: JavaScript files are not checked, and npm lockfiles (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) are not scanned. The dependency check adds the plain note "JavaScript/npm dependencies are not supported and were not scanned." It does not change that check's status or the verdict, and a project with only those files shows the check as `not_applicable`, never as a pass.

**Network.** Scans never use the network. Semgrep, OSV-Scanner and gitleaks run in the analyzer container (no network, read-only project, see PROJECT.md *Phase 5 security status*);
OSV-Scanner reads local OSV data. Build the image once with `docker/analyzer/build.sh` and fetch the data with `saferun osv-db update` (the only command that downloads anything, apart from the opt-in `saferun check-names --online`, which sends package names only:
public data from osv-vulnerabilities.storage.googleapis.com, nothing about any project; `--dir` or `SAFERUN_OSV_DB` choose the directory). Without the image the Semgrep/OSV checks are `unavailable`
(or `error` if the image fails verification, including an unsafe lock file: the lock and its directory must be owner-only, 0600 / 0700); without valid data the dependency check is `error`; data older than 30 days makes it `incomplete`; either way the verdict is at best WARNING. There is no fallback to host-installed Semgrep/OSV-Scanner.
Behaviour change in Phase 5B: the former default (online OSV queries) and the stderr notice about it no longer exist; a project with lockfiles but no local OSV data now ends in WARNING instead of findings.

| Exit code | Meaning |
|---|---|
| 0 | **PASS**: all applicable checks completed, no findings above informational |
| 1 | **FAIL**: at least one high or critical finding |
| 2 | **WARNING**: lower-severity findings, *or* the project was not fully checked (tool missing/timed out/errored, check skipped, partial copy) |
| 64 | invalid usage: bad option or value, path missing or not a directory |
| 70 | fatal: no verdict possible (e.g. the sandbox could not copy the project, internal error) |
| 130 | interrupted |

Incomplete scans never exit 0. Text output example:
```
Verdict: WARNING    Scan complete: NO - see coverage gaps
Reasons:
  - dependency-vulnerabilities: unavailable - analyzer image unavailable; OSV-Scanner was not run (no host fallback): ...
Checks:
  passed         python-syntax  (0 finding(s))
  unavailable    dependency-vulnerabilities  (0 finding(s)) - analyzer image unavailable; OSV-Scanner was not run (no host fallback): ...
Findings: none
Coverage gaps and operational problems:
  - dependency-vulnerabilities: unavailable - analyzer image unavailable; OSV-Scanner was not run (no host fallback): ...
```
Findings are listed most severe first as `[HIGH] rule-id  path:line`. The CLI inherits the Phase 2 limitations (
unsupported/unverified lockfile formats, no transitive resolution); PASS is not a proof that code is safe.


## `saferun run [--timeout S] [--project-dir DIR] [--allow-warnings] SCRIPT [-- ARGS...]`
Scans a Python script (`.py`; symlinks refused), then runs it **only inside the sandbox** (pinned `python:3.12-slim` by digest, no network, read-only root and project, non-root, no capabilities, resource limits, output cap, secrets redacted). Never on the host.
By default only the script is copied to a private temporary directory and scanned; `--project-dir` stages the whole directory (the script must be inside it). saferun options must precede `SCRIPT`; everything after it goes to the script.
The command is `python -I /workspace/<script> ARGS…` as an argument list (no shell).

| Scan result | `run` |
|---|---|
| PASS | runs the script |
| FAIL | refuses, exit 1; `--allow-warnings` does not change this |
| WARNING | refuses, exit 2. With `--allow-warnings` it runs only if the scan is **complete**, every check finished (passed / findings / not applicable) and no finding is high or critical; an incomplete, errored, timed-out, skipped or unavailable check is never overridden |
| scan impossible (Docker, analyzer, internal error) | refuses, exit 70 |

| Exit code | Meaning |
|---|---|
| 0 | the script ran and exited 0 |
| 1 / 2 | refused: FAIL / WARNING (the script did not run) |
| 3 | the script ran but exited non-zero, timed out (`--timeout`, default 30 s, max 3600) or was killed for memory |
| 64 | usage (missing file, not `.py`, symlink, script outside `--project-dir`) |
| 70 | no verdict or the sandbox could not start; the script did not run |
| 130 | interrupted |

A passing scan is not proof that a script is safe. Output is shown after the script finishes (not streamed), is capped, and has control, escape and bidi characters replaced by `?` (a script cannot rewrite your terminal or fake SafeRun's messages); scripts that need the network or third-party packages fail inside the sandbox.

## `saferun verify-images`
Checks that the container images SafeRun runs are present locally with the digests pinned in `saferun/sandbox/images.py`
(read-only: nothing is pulled, no container is started). `--format json` prints `{schema_version, ok, images[{name, reference,
pinned_digest, status, detail}]}`; `status` is `verified`, `missing` (the detail gives the exact `docker pull`), `mismatch` or `error`.
Exit codes: 0 all verified; 1 any image missing, mismatched or uninspectable; 64 usage; 70 Docker unusable (e.g. remote endpoint).
`saferun scan` itself refuses to start a sandbox run when the image digest does not match (exit 70, no verdict).
`--signature` (online; uses SafeRun's own verified cosign or one on PATH) additionally verifies the cosign signature of the published analyzer release (`ANALYZER_RELEASE`, currently `analyzer-v1.2.0`; with no release configured it reports that there is nothing to verify and exits 1): it must come from this repository's
release workflow on an `analyzer-v*` tag and name exactly the pinned repository and digest. JSON gains a `signature` object `{ok, reference, detail}` only when the flag is given; any failure
(including cosign missing) makes the exit code 1. See [release-images.md](release-images.md).

See [engine.md](engine.md) for the checks, statuses and verdict rules, and [PROJECT.md](../PROJECT.md) for limitations.

## `saferun osv-db`
`update [--dir D] [--allow-unverified] [--if-stale] [--max-age-days N]` downloads `PyPI` data (HTTPS). It refuses a download when the server sends no usable MD5 hash (unless `--allow-unverified`, which is recorded and shown in every
later scan), refuses archives that are unreadable or list fewer advisories than a sanity floor (PyPI 5 000; October 2026: 26 726), (connection failures and HTTP 408/429/5xx are retried three times with a back-off; any other failure keeps the previous file and manifest, and the data does not become "fresher"). `--if-stale` downloads only when the data is missing, invalid or older than `--max-age-days` (default 30). It records SHA-256, size, advisory count and time in
`manifest.json`. An existing directory passed with `--dir` is **never chmod'ed**; directories it creates are 0755 so the analyzer container (uid 65534) can read them. `status [--dir D] [--max-age-days N]` validates the data and prints
its age (exit 0 usable and fresh, 1 otherwise). Every scan re-validates: manifest present and well-formed, SHA-256 and size equal the recorded values, no symlinks, readable by the container user, advisory count above the floor, timestamp not
in the future. Any failure -> the dependency check is `error`; valid but older than 30 days -> `incomplete` (findings are still reported).
**Limits:** the MD5 and the recorded SHA-256 detect corruption and later modification of the files, not a malicious or compromised server (the MD5 comes from the same server; the SHA-256 is computed locally after download, so it does not
authenticate the original). The manifest sits next to the data, so whoever can write the directory can rewrite both. The advisory-count floor is a sanity check, not proof of completeness. The host reads only the zip's central directory (stdlib `zipfile`) to count advisories; the advisories themselves are opened only by OSV-Scanner in the container.

## `saferun check-names [NAME ...] [--project DIR] [--online] [--format json]`
Looks for dependency names that resemble popular PyPI packages (`reqeusts` for `requests`). It is a separate command: **`scan` and `run` are unchanged and never do this check.** Nothing is installed or executed.

**Input.** Any `NAME`s given on the command line, and, with `--project DIR`, the dependency names declared in `requirements*.txt` and `pyproject.toml` **directly inside DIR** (not in sub-directories): `[project]` dependencies and optional dependencies, `[dependency-groups]`, `[build-system] requires` and Poetry's dependency tables. Symbolic links and files over 1 MB are not read; a file that is skipped, unparsable or referenced with `-r`/`-c` but not read is reported under "Not checked". URL, path and `-e` lines are listed as notes, not checked. Python only: `package.json` is not read.

**Offline (default, no network).** Each name is normalised (PEP 503) and compared with a snapshot of the 10 000 most downloaded PyPI package names bundled in the wheel (`saferun/data/top_pypi.txt`; the dataset date is printed on every run). A name in the snapshot is fine. A name that is not in it but is within 1 edit of a snapshot name (2 edits when both names have 8+ characters; insert, delete, replace or swap neighbouring letters) is flagged as *similar*; snapshot names of 4 characters or fewer (`six`, `pip`) and names of 4 characters or fewer are never matched. Any other name is *not in the snapshot* and is listed as such, not flagged.

**Online (`--online`, opt-in).** For names that are **not** in the snapshot, SafeRun asks PyPI (`GET https://pypi.org/simple/<name>/`, JSON) whether the project exists and when its first file was uploaded. **Only the package name is sent**, never code, paths or file contents. A name is flagged when PyPI has no such project or its first upload is under 30 days old. Existence and age only: download counts are not looked up. At most 2 000 names are looked up per run. If a lookup fails for any reason (offline, timeout, HTTP error, unexpected answer) the result is "could not check online", never a pass.

**Exit codes.** 0: nothing flagged and everything asked for was checked. 2: a name was flagged, a name could not be parsed, a file was not read, or an online lookup failed (never 0). 64: usage (no names and no `--project`, or the directory does not exist). 70: internal error. `--format json` prints `{schema_version: 1, exit_code, complete, online, snapshot{source, date, names}, names[{name, declared_in, state, similar_to, distance, findings, lookup}], invalid, notes, gaps}`; `state` is `popular`, `similar` or `unknown`.

**Limits (measured, not guaranteed).** It is a hint, not proof. Tested against the bundled snapshot with the dataset itself: about 98% of single-edit typos of popular names are caught; about 7% of real packages ranked just below the snapshot are flagged as similar to a popular one (a false alarm), roughly half of that from the 2-edit rule. It cannot recognise look-alikes of packages outside the snapshot, nor prefix/suffix tricks (`python-requests`) or other kinds of look-alikes. The snapshot ages; refresh it with `python tools/update_top_pypi.py` before a release and review the diff.

### Plain-English explanations (`In plain words:`)
Under each finding the text and styled reports print one extra line, `In plain words: ...`: one or two short sentences on what it is, why it matters and how to fix it. It is shown by default (no flag). The finding's `message` is unchanged.
- **JSON:** the finding gets an `explanation` string, only when one exists (reports and findings without one are unchanged; `schema_version` stays 1).
- **Covered:** the 14 Semgrep rules, withheld-file findings, Python syntax errors, secrets (one generic text for every `secrets.*` rule, never containing the value), and dependency findings. Anything else has no explanation.
- **Dependency findings** use a fixed template filled from the finding's own data (package, installed version, fixed versions, patch/minor/major label); advisory texts are not rewritten. With no fixed version it says so.
- **Wording:** "can" / "could" only. It never says an attack will happen or that a fix makes the project safe.

## Reading the output (colours, icons, progress)
On a terminal the commands are laid out for quick reading; piped output, CI logs and `--format json` stay plain and unchanged.
- **Verdict banner**: green `✓ PASS`, yellow `! WARNING`, red `✗ FAIL`, then why, then one line per check with an icon (`✓` passed, `✗` findings or error, `!` incomplete/unavailable/timeout, `–` skipped / not applicable).
- **Severity tags**: `[CRITICAL]` bold magenta, `[HIGH]` bold red, `[MEDIUM]` yellow, `[LOW]` cyan, `[INFO]` dim; a tally (`CRITICAL 2  HIGH 13  MEDIUM 15`) sits above the list. Fixed versions are green, long messages are wrapped, and a **What to do next** block follows (upgrade the packages, fix the flagged lines, run `saferun status`).
- **Progress**: `scan` shows a spinner with elapsed seconds on stderr while it works (so stdout and JSON are never touched), `init` shows a download progress bar for the OSV data and a spinner during the analyzer build. The cursor is hidden while animating and always restored, also on Ctrl-C.
- **Control**: `--color auto|always|never` on `scan`, `init`, `status`, `verify-images`, `osv-db status`, `check-names`. `auto` = only on a terminal; `NO_COLOR` turns colour off, `FORCE_COLOR` on, `TERM=dumb` off; `SAFERUN_ASCII=1` (or a non-UTF-8 terminal) uses `+ x ! -` instead of `✓ ✗ ! –`.
- Untrusted text (file names, messages) is sanitized to one line **before** it is painted, so a project cannot inject escape sequences or fake report lines; colours are for people, the exit code and JSON are what scripts should use.
