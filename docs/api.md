# Web dashboard and API (Phase 4)

> **Local, loopback-only demonstration interface. The CLI remains the primary product.**
> **Do not expose this server beyond your own machine.** Uploaded archives are never *executed*. Since Phase 5B Semgrep and OSV-Scanner *parse*
> them inside a locked-down analyzer container (no network, read-only project, non-root, no capabilities, resource limits) instead of on the host, which
> removes the former "host-side analyzer" exposure **as far as the container boundary holds** (see PROJECT.md *Phase 5 security status*: tested, not proven).
> The dashboard is still loopback-only in code, has **no authentication**, and any local user can use the port; that restriction stays until the isolation has been reviewed.

## Run
```bash
.venv/bin/pip install -e '.[dev,web]'     # fastapi + uvicorn are an optional extra; `pip install saferun` alone is unchanged
(cd web && npm ci --ignore-scripts && npm run build)   # builds web/dist (git-ignored); needs Node 20.19+/22.12+
.venv/bin/saferun-web                              # or: python -m saferun.api   → http://127.0.0.1:8765/
```
`saferun-web [--host 127.0.0.1|::1] [--port N]`. Anything but a loopback IP literal (`localhost` maps to `127.0.0.1`) exits with
status 64 **before** the server is created; there is no environment variable or option to override it. Additionally every request is
checked by `GuardMiddleware`, so the restriction also holds if the ASGI app is started some other way.
Development: `cd web && npm run dev` (Vite on 127.0.0.1:5173, proxying `/api` to 8765). Frontend tests: `npm test`. The frontend is plain JavaScript (React + Vite, `.jsx`); there is no TypeScript.

The dashboard needs the same things as the CLI: Docker, the runtime images and the analyzer image (`docker/analyzer/build.sh`), plus validated OSV data (`saferun osv-db update`; scans refuse invalid data and report data older than 30 days as `incomplete`). `GET /api/health` (`docker_cli`, `analyzer`; `semgrep`/`osv_scanner` mirror `analyzer`) and the
UI say what is missing; a missing piece means that check is `unavailable`/`error` and the verdict is at best WARNING.

## Design
```
browser (React, same origin) ── POST raw ZIP ──► streamed to a 0600 temp file (size-capped)
                                                  │ queued (1 running + 4 waiting)
                                                  ▼
                                   archive.extract_zip  (validate everything, then write; reject whole archive on any doubt)
                                                  │
                                                  ▼
          python -I -m saferun scan <dir> --format json  [--osv-offline | --no-dependency-scan]   (child process, own process group)
                                                  │ exit code must agree with report.verdict
                                                  ▼
                       report relayed UNCHANGED (schema_version 1) ──► GET /api/scans/{id}
```
There is **no validation code in the web layer**: the worker is the existing CLI, so verdict rules, exit codes, the report schema, the engine
and the sandbox are exactly those of `saferun scan`. A test runs both paths on the same archive and requires identical reports.
The UI only renders `report.verdict`; it never computes one. Nothing in the API runs code, commands or shells.

### Frontend layout (`web/src/`)
```
main.jsx, App.jsx          entry points (App renders the single page)
index.css                  global only: design tokens, reset, primitives shared by several components
pages/DashboardPage/       DashboardPage.jsx + .css (+ .test.jsx): state machine upload → poll → result
components/<Name>/         one folder per component: <Name>.jsx + matching <Name>.css (only where it has own styles)
                           Header, Footer, UploadPanel, ArchiveCard, ResultPanel, ReportView (composition),
                           VerdictCard, CheckCoverage, StatusBadge, FindingsTable, SeverityTally, GapsPanel
api/client.ts              fetch wrappers (same origin, custom CSRF header)
types/index.js             JSDoc typedefs of the report/job shapes (documentation only), mirroring saferun/engine/model.py
utils/                     report.ts (sorting, gaps, sanitising text), errors.ts (messages for stable error codes)
fixtures/report.json       golden report generated from the real engine model (pinned by tests/test_api_schema_fixture.py)
```
Tests live beside what they test. Plain global class names are used (no CSS modules), so moving a rule between files changes nothing visually as long as the import order in `main.tsx` is kept (`index.css` first).

### Endpoints
| | |
|---|---|
| `POST /api/scans?osv=offline\|disabled` (default `offline`; `online` → `422 osv-online-unsupported`) | body = raw ZIP, `Content-Type: application/zip`, header `X-SafeRun-Request: 1` → `202 {id,status}`. `413` too large · `415` wrong type · `429` queue full (`Retry-After`) · `408` upload too slow · `507 insufficient-storage` disk (nearly) full · `400/422` malformed |
| `GET /api/scans/{id}` | `{id,status,osv_mode,created_at,archive,error,report?}`; status ∈ `queued, running, done, failed, rejected`. HTTP 200 whatever the verdict |
| `DELETE /api/scans/{id}` | `204` (finished only; `409` if running) |
| `GET /api/health` | tool availability (booleans), queue occupancy, limits. No paths |
| `GET /`, `/assets/*` | the built dashboard (only if `web/dist` exists) |

Job states: **done** (a verdict exists), **rejected** (the archive was refused; stable `error.code` such as `unsafe-name`, no member names), **failed**
(no verdict: deadline, worker error, unusable output — *never* shown as a pass). Bad archives are rejected by the worker thread, not in the request, so at
most one extraction runs at a time.

### Limits (defaults, all tested)
Upload 100 MiB · extracted 400 MiB · 5 000 entries · 25 MiB per file · depth 32 · path 1 024 B / component 255 B · ratio cap 100:1 (above 1 MiB) ·
extraction 60 s · job deadline 10 min (process group killed) · tool timeout 120 s (CLI `--timeout`) · 1 running + 4 queued jobs · results kept 30 min, max 50 ·
worker output ≤ 8 MiB · upload read deadline 120 s · uploads still being read count against the 5 slots (a stalled client cannot hold unbounded temp files) · uvicorn `limit_concurrency` 32 connections.

## Archive handling (`saferun/api/archive.py`)
Whole-archive validation before the first byte is written (the central directory is walked and counted by SafeRun itself before `zipfile` builds any object, so a lying end record cannot make a small upload allocate hundreds of MiB; **ZIP64 archives are refused**, nothing within the limits needs them); **any** unsafe or invalid member rejects the whole archive. Rejected: absolute paths, `..`/`.`/empty
components, backslash, colon, NUL, control/bidi/format characters, non-UTF-8 names, over-long or too-deep paths; symlinks, hard-link-style special members, devices,
FIFOs, sockets, Windows reparse points; encrypted entries; compression other than STORED/DEFLATE; duplicate paths (also after case/Unicode folding) and file-vs-directory
conflicts; local headers that disagree with the central directory, overlapping entries (zip quines), junk before the first entry or after the end record, multi-disk
archives; declared *and* actual sizes beyond the limits (headers can lie, so counts are enforced on the bytes produced). `__MACOSX/` (top level) and `.DS_Store` files are
validated, then excluded and listed in the response; one top-level wrapper directory is stripped only when it is unambiguous. Extraction uses fd-relative `O_NOFOLLOW|O_EXCL`
writes into a fresh 0700 directory, files 0644 / directories 0755 regardless of the archive (the Phase 1 copier would otherwise withhold 0600 files).

## Worker environment
The worker is started with an environment built from an allow-list, never from `os.environ` as a whole, and as `python -I` (no `PYTHONPATH`, no user site, no cwd on `sys.path`).
| Variable | Preserved because |
|---|---|
| `PATH` (the server interpreter's bin dir is prepended) | the worker must find `docker`; analyzers run in a container, not from PATH |
| `SAFERUN_ANALYZER_LOCK`, `SAFERUN_OSV_DB` | explicit locations of the analyzer build lock and the offline OSV data; resolved in the server (the worker's HOME is a private directory) and passed on |
| `LANG`, `LC_ALL`, `TZ` | decoding of tool output; timestamps |
| `DOCKER_HOST` | the sandbox reads it and accepts only `unix://` endpoints; a different local socket must keep working |
| `DOCKER_CONTEXT` | selects the context the docker CLI talks to |
| `DOCKER_CONFIG` | only if the operator set it explicitly. The real `~/.docker` (registry credentials) is **not** exposed |
| `HOME`, `TMPDIR` | *set by SafeRun* to a private per-job directory (deleted with the job), not inherited |
Everything else is dropped, notably cloud/API tokens (`AWS_*`, `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`…), `SSH_AUTH_SOCK`, and the code-injection variables `PYTHON*`, `LD_*`,
`BASH_ENV`, `ENV`. The analyzers run in a container that receives no host environment at all. Consequence: a non-default Docker context that is defined only in `~/.docker` is not
visible to the worker — set `DOCKER_CONTEXT`/`DOCKER_CONFIG` for the server if you need that.

## Network-facing protections
Peer address must be loopback (`403`); `Host` header must be a loopback name (`400`, DNS-rebinding defence); state-changing requests need `X-SafeRun-Request: 1` and, when an
`Origin` header is present, exactly this server's own origin (`403`); CORS preflights are never answered; WebSockets are refused; no OpenAPI/docs pages; `proxy_headers` off;
security headers on every response (`Content-Security-Policy` without inline script/style, `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, CORP/COOP same-origin);
`Cache-Control: no-store` on the API. IDs are 128-bit random capabilities; there is no list endpoint. **There is no authentication** and none is claimed: anyone who can reach
the loopback port (any local user) can use the dashboard and read results by ID.

## Privacy
Nothing leaves the machine: scans run offline. There is no OSV *online* mode (it was removed in Phase 5B); `disabled` skips the dependency check (→ WARNING). Refresh the local OSV data with `saferun osv-db update`.

## Cleanup
The upload, the extraction directory and the worker's HOME are deleted before a job's result is published. A killed or timed-out job triggers `reap_orphans()` (containers also die by their own container-side timeout).

**Server stopped (Ctrl+C / SIGTERM).** A running scan is cancelled, not left behind: the worker's process group gets SIGINT (so the CLI removes its own container and workspace), SIGKILL after 15 s; the job ends `failed` with code `shutdown`, and its upload and extraction directory are deleted. Queued jobs are failed and their uploads deleted.

**Server SIGKILLed.** Nothing can run at that moment, so recovery happens at the next start (Phase 5D). The launcher takes a per-user `flock` (`<tmpdir>/saferun-server-<uid>.lock`, owner and symlink checked; the kernel releases it when the process dies). While it holds the lock no other live server of this user exists, so **every** leftover `saferun-up-*` directory and `saferun-upl-*` file is deleted (not only old ones) and orphaned workers are SIGKILLed first (processes of the same user whose working directory is inside a `saferun-up-*` directory). Then `reap_orphans()` removes abandoned containers and workspaces. If the lock cannot be taken (another server may be running, or the lock file is not ours), only entries older than 40 min are swept, as before. Not covered: a worker's docker containers outlive the kill only until their own container-side timeout.

**Disk full.** An upload is refused with `507 insufficient-storage` when free space in the temp directory is below the declared `Content-Length` plus 64 MiB, and also when the disk fills while the upload is written or the temp file is created (partial files are deleted and the slot is released). Extraction already refuses when free space is below twice the extracted size (`insufficient-space`).

**Hung Docker daemon.** Every Docker CLI call has a timeout (30 s). `/api/health` runs its analyzer check with a 10 s limit, shares one pending check between requests and caches the answer for 5 s, so a hung daemon reports `analyzer: false` instead of piling up threads. A scan whose container cannot be killed because the daemon hangs ends with an error after at most 30 s, our `docker start -a` client process is killed, and the reaper still removes workspaces when it cannot list containers.

## OSV modes
`offline` (default): OSV-Scanner runs in the analyzer container without network, reading the local OSV data mounted read-only; verified through the real chain (API -> worker CLI -> engine -> container) with the real osv-scanner 2.7.0. No local data → the dependency check ends in `error`, verdict WARNING, never clean. `disabled` → `skipped`, WARNING. `online` is refused with `422`: a container with network access cannot be restricted to api.osv.dev without a host firewall or egress proxy (see PROJECT.md *Phase 5B*), and SafeRun does not pretend otherwise.

## Limitations
No authentication, loopback only; analyzers isolated in a container (tested, not proven; the container shares the host kernel); in-memory results (lost on restart); one job at a time; ZIP only; the 408 timeout covers the upload only; the dashboard
inherits every engine limitation (Python-focused rules, no transitive dependency resolution, PASS ≠ safe). The UI was verified with component tests (jsdom), `curl`, and a scripted run in real Google Chrome 153 (headless, via playwright-core kept outside the repo); it was not tried in other browsers or by a human reviewer. Its styling is an original design — the reference images mentioned in the task were not available.
