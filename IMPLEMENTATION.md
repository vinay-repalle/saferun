# SafeRun — Implementation Status

## Environment (inspected 2026-10-28)
Ubuntu 24.04 host, kernel 7.0.0-38, 12 CPU / 15 GiB, ext4 `/tmp`. Python 3.12.3 (no pip/venv module: project-local `.venv`
created with `--without-pip` + official `get-pip.py`). Docker 29.8.0 (runc, cgroup v2, AppArmor + builtin seccomp reported by the
daemon, no userns remap), user in the `docker` group, default context `unix:///var/run/docker.sock`.
Phase 2 tooling status on this host: `semgrep` and `osv-scanner` were **not installed** at the start of Phase 2. Semgrep 1.182.1 was then installed
**into the project-local `.venv` only** (`pip install semgrep`, binary wheel, no project code involved; `.venv` is git-ignored) so the rules and parser could be checked
against the real tool. `osv-scanner` 2.7.0 was installed during the final review (see *Final review*). (node 22/npm exist on the host but SafeRun never runs them on the host.)
Images used by SafeRun: `python:3.12-slim` (present from the start) and `node:22-slim` (digest `sha256:4b150b48…`, pulled explicitly
during the completion pass for the JavaScript tests; remove with `docker rmi node:22-slim` if unwanted). Not installed: semgrep,
osv-scanner (Phase 2). The Docker host also holds unrelated images/containers — never touched.

## Phase 1 — Environment and Sandbox
**Acceptance status: every documented Phase 1 criterion is met on the evidence below (236 tests, 0 skipped; limits listed).
APPROVED by the owner as a project milestone and the baseline for Phase 2 — not a claim of perfect security or independent certification.
Phase 1 may be changed later only for a concrete reason, with regression tests. Passing tests do not prove the sandbox secure; see *Limitations*.**

### Requirements checklist
| Requirement (Phase 1 brief + review hardening list) | Status | Evidence |
|---|---|---|
| Inspect repository and environment; verify Docker availability/permissions | done | environment above; preflight at every run |
| Threat model and security boundaries | done | PROJECT.md |
| Safe workspace creation/copy: paths, symlinks, hard links, concurrent changes | done | `copy.py`; test_workspace 11, test_races 43, test_hardlinks 8 |
| Workspace cleanup incl. failure paths and abandoned workspaces | done | test_cleanup (8), reaper, hardening (daemon-down cases) |
| Docker: non-root, read-only root, no network, caps dropped, no-new-privileges, seccomp/AppArmor | done | applied-config verification (28 checks) + kernel-view attestation, both images |
| CPU, memory, swap, PID, fd, tmp, file-size, output, wall-time limits | done | test_sandbox, attestation (cgroup values), verification |
| Safe subprocess/Docker invocation, timeouts, errors, container cleanup | done | argv only, absolute docker path, `SandboxError` for odd Docker output, hung CLI, kill failure, daemon down |
| Sensitive-file detection, warnings, redaction | done | test_sensitive (27) |
| Seccomp/AppArmor availability checks; honest reporting of unverifiable controls | done | `daemon_controls`, `SandboxResult.controls`, `attest()` |
| Malformed inputs, unexpected Docker responses, daemon failures | done | test_hardening (102) |
| Python sandbox preserved and verified | done | all existing tests green; attestation on `python:3.12-slim` |
| JavaScript/Node.js | **partial by design** | the sandbox runs a JS file in `node:22-slim` under identical controls (11 tests); dependency handling/test runners/analysis are Phase 2 |
| OpenSandbox reuse assessment | done | PROJECT.md (nothing copied; ideas adapted; no new dependency) |

### History (nothing hidden)
1. Initial PoC: 18 tests (first run 17/1 — an over-broad test filter caught Docker's own `--init` mount; test narrowed, no control changed).
2. Independent review → 8 fixes (cleanup, orphan recovery, copy limits, seccomp/AppArmor/swap tests, `skipped`, race-safe copy, test quality, docs): 45 tests.
3. ZIP-review follow-ups: sensitive files, hard links: 80. 4. Result metrics (`copied_*` vs `entries_scanned`): 81.
5. Copy-race fix (replacement after pre-scan): 99. 6. Directory-mutation race (final validation pass): 120.
7. **Phase 1 completion pass (this document's latest update): 120 → 236 tests.** Test-code bugs found along the way (a network
   mutation that also rewrote `--log-driver none`; a fake-`docker` script whose restricted `PATH` hid `sleep`; earlier: self-copying temp dir,
   misplaced failure injection, miscounted expectation, token padding, wrong-file hook) were fixed in the *tests*; no control was weakened.
   One process slip: a presence check used `docker run`, which attempted an implicit pull of `node:22-slim` (it failed on a network
   reset; nothing was created). An earlier `IMPLEMENTATION.md` edit of mine had duplicated sections; the file was rewritten.

### Completion pass: what changed and why
Inspection of the then-current code against the hardening list found these real gaps (all fixed, each with regression tests):
| # | Gap found | Fix |
|---|---|---|
| H1 | Docker's *applied* config was verified only in tests, not at run time | After `create`, before `start`: `docker inspect` is checked against 28 policy properties (`controls.verify_applied_config`); any deviation raises and the code never runs. Each property is shown to flip on the opposite value (28 mutation tests) and the fail-closed path is tested for 5 weakened-create scenarios |
| H2 | Daemon capability not checked; unverifiable controls not reported | `preflight()` refuses a run when seccomp is missing/unconfined or memory/swap/pids/CPU limits are unsupported (explicit `allow_degraded` opt-out, still reported); AppArmor reported, not required; `SandboxResult.controls` lists every control as verified / violated / unavailable / unverified; `attest(image)` reads the kernel's view from inside a sandbox |
| H3 | `force_remove` counted *any* `inspect` failure as "container gone" (daemon down ⇒ false success) | distinguishes "No such object" from daemon errors (regression test; reaper likewise reports a `docker ps` failure instead of an empty success) |
| H4 | Odd Docker output raised raw exceptions or produced `exit_code=None`; a kill that did not stop the container leaked `TimeoutExpired` | wrapped in `SandboxError`; unreadable final state is an error ("outcome unknown") |
| H5 | `create` could pull a missing image or follow a re-pointed tag; image/args unvalidated; image `ENTRYPOINT` could reinterpret argv; remote endpoint only documented | `--pull never`; created from the resolved image ID (`image_id` recorded and verified); image/command validation; `--entrypoint ""`; non-`unix://` endpoints refused |
| H6 | `/dev/shm` unbounded; images with `VOLUME` would get writable, unbounded anonymous volumes | `--shm-size` (`shm_mb`) verified and tested; images declaring `VOLUME` refused (unit-tested on the inspect data; no VOLUME image was built) |
| H7 | Untested: concurrent runs, hung CLI, non-UTF-8 output, malformed paths, removal/truncation windows | tests added (6 parallel runs; fake hung/garbled `docker`; NUL path; entry/dir removed between stat and open; truncation mid-read) |

### Test results (actual, final run of this pass)
Relevant tests were run incrementally while building (e.g. hardening 98/98 at the time, Node 11/11, races 43/43). Final, once:
`SAFERUN_REQUIRE_DOCKER=1 .venv/bin/pytest -v -rs` → **236 passed, 0 failed, 0 skipped** in 35 s
(test_hardening 102, test_races 43, test_sensitive 27, test_sandbox 24, test_workspace 11, test_node_profile 11, test_hardlinks 8,
test_cleanup 8, test_require_docker 2). The AppArmor-dependent checks ran (daemon reports AppArmor); the Node tests ran (image present).
After the run: 0 containers labelled `saferun.sandbox=1`, 0 `saferun-*`/test containers, 0 `/tmp/saferun-ws-*`, 0 `saferun-attest-*`,
no non-symlink workspace directory under pytest's temp area. Unrelated containers/images were not modified.
In-memory mutation checks (not part of the suite), each making the intended tests fail: pre-start verification disabled (5 tests);
old `force_remove` (1); `--pull never` removed (1); old reaper ignoring a `docker ps` failure (1). Earlier passes added: private-mode
check disabled, hard-link check disabled, chunk overlap shrunk, `copied_files = entries_scanned`, `O_NOFOLLOW` removed, and old-code
comparisons for both race fixes.
Not run / could not run: rootless Docker, Podman, a host without AppArmor, a host with `docker`'s seccomp disabled, an actually
hung Docker daemon (simulated with fakes), disk-full, kernels < 6.13.

### Verified security controls and how each is evidenced
*Per run*, a control is reported `verified` only from Docker's own applied config (pre-start) or the daemon's own capability report.
*On demand*, `attest()` adds what the kernel reports inside a sandbox. † = also shown to fail when disabled (mutation, not in suite).
- **Isolation flags as applied** (28 properties, †): not privileged, `network none`, read-only root, `CapDrop=ALL`/no `CapAdd`,
  `no-new-privileges`, no `unconfined` profile, empty entrypoint, uid 65534, memory = memory-swap, CPU quota, pids, nofile/fsize/core ulimits,
  `/tmp` tmpfs `noexec,nosuid,nodev` + size, shm size, one read-only `/workspace` bind (no binds/extra mounts), no image `VOLUME`,
  no devices, no published ports, private PID/IPC/user/UTS, `--init`, log driver none, OOM kill enabled, no restart, resolved image ID, label.
- **Daemon** (†): seccomp present and not unconfined; memory/swap/pids/CPU cgroup support (else refused unless `allow_degraded`); AppArmor reported.
- **Kernel view** (`attest`, both images): `Seccomp: 2`, `NoNewPrivs: 1`, `CapEff/CapBnd/CapAmb = 0`, uid 65534, only `lo`, `memory.max`,
  `memory.swap.max = 0`, `pids.max`, `cpu.max`, workspace and root not writable, `/tmp` writable, AppArmor `docker-default (enforce)` (this host).
- **Behavioural evidence** (Python and, for the subset listed in test_node_profile, Node): no network and no DNS; read-only filesystem except `/tmp`;
  `/tmp` noexec and size-limited; `/dev/shm` size-limited; no host env/socket/home; OOM kill; exact PID limit (Python); CPU quota in cgroup;
  file-size ulimit is the cause of `EFBIG`; output cap without blocking; host timeout and container-side `timeout -s KILL` (parent SIGKILLed); kernel view above.
- **Workspace copy:** † pre-scan signatures of every entry/listing, verified lstat + opened fd, listings, post-read check and final validation pass
  (see *Concurrent modification*); fd-relative `O_NOFOLLOW`; limits enforced before and during the copy; lazy, bounded directory listing.
- **Sensitive data:** † mode-based and content-signature withholding, `allow_paths`/`honor_private_modes`, output redaction with truncated-tail dropping.
- **Hard links:** † copied only if every name of the inode was seen inside the tree.
- **Cleanup and recovery:** independent container/workspace cleanup, original exception preserved, failure paths tested; `reap_orphans()`
  (deadline label, flock-guarded workspaces, daemon failure reported); concurrent runs isolated.
- **Invocation hygiene:** argv only, absolute docker path, validated image/command, `--pull never`, local endpoints only, odd Docker output → `SandboxError`.

### Concurrent modification — what is and is not claimed
Mechanism: pre-scan records a signature (mode/type, dev, ino, size, mtime_ns, ctime_ns) of every entry and each directory's names; the copy
pass requires lstat and the opened fd to match, listings to match, and files to be unchanged after reading; a final pass re-validates every
directory (identity, metadata, listing) and entry. Any difference aborts with `WorkspaceChangedError` and nothing is kept. This is
**detection on a live filesystem, not an atomic snapshot** (that needs LVM/btrfs/ZFS/overlay snapshots). Not detected: changes after the final
validation (they cannot alter already-copied files), changes leaving every recorded field identical (possible within one coarse timestamp tick
on kernels < 6.13 — this host runs 7.0; untested elsewhere), content already present at scan time, cross-file inconsistency that predates the scan.
A concurrent writer can force repeated aborts. The top-level path is resolved once by the caller; the destination is private (0700) until done.

### Result accounting
`copied_files`/`copied_dirs`/`copied_bytes` = what was written and kept; `entries_scanned == copied_files + copied_dirs + len(skipped) + len(withheld)`;
plus `skipped`, `withheld`, `redactions`, `controls`, `image_id`. Size limits count bytes *read* (conservative).

### JavaScript / Node.js status
- **Done:** a JavaScript file runs in `node:22-slim` through the same `run_sandboxed`, with identical, verified restrictions (11 tests: attestation, run/exit/output,
  uid and clean env, no network incl. DNS, read-only fs except `/tmp`, `/tmp` noexec, OOM kill at 96 MB, timeout, output cap, symlink/secret handling).
  The architecture needed no change beyond the image-agnostic hardening above and an entrypoint reset (the Node image sets an `ENTRYPOINT`).
- **Not done (Phase 2, and why):** dependency acquisition needs a *separate* network-enabled, allowlisted sandbox (`npm ci --ignore-scripts`) and offline
  execution afterwards; `package.json`/lockfile handling; test-runner integration (`node --test`, jest) and result parsing; `node --check`; Semgrep JS
  rules; OSV for npm; Node version selection; digest pinning; behaviour on Alpine/distroless (`timeout`/`sh` required, verified only on the two Debian-slim
  images); V8 heap vs cgroup tuning. A JavaScript SDK that merely controls a sandbox does not run JavaScript; this status concerns SafeRun's own Docker sandbox.

### OpenSandbox reuse — decisions (full table in PROJECT.md)
Nothing was copied, installed, run or deployed; reviewed read-only over the web. Reuse: **none of the platform** (server, execd, egress sidecar, SDKs, code
interpreter, isolation sessions — avoided: extra infrastructure, in-sandbox daemon, weaker defaults, privileges the sandbox must not have). **Adapted as ideas,
re-implemented in our own code:** explicit-acknowledgement fail-fast (`startup_guard.py` → `preflight` + `allow_degraded`); input hygiene (`validators.py` →
`validate_command`, `validate_image`, mount-path check); argv-only command semantics. **Built our own:** orphan labels/reaper, resource limits, runtime
profiles. **Deferred:** stronger runtimes (gVisor/Kata) as a possible future backend; cosign/digest practices for Phase 5. Licence: all reviewed code is
Apache-2.0; no code copied ⇒ no §4 obligations; no new SafeRun dependency. Limits of the review: only the files listed in PROJECT.md were read (not
`volumes.py`, `networking.py`, `runtime.py`, execd Go sources); decisions are confined to that evidence.

### Limitations and unverified claims
- **Not proven secure.** The container shares the host kernel; kernel/runc escapes are neither mitigated nor assessed. No userns remap, gVisor or Kata.
  The `docker` group is root-equivalent; the invoking user, `PATH` and the local daemon are trusted. Seccomp *rules* and the AppArmor profile *contents*
  are not audited — only that they are active. A sandbox limits the impact of running untrusted code; it does not make the code safe.
- AppArmor is verified only on this host; the no-AppArmor and `allow_degraded` paths are unit-tested with fakes, not on such a host. Rootless Docker, Podman
  and non-default contexts are untested. Per-run `controls` come from Docker's config/daemon report; the kernel view requires calling `attest()` (not run automatically per scan).
- Preflight → create is not atomic, but the container is created from the *resolved image ID* and that is verified; an image's *contents* are not audited.
- Redaction is best-effort (code can encode a secret first; a test documents base64 passing through). A world-readable secret in an unrecognised format is readable
  by sandboxed code; the signature list is not exhaustive; withheld files are not analysed.
- `/proc`/`/sys` expose host details (kernel, CPU, host workspace path in `mountinfo`); file modes are flattened to 0644/0755 (exec bits lost).
- Behaviour under a truly hung daemon, a full disk and extreme load is untested; the host timeout excludes `docker create` time; Docker/`timeout` failures after start look
  like exit 125–127 (stderr untrusted). CPU throttling accuracy is not measured (only the quota). Hard-link detection relies on `st_nlink` (verified on ext4).
- Images must provide `timeout` and `sh`; verified on two images. Sandbox output is not sanitized for terminals by the sandbox itself; the Phase 3 CLI sanitizes what it prints. `reap_orphans()` is not called automatically.
- The remote-endpoint refusal is exercised through `DOCKER_HOST` only (the context-based branch runs on every real run for the default context, but a remote *context* was not tested).
- Secret values live in host memory during a run. Submounts inside a scanned directory are not handled specially.

### Steps requiring the owner's approval
1. **Phase 1 acceptance** (not self-approved). 2. **`node:22-slim` was pulled** (≈326 MB, official image) to test JavaScript; keep, or remove with `docker rmi node:22-slim`.
3. Whether the **Phase 2** plan below may start. 4. A **licence for SafeRun itself** is undecided (no copied code constrains it). 5. Whether the default policy
(`allow_degraded` empty ⇒ refuse hosts without swap/pids/memory/CPU cgroup support) should stay strict.

### Hand-offs to later phases
Phase 2 must report any non-empty `skipped`/`withheld`/`redactions` as a **partial scan**, surface withheld credential files as findings, run analyzers inside the
sandbox, keep dependency acquisition a separate network-enabled step, and add the JavaScript items above. Phase 4: refuse hard-link/symlink/device archive members,
enforce upload limits, extract into a private directory. Phase 5: pin images by digest, decide whether a second backend is real before extracting an interface.

## Git
The directory was not a repository. `git init` + one local commit `Add restricted Docker sandbox foundation` (Phase 1 baseline, 27 files; `.gitignore` extended with
`artifacts/` (a generated review zip), env/key patterns). No remote configured, nothing pushed.

## Phase 2 — Validation Engine (committed `088b279`)

### Requirements checklist
| Requirement | Status | Evidence / notes |
|---|---|---|
| A. Semgrep integration (controlled subprocess, rules, parsing, missing tool/malformed/timeout/non-zero) | done; verified against real Semgrep 1.182.1 (`--validate` of the rules, real scan, `# nosem` ignored) | `engine/semgrep.py`, `rules/python.yml` (11 rules), `tools.py`; 22 mocked-output tests + 2 tests that run the real binary when installed |
| B. OSV-Scanner integration (ecosystems, normalization, unavailable/timeout/invalid/error, never silently clean) | done; **verified against real osv-scanner 2.7.0** (see *Final review*) | `engine/osv.py`; mocked-output tests plus real-binary tests in `tests/test_engine_real_tools.py` |
| C. JavaScript: `node --check`, npm lockfile scan, deferred list | done (plus a sandboxed Python syntax check, added after real-Semgrep testing) | `engine/node.py` runs in the sandbox; real-sandbox tests (2); npm scan via OSV (mocked). Deferred: installation, test runners, JS Semgrep rules |
| D. Normalized model + verdicts | done | `engine/model.py`, `verdict.py`; 17 verdict tests; rules in docs/engine.md |
| E. Integration without breaking the sandbox API | done | `engine/engine.py` uses `create_workspace`/`run_sandboxed`; no sandbox file modified; all 236 Phase 1 tests unchanged and green |
| F. Tests and docs | done | below; README/PROJECT/IMPLEMENTATION updated (since reorganized into docs/) |

### Issues found by running the real tools (fixed in Phase 2 code)
1. Semgrep prefixed rule ids with the rule file's directory path (`home.user….saferun.python.…`); fixed with `--no-rewrite-rule-ids` (mocked tests could not catch this).
2. Semgrep does **not** report Python syntax errors (a file with `def f(:` is "scanned", no error), so a broken file looked clean. Added the sandboxed `python-syntax` check.

### Design decisions worth reviewing
1. **Semgrep and OSV-Scanner run on the host, against the sanitized copy** (see PROJECT.md *Validation engine* for the reasoning and mitigations). This is a
   conscious deviation from the Phase 1 hand-off note "run analyzers inside the sandbox": no analyzer image exists locally, SafeRun does not pull images, and OSV needs network.
   `node --check` does run in the sandbox. Decision needed from the owner: build/approve an analyzer image later, or accept host-side analyzers.
2. Operational failures yield `WARNING`, not `FAIL`; `FAIL` is reserved for findings. `PASS` requires at least one completed analysis check and no partial scan.
3. A non-empty `skipped`/`withheld` workspace is a partial scan (WARNING at least); withheld credential files are HIGH findings (as the Phase 1 hand-off asked).
4. JavaScript syntax errors are MEDIUM (WARNING), not HIGH.

### Phase 1 changes
**None.** No file under `saferun/sandbox/` was modified in Phase 2. No Phase 1 defect was found.

### Test results
See the completion report in the conversation for exact commands/output; summary: final-review runs (see *Final review*): with both real tools on PATH
`PATH="$S/osv:$PWD/.venv/bin:$PATH" SAFERUN_REQUIRE_DOCKER=1 .venv/bin/pytest -q -rs` → **396 passed, 0 skipped** (77 s); with neither on PATH
`SAFERUN_REQUIRE_DOCKER=1 .venv/bin/pytest -q -rs` → **382 passed, 14 skipped** (all skips are real-tool tests, each reporting why) (39 s).
Phase 1 = 236, Phase 2 = 160. Afterwards: 0 containers labelled `saferun.sandbox=1`, 0 `/tmp/saferun-ws-*`.

### Unavailable / not verified in this environment
- `osv-scanner`: not on the system PATH; a checksum-verified 2.7.0 binary lives in the session scratchpad only (see *Final review*). Real-binary tests skip visibly without it.
- `semgrep`: available only via the project `.venv` (not on the system PATH); real-tool tests run when it is on PATH, otherwise skip visibly.
- No network-dependent test exists; ordinary tests need neither network nor either tool.

### Limitations and deferred work
See PROJECT.md *Validation engine → Limitations*. Additionally: rule quality is unmeasured (no false-positive/negative evaluation); the verdict thresholds are policy
choices, not validated; host-side analyzers are part of the trusted base; OSV online mode discloses dependency names/versions to OSV.dev.

## Final review of Phase 2 (verification pass)
No commit, no push, no Phase 3. No file under `saferun/sandbox/` changed.

### Environment changes made in this pass
- **osv-scanner v2.7.0** (`osv-scanner_linux_amd64` from the official GitHub release; SHA-256 checked against the release's `osv-scanner_SHA256SUMS`: OK) placed in the session
  scratchpad `…/scratchpad/osv/` only. Not on the system PATH, nothing installed system-wide, no Docker resources touched. Test inputs were hand-written lockfiles; **no dependency was installed or built**.
- Semgrep 1.182.1 remains in the project `.venv` (from the previous pass). The scanner contacted `api.osv.dev` (package names/versions only) during the real-tool tests.

### Verified with the REAL osv-scanner 2.7.0
| Item | Result |
|---|---|
| CLI flags used (`scan source`, `--format json`, `--no-resolve`, `--offline`, `--lockfile=`) | all exist in 2.7.0 (`--help` read) |
| `--offline` | does **not** merely skip the network: it switches to local databases and fails (exit 127, "no offline version of the OSV database is available") when none are cached → reported `error`; the doc claim was right, my earlier reading of the flag was incomplete |
| JSON shape (`results[].source.path`, `packages[].package`, `vulnerabilities[]`, `groups[].max_severity`, `aliases`, `database_specific.severity`, `affected[].ranges[].events[].fixed`) | matches the parser; real output parsed into findings with correct package/ecosystem/path, alias de-duplication, fixed versions |
| Known vulnerable dependency | `django==2.2.0` → 43 findings (PyPI) incl. critical; `lodash 4.17.15` in `package-lock.json` → GHSA-35jh-r3h4-6jhm / CVE-2021-23337, high, fixed in 4.17.21 |
| Clean result | `six==1.17.0` → exit 0, `{"results": []}` → `passed` |
| Exit codes | 0 clean, 1 findings, 127 error, 128 no packages (empty lockfile → `incomplete`) |
| Failure modes | malformed lockfile (127), missing file (127), unreachable network, `--offline` without DB, timeout, missing tool → `error`/`error`/`error`/`error`/`timeout`/`unavailable`; verdict `WARNING`, never PASS |
| Exit 127 **with a clean-looking** `{"results": []}` (network down) | the engine checks the exit code before parsing → `error` (regression-tested against the real binary) |
| Python/npm support | `requirements.txt` and `package-lock.json` verified. `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`, `yarn.lock`, `pnpm-lock.yaml` are passed to the tool by name but were **not** exercised with it |

### Defects found in Phase 2 code and fixed (each with regression tests, mostly against the real binaries)
1. **Semgrep skipped files silently.** A project `.semgrepignore` hid a file containing `eval(x)` (result still `findings`/complete), and a 1.8 MB file was skipped without any error. Fix: `.semgrepignore`
   files are removed from the analysis copy only, and every targeted Python file must appear in Semgrep's `paths.scanned`, else the check is `incomplete`.
2. **OSV-Scanner silently skips npm lockfile entries it cannot match** (no registry `resolved` URL, or git): "found 1 package", exit 0, no results — a vulnerable package then looked clean.
   Fix: `package-lock.json` is cross-checked (`npm_unmatched`); such entries make the check `incomplete`. Not done for yarn.lock/pnpm-lock.yaml (unverified).
3. **Requirements variants** (`requirements-dev.txt`, …) were silently ignored → now a reported coverage gap.
4. **Misleading error detail:** OSV-Scanner's progress lines hid its error text in `detail` → error lines are preferred.
5. **Documentation:** `requirements.txt` had been grouped with lockfiles. Fixed everywhere: it is a *manifest/requirements file*; unpinned entries (`flask>=1.0`, verified: evaluated as exactly 1.0) are unreliable and no transitive resolution happens.

### Code review notes (no defect found unless listed above)
Subprocess: argv only, absolute exe, minimal env, own process group killed on timeout/output cap, stdin closed. Paths: tool paths accepted only as relative paths inside the copy; lockfile names
restricted before use in `--lockfile=./…` (`:` and control characters refused). Symlinks: the Phase 1 copy contains none; `os.walk(followlinks=False)`. Cleanup: workspace deleted in `finally`; tests assert an empty workspace root;
no leftover containers/workspaces after the full run. Verdict: no status other than `passed`/`findings` counts as completed; operational problems force `WARNING`; nothing-ran is `WARNING`.
Residual: a cleanup failure raises instead of returning the computed report (fail loud); `yarn.lock`/`pnpm-lock.yaml` may have analogous unmatched-entry gaps; Semgrep's tolerant parser can hide
partially-unparseable regions (syntax errors are caught separately by `python-syntax`).

### Host-side analyzer risk (decision required — nothing changed)
Semgrep and OSV-Scanner run **as the invoking user on the host** and parse files from the sanitized copy. The copy removes symlinks, special files and credential files and nothing is executed from the project,
but a parser/memory-safety or logic bug in either tool (or a crafted file triggering excessive resource use) would run with that user's full privileges: home directory, SSH keys, the `docker` group. Limits in place:
minimal environment, private HOME, process-group kill, 8 MiB output cap, wall-clock timeout. **Not** in place: memory/CPU/pids limits, filesystem or network confinement for the host process.
Both tools are widely used, but "widely used" is not a security guarantee, and nothing here was assessed for exploitability.

| | 1. Documented temporary host-side limitation | 2. Analyzers in a restricted container |
|---|---|---|
| Security | weakest: analyzer bug ⇒ user-level compromise | strong: same verified controls as the sandbox (non-root, no caps, no-new-privileges, read-only, limits, no network, no socket) |
| Work | none (already documented) | an analyzer image (semgrep + osv-scanner, pinned by digest, built on a networked step then used offline); `run_sandboxed` today mounts only the project, so Semgrep (needs a writable cache in tmpfs) fits, but OSV needs vulnerability data |
| OSV network | works online | the sandbox has no network by design; use `--offline` with databases downloaded by a trusted host step that never sees project input (`--download-offline-databases`), mounted read-only — needs a new read-only extra mount in the sandbox (a Phase 1 change, reviewed) |
| Risk of the change itself | none | a new mount and image add surface; must not weaken any existing control; database freshness/size policy needed |
| Verified here | — | **not built or tested** (no image exists; building one is a Docker change not authorised in this pass) |

**Recommendation:** keep option 1 as the explicit, documented interim state for Phase 2 review, and adopt option 2 as the target before SafeRun scans genuinely untrusted uploads (Phase 4) —
a hardened analyzer image run through the existing sandbox, with OSV databases refreshed by a separate trusted step. **Needs your decision:** (a) accept option 1 for now; (b) approve building a digest-pinned
analyzer image and a read-only extra mount (a reviewed Phase 1 change); (c) the offline-database refresh policy; (d) whether OSV online mode (disclosing dependency names/versions to OSV.dev) is acceptable in the interim.

## Phase 4 — Web dashboard: revised plan (2026-10-29)

**Priorities (owner):** the CLI stays the primary product; the dashboard is a secondary, professional-looking *demonstration* interface for
verification and validation. No public deployment, no online code execution, no separate validation implementation: the server runs the existing
`saferun scan --format json` as a subprocess and relays the engine's report unchanged. CLI, exit codes, report schema, engine and sandbox are not modified.

**State found at the start of this revision (reviewed, nothing reset):** HEAD `a9ea5dc` (Phase 3 CLI committed); uncommitted and new: `saferun/api/` (extractor only)
and `tests/test_archive.py` (101 tests, mutation-checked). No API, no frontend, no docs for Phase 4. README/PROJECT still said Phase 3 was "awaiting review".
The "interface reference images" mentioned by the owner are **not available in the repository or the project folder**; the dashboard styling is therefore
an original, neutral professional design and has not been matched to any reference.

**Deviations from the first plan, and why**
| Plan said | Now | Reason |
|---|---|---|
| bad archives answered 422 at upload | upload is streamed to a temp file; extraction runs in the single worker and a bad archive becomes job state `rejected` (with the stable `ArchiveError` code) | bounds concurrent extraction (CPU/disk) to one; the POST stays cheap |
| fastapi 0.162.0 | fastapi **0.140.13** | 0.162.0 requires `opentelemetry-api>=1.44`, Semgrep pins `~=1.37`; installing it broke the venv's Semgrep (repaired; `pip check` clean). A dry run had not shown the conflict |
| sweeper for leftovers "in step 2" | startup sweep of `saferun-up-*` dirs / `saferun-upl-*` files by age + owner | the extractor cannot clean up after SIGKILL |

**Execution units** (each: implement → run its tests → review the diff)
1. Secure ZIP extraction + adversarial tests — **done** (`saferun/api/archive.py`, `tests/test_archive.py`).
2. Bounded job runner (`saferun/api/jobs.py`): one worker, queue of 4, per-job deadline with process-group kill, allow-listed worker environment, cleanup in `finally`, startup sweep + `reap_orphans()`.
3. Validation API (`saferun/api/app.py`): raw-ZIP upload with streaming size cap, scan status/report, delete, health; guard middleware (loopback client, Host allow-list, custom header + Origin check, security headers); no docs endpoints.
4. Application-enforced loopback (`saferun/api/server.py`): the launcher refuses any non-loopback bind; the middleware independently refuses non-loopback peers.
5. React + Vite dashboard (`web/`): upload, OSV mode with privacy disclosure, verdict, check coverage, findings, gaps; Vitest tests driven by a Python-generated golden report fixture.
6. Docs, end-to-end test through real Docker, parity test against the CLI, security self-review, full regression.

**Host-side analyzer risk (Semgrep/OSV-Scanner on the host):** *not solved.* It is handled by policy: remote/untrusted uploads are **not permitted** — the application refuses
non-loopback binds and non-loopback peers. Isolated analyzers (hardened image run through the sandbox, offline OSV databases) remain the prerequisite for any wider exposure.

## Phase 4 — implementation status (committed `e4bceef`)
Documentation of the real implementation: [docs/api.md](docs/api.md). The CLI, the engine and the sandbox are **unchanged** (`git diff` on `saferun/cli.py`, `saferun/engine/`, `saferun/sandbox/` is empty).

| Unit | Files | Evidence |
|---|---|---|
| 1 ZIP extractor | `saferun/api/archive.py` | `tests/test_archive.py` — 101 tests; 33 individual controls disabled in a scratch copy, 30 caught, 3 survivors are redundant defences (NUL byte also caught as control char; absolute path also caught as empty component; early end-record entry-count check also caught by the later one) |
| 2 Job runner | `saferun/api/jobs.py` | `tests/test_api_jobs.py` — 37 tests incl. real process-group kill of a grandchild, output flood, env allow-list against a real child, sweeper with a symlink decoy |
| 3 API + guard | `saferun/api/app.py`, `guard.py` | `tests/test_api_app.py` — 37 tests (limits, lifecycle, guards, headers, static serving, slow-upload and oversize pre-read at ASGI level) |
| 4 Loopback enforcement | `saferun/api/server.py`, `guard.py` | `tests/test_api_server.py` — 65 tests (bind validation table, launcher refuses and never starts uvicorn, env vars cannot override, real-process refusal of `0.0.0.0`) |
| 5 Dashboard | `web/` (React 19, Vite 8, plain JavaScript/JSX, plain CSS; component folders, see docs/api.md) | `npm test` — 23 tests (Vitest/jsdom) driven by `web/src/fixtures/report.json`, generated from the real engine model and pinned by `tests/test_api_schema_fixture.py` (2 tests) |
| 6 End to end | `tests/test_api_e2e.py` | 4 Docker tests: upload → extraction → real CLI → real sandbox + Semgrep; API report **equals** the CLI's report for the same archive; hostile archive rejected; no containers left |

Mutation checks on units 2–4: 36 controls disabled one at a time; 33 caught, 3 survivors: Host-regex looseness (a second strict check follows), sweeper ownership check (needs a second OS user to test),
and the Content-Length pre-check — the last one **was a real gap**, a test now proves the body is not read. Real bugs found by the tests while building: (1) a job was published as `done` *before* its
upload/extraction directory were deleted (race seen as a flaky test) — fixed by publishing after cleanup; (2) installing the newest fastapi broke the venv's Semgrep (see deviations table).

Full regression (this host, Docker up, Semgrep in `.venv`, **OSV-Scanner not installed**): `PATH=".venv/bin:$PATH" SAFERUN_REQUIRE_DOCKER=1 .venv/bin/pytest -q -rs` → **664 passed, 9 skipped** at the time of the first Phase 4 pass (all 9 are the real OSV-Scanner tests). After the final security review: **674 passed, 9 skipped** without osv-scanner, and **683 passed, 0 skipped** with the real osv-scanner 2.7.0 on PATH (network tests contacted api.osv.dev). Phase 4 contributes ~260 of them (`tests/test_archive.py` 104, `test_api_app.py` 40, `test_api_jobs.py` 37, `test_api_server.py` 65, `test_api_osv_plumbing.py` 4, `test_api_e2e.py` 4, `test_api_schema_fixture.py` 2). Before the run: 0 `saferun-*` temp entries and 0 sandbox containers; after: the same.
Live check: the real server was started on 127.0.0.1, `curl`ed (health, headers, forged Host, missing header, foreign Origin, a real upload → FAIL with Semgrep and the sandboxed syntax check reporting), and stopped.

**Not verified / limitations**
- The dashboard was **not inspected in a real browser** (component tests under jsdom and `vite build` only). The task's interface reference images were not available; the styling is original.
- OSV online/offline were not exercised through the API (OSV-Scanner is not installed here); `osv=disabled` was, and the mapping to CLI flags is unit-tested.
- Host-side analyzer risk remains as documented. No authentication. Loopback is enforced in the launcher and middleware, but any local user can reach the port. Reports live in memory only.
- Behaviour under a truly stalled disk, very large concurrent uploads and a hung Docker daemon is untested (the job deadline and the pre-start checks are tested with fakes).
- The `saferun-up-*` sweep trusts file mtime and ownership; a SIGKILLed server leaves its files until the next start.
- `fastapi` is pinned `<0.141` (newer releases require `opentelemetry-api>=1.44`, Semgrep needs 1.37). Starlette emits a deprecation warning that its `TestClient` will want `httpx2`.
- Frontend dependency tree: 94 packages installed with `--ignore-scripts`; `npm audit` reported 0 known vulnerabilities at install time (not a guarantee).

## Phase 4 — final security review (2026-10-29; since committed as `e4bceef`)
Scope: ZIP extraction, API/guard, job isolation, timeouts, cleanup, dependency compatibility. The CLI, engine and sandbox were not changed.

**Defects found and fixed (each with a regression test that failed before the fix)**
| # | Defect | Fix | Test |
|---|---|---|---|
| 1 | The entry cap trusted the end record's count; `zipfile` builds one `ZipInfo` per central-directory record, so a ≤100 MiB archive with a lying count (claims 1, holds ~500 000 records) could allocate hundreds of MiB | SafeRun walks and counts the central directory itself first (records must tile it exactly); ZIP64 end-record markers are refused | `test_central_directory_is_walked_and_counted_before_zipfile_builds_objects` (asserts `ZipFile` is never constructed), `…zip64…`, `…does_not_end_at_the_end_record…` |
| 2 | Capacity counted jobs only: any number of concurrent slow uploads each held up to 100 MiB of temp file for 120 s (slowloris / disk exhaustion) | uploads in flight count against the 5 slots (429 beyond); `limit_concurrency=32` and a small header-size cap in the launcher | `test_concurrent_stalled_uploads_are_bounded`, `test_uploads_in_flight_are_released_after_errors` |
| 3 | `created_at` in job responses was a monotonic-clock value, not a timestamp | wall-clock `created_wall` reported; monotonic kept for TTL | `test_created_at_is_a_wall_clock_timestamp` |
| 4 | Dashboard requested `/favicon.ico` (404 in the console) | inline `data:` icon (CSP-compatible) | seen in the real-browser run |
| 5 | Cosmetic: "0 error(s)" wording, short paths wrapping character by character | text and CSS fixed | seen in screenshots |
(Earlier in Phase 4: job published before cleanup; fastapi/Semgrep conflict — see above.)

**Verified**
- Clean install: a pristine copy of the tree, **non-editable** install into a fresh virtualenv with `.[dev,web,analysis]`: fastapi 0.140.13, starlette 1.10.0, uvicorn 0.54.0, semgrep 1.182.1, opentelemetry-api 1.37.0; `pip check` → "No broken requirements found"; the registered `saferun-web` script runs and refuses `--host 0.0.0.0` (exit 64); the 251 Phase 4 Python tests pass against the installed package. Frontend: `npm ci --ignore-scripts` from the lockfile in a clean copy, 23 tests, `vite build`, `npm audit` → 0 vulnerabilities.
- OSV through the real server with the real osv-scanner 2.7.0 (binary from an earlier session's scratchpad; its SHA-256 matches the release `SHA256SUMS` stored beside it, not re-verified against upstream today): online → 43 findings, FAIL; offline without databases → `error`, WARNING; disabled → `skipped`, WARNING. No host paths in reports (checked in offline and online modes; asserted in the e2e test).
- Real Google Chrome 153 (headless, scripted with playwright-core from the scratchpad, system Chrome, no download): upload → verdict FAIL with 5 checks and 45 findings rendered; severity filter; dark mode; 390 px viewport without horizontal overflow; **no CSP violations and no console errors/warnings** after the favicon fix; a member named `<img src=x onerror=window.__pwned=1>.py` rendered as inert text (no `<img>`, handler not run); a symlink archive shown as "Archive refused"; a page on another loopback origin could not create a job (simple `text/plain` POST, `application/zip` + custom header preflight, cross-origin read, `localhost` name) — the server's queue/stored-result counters showed only the intended scans.

**Unresolved risks (not fixed)**
1. **Host-side Semgrep/OSV-Scanner parse hostile files as the server user** (typically `docker` group). Contained only by policy: loopback-only, enforced in code. Not safe for untrusted or remote users until the analyzers run isolated (Phase 5).
2. No authentication; any local OS user can use the port and, knowing an ID, read a result.
3. **OSV online sends package names/versions to OSV.dev** by default; offline needs cached databases and otherwise yields WARNING.
4. Stopping the server mid-scan leaves that worker running until its own timeouts and its extraction directory until the next startup sweep (age ≥ 40 min). A SIGKILLed server likewise.
5. The sweeper's ownership check cannot be tested without a second OS user; the Docker daemon being hung/disk-full paths are tested with fakes only; the 408 timeout covers uploads only.
6. Chrome only (one version); no accessibility audit; reference images unavailable.
7. Starlette's `TestClient` deprecation warning (httpx → httpx2) will need attention on a future upgrade; fastapi is capped `<0.141` because of Semgrep's opentelemetry pin.

## Remaining
- Phase 3 (CLI) is committed. Phase 4 (local dashboard) is **committed and pushed (`e4bceef`)** (see *Phase 4 — implementation status*). Phase 5 (integration/security testing/release, isolated analyzers, digest pinning) is in planning; implementation starts only after the owner approves the plan.

## Phase 3: CLI (committed `a9ea5dc`)
`saferun/cli.py` (+ `saferun/__main__.py`, console script `saferun` in pyproject.toml): `saferun scan PATH [--format text|json] [--timeout S]
[--osv-offline] [--no-python-syntax] [--no-python-analysis] [--no-dependency-scan] [--no-javascript-check]`. It calls `validate_project` and renders
the report; it contains no validation logic and no sandbox/Docker code, and Phase 1 and `saferun/engine/` are unchanged. Exit codes: 0 PASS, 1 FAIL,
2 WARNING (including every incomplete scan), 64 usage/bad path, 70 fatal (SandboxError or internal error; no verdict, nothing on stdout), 130 interrupted.
argparse's default usage exit code 2 is overridden to 64 so that 2 only ever means WARNING.
- Defaults unchanged: online OSV remains the engine default. The CLI prints a disclosure notice on stderr when the dependency scan will contact OSV.dev, and exposes the existing `osv_offline` option as `--osv-offline`.
- Terminal safety: all text rendered from reports is passed through `clean_text` again.
- Tests: `tests/test_cli.py` (stubbed engine for exit codes/arguments/errors; real engine with checks disabled or tools missing; one Docker test through the real sandbox).
- Limitations: one subcommand; no config file, output file, color, or progress output; `--timeout` is per tool run, not total; host-side analyzer risk unchanged (accepted interim limitation).

## Phase 5A: image digest pinning and image build recipe (implemented, uncommitted, awaiting owner review)
New: `saferun/sandbox/images.py` (pins, pure helpers), `saferun/sandbox/verify.py`, `saferun verify-images` in `saferun/cli.py`, `docker/analyzer/` (Dockerfile,
`fetch_verified.py`, hash-locked `semgrep-requirements.txt`, `build.sh`, README), `tests/test_image_pins.py` (30 tests).
Changed: `profiles.py`/`config.py` use the pinned references; `docker.resolve_image` verifies `RepoDigests` for digest references; docs and the dashboard Guide page
show digest pulls. Engine logic, report schema, scan exit codes and the sandbox runner are untouched; the only engine edit is display-only (`tool` strings use `RuntimeProfile.label`, so they read exactly as before pinning).
Not done on purpose: the analyzer image is not built or used (Phase 5B); no network/registry call at run time; `verify-images` is local-only (no staleness check against the registry).

## Phase 5B (analyzer isolation) and 5C (adversarial testing): implemented, uncommitted, awaiting owner review
**Built for real:** `PYTHON=.venv/bin/python docker/analyzer/build.sh` -> `saferun-analyzer:local`, image ID recorded in `~/.local/share/saferun/analyzer-image-id`. The Dockerfile `RUN` chain
executed in the digest-pinned base (hash-locked Semgrep 1.182.1 wheels, checksum-verified OSV-Scanner 2.7.0, in-image version checks, rules sha256 check). Inside the container: `semgrep --version`
-> 1.182.1, `osv-scanner --version` -> 2.7.0, uid 65534.
**Code:** `sandbox/analyzer.py` (lock + label verification), `engine/analyzer.py` (container runner), `engine/osvdb.py` (offline data, `saferun osv-db update`), `run_sandboxed(readonly_mounts=...)` with exact
mount-set verification, Semgrep/OSV checks rewritten to use the container only (no `run_tool`/`find_tool`), `saferun verify-images` now includes the analyzer (`--base-only` for the base images),
API: `osv=online` -> 422, default `offline`, health reports `analyzer`; dashboard: no online option. CLI `--osv-offline` kept as a no-op, the OSV network notice removed.
**Behaviour changes (deliberate, required by "offline by default / no host fallback"):** no per-scan online OSV; no OSV notice on stderr; projects with lockfiles and no local OSV data give WARNING (error) not findings;
Semgrep/OSV on the host are no longer used or needed; the `semgrep`/`osv_scanner` health keys now mean "analyzer image verified". Unchanged: scan exit codes, report schema (key sets asserted), verdict rules, `tool` strings, Phase 1 controls.
**Fixed in 5C:** CLI text output could be given forged finding lines by newline/U+2028 in file names (`cli._s` is now single-line).

**Commands and results (this host: Docker 29.8.0, Linux 7.0, x86_64):**
- `SAFERUN_REQUIRE_DOCKER=1 SAFERUN_OSV_DB=<dir with PyPI+npm all.zip from "saferun osv-db update"> .venv/bin/python -m pytest -q -p no:cacheprovider -rs` -> **806 passed, 0 skipped** (252 s). Baseline before Phase 5: 678 passed, 5 skipped.
- Without `SAFERUN_OSV_DB` (no data in the default directory): the 3 DB-dependent files give `44 passed, 14 skipped` (skip reason printed); everything else unchanged.
- `cd web && npm test` -> 23 passed; `npm run build` ok; `npm audit --omit=dev` -> 0 vulnerabilities.
- Real scans: `saferun scan` on a Python+JS project: Semgrep check result byte-identical (minus duration) to the previous host-run result; requests 2.19.0 + lodash 4.17.15 -> 11 findings from the offline DB in the container.
- Mutation checks (change made, targeted tests, change reverted): skip image-ID comparison, writable extra mount, drop `--offline`, re-import `find_tool` into semgrep.py -> each made at least one test fail (the last one only after strengthening the AST test).
- Cleanup after the full run: 0 containers with label `saferun.sandbox=1`, 0 `saferun*` entries in /tmp.
**Not verified / environmental:** only Docker 29.8.0 with the builtin seccomp profile and AppArmor `docker-default` (corrected: an earlier version of this line wrongly said "no AppArmor"); no second OS user; no rootless/userns-remap Docker; no non-amd64 build; no other browser than the earlier Chrome run (dashboard UI changes covered by jsdom tests only); the OSV data was downloaded once (PyPI 37 MB, npm 219 MB) into a scratch directory, not into the default location.

## Phase 5B/5C review fixes (applied; uncommitted, awaiting owner review)
Findings from the focused review were first re-confirmed against the code (empty-zip database -> `passed`; MD5 skipped without a header; lock 664/775; `--dir` chmod 700 -> 755; stale guidance), then fixed.
**Found while fixing (worse than reviewed):** the real OSV server sends `x-goog-hash` as TWO headers (`crc32c`, `md5`); `resp.headers.get()` returned only the first, so the MD5 comparison in the earlier `osvdb.update` never ran against real downloads
(the earlier documentation claim of an MD5 check was true of the code path but not of the behaviour). Fixed with `_header_values` (all header lines); a real download now reports `MD5 verified`.
**OSV database (`engine/osvdb.py`, `engine/osv.py`):** `manifest.json` per database (SHA-256, size, advisory count, update time, MD5 status); `update` refuses a missing/invalid MD5 header unless `--allow-unverified` (recorded as `unverified` and shown in every scan's notes),
refuses non-zip/empty/below-floor archives (PyPI 5 000, npm 40 000), never chmods an existing directory (creates missing ones 0755), refuses symlinked directories; `validate()` re-hashes before every scan and returns problems (-> check `error`, container not started) or a stale
notice (older than `osv_db_max_age_days`, default 30 -> `incomplete`, findings kept). Freshness/hash/MD5 status are appended to the check's `notes` (existing notes keep their order). New: `saferun osv-db status`, `osv-db update --allow-unverified`.
**Analyzer lock (`sandbox/analyzer.py`, `docker/analyzer/build.sh`):** the lock and its directory must be owned by the current user and owner-only (0600 / 0700), opened with `O_NOFOLLOW`; anything else raises `AnalyzerIntegrityError` before Docker is consulted. `write_lock` (used by `build.sh`) creates the directory 0700 and the file 0600 atomically and refuses an existing loose directory instead of chmod'ing it.
On this machine I tightened SafeRun's own directory once by hand: `chmod 700 ~/.local/share/saferun; chmod 600 ~/.local/share/saferun/analyzer-image-id` (it had been created 775/664 by the previous `build.sh`). No other existing directory was changed.
**Docs/UI:** Guide page, README, `docs/cli.md`, `docs/api.md`, `docs/engine.md`, `pyproject.toml` (the `analysis` extra is removed; Semgrep is never taken from the host environment) no longer describe online OSV or host tools; AppArmor claims corrected (it is active: `docker-default (enforce)` read from inside the analyzer container by the Phase 1 attestation, now tested);
the "all host process creation" wording corrected to `subprocess.Popen`/`subprocess.run`; "parses nothing" corrected (the host reads the zip central directory). Limits of the checks are documented in PROJECT.md and `docs/cli.md`.
**Tests (new):** `tests/test_osv_db_integrity.py` (53), `tests/test_analyzer_lock.py` (26), attestation of the analyzer image (1); fixtures `make_osv_db` / `low_osv_floor`. Nine mutations (skip SHA-256, skip floor at scan/update time, silently skip MD5, original single-header bug, chmod existing dirs, ignore staleness, ignore lock file mode, ignore lock directory mode) each make tests fail; all restored.
**Behaviour changes (security fixes):** a database installed by the earlier version has no manifest and is now refused until `saferun osv-db update` is re-run; data older than 30 days makes the dependency check `incomplete` (verdict WARNING unless a finding says FAIL); a lock file with group/other access, or in such a directory, is refused; `osv-db update` fails when the server sends no MD5 header.
**Not changed (still open):** second sanitization copy ignores custom workspace limits (L6); the health endpoint does not report OSV data state (L8); `tools.py` still contains unused host-runner helpers (Info); redaction of analyzer output is untested (Info); lock/image trust remains local-file based (registry digest/signing is 5E).

## Setup workflow: `saferun init` and `saferun status` (implemented; uncommitted, awaiting owner review)
**Request:** a user-friendly installation/setup flow, extending the existing code. The pasted request was cut off after "Preserve existing CLI commands, exit codes, report"; I applied the constraints stated for earlier phases (schema, verdicts, offline-only scans, no host analyzers).
**New:** `saferun/setup.py` (components, detection, selection parsing, workflow, scan hints), CLI subcommands `init` / `status`, `verify-images --only`, `osvdb.update(progress=...)`, `images.AnalyzerRelease` + `ANALYZER_RELEASE = None`, `sandbox/analyzer.py` split into `inspect_analyzer_tag` / `check_labels` (behaviour unchanged),
`docs/release-images.md`, Guide page sections (components, setup commands, missing/outdated, offline), `tests/test_setup.py` (73), `GuidePage.test.jsx` (2).
**Components (derived from the code):** `python` and `node` (the two pinned images in `sandbox/images.py`), `analyzer` (image holding Semgrep, OSV-Scanner and the rules; OSV-Scanner is not separable from it), `osv-db` (validated data). Checks map: python-syntax -> python; javascript-syntax -> node; python-static-analysis -> analyzer; dependency-vulnerabilities -> analyzer + osv-db.
**Behaviour:** state is `ready` only if the existing verification passes now (image RepoDigests contain the pin; analyzer lock+labels+rules; OSV manifest hashes/age). Valid components are skipped without any network probe; missing/invalid/outdated are offered (interactive) or acted on (flags). Pulls use `repo@digest`. Everything installed is re-verified.
A failed analyzer is rebuilt only with `--repair` or an interactive "y". Offline: no downloads attempted, valid components still used, missing ones listed, preload instructions printed, exit 1. A scan with an unready component adds `setup: ... -> fix: saferun init --only X` lines on stderr only.
**Prebuilt images:** base images are pulled by pinned digest (Docker Hub, content-addressed). **No prebuilt analyzer exists**: there is no registry/repository/digest in the repository and none was invented; `init` builds it locally with `docker/analyzer/build.sh` (requires a checkout; the pip package does not contain `docker/`). The download path for a future published image is implemented and tested with a fake Docker but inactive.
**Real runs on this machine:** `saferun status` (all ready after `init`), `saferun init --only python,node,analyzer` (all skipped, no downloads), `saferun init --only osv-db` (real download of 256 MB with progress into `~/.local/share/saferun/osv-db`, verified), `saferun init --all` (everything skipped), `saferun init` without a terminal (exit 64), real scan with the default data location (FAIL with findings). Not run for real: a fresh pull of a missing sandbox image, a fresh analyzer build through `init`, offline mode (these are covered with fakes), interactive menu in a real terminal.
**Mutation checks (change, run tests, revert):** never skip valid, trust a digest mismatch, assume success without re-verifying, rebuild without consent, ignore missing internet, pull a floating tag, ignore Docker errors -> each failed tests.
**Known gaps:** analyzer cannot be installed without internet; `docker load` may drop registry digests (then images read as invalid; untested across Docker versions); disk-space check covers only the OSV directory; `init` of images does not check Docker's disk; the pip package lacks `docker/`.

## Terminal presentation: colours, icons, spinner, progress bar (implemented; uncommitted, awaiting owner review)
**Request:** make CLI output quicker to read: a loading animation instead of a bare cursor, coloured headings, ticks/crosses, severity colours. Presentation only; no check, engine, schema, exit-code or JSON change.
**New:** `saferun/ui.py` (Theme, colour policy, Spinner, progress bar), `render_styled` + `_next_steps` in `saferun/cli.py`, `--color auto|always|never` on `scan`/`init`/`status`/`verify-images`/`osv-db status`, themed `status_report`/`init` output/menu/progress bar in `saferun/setup.py`, `tests/test_ui.py` (25), a Guide entry.
**Rules:** colour/animation only on a terminal (`NO_COLOR`, `FORCE_COLOR`, `TERM=dumb`, `--color` honoured); the spinner writes to stderr and hides/restores the cursor even on Ctrl-C; plain text (pipes, CI, all earlier tests) is byte-identical to before; JSON is never decorated; every untrusted value is sanitized by the existing one-line cleaner before painting (hostile-name test strips our own sequences and finds nothing else).
**Verified:** real PTY run of `saferun scan` (53 spinner frames, cursor hidden then restored, report after), rendering of the coloured output for clean / insecure-code / vulnerable-dependency projects (ANSI converted to HTML, screenshots in headless Chrome), 130 tests in the CLI/setup/UI files. Mutation checks: colour on non-terminals, painting unsanitized text, leaving the cursor hidden, decorating JSON: each failed tests.
**Process note:** during these mutation checks the backup directory was missing, so four mutations stayed applied in `ui.py`/`cli.py` until I noticed and reverted them by hand; the code was then re-verified by the test files above and by the full suite below.
**Not done:** per-check live progress (the engine runs the checks in one call; adding a callback would touch the engine), a dark/light theme switch, Windows terminals, screen-reader review.

## Phase 5D: cleanup and exhaustion hardening (implemented; uncommitted, awaiting owner review)
**Scope:** failure paths only. Scan behaviour, report schema, verdict rules, exit codes and the Phase 1 sandbox controls are unchanged; 5E (cosign, registry digests) not started at that time (see *Phase 5E*).
**Code:** `engine/tools.py` (`run_tool(cancel=, cancel_grace_s=)`, `ToolRun.cancelled`: SIGINT to the process group, SIGKILL after the grace period), `api/jobs.py` (`JobManager.shutdown` cancels the running worker, job error `shutdown`; `acquire_instance_lock`, `kill_orphan_workers`, `startup_cleanup`),
`api/app.py` (lifespan uses `startup_cleanup` and holds the lock; `507 insufficient-storage` for a nearly full disk, ENOSPC/EDQUOT while creating or writing the upload; `_AnalyzerProbe` bounds `/api/health`), `sandbox/reaper.py` (a hung/missing Docker no longer aborts workspace reaping),
`sandbox/runner.py` (our `docker start -a` client is always killed if still running, also when `docker kill` fails), `web/src/utils/errors.js` (two wording entries). Docs: `docs/api.md` *Cleanup*.
**Open items from earlier phases, now:** worker/directory cleanup after a SIGKILLed server -> done (real test: a server subprocess is SIGKILLed mid-scan; the next `startup_cleanup` kills the orphaned worker and removes its directory); hung Docker daemon -> reaper, health, sandbox client (fakes + a real-Docker test); disk-full -> upload and extraction (simulated ENOSPC / free-space); second OS user for the sweeper -> simulated by making `os.getuid()` differ from the owner of the entries (sweeper, reaper, lock file, orphan-worker kill each leave foreign objects alone).
**Tests:** `tests/test_phase5d.py` (29), `tests/test_hardening.py` (the stuck-client fake gained `poll`/`kill`, as a real `Popen` has). Full suite with `SAFERUN_REQUIRE_DOCKER=1`: **1010 passed, 0 skipped** (298 s); 0 containers with label `saferun.sandbox=1` afterwards.
**Mutation checks (change, run `test_phase5d.py`, revert):** SIGINT removed, final group kill removed, shutdown not cancelling, age-based sweep always, orphan uid check removed, lock owner check removed, lock following symlinks, ENOSPC mid-upload unmapped, free-space precheck removed, health probe unbounded, reaper aborting on a hung daemon, docker client not killed -> each failed at least one test.
**Not verified:** a really hung `dockerd` (only a fake CLI that sleeps / raises), a real full filesystem (ENOSPC injected), a real second OS user, non-Linux `/proc`, SIGKILL of the server while the worker is inside `docker start` (the container then ends by its own container-side timeout or `reap_orphans`).
**Known limits:** the instance lock is per user and per temp directory; an older SafeRun server that does not take the lock is treated like "another server" only if it holds the lock, so it is not protected from a new server's full sweep; `kill_orphan_workers` identifies workers by working directory, so a descendant that changed directory survives (its container still has the container-side deadline).

## Phase 5E: signed analyzer release (implemented; uncommitted, awaiting owner review; NO release published yet; text below is the old repository's history, adapted to `vinay-repalle` names)
**Decisions (owner):** registry `ghcr.io/vinay-repalle/saferun-analyzer`; keyless cosign signing from GitHub Actions; the owner runs the first push; verification through the `cosign` command line tool (option A).
**New:** `.github/workflows/release-analyzer.yml` (tag-only trigger `analyzer-v*`, tag format and "commit is on main" checks, build from the same recipe as `build.sh`, single linux/amd64 manifest, push, `cosign sign` of the digest, self-verification with SafeRun's own identity expression, digest printed in the run summary; all actions pinned to commit SHAs; minimal permissions),
`saferun/sandbox/signature.py` (`verify_release_signature`: cosign argv, minimal environment, private HOME, timeout, output cap, payload must name exactly this repository and digest; `CosignMissing`), `images.py` (`ANALYZER_REGISTRY_REPOSITORY`, `ANALYZER_SIGNER_IDENTITY_REGEXP`, `GITHUB_OIDC_ISSUER`, `AnalyzerRelease` gains the signer identity and issuer),
`setup.py` (published install = verify signature -> pull by digest -> digest re-check -> tag -> labels -> lock; release hosts `ghcr.io` + Sigstore; `build_local`), `cli.py` (`init --build-local`, `verify-images --signature`).
**Unchanged:** scan behaviour, report schema, verdicts, exit codes, sandbox controls, python/node pins, the local build path. `ANALYZER_RELEASE` is still `None`, so `saferun init` behaves exactly as before until a release digest is recorded.
**Behaviour once a release is recorded:** `init` requires cosign and internet (ghcr.io, TUF, Rekor); no unsigned install and no silent fallback (`--build-local` is explicit); an INVALID analyzer is repaired (`--repair`) from the signed image.
**Tests:** `tests/test_release_signature.py` (61: command, environment, malformed releases, missing cosign, failures/timeouts, payload checks, a fake cosign process, identity expression accept/reject lists, workflow properties, CLI flags) and updated `tests/test_setup.py`.
**Mutation checks (change, run tests, revert):** signature check skipped, bad signature unhandled, `--build-local` ignored, payload digest / repository not checked, whole environment passed to cosign, issuer flag dropped, empty identity allowed, identity accepting branches, workflow also on branches, workflow signing a tag, extra workflow permission -> each failed tests.
**Not verified:** cosign has never been run (not installed here; no image exists); the workflow has never run on GitHub; ghcr.io push/visibility; cosign output format differences between versions (only the documented `critical.image` / `critical.identity` fields are read); Docker pulling a digest from ghcr.io. These are covered by the first-release checklist in `docs/release-images.md` (step 5: `saferun verify-images --signature`).
**Known limits:** cosign runs on the host and parses registry/Sigstore data; the pip package still lacks `docker/` (so `--build-local` needs a checkout, the signed pull does not); the analyzer still cannot be installed on a machine that never has internet; account/repository takeover would allow validly signed malicious tags.

**[OLD REPOSITORY, not this one. Historical record of the previous owner's release; no equivalent release exists for `vinay-repalle/saferun`.]** **5E release recorded (2026-10-30):** the workflow run for tag `analyzer-v1.0.0` (commit `f351608`) succeeded; the package was made public; the digest was read back from the registry (`docker buildx imagetools inspect`), not copied from a screenshot:
[SUPERSEDED, see *Repository ownership change* below: this digest belonged to the previous owner's registry and is no longer recorded] `sha256:3b7adfc9b5052d1c7168df8be2cf8a6f5d3da6135d67db813586e1cf43a59508`, was in `ANALYZER_RELEASE` (rules and `docker/analyzer/` unchanged since the tag). **At that time `saferun init` installed this image and required cosign. That is no longer the case: `ANALYZER_RELEASE` is `None` again and `init` builds locally.**
Setup tests that describe the local-build path now set `ANALYZER_RELEASE = None` explicitly. Still not run: a real `cosign verify` / `saferun verify-images --signature` and a real `saferun init --only analyzer` from a published image (cosign is not installed on the development machine). This applies equally to a future release from `vinay-repalle/saferun`.

## Status audit (2026-10-30)
Git was clean at HEAD `3c3a50b`; the "uncommitted, awaiting owner review" headings above are historical: 5A-5E are all committed. **[OLD REPOSITORY]** The previous maintainer reported a successful real `saferun verify-images --signature` against the previous owner's `analyzer-v1.0.0` (valid signature from that repository's release workflow, all pinned images verified); that output was not captured, and it says nothing about a release from `vinay-repalle/saferun`, which does not exist yet.
Added in this revision (uncommitted): the SafeRun logo at the start of `saferun init` (`ui.BANNER`, `Setup.show_banner`, colour terminals only, so plain/piped output is unchanged), a full beginner setup section in the dashboard guide (requirements, Python, Docker, SafeRun, cosign without sudo, `init --all`, `status`, `verify-images --signature`, first scan, troubleshooting), and corrected status text in README/PROJECT/release-images.
Open items are listed in PROJECT.md *Remaining work*. (The stale `PRELOAD_HELP` / `saferun/setup.py` "once a published image exists" wording noted here was fixed in the ownership change below.)

## Repository ownership change (2026-10-30)
Owner references moved from the previous owner to `vinay-repalle` (registry `ghcr.io/vinay-repalle/saferun-analyzer`, cosign signer identity `vinay-repalle/saferun`, workflow, website links, tests). `ANALYZER_RELEASE` is now `None`: the earlier `analyzer-v1.0.0` release (and the maintainer's earlier `verify-images --signature` report) belonged to the previous owner's identity and no longer applies. `saferun init` builds the analyzer locally until a new signed release is published and recorded. Setup messages that referred to an existing published image were reworded. Tests were edited but **not run** after this change.


**Documentation follow-up (same change):** the website content and setup guide (`web/src/content/site.js`, `GuidePage.jsx`, with `GuidePage.test.jsx`, `LandingPage.test.jsx`, `Faq.jsx`), `README.md` and `PROJECT.md` now describe the local analyzer build as the current path and the cosign-signed download as a future step. Earlier entries about `analyzer-v1.0.0` are labelled as belonging to the old repository. Tests were edited but **not run**.

## Release preparation pass (2026-10-30; nothing run)
Changed in `SafeRun-personal` only; no tests, builds, installs, Git commands or publishing were run, so none of the following is verified by execution.
* **CI added:** `.github/workflows/ci.yml` (PR + push to `main`; read-only token; no secrets; no publishing; actions pinned to SHAs). Blocking jobs: `python` (`pytest -m "not docker"`), `web`, `package` (build, inspect, clean-venv install). Advisory: `audit`, `docker`. New `tests/test_ci_workflow.py` checks pinning, permissions, triggers and that nothing publishes.
* **Release workflow hardened:** build locally -> smoke-test that exact image (labels, versions, rules hash, no network, real scan) -> login -> push the same image -> sign the digest -> verify -> check that a wrong identity is refused. `tests/test_release_signature.py` updated (13 steps, ordering, old-owner identities rejected).
* **Analyzer Dockerfile:** ends with `USER 65534:65534` (defence in depth; SafeRun still passes `--user` and all other restrictions).
* **Packaging:** `[build-system]`, readme, classifiers, URLs, `dev` extra gains `ruamel.yaml` and `build`; `MANIFEST.in` for the sdist; `.gitignore` extended. The wheel still excludes `docker/` and `web/dist` (documented in `docs/install-and-test.md`; fixing it needs code changes).
* **Docs:** `docs/install-and-test.md` (new), `docs/release-images.md` (manual GitHub configuration, release order, install/verify commands, trust boundary), `docker/analyzer/README.md` (stale "not used yet" text).
* **No license added** (owner decision pending).
* **Pre-validation review (same day):** packaging decision = source-install-only (see `docs/install-and-test.md`); release workflow now asserts the image's default user and writes a warning to the run summary when a step after the push fails; the five inherited action pins were checked against the GitHub API (all resolve to the tagged commits).
