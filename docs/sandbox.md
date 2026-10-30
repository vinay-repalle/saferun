# Sandbox (Phase 1) — library reference

Design, threat model and known exposures: [PROJECT.md](../PROJECT.md). Evidence and limitations: [IMPLEMENTATION.md](../IMPLEMENTATION.md).

## Usage
```python
from saferun.sandbox import run_sandboxed, SandboxLimits
from saferun.sandbox.profiles import PYTHON, NODE
r = run_sandboxed("./proj", ["python", "-I", "main.py"], SandboxLimits(timeout_s=10, memory_mb=128), image=PYTHON.image)
r = run_sandboxed("./js",   ["node", "main.js"], image=NODE.image)            # same restrictions, Node image
print(r.exit_code, r.stdout, r.timed_out, r.oom_killed)
print([(c.name, c.state) for c in r.controls])   # verified / violated / unavailable / unverified, per run

from saferun.sandbox.attestation import attest
print(attest(NODE.image).ok)                      # kernel-view check from inside a sandbox (one short container run)
```
- `run_sandboxed(..., readonly_mounts=((host_dir, "/name"),))` (Phase 5B) adds read-only bind mounts (existing real directories only; fresh top-level target name, never a system path). The applied mount set is verified exactly after `docker create`; the network stays off. Used for the offline OSV data.
- The project is copied (symlinks and special files dropped, external hard links skipped, credential-like files withheld,
  concurrent modification detected) and mounted read-only; no network; non-root; all capabilities dropped; read-only root.
- Before any code starts, Docker's *applied* configuration is verified and the run is refused on any deviation; the daemon
  must support the required controls (seccomp, memory/swap/pids/CPU limits) unless you explicitly pass `allow_degraded`.
- `SandboxResult` reports `controls`, `image_id`, `skipped`, `withheld`, `redactions`, and honest accounting:
  `entries_scanned == copied_files + copied_dirs + len(skipped) + len(withheld)`. A non-empty `skipped`/`withheld` means
  a partial scan. `reap_orphans()` removes containers/workspaces abandoned by a crashed run.

