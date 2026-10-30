"""Run Semgrep and OSV-Scanner inside the verified analyzer container (Phase 5B). There is no host-side path.

`analyzer_runner` has the `ToolRunner` shape the checks already use, but instead of starting a host process it:
  1. verifies the analyzer image (lock-file ID, pinned tool and rules labels) and gets its immutable ID,
  2. runs the argv through the Phase 1 sandbox *by that ID*: no network, read-only root, non-root, all capabilities dropped,
     seccomp/no-new-privileges, memory/swap/CPU/pids/fd/file-size limits, private tmpfs, container-side kill deadline,
  3. mounts only the sanitized project (read-only) and, for OSV, the vulnerability database directory (read-only).
The host environment is deliberately not forwarded (`env` is ignored): no host credentials or proxy settings can reach a container.
Any failure raises (`SandboxError` and subclasses); callers turn that into a non-clean check status. Nothing falls back to the host.
"""
from __future__ import annotations

from pathlib import Path

from ..sandbox import SandboxLimits, run_sandboxed
from ..sandbox.analyzer import verify_analyzer_image
from .tools import ToolRun

# Larger than the syntax-check profile: Semgrep needs memory and a few worker processes. Still hard limits.
ANALYZER_LIMITS = dict(memory_mb=1536, cpus=2.0, pids=256, tmpfs_mb=256, nofile=1024, fsize_mb=64, shm_mb=64)


def analyzer_runner(argv: list[str], *, cwd: Path, env=None, timeout_s: float, max_output: int,
                    mounts: tuple[tuple[Path, str], ...] = (), sandbox=run_sandboxed, verify=verify_analyzer_image) -> ToolRun:
    image_id = verify()
    limits = SandboxLimits(timeout_s=timeout_s, max_output_bytes=max_output, **ANALYZER_LIMITS)
    res = sandbox(cwd, list(argv), limits, image=image_id, readonly_mounts=mounts)
    killed = bool(res.timed_out or res.output_truncated)
    return ToolRun(argv=list(argv), exit_code=None if killed else res.exit_code, stdout=res.stdout, stderr=res.stderr,
                   timed_out=bool(res.timed_out), output_truncated=bool(res.output_truncated), duration_s=res.duration_s)
