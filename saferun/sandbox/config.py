"""Sandbox policy and result types."""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from .images import PYTHON_IMAGE

DEFAULT_IMAGE = PYTHON_IMAGE.reference  # pinned by digest (Phase 5A)
SANDBOX_UID = 65534  # "nobody"
CONTAINER_LABEL = "saferun.sandbox=1"
DEADLINE_LABEL = "saferun.deadline"  # epoch seconds after which a container is an orphan
REAP_MARGIN_S = 60  # slack added to the deadline so live runs are never reaped


class SandboxError(RuntimeError):
    """Sandbox could not be set up or torn down safely."""


class WorkspaceLimitError(SandboxError):
    """The project exceeds the configured copy limits."""


class WorkspaceChangedError(SandboxError):
    """The source tree changed while SafeRun was copying it; the copy is abandoned (fail closed)."""


@dataclass(frozen=True)
class SandboxLimits:
    timeout_s: float = 30.0          # host-side wall clock, from `docker start`
    container_grace_s: float = 5.0   # container-side `timeout` fires at timeout_s + grace
    memory_mb: int = 256
    cpus: float = 1.0
    pids: int = 64
    tmpfs_mb: int = 64
    max_output_bytes: int = 256 * 1024
    nofile: int = 256
    fsize_mb: int = 64
    shm_mb: int = 16

    def __post_init__(self):
        for k, v in vars(self).items():
            if not (isinstance(v, (int, float)) and math.isfinite(v) and v > 0):
                raise ValueError(f"SandboxLimits.{k} must be a positive finite number, got {v!r}")


@dataclass(frozen=True)
class WorkspaceLimits:
    max_bytes: int = 400 * 1024 * 1024
    max_files: int = 20_000   # counts files, directories and skipped entries
    max_depth: int = 32       # directory levels below the project root

    def __post_init__(self):
        for k, v in vars(self).items():
            if not (isinstance(v, int) and v > 0):
                raise ValueError(f"WorkspaceLimits.{k} must be a positive integer, got {v!r}")


@dataclass(frozen=True)
class SensitivePolicy:
    """How credential-like files are treated when building the workspace.

    By default a source file that is not world-readable (directory: no other r/x) is withheld, since the
    sandbox user is "other" and would not have been able to read it. Files with a credential signature
    (see secrets.py) are withheld whatever their name. `allow_paths` (relative, posix) opts specific
    paths back in; `honor_private_modes=False` is for umask-077 trees where everything is private.
    """
    honor_private_modes: bool = True
    allow_paths: frozenset[str] = frozenset()

    def __post_init__(self):
        object.__setattr__(self, "allow_paths", frozenset(self.allow_paths))


@dataclass(frozen=True)
class WithheldEntry:
    path: str    # relative path (untrusted; sanitize before display)
    reason: str  # private-mode | private-key | token:<vendor>  -- never the secret itself


@dataclass(frozen=True)
class ControlStatus:
    """One security control and what is actually known about it.

    state: verified    - confirmed from Docker's own configuration or from inside the sandbox
           violated    - observed to differ from policy (a run is refused / flagged)
           unavailable - the host or daemon cannot provide it
           unverified  - not checked, or the evidence needed is not obtainable
    """
    name: str
    state: str
    detail: str = ""


@dataclass(frozen=True)
class SkippedEntry:
    path: str    # relative to the project root; untrusted, sanitize before display
    reason: str  # symlink | hardlink-external | not-regular-file | unreadable


@dataclass
class SandboxResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    oom_killed: bool = False
    output_truncated: bool = False
    duration_s: float = 0.0
    container_name: str = ""
    hardening: dict = field(default_factory=dict)  # HostConfig as Docker applied it
    controls: list[ControlStatus] = field(default_factory=list)  # evidence for this run, see ControlStatus
    image_id: str = ""  # the exact image (sha256:...) the container was created from
    skipped: list[SkippedEntry] = field(default_factory=list)
    withheld: list[WithheldEntry] = field(default_factory=list)  # sensitive files NOT given to the sandbox
    redactions: int = 0  # secrets masked in stdout/stderr
    # Workspace accounting. entries_scanned == copied_files + copied_dirs + len(skipped) + len(withheld)
    entries_scanned: int = 0  # every directory entry visited
    copied_files: int = 0     # regular files actually written to the workspace
    copied_dirs: int = 0
    copied_bytes: int = 0     # bytes of those files (withheld content is not counted)
