"""Shared inputs for checks."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..sandbox import docker as _docker
from ..sandbox import run_sandboxed
from ..sandbox.analyzer import verify_analyzer_image
from .analyzer import analyzer_runner
from .tools import ToolRunner


@dataclass
class CheckContext:
    project: Path                 # sanitized copy of the project (never the user's original directory)
    home: Path                    # private scratch/HOME for analyzers
    files: list[str]              # relative posix paths of every regular file in `project`
    analyzer: ToolRunner = analyzer_runner   # Semgrep / OSV-Scanner run ONLY here (analyzer container); injectable for tests
    analyzer_available: Callable[[], str] = verify_analyzer_image  # returns the verified image ID or raises SandboxError
    sandbox: Callable = run_sandboxed                    # container runner; injectable for tests
    image_available: Callable[[str], None] = _docker.check_available  # raises SandboxError if unusable
    timeout_s: float = 120.0
    max_output: int = 8 * 1024 * 1024
    max_findings: int = 1000
    options: dict = field(default_factory=dict)
