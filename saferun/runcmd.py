"""`saferun run SCRIPT [ARGS...]`: scan a Python script, and only if the scan allows it, run it INSIDE the existing hardened sandbox.

The script never runs on the host. The scan is the normal `validate_project` (syntax, Semgrep, dependencies); the run is the normal
`run_sandboxed` (pinned python image, no network, read-only root and project, non-root, no capabilities, resource limits, output cap and
secret redaction). By default only the script itself is staged and scanned (a copy in a private temporary directory); `--project-dir`
stages a whole directory that contains it. A passing scan is NOT a proof of safety: it only means the checks found nothing they know about.

Refusal (script not run): FAIL -> exit 1; WARNING -> exit 2. --allow-warnings only accepts a WARNING that comes from a COMPLETE scan whose
findings are all below high severity; an incomplete, errored, timed-out, skipped or unavailable check, or any high/critical finding, is never overridden.
Other exit codes: 0 the script ran and exited 0; 3 it ran and exited non-zero / timed out / was killed; 64 usage; 70 could not be scanned or sandboxed.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .engine import ValidationOptions, Verdict, validate_project
from .engine.model import CheckStatus, Severity
from .sandbox import SandboxError, SandboxLimits, run_sandboxed
from .sandbox.profiles import PYTHON

EXIT_PASS, EXIT_FAIL, EXIT_WARNING, EXIT_SCRIPT_FAILED, EXIT_USAGE, EXIT_FATAL = 0, 1, 2, 3, 64, 70
MAX_SCRIPT_BYTES = 5 * 1024 * 1024


_COMPLETED = frozenset({CheckStatus.PASSED, CheckStatus.FINDINGS, CheckStatus.NOT_APPLICABLE})
_SERIOUS = frozenset({Severity.CRITICAL, Severity.HIGH})


def warning_blockers(report) -> list[str]:
    """Reasons a WARNING can NOT be overridden by --allow-warnings (empty list: it may be). Fail closed."""
    out = []
    if not report.complete:
        out.append("the scan is incomplete")
    out += [f"check {c.name} did not complete ({c.status.value})" for c in report.checks if c.status not in _COMPLETED]
    out += [f"{f.severity.value} finding {f.rule_id}" for f in report.findings if f.severity in _SERIOUS]
    return out


# The script's output is untrusted text: terminal escape sequences in it could clear the screen, rewrite earlier lines or fake SafeRun's own
# messages. Everything except newline and tab that is a control, escape, C1 or bidi-override character is replaced before it reaches the terminal.
_UNSAFE_OUTPUT = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def safe_output(text: str) -> str:
    return _UNSAFE_OUTPUT.sub("?", text.replace("\r\n", "\n"))


class RunUsageError(ValueError):
    pass


@dataclass
class Staged:
    root: Path          # directory handed to scan and sandbox
    rel_script: str     # script path relative to root, posix


def stage(script: Path, project_dir: Path | None, tmp_root: Path) -> Staged:
    """Describe what will be scanned and run. Raises RunUsageError."""
    try:
        st = os.lstat(script)
    except OSError:
        raise RunUsageError(f"script does not exist: {script}") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RunUsageError(f"not a regular file (symlinks are refused): {script}")
    if script.suffix != ".py":
        raise RunUsageError("only Python scripts (.py) can be run")
    if st.st_size > MAX_SCRIPT_BYTES:
        raise RunUsageError(f"script is larger than {MAX_SCRIPT_BYTES} bytes")
    if project_dir is not None:
        root = project_dir.resolve()
        if not root.is_dir():
            raise RunUsageError(f"not a directory: {project_dir}")
        try:
            rel = script.resolve().relative_to(root)
        except ValueError:
            raise RunUsageError("the script must be inside --project-dir") from None
        return Staged(root, rel.as_posix())
    root = tmp_root / "project"
    root.mkdir(mode=0o755)
    os.chmod(root, 0o755)                        # the sandbox user is "other": it must be able to read what it is given
    dest = root / script.name
    shutil.copyfile(script, dest)
    os.chmod(dest, 0o644)
    return Staged(root, script.name)


def run_script(script: str, script_args: list[str], *, project_dir: str | None = None, timeout_s: float = 30.0,
               allow_warnings: bool = False, out, err, render=None, scan=validate_project, sandbox=run_sandboxed) -> int:
    """Returns the process exit code. `scan` and `sandbox` are injectable for tests."""
    with tempfile.TemporaryDirectory(prefix="saferun-run-") as tmp:
        try:
            staged = stage(Path(script), Path(project_dir) if project_dir else None, Path(tmp))
        except RunUsageError as e:
            err.write(f"saferun: {e}\n")
            return EXIT_USAGE
        try:
            report = scan(staged.root, ValidationOptions())
        except SandboxError as e:
            err.write(f"saferun: cannot scan, so the script was NOT run (no verdict): {e}\n")
            return EXIT_FATAL
        except Exception as e:  # noqa: BLE001 - never run anything after an unexpected scan failure
            err.write(f"saferun: internal error while scanning, so the script was NOT run: {type(e).__name__}: {e}\n")
            return EXIT_FATAL
        if render:
            out.write(render(report))
        if report.verdict is Verdict.FAIL:
            err.write("saferun: the scan found high-severity problems: the script was NOT run.\n")
            return EXIT_FAIL
        if report.verdict is not Verdict.PASS:
            blockers = warning_blockers(report) if allow_warnings else ["--allow-warnings was not given"]
            if blockers:
                err.write("saferun: the scan verdict is WARNING: the script was NOT run (" + "; ".join(blockers[:5]) + "). Fix the findings or the "
                          "missing setup (`saferun doctor`); --allow-warnings never overrides an incomplete check or a high/critical finding.\n")
                return EXIT_WARNING
        err.write("saferun: scan verdict " + report.verdict.value.upper() + ". A scan is not proof of safety; running inside the sandbox "
                  "(no network, read-only filesystem, non-root, resource limits).\n")
        try:
            res = sandbox(staged.root, [PYTHON.interpreter, "-I", f"/workspace/{staged.rel_script}", *script_args],
                          limits=SandboxLimits(timeout_s=timeout_s), image=PYTHON.image)
        except SandboxError as e:
            err.write(f"saferun: the sandbox could not run the script: {e}\n")
            return EXIT_FATAL
    out.write(safe_output(res.stdout))
    if res.stderr:
        err.write(safe_output(res.stderr))
    if res.timed_out:
        err.write(f"saferun: the script was stopped after {timeout_s:g} s.\n")
    if res.oom_killed:
        err.write("saferun: the script was killed for exceeding the memory limit.\n")
    if res.output_truncated:
        err.write("saferun: output was truncated at the sandbox limit.\n")
    return EXIT_PASS if res.exit_code == 0 and not res.timed_out and not res.oom_killed else EXIT_SCRIPT_FAILED
