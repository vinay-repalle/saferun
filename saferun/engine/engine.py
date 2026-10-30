"""Validation engine: sanitized copy -> checks -> normalized report -> verdict."""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from ..sandbox import SensitivePolicy, WorkspaceLimits
from ..sandbox.workspace import create_workspace
from . import node, osv, pysyntax, semgrep
from .context import CheckContext
from .model import CheckResult, CheckStatus, Finding, Severity, ValidationReport, clean_text
from .verdict import compute_verdict

WORKSPACE_CHECK = "workspace-sensitive-files"


@dataclass(frozen=True)
class ValidationOptions:
    python_analysis: bool = True       # Semgrep
    python_syntax: bool = True         # compile() in the sandbox
    dependency_scan: bool = True
    javascript_check: bool = True
    tool_timeout_s: float = 120.0      # per external tool / sandbox run
    osv_offline: bool = True           # kept for compatibility: OSV-Scanner always runs offline (no network) since Phase 5B
    osv_db_dir: Path | None = None     # offline OSV database directory (default: saferun.engine.osvdb.default_dir())
    osv_db_max_age_days: float = 30.0  # older (but valid) OSV data makes the dependency check INCOMPLETE, never clean
    workspace_limits: WorkspaceLimits | None = None
    sensitive_policy: SensitivePolicy | None = None


def _list_files(root: Path) -> list[str]:
    out = []
    for dirpath, _dirs, names in os.walk(root, followlinks=False):
        d = Path(dirpath).relative_to(root).as_posix()
        out += [n if d == "." else f"{d}/{n}" for n in names]
    return sorted(out)


def _workspace_check(ws) -> CheckResult:
    """Withheld credential-like files become findings; the content was never read by any analyzer."""
    findings = []
    for w in ws.withheld:
        secret = w.reason.startswith(("private-key", "token:"))
        findings.append(Finding(
            check=WORKSPACE_CHECK, rule_id=f"withheld.{clean_text(w.reason, 60)}",
            severity=Severity.HIGH if secret else Severity.LOW, category="workspace",
            path=clean_text(w.path, 300),
            message=("credential-like file found in the project; it was withheld from analysis and the sandbox"
                     if secret else "file not readable by other users was withheld from analysis (not analysed)")))
    return CheckResult(WORKSPACE_CHECK, CheckStatus.FINDINGS if findings else CheckStatus.PASSED, findings=findings,
                       notes=["content of withheld files is never read by SafeRun analyzers"])


def _guarded(name: str, fn, ctx: CheckContext) -> CheckResult:
    """A crashing check is an ERROR result, never an absent (= clean) one."""
    try:
        return fn(ctx)
    except Exception as e:  # noqa: BLE001 - any bug must surface as an operational error
        return CheckResult(name, CheckStatus.ERROR, detail=clean_text(f"internal error: {type(e).__name__}: {e}"))


def validate_project(project_dir, options: ValidationOptions | None = None, *, ctx_overrides: dict | None = None
                     ) -> ValidationReport:
    """Validate the project at `project_dir`. Raises SandboxError if a safe copy cannot be made (no verdict
    is possible then). `ctx_overrides` replaces CheckContext fields (tool runner, sandbox runner) for tests."""
    opts = options or ValidationOptions()
    ws = create_workspace(Path(project_dir), opts.workspace_limits, opts.sensitive_policy)
    try:
        home = ws.root / "home"
        home.mkdir(mode=0o700)
        ctx = CheckContext(project=ws.project, home=home, files=_list_files(ws.project),
                           timeout_s=opts.tool_timeout_s, options={"osv_offline": True, "osv_db_dir": opts.osv_db_dir,
                                                   "osv_db_max_age_days": opts.osv_db_max_age_days})
        if ctx_overrides:
            ctx = replace(ctx, **ctx_overrides)
        checks = [_workspace_check(ws)]
        checks[0].analysis = False
        for enabled, name, mod in ((opts.python_syntax, pysyntax.NAME, pysyntax),
                                   (opts.python_analysis, semgrep.NAME, semgrep),
                                   (opts.dependency_scan, osv.NAME, osv),
                                   (opts.javascript_check, node.NAME, node)):
            if enabled:
                checks.append(_guarded(name, mod.run_check, ctx))
            else:
                checks.append(CheckResult(name, CheckStatus.SKIPPED, detail="disabled by options"))
        partial = []
        if ws.skipped:
            partial.append(f"{len(ws.skipped)} entr(y/ies) skipped (symlinks, special files or external hard links)")
        if ws.withheld:
            partial.append(f"{len(ws.withheld)} sensitive file(s) withheld")
        workspace = {"entries_scanned": ws.entries_scanned, "copied_files": ws.copied_files,
                     "copied_dirs": ws.copied_dirs, "copied_bytes": ws.copied_bytes,
                     "skipped": [{"path": clean_text(s.path, 300), "reason": s.reason} for s in ws.skipped],
                     "withheld": [{"path": clean_text(w.path, 300), "reason": clean_text(w.reason, 60)} for w in ws.withheld]}
        verdict, reasons, complete = compute_verdict(checks, "; ".join(partial))
        return ValidationReport(verdict, reasons, complete, checks, workspace)
    finally:
        ws.cleanup()
