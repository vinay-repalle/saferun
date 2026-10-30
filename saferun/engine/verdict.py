"""Verdict rules. Deterministic and documented (README/PROJECT.md mirror this).

FAIL     any finding of severity CRITICAL or HIGH.
WARNING  not FAIL, and any of: a finding of severity MEDIUM, LOW or UNKNOWN (UNKNOWN is treated as MEDIUM);
         a check that is INCOMPLETE, ERROR, TIMEOUT, UNAVAILABLE or SKIPPED (the project was not fully
         checked); a partial workspace copy (skipped/withheld entries); no check completed at all.
PASS     at least one check ran to completion, none of the above applies. INFO findings do not matter.

PASS means "the checks that exist found nothing", not "the code is safe". An operational problem can never
produce PASS, and can never be hidden by a clean result from another check; it also does not by itself
produce FAIL, because FAIL is reserved for demonstrated findings.
"""
from __future__ import annotations

from .model import CheckResult, CheckStatus, Severity, Verdict

_FAIL_AT = Severity.HIGH.rank


def compute_verdict(checks: list[CheckResult], partial_workspace: str = "") -> tuple[Verdict, list[str], bool]:
    """Return (verdict, reasons, complete). `partial_workspace` is a non-empty description when the
    sandbox copy skipped or withheld entries."""
    fail, warn = [], []
    complete = True
    for c in checks:
        n_fail = sum(1 for f in c.findings if f.severity.rank >= _FAIL_AT)
        n_warn = sum(1 for f in c.findings if 2 <= f.severity.rank < _FAIL_AT)
        if n_fail:
            fail.append(f"{c.name}: {n_fail} finding(s) of severity high or critical")
        if n_warn:
            warn.append(f"{c.name}: {n_warn} finding(s) of severity medium, low or unknown")
        if c.truncated_findings:
            warn.append(f"{c.name}: {c.truncated_findings} further finding(s) not listed (cap reached)")
        if c.status.operational_problem:
            complete = False
            warn.append(f"{c.name}: {c.status.value}" + (f" - {c.detail}" if c.detail else ""))
    if partial_workspace:
        complete = False
        warn.append(f"partial scan: {partial_workspace}")
    if not any(c.status.completed and c.analysis for c in checks):
        complete = False
        warn.append("no check ran to completion; nothing was validated")
    if fail:
        return Verdict.FAIL, fail + warn, complete
    if warn:
        return Verdict.WARNING, warn, complete
    return Verdict.PASS, ["all applicable checks completed with no findings above informational"], complete
