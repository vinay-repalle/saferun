"""Normalized result model for the validation engine.

Two things are kept strictly apart:
  * a *finding*   - something the analysis found in the project (a security signal), and
  * a *check status* - whether the analysis itself ran to completion (an operational fact).
A check that errored, timed out, was unavailable or was skipped has NO findings by definition, and that
is never the same as a clean result: see `verdict.compute_verdict`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

SCHEMA_VERSION = 1
MAX_TEXT = 500


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"  # the tool gave no usable severity; the verdict treats it as MEDIUM

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.UNKNOWN: 3,
         Severity.LOW: 2, Severity.INFO: 1}


class CheckStatus(str, Enum):
    PASSED = "passed"                    # ran to completion, no findings
    FINDINGS = "findings"                # ran to completion, findings reported
    INCOMPLETE = "incomplete"            # ran, but not everything was analysed (partial results kept)
    ERROR = "error"                      # tool failed / produced unusable output; nothing can be concluded
    TIMEOUT = "timeout"                  # tool exceeded its time limit; nothing can be concluded
    UNAVAILABLE = "unavailable"          # tool or runtime missing; the check did not run
    SKIPPED = "skipped"                  # applicable, but deliberately not run (reason given)
    NOT_APPLICABLE = "not_applicable"    # nothing for this check to look at (e.g. no JavaScript files)

    @property
    def completed(self) -> bool:
        """The analysis ran to completion: its (lack of) findings is a real result."""
        return self in (CheckStatus.PASSED, CheckStatus.FINDINGS)

    @property
    def operational_problem(self) -> bool:
        """Something that should have been checked was not (fully) checked."""
        return self in (CheckStatus.INCOMPLETE, CheckStatus.ERROR, CheckStatus.TIMEOUT,
                        CheckStatus.UNAVAILABLE, CheckStatus.SKIPPED)


class Verdict(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"


_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")


def clean_text(value, limit: int = MAX_TEXT) -> str:
    """Tool output and project content are untrusted: drop control/escape/bidi characters, bound length."""
    s = _CTRL.sub("?", str(value)).replace("\r", " ")
    return s if len(s) <= limit else s[: limit - 1] + "…"


@dataclass(frozen=True)
class PackageRef:
    name: str
    version: str = ""
    ecosystem: str = ""   # OSV ecosystem name, e.g. "PyPI", "npm"


@dataclass(frozen=True)
class Finding:
    check: str                      # name of the check that produced it
    rule_id: str                    # rule / vulnerability id
    severity: Severity
    message: str
    category: str = "code"          # code | dependency | syntax | workspace
    path: str | None = None         # relative, posix, sanitized; None when not file-specific
    line: int | None = None
    end_line: int | None = None
    package: PackageRef | None = None
    vulnerability_ids: tuple[str, ...] = ()   # primary id first, then aliases (CVE-..., GHSA-...)
    fixed_versions: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "check": self.check, "rule_id": self.rule_id, "severity": self.severity.value,
            "message": self.message, "category": self.category, "path": self.path,
            "line": self.line, "end_line": self.end_line,
            "package": None if self.package is None else vars(self.package).copy(),
            "vulnerability_ids": list(self.vulnerability_ids),
            "fixed_versions": list(self.fixed_versions), "cwe": list(self.cwe),
        }


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    findings: list[Finding] = field(default_factory=list)
    detail: str = ""                # human-readable reason, always set for non-passing statuses
    tool: str = ""                  # tool name and version when known
    duration_s: float = 0.0
    errors: list[str] = field(default_factory=list)   # operational problems (never security findings)
    notes: list[str] = field(default_factory=list)    # coverage notes (what was / was not looked at)
    truncated_findings: int = 0     # findings dropped because of the per-check cap
    analysis: bool = True           # False for bookkeeping checks that must not count as 'something was validated'

    def to_dict(self) -> dict:
        return {
            "name": self.name, "status": self.status.value, "detail": self.detail, "tool": self.tool,
            "duration_s": round(self.duration_s, 3), "errors": list(self.errors), "notes": list(self.notes),
            "truncated_findings": self.truncated_findings,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ValidationReport:
    verdict: Verdict
    reasons: list[str]              # why this verdict (one line each, ordered by importance)
    complete: bool                  # every applicable check ran to completion on the whole project
    checks: list[CheckResult]
    workspace: dict = field(default_factory=dict)   # copy accounting (entries, skipped, withheld)
    schema_version: int = SCHEMA_VERSION

    @property
    def findings(self) -> list[Finding]:
        return [f for c in self.checks for f in c.findings]

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version, "verdict": self.verdict.value, "reasons": list(self.reasons),
            "complete": self.complete, "workspace": dict(self.workspace),
            "checks": [c.to_dict() for c in self.checks],
        }
