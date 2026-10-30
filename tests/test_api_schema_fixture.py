"""The dashboard's golden report fixture is generated from the REAL engine model and pinned by this test.

web/src/fixtures/report.json is consumed by the frontend tests. If the engine's report schema changes, this test fails
until the fixture is regenerated (SAFERUN_UPDATE_FIXTURES=1 .venv/bin/pytest tests/test_api_schema_fixture.py) and the
frontend types/tests are reviewed - the UI can never silently drift from the engine.
"""
import json
import os
from pathlib import Path

from saferun.engine import (CheckResult, CheckStatus, Finding, PackageRef, Severity, ValidationReport, compute_verdict)

FIXTURE = Path(__file__).resolve().parents[1] / "web" / "src" / "fixtures" / "report.json"


def build_report() -> ValidationReport:
    f = lambda **kw: Finding(**kw)  # noqa: E731
    checks = [
        CheckResult("workspace-sensitive-files", CheckStatus.FINDINGS, analysis=False, notes=["content of withheld files is never read by SafeRun analyzers"],
                    findings=[f(check="workspace-sensitive-files", rule_id="withheld.private-key", severity=Severity.HIGH,
                                message="credential-like file found in the project; it was withheld from analysis and the sandbox",
                                category="workspace", path="deploy/id_rsa")]),
        CheckResult("python-syntax", CheckStatus.FINDINGS, tool="python 3.12", duration_s=1.234,
                    findings=[f(check="python-syntax", rule_id="python.syntax-error", severity=Severity.MEDIUM,
                                message="invalid syntax", category="syntax", path="src/broken.py", line=1, end_line=1)]),
        CheckResult("python-static-analysis", CheckStatus.FINDINGS, tool="semgrep 1.182.1", duration_s=3.5,
                    notes=["2 Python file(s) targeted", "rules: bundled local set (saferun/engine/rules/python.yml)"],
                    findings=[
                        f(check="python-static-analysis", rule_id="saferun.python.eval", severity=Severity.HIGH,
                          message="<img src=x onerror=alert(1)> eval() on non-constant input", path="src/app.py", line=4, end_line=4, cwe=("CWE-95",)),
                        f(check="python-static-analysis", rule_id="saferun.python.assert", severity=Severity.LOW,
                          message="assert used for validation", path="src/app.py", line=9, end_line=9)]),
        CheckResult("dependency-vulnerabilities", CheckStatus.INCOMPLETE, tool="osv-scanner 2.7.0", duration_s=2.0,
                    detail="package.json: no npm lockfile; dependencies not scanned",
                    errors=["package.json: no npm lockfile"], notes=["1 lockfile(s) scanned"], truncated_findings=3,
                    findings=[f(check="dependency-vulnerabilities", rule_id="GHSA-35jh-r3h4-6jhm", severity=Severity.CRITICAL,
                                message="Command Injection in lodash", category="dependency", path="package-lock.json",
                                package=PackageRef("lodash", "4.17.15", "npm"),
                                vulnerability_ids=("GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"), fixed_versions=("4.17.21",)),
                              f(check="dependency-vulnerabilities", rule_id="PYSEC-0000", severity=Severity.UNKNOWN,
                                message="severity not reported", category="dependency", path="requirements.txt",
                                package=PackageRef("flask", "1.0", "PyPI"))]),
        CheckResult("javascript-syntax", CheckStatus.UNAVAILABLE, detail="node image not present locally"),
        CheckResult("example-skipped", CheckStatus.SKIPPED, detail="disabled by options"),
        CheckResult("example-timeout", CheckStatus.TIMEOUT, detail="tool exceeded 120s and was killed"),
        CheckResult("example-not-applicable", CheckStatus.NOT_APPLICABLE, detail="no files"),
        CheckResult("example-passed", CheckStatus.PASSED, tool="example 1.0", duration_s=0.5),
        CheckResult("example-error", CheckStatus.ERROR, detail="tool exited with code 2", errors=["stderr: boom"]),
    ]
    verdict, reasons, complete = compute_verdict(checks, "1 entr(y/ies) skipped (symlinks, special files or external hard links); 1 sensitive file(s) withheld")
    workspace = {"entries_scanned": 12, "copied_files": 9, "copied_dirs": 2, "copied_bytes": 4096,
                 "skipped": [{"path": "link-to-etc", "reason": "symlink"}],
                 "withheld": [{"path": "deploy/id_rsa", "reason": "private-key"}]}
    return ValidationReport(verdict, reasons, complete, checks, workspace)


def test_fixture_matches_the_engine_schema():
    current = build_report().to_dict()
    if os.environ.get("SAFERUN_UPDATE_FIXTURES") == "1":
        FIXTURE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
    assert json.loads(FIXTURE.read_text()) == current, "report schema changed: regenerate the fixture and review the frontend"


def test_fixture_covers_every_status_severity_and_verdict_inputs():
    d = build_report().to_dict()
    assert {c["status"] for c in d["checks"]} == {s.value for s in CheckStatus}
    assert {x["severity"] for c in d["checks"] for x in c["findings"]} == {"critical", "high", "medium", "low", "unknown"}
    assert d["verdict"] == "FAIL" and d["complete"] is False and d["schema_version"] == 1
