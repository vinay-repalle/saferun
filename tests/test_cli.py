"""CLI tests. Most replace `validate_project` with a stub (no Docker, no tools); a few drive the real engine."""
import json
import subprocess
import sys

import pytest

from saferun import cli
from saferun.engine import (CheckResult, CheckStatus, Finding, PackageRef, Severity, ValidationReport, Verdict,
                            compute_verdict)
from saferun.sandbox import SandboxError


def report(*checks, partial=""):
    v, reasons, complete = compute_verdict(list(checks), partial)
    return ValidationReport(v, reasons, complete, list(checks), {"skipped": [], "withheld": []})


def finding(sev, **kw):
    return Finding(check="c", rule_id="r.1", severity=sev, message="msg", path="a/b.py", line=7, **kw)


def stub(monkeypatch, rep=None, exc=None):
    calls = []

    def fake(path, options):
        calls.append((path, options))
        if exc:
            raise exc
        return rep
    monkeypatch.setattr(cli, "validate_project", fake)
    return calls


@pytest.fixture
def proj(tmp_path):
    (tmp_path / "x.py").write_text("x = 1\n")
    return tmp_path


PASS_R = lambda: report(CheckResult("c", CheckStatus.PASSED))  # noqa: E731


@pytest.mark.parametrize("rep,code", [
    (PASS_R(), 0),
    (report(CheckResult("c", CheckStatus.FINDINGS, findings=[finding(Severity.HIGH)])), 1),
    (report(CheckResult("c", CheckStatus.FINDINGS, findings=[finding(Severity.CRITICAL)])), 1),
    (report(CheckResult("c", CheckStatus.FINDINGS, findings=[finding(Severity.LOW)])), 2),
    (report(CheckResult("c", CheckStatus.PASSED), CheckResult("d", CheckStatus.TIMEOUT, detail="slow")), 2),
    (report(CheckResult("c", CheckStatus.UNAVAILABLE, detail="no tool")), 2),
])
def test_exit_codes_follow_verdict(monkeypatch, proj, capsys, rep, code):
    stub(monkeypatch, rep)
    assert cli.main(["scan", str(proj)]) == code


def test_incomplete_scan_is_never_exit_zero(monkeypatch, proj, capsys):
    stub(monkeypatch, report(CheckResult("c", CheckStatus.PASSED), CheckResult("d", CheckStatus.ERROR, detail="boom",
                                                                               errors=["tool crashed"])))
    assert cli.main(["scan", str(proj)]) == 2
    out = capsys.readouterr().out
    assert "Scan complete: NO" in out and "Coverage gaps" in out and "tool crashed" in out and "d: error - boom" in out


def test_text_output_contents(monkeypatch, proj, capsys):
    pkg = PackageRef("flask", "1.0", "PyPI")
    stub(monkeypatch, report(
        CheckResult("c", CheckStatus.FINDINGS, findings=[finding(Severity.LOW), finding(Severity.HIGH, package=pkg,
                                                                                         fixed_versions=("2.0",))]),
        partial="1 sensitive file(s) withheld"))
    cli.main(["scan", str(proj)])
    out = capsys.readouterr().out
    assert "Verdict: FAIL" in out and "Findings (2)" in out and "a/b.py:7" in out
    assert out.index("[HIGH]") < out.index("[LOW]")                      # most severe first
    assert "flask 1.0 (PyPI)" in out and "fixed in: 2.0" in out and "not a proof" in out


def test_untrusted_text_is_neutralized(monkeypatch, proj, capsys):
    f = Finding(check="c", rule_id="r", severity=Severity.LOW, message="evil\x1b[31mred\x07", path="p\x1b]0;x")
    stub(monkeypatch, report(CheckResult("c", CheckStatus.FINDINGS, findings=[f])))
    cli.main(["scan", str(proj)])
    assert "\x1b" not in capsys.readouterr().out


def test_json_output_is_the_engine_schema_only(monkeypatch, proj, capsys):
    rep = report(CheckResult("c", CheckStatus.FINDINGS, findings=[finding(Severity.MEDIUM)]))
    stub(monkeypatch, rep)
    assert cli.main(["scan", str(proj), "--format", "json"]) == 2
    assert json.loads(capsys.readouterr().out) == rep.to_dict()          # stdout is exactly the report


def test_options_are_passed_to_engine(monkeypatch, proj, capsys):
    calls = stub(monkeypatch, PASS_R())
    cli.main(["scan", str(proj), "--osv-offline", "--no-python-syntax", "--no-python-analysis",
              "--no-dependency-scan", "--no-javascript-check", "--timeout", "30"])
    o = calls[0][1]
    assert (o.osv_offline, o.python_syntax, o.python_analysis, o.dependency_scan, o.javascript_check,
            o.tool_timeout_s) == (True, False, False, False, False, 30.0)
    cli.main(["scan", str(proj)])
    d = calls[1][1]
    assert d.dependency_scan and d.osv_offline and d.python_syntax and d.tool_timeout_s == 120.0


def test_no_osv_network_notice_because_scans_are_always_offline(monkeypatch, proj, capsys):
    """Phase 5B: nothing is sent to OSV.dev, so no disclosure is printed; --osv-offline stays accepted (a no-op)."""
    stub(monkeypatch, PASS_R())
    for flags in ([], ["--osv-offline"], ["--no-dependency-scan"]):
        assert cli.main(["scan", str(proj), *flags]) == 0
        assert "OSV.dev" not in capsys.readouterr().err


@pytest.mark.parametrize("argv", [
    [], ["scan"], ["bogus"], ["scan", "--nope", "."], ["scan", ".", "--format", "xml"],
    ["scan", ".", "--timeout", "0"], ["scan", ".", "--timeout", "-1"], ["scan", ".", "--timeout", "abc"],
    ["scan", ".", "--timeout", "nan"], ["scan", ".", "--timeout", "inf"], ["scan", ".", "--timeout", "99999"],
])
def test_invalid_usage_exits_64_without_calling_engine(monkeypatch, capsys, argv):
    calls = stub(monkeypatch, PASS_R())
    assert cli.main(argv) == 64 and calls == []


def test_missing_path_and_file_path(monkeypatch, tmp_path, capsys):
    calls = stub(monkeypatch, PASS_R())
    assert cli.main(["scan", str(tmp_path / "nope")]) == 64
    f = tmp_path / "f.py"
    f.write_text("")
    assert cli.main(["scan", str(f)]) == 64
    assert calls == [] and capsys.readouterr().out == ""


def test_sandbox_error_is_fatal_not_success(monkeypatch, proj, capsys):
    stub(monkeypatch, exc=SandboxError("project too large"))
    assert cli.main(["scan", str(proj)]) == 70
    cap = capsys.readouterr()
    assert cap.out == "" and "project too large" in cap.err and "no verdict" in cap.err


def test_unexpected_exception_is_fatal_without_traceback(monkeypatch, proj, capsys):
    stub(monkeypatch, exc=RuntimeError("bug"))
    assert cli.main(["scan", str(proj), "--format", "json"]) == 70
    cap = capsys.readouterr()
    assert cap.out == "" and "Traceback" not in cap.err and "bug" in cap.err


def test_keyboard_interrupt(monkeypatch, proj, capsys):
    stub(monkeypatch, exc=KeyboardInterrupt())
    assert cli.main(["scan", str(proj)]) == 130


def test_help_exits_zero_with_examples_and_exit_codes(capsys):
    for argv in (["--help"], ["scan", "--help"]):
        assert cli.main(argv) == 0
        out = capsys.readouterr().out
        assert "examples:" in out and "exit codes:" in out and "saferun scan" in out


# ---- integration with the real engine ----

def test_real_engine_all_checks_disabled_is_warning_not_pass(proj, capsys):
    argv = ["scan", str(proj), "--no-python-syntax", "--no-python-analysis", "--no-dependency-scan",
            "--no-javascript-check", "--format", "json"]
    assert cli.main(argv) == 2
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "WARNING" and data["complete"] is False and data["schema_version"] == 1
    assert [c["status"] for c in data["checks"][1:]] == ["skipped"] * 4


def test_real_engine_missing_tools_do_not_crash_or_pass(proj, monkeypatch, capsys):
    monkeypatch.setenv("PATH", "/nonexistent")
    code = cli.main(["scan", str(proj), "--no-python-syntax", "--no-javascript-check", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 2 and data["verdict"] == "WARNING" and data["complete"] is False


@pytest.mark.docker
def test_real_engine_and_sandbox_syntax_error(tmp_path, capsys):
    (tmp_path / "bad.py").write_text("def f(:\n")
    code = cli.main(["scan", str(tmp_path), "--no-python-analysis", "--no-dependency-scan",
                     "--no-javascript-check", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 2
    f = [x for c in data["checks"] for x in c["findings"]]
    assert f and f[0]["path"] == "bad.py" and f[0]["line"] == 1


def test_entry_points_module_and_console_script(tmp_path):
    r = subprocess.run([sys.executable, "-m", "saferun", "scan", str(tmp_path / "missing")],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 64 and "does not exist" in r.stderr
    from importlib.metadata import entry_points
    assert any(e.value == "saferun.cli:main" for e in entry_points(group="console_scripts") if e.name == "saferun")
