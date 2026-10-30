import json
from pathlib import Path

import pytest

from engine_helpers import SEMGREP_JSON, FakeRunner, make_ctx, sg_json, tool_run
from saferun.engine import CheckStatus, Severity, semgrep
from saferun.sandbox import SandboxError
from saferun.sandbox.analyzer import AnalyzerIntegrityError, AnalyzerUnavailable
from saferun.engine.tools import ToolUnavailable


def run(tmp_path, runner, files=("app.py", "lib/h.py")):
    return semgrep.run_check(make_ctx(tmp_path, files, runner))


def test_parse_normalizes_findings(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(SEMGREP_JSON)))
    assert res.status is CheckStatus.FINDINGS
    a, b = res.findings
    assert (a.rule_id, a.severity, a.path, a.line, a.end_line, a.category, a.cwe) == (
        "saferun.python.dynamic-code-execution", Severity.HIGH, "app.py", 3, 3, "code", ("CWE-95",))
    assert b.severity is Severity.MEDIUM and b.path == "lib/h.py" and b.line == 9


def test_clean_scan_is_passed(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(sg_json())))
    assert res.status is CheckStatus.PASSED and not res.findings


def test_severity_fallback_and_unknown(tmp_path):
    def one(extra):
        out = sg_json([{"check_id": "x", "path": "a.py", "start": {"line": 1}, "end": {"line": 1}, "extra": extra}], scanned=["a.py"])
        return run(tmp_path, FakeRunner(tool_run(out)), ["a.py"]).findings[0].severity
    assert one({"message": "m", "severity": "ERROR"}) is Severity.HIGH
    assert one({"message": "m", "severity": "INFO"}) is Severity.LOW
    assert one({"message": "m", "severity": "weird"}) is Severity.UNKNOWN
    assert one({"message": "m", "metadata": {"saferun_severity": "critical"}}) is Severity.CRITICAL


def test_hostile_paths_and_text_are_sanitized(tmp_path):
    out = json.dumps({"paths": {"scanned": ["app.py", "lib/h.py"]}, "results": [
        {"check_id": "x", "path": "../../etc/passwd", "start": {"line": -1}, "end": {}, "extra": {"message": "\x1b[31mred\x1b[0m‮" + "A" * 2000}},
        {"check_id": "y", "path": "/etc/shadow", "start": {"line": True}, "end": {}, "extra": {"message": "m"}}]})
    a, b = run(tmp_path, FakeRunner(tool_run(out))).findings
    assert a.path is None and b.path is None and a.line is None and b.line is None
    assert "\x1b" not in a.message and "‮" not in a.message and len(a.message) <= 500


def test_absolute_path_inside_project_is_made_relative(tmp_path):
    ctx = make_ctx(tmp_path, ["app.py"], FakeRunner(tool_run(sg_json([
        {"check_id": "x", "path": str(tmp_path / "project" / "app.py"), "start": {"line": 1}, "end": {"line": 1}, "extra": {"message": "m"}}], scanned=["app.py"]))))
    assert semgrep.run_check(ctx).findings[0].path == "app.py"


@pytest.mark.parametrize("bad", ["", "not json", "[]", "{}", '{"results": {}}', '{"results": [1]}', '{"results": [{"extra": 1}]}', "[" * 100000])
def test_malformed_output_is_error_not_clean(tmp_path, bad):
    res = run(tmp_path, FakeRunner(tool_run(bad)))
    assert res.status is CheckStatus.ERROR and not res.findings and "unusable" in res.detail


def test_nonzero_exit_is_error_even_with_valid_json(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(SEMGREP_JSON, exit_code=2, stderr="boom")))
    assert res.status is CheckStatus.ERROR and "code 2" in res.detail and "boom" in res.detail and not res.findings


def test_timeout(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(timed_out=True)))
    assert res.status is CheckStatus.TIMEOUT and not res.findings


def test_output_cap(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(truncated=True)))
    assert res.status is CheckStatus.ERROR and "size limit" in res.detail


def test_tool_reported_errors_make_it_incomplete_keeping_findings(tmp_path):
    out = json.loads(SEMGREP_JSON)
    out["errors"] = [{"type": "PartialParsing", "path": "bad.py", "message": "x"}]
    res = run(tmp_path, FakeRunner(tool_run(json.dumps(out))))
    assert res.status is CheckStatus.INCOMPLETE and len(res.findings) == 2 and "bad.py" in res.errors[0]


def _unavailable():
    raise AnalyzerUnavailable("the analyzer image has not been built")


def _tampered():
    raise AnalyzerIntegrityError("analyzer image ID mismatch")


def test_missing_analyzer_image_is_unavailable_and_nothing_runs(tmp_path):
    r = FakeRunner(tool_run(SEMGREP_JSON))
    res = semgrep.run_check(make_ctx(tmp_path, ("app.py",), r, analyzer_available=_unavailable))
    assert res.status is CheckStatus.UNAVAILABLE and not r.calls and not res.findings and "no host fallback" in res.detail


def test_tampered_analyzer_image_is_error_and_nothing_runs(tmp_path):
    r = FakeRunner(tool_run(SEMGREP_JSON))
    res = semgrep.run_check(make_ctx(tmp_path, ("app.py",), r, analyzer_available=_tampered))
    assert res.status is CheckStatus.ERROR and not r.calls and not res.findings and "mismatch" in res.detail


def test_sandbox_failure_is_error_never_clean(tmp_path):
    res = run(tmp_path, FakeRunner(exc=SandboxError("container was not started: applied configuration violates the sandbox policy")))
    assert res.status is CheckStatus.ERROR and not res.findings and "no host fallback" in res.detail


def test_tool_vanishing_is_unavailable(tmp_path):
    assert run(tmp_path, FakeRunner(exc=ToolUnavailable("gone"))).status is CheckStatus.UNAVAILABLE


def test_no_python_files_not_applicable(tmp_path):
    r = FakeRunner(tool_run(SEMGREP_JSON))
    res = run(tmp_path, r, files=["a.js", "venv/lib/x.py", "node_modules/p/y.py"])
    assert res.status is CheckStatus.NOT_APPLICABLE and not r.calls


def test_invocation_is_controlled(tmp_path):
    r = FakeRunner(tool_run(sg_json(scanned=["a.py"])))
    ctx = make_ctx(tmp_path, ["a.py"], r, timeout_s=7)
    semgrep.run_check(ctx)
    c = r.calls[0]
    argv = c["argv"]
    assert argv[0] == "/usr/local/bin/semgrep" and argv[-1] == "." and c["cwd"] == ctx.project and c["timeout_s"] == 7
    assert "--no-rewrite-rule-ids" in argv and "--metrics=off" in argv and "--disable-nosem" in argv and "--disable-version-check" in argv
    cfg = argv[argv.index("--config") + 1]
    assert cfg == "/opt/saferun/rules/python.yml" and argv.count("--config") == 1   # rules baked into the image: local only, no registry/auto
    assert not any(a in ("auto", "p/default") or a.startswith("http") for a in argv)
    assert c["env"] is None and c["mounts"] == ()   # no host environment is forwarded; Semgrep needs no extra mount


def test_bundled_rules_are_well_formed_yaml_structure():
    text = semgrep.RULES_FILE.read_text()
    assert text.count("- id: saferun.python.") == text.count("metadata: {saferun_severity")


def test_unscanned_target_makes_check_incomplete_never_clean(tmp_path):
    """Semgrep silently skips e.g. files over --max-target-bytes (observed with the real tool)."""
    res = run(tmp_path, FakeRunner(tool_run(sg_json(scanned=["app.py"]))))
    assert res.status is CheckStatus.INCOMPLETE and "lib/h.py" in res.detail and "lib/h.py" in res.errors[-1]
    res = run(tmp_path, FakeRunner(tool_run(SEMGREP_JSON.replace('"lib/h.py"]}', '"x.py"]}'))))
    assert res.status is CheckStatus.INCOMPLETE and len(res.findings) == 2     # findings kept, coverage gap reported


def test_missing_scanned_list_is_incomplete(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(sg_json(scanned=None))))
    assert res.status is CheckStatus.INCOMPLETE and "coverage cannot be verified" in res.detail


def test_semgrepignore_files_are_removed_from_the_copy(tmp_path):
    ctx = make_ctx(tmp_path, ["app.py", "lib/h.py", ".semgrepignore", "lib/.semgrepignore", ".gitignore"],
                   FakeRunner(tool_run(sg_json())))
    res = semgrep.run_check(ctx)
    assert not (ctx.project / ".semgrepignore").exists() and not (ctx.project / "lib" / ".semgrepignore").exists()
    assert (ctx.project / ".gitignore").exists() and res.status is CheckStatus.PASSED
    assert any("2 .semgrepignore" in n for n in res.notes)
