import json
import shutil

import pytest

from engine_helpers import OSV_JSON, SEMGREP_JSON, FakeRunner, make_osv_db, overrides, sg_json, tool_run
from saferun.engine import CheckStatus, ValidationOptions, Verdict, node, osv, pysyntax, semgrep, validate_project
from test_engine_node import BAD, DONE2, OK, out


@pytest.fixture
def tools_present(tmp_path, monkeypatch, low_osv_floor):
    """Analyzers are faked in these tests; give the OSV check a small consistent offline database so it reaches the fake runner."""
    make_osv_db(tmp_path / "osvdb")
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "osvdb"))


def by_name(rep):
    return {c.name: c for c in rep.checks}


def project(tmp_path, files):
    p = tmp_path / "proj"
    for name, text in files.items():
        (p / name).parent.mkdir(parents=True, exist_ok=True)
        (p / name).write_text(text)
    return p


def _analyzer_built() -> bool:
    try:
        from saferun.sandbox.analyzer import verify_analyzer_image
        verify_analyzer_image()
        return True
    except Exception:  # noqa: BLE001
        return False


ANALYZER_BUILT = _analyzer_built()
PY_SCANNED = ("app.py", "lib/h.py")


def routed(semgrep_out=None, osv_out=None, osv_code=0):
    """One runner that answers by tool, like the real engine would see."""
    def run(argv, **kw):
        if argv[0].endswith("semgrep"):
            return semgrep_out or tool_run(sg_json(scanned=PY_SCANNED))
        return osv_out or tool_run(json.dumps({"results": []}), exit_code=osv_code)
    return run


def test_python_project_with_findings_fails(tmp_path, ws_root, tools_present):
    p = project(tmp_path, {"app.py": "eval(input())\n", "lib/h.py": "", "requirements.txt": "flask==2.0.0\n"})
    rep = validate_project(p, ctx_overrides=overrides(routed(tool_run(SEMGREP_JSON))))
    c = by_name(rep)
    assert rep.verdict is Verdict.FAIL
    assert c[semgrep.NAME].status is CheckStatus.FINDINGS and c[osv.NAME].status is CheckStatus.PASSED
    assert c[node.NAME].status is CheckStatus.NOT_APPLICABLE and c[pysyntax.NAME].status is CheckStatus.PASSED
    assert any("python-static-analysis" in r for r in rep.reasons)
    assert list(ws_root.iterdir()) == []                      # workspace removed


def test_python_project_clean_passes(tmp_path, ws_root, tools_present):
    p = project(tmp_path, {"app.py": "print(1)\n", "requirements.txt": "flask==2.0.0\n"})
    rep = validate_project(p, ctx_overrides=overrides(routed()))
    assert rep.verdict is Verdict.PASS and rep.complete


def test_node_project_dependency_and_syntax(tmp_path, ws_root, tools_present):
    p = project(tmp_path, {"a.js": "", "b.js": "", "package.json": "{}", "package-lock.json": "{}"})
    rep = validate_project(p, ctx_overrides=overrides(routed(osv_out=tool_run(OSV_JSON, exit_code=1)), node_stdout=out(OK, BAD, DONE2)))
    c = by_name(rep)
    assert c[osv.NAME].status is CheckStatus.FINDINGS and c[node.NAME].status is CheckStatus.FINDINGS
    assert rep.verdict is Verdict.FAIL                         # lodash GHSA scores 7.2 -> high
    assert {f.category for f in rep.findings} == {"dependency", "syntax"}


def test_all_tools_missing_is_warning_never_pass(tmp_path, ws_root, monkeypatch):
    from saferun.sandbox import SandboxError
    from saferun.sandbox.analyzer import AnalyzerUnavailable

    def no_docker(image):
        raise SandboxError("no docker")

    def no_analyzer():
        raise AnalyzerUnavailable("not built")
    p = project(tmp_path, {"app.py": "x=1\n", "a.js": "", "package-lock.json": "{}"})
    rep = validate_project(p, ctx_overrides={"image_available": no_docker, "analyzer_available": no_analyzer})
    assert rep.verdict is Verdict.WARNING and not rep.complete and not rep.findings
    assert {c.status for c in rep.checks if c.analysis} == {CheckStatus.UNAVAILABLE}
    assert "nothing was validated" in " ".join(rep.reasons)


def test_one_clean_check_does_not_hide_another_failed_one(tmp_path, ws_root, tools_present):
    p = project(tmp_path, {"app.py": "x=1\n", "requirements.txt": "a==1\n"})
    rep = validate_project(p, ctx_overrides=overrides(routed(osv_out=tool_run("", exit_code=127, stderr="no network"))))
    c = by_name(rep)
    assert c[semgrep.NAME].status is CheckStatus.PASSED and c[osv.NAME].status is CheckStatus.ERROR
    assert rep.verdict is Verdict.WARNING and not rep.complete


def test_crashing_check_becomes_error_result(tmp_path, ws_root, tools_present):
    def explode(argv, **kw):
        raise RuntimeError("bug in runner")
    p = project(tmp_path, {"app.py": "x=1\n"})
    rep = validate_project(p, ctx_overrides=overrides(explode))
    c = by_name(rep)[semgrep.NAME]
    assert c.status is CheckStatus.ERROR and "bug in runner" in c.detail and rep.verdict is Verdict.WARNING


def test_withheld_credential_file_is_a_high_finding_and_marks_partial(tmp_path, ws_root, tools_present):
    p = project(tmp_path, {"app.py": "x=1\n", "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "ZmFrZWtleW1hdGVyaWFsZm9ydGVzdGluZ29ubHkwMTIzNDU2Nzg5" * 2 + "\n-----END OPENSSH PRIVATE KEY-----\n"})
    rep = validate_project(p, ctx_overrides=overrides(routed()))
    assert rep.verdict is Verdict.FAIL and not rep.complete
    (f,) = [f for f in rep.findings if f.category == "workspace"]
    assert f.path == "id_rsa" and f.rule_id.startswith("withheld.") and "ZmFrZWtleW1hdGVy" not in json.dumps(rep.to_dict())
    assert rep.workspace["withheld"][0]["path"] == "id_rsa"


def test_skipped_symlink_makes_scan_partial(tmp_path, ws_root, tools_present):
    p = project(tmp_path, {"app.py": "x=1\n"})
    (p / "link").symlink_to("app.py")
    rep = validate_project(p, ctx_overrides=overrides(routed()))
    assert rep.verdict is Verdict.WARNING and not rep.complete and rep.workspace["skipped"][0]["reason"] == "symlink"


def test_disabled_checks_are_skipped_not_clean(tmp_path, ws_root, tools_present):
    p = project(tmp_path, {"app.py": "x=1\n"})
    rep = validate_project(p, ValidationOptions(python_analysis=False, python_syntax=False, dependency_scan=False, javascript_check=False))
    assert {c.status for c in rep.checks if c.analysis} == {CheckStatus.SKIPPED} and rep.verdict is Verdict.WARNING


def test_original_project_is_untouched_and_tools_see_only_the_copy(tmp_path, ws_root, tools_present):
    p = project(tmp_path, {"app.py": "x=1\n"})
    seen = []

    def run(argv, *, cwd, **kw):
        seen.append(cwd)
        return tool_run(sg_json(scanned=["app.py"]))
    before = sorted(x.name for x in p.iterdir())
    validate_project(p, ctx_overrides=overrides(run))
    assert sorted(x.name for x in p.iterdir()) == before
    assert seen and all(str(c).startswith(str(ws_root)) and c != p for c in seen)


def test_report_is_json_serializable_and_schema_stable(tmp_path, ws_root, tools_present):
    p = project(tmp_path, {"app.py": "eval(x)\n"})
    d = validate_project(p, ctx_overrides=overrides(routed(tool_run(SEMGREP_JSON)))).to_dict()
    d2 = json.loads(json.dumps(d))
    assert d2["schema_version"] == 1 and d2["verdict"] == "FAIL" and set(d2) == {"schema_version", "verdict", "reasons", "complete", "workspace", "checks"}
    f = next(c for c in d2["checks"] if c["name"] == semgrep.NAME)["findings"][0]
    assert set(f) == {"check", "rule_id", "severity", "message", "category", "path", "line", "end_line", "package", "vulnerability_ids", "fixed_versions", "cwe"}


def test_invalid_project_path_raises(tmp_path):
    from saferun.sandbox import SandboxError
    with pytest.raises(SandboxError):
        validate_project(tmp_path / "missing")


# --- real Semgrep, only if installed (no network needed: local rules) ---
@pytest.mark.docker
@pytest.mark.skipif(not ANALYZER_BUILT, reason="analyzer image not built (docker/analyzer/build.sh)")
def test_real_semgrep_on_bundled_rules(tmp_path, ws_root):
    p = project(tmp_path, {
        "bad.py": "import os, subprocess, pickle\neval(input())\nos.system('ls')\nsubprocess.run('ls', shell=True)\n"
                  "pickle.loads(b'')\npassword = 'hunter2'\n",
        "good.py": "import subprocess\nsubprocess.run(['ls'])\n"})
    rep = validate_project(p, ValidationOptions(python_syntax=False, dependency_scan=False, javascript_check=False))
    c = by_name(rep)[semgrep.NAME]
    assert c.status is CheckStatus.FINDINGS, (c.status, c.detail)
    assert {f.path for f in c.findings} == {"bad.py"}
    assert {"saferun.python.dynamic-code-execution", "saferun.python.os-command-execution",
            "saferun.python.subprocess-shell-true", "saferun.python.unsafe-deserialization",
            "saferun.python.hardcoded-secret"} <= {f.rule_id for f in c.findings}
    assert rep.verdict is Verdict.FAIL
