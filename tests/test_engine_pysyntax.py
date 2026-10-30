import json
from types import SimpleNamespace

import pytest

from conftest import require_image
from engine_helpers import make_ctx
from saferun.engine import CheckStatus, Severity, pysyntax
from saferun.sandbox import SandboxError
from saferun.sandbox.profiles import PYTHON


def L(**o):
    return json.dumps(o)


OK = L(file="a.py", ok=True)
BAD = L(file="b.py", ok=False, line=3, msg="invalid syntax")
DONE2 = L(done=True, count=2, truncated=False)


def sb(stdout="", exit_code=0, **kw):
    calls = []

    def fake(project, command, limits=None, image=None, **_):
        calls.append({"command": command, "image": image})
        return SimpleNamespace(exit_code=exit_code, stdout=stdout, stderr=kw.get("stderr", ""), timed_out=kw.get("timed_out", False),
                               oom_killed=kw.get("oom_killed", False), output_truncated=kw.get("output_truncated", False))
    fake.calls = calls
    return fake


def run(tmp_path, sandbox, files=("a.py", "b.py"), available=lambda i: None):
    return pysyntax.run_check(make_ctx(tmp_path, files, sandbox=sandbox, image_available=available))


def test_syntax_error_finding(tmp_path):
    res = run(tmp_path, sb("\n".join([OK, BAD, DONE2])))
    (f,) = res.findings
    assert res.status is CheckStatus.FINDINGS
    assert (f.path, f.line, f.severity, f.category, f.rule_id) == ("b.py", 3, Severity.MEDIUM, "syntax", "python.syntax-error")


def test_clean(tmp_path):
    assert run(tmp_path, sb("\n".join([OK, L(file="b.py", ok=True), DONE2]))).status is CheckStatus.PASSED


@pytest.mark.parametrize("stdout", ["\n".join([OK, BAD]), "junk", "[]", "", L(file="zzz.py", ok=True),
                                    "\n".join([OK, BAD, L(done=True, count=9, truncated=False)]), L(weird=1), L(file="a.py")])
def test_unusable_output_is_error(tmp_path, stdout):
    res = run(tmp_path, sb(stdout))
    assert res.status is CheckStatus.ERROR and not res.findings


def test_per_file_failure_and_cap_are_incomplete(tmp_path):
    res = run(tmp_path, sb("\n".join([OK, L(file="b.py", failed="RecursionError"), DONE2])))
    assert res.status is CheckStatus.INCOMPLETE and "b.py" in res.errors[0]
    assert run(tmp_path, sb("\n".join([OK, L(done=True, count=1, truncated=True)])), files=["a.py"]).status is CheckStatus.INCOMPLETE


def test_failure_modes(tmp_path):
    assert run(tmp_path, sb(timed_out=True, exit_code=137)).status is CheckStatus.TIMEOUT
    for kw in ({"oom_killed": True}, {"output_truncated": True}, {"exit_code": 1}):
        assert run(tmp_path, sb("\n".join([OK, BAD, DONE2]), **kw)).status is CheckStatus.ERROR

    def boom(*a, **k):
        raise SandboxError("nope")
    assert run(tmp_path, boom).status is CheckStatus.ERROR


def test_unavailable_and_not_applicable(tmp_path):
    def no(i):
        raise SandboxError("no docker")
    s = sb()
    assert run(tmp_path, s, available=no).status is CheckStatus.UNAVAILABLE and not s.calls
    assert run(tmp_path, s, files=["x.js", "venv/a.py"]).status is CheckStatus.NOT_APPLICABLE and not s.calls


def test_fixed_driver_in_python_image_no_project_data_in_argv(tmp_path):
    s = sb("\n".join([OK, BAD, DONE2]))
    run(tmp_path, s, files=["a.py", "b.py", "evil'; import os.py"])
    c = s.calls[0]
    assert c["image"] == PYTHON.image and c["command"] == ["python", "-I", "-c", pysyntax.DRIVER] and "evil" not in c["command"][3]
    assert "import_module" not in pysyntax.DRIVER and "exec(" not in pysyntax.DRIVER and "eval(" not in pysyntax.DRIVER


@pytest.mark.docker
def test_real_sandbox_python_syntax(tmp_path, ws_root):
    from saferun.engine import ValidationOptions, validate_project
    proj = tmp_path / "p"
    (proj / "pkg").mkdir(parents=True)
    (proj / "ok.py").write_text("print('hi')\n")
    (proj / "pkg" / "broken.py").write_text("x = 1\ndef f(:\n  pass\n")
    (proj / "venv").mkdir()
    (proj / "venv" / "skipped.py").write_text("def (:")
    (proj / "sideeffect.py").write_text("open('/tmp/executed', 'w').write('x')\nraise SystemExit(9)\n")
    rep = validate_project(proj, ValidationOptions(python_analysis=False, dependency_scan=False, javascript_check=False))
    (c,) = [c for c in rep.checks if c.name == pysyntax.NAME]
    assert c.status is CheckStatus.FINDINGS, c.detail
    assert [(f.path, f.line) for f in c.findings] == [("pkg/broken.py", 2)] and "3 Python file(s)" in c.notes[0]
    assert list(ws_root.iterdir()) == []


def test_tool_string_is_the_unpinned_label_in_every_path(tmp_path):
    """Compatibility: report `tool` values must stay `compile() (python:3.12-slim[, sandboxed])`, not carry the digest."""
    def no(i):
        raise SandboxError("no docker")
    assert run(tmp_path, sb(), available=no).tool == "compile() (python:3.12-slim)"
    assert run(tmp_path, sb("\n".join([OK, BAD, DONE2]))).tool == "compile() (python:3.12-slim, sandboxed)"
    assert run(tmp_path, sb("junk")).tool == "compile() (python:3.12-slim, sandboxed)"
    assert PYTHON.label == "python:3.12-slim" and "@" in PYTHON.image   # the image actually used is still the pinned one
