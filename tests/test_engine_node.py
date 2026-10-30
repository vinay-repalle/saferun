import json
from types import SimpleNamespace

import pytest

from conftest import require_image
from engine_helpers import make_ctx
from saferun.engine import CheckStatus, Severity, node
from saferun.sandbox import SandboxError
from saferun.sandbox.profiles import NODE


def line(**o):
    return json.dumps(o)


def out(*lines):
    return "\n".join(lines) + "\n"


OK = line(file="a.js", status=0, signal=None, failed=False, err="")
BAD = line(file="b.js", status=1, signal=None, failed=False, err="/workspace/b.js:2\nconst y = ;\n          ^\n\nSyntaxError: Unexpected token ';'\n    at x")
DONE2 = line(done=True, count=2, truncated=False)


def sandbox_returning(stdout="", exit_code=0, **kw):
    calls = []

    def fake(project, command, limits=None, image=None, **_):
        calls.append({"project": project, "command": command, "limits": limits, "image": image})
        return SimpleNamespace(exit_code=exit_code, stdout=stdout, stderr=kw.get("stderr", ""), timed_out=kw.get("timed_out", False),
                               oom_killed=kw.get("oom_killed", False), output_truncated=kw.get("output_truncated", False))
    fake.calls = calls
    return fake


def run(tmp_path, sandbox, files=("a.js", "b.js"), available=lambda image: None):
    return node.run_check(make_ctx(tmp_path, files, sandbox=sandbox, image_available=available))


def test_syntax_error_becomes_finding_with_line(tmp_path):
    res = run(tmp_path, sandbox_returning(out(OK, BAD, DONE2)))
    assert res.status is CheckStatus.FINDINGS
    (f,) = res.findings
    assert (f.path, f.line, f.severity, f.category, f.rule_id) == ("b.js", 2, Severity.MEDIUM, "syntax", "javascript.syntax-error")
    assert f.message.startswith("SyntaxError")


def test_clean(tmp_path):
    ok2 = line(file="b.js", status=0, signal=None, failed=False, err="")
    assert run(tmp_path, sandbox_returning(out(OK, ok2, DONE2))).status is CheckStatus.PASSED


@pytest.mark.parametrize("stdout", [
    out(OK, BAD),                                        # cut off: no completion marker
    "garbage\n",
    out(OK, line(file="../../etc/passwd", status=0), line(done=True, count=2, truncated=False)),   # unknown file
    out(OK, BAD, line(done=True, count=5, truncated=False)),                                      # count mismatch
    out(line(surprise=1)),
    out("[1]"),
    "",
])
def test_unusable_driver_output_is_error_never_clean(tmp_path, stdout):
    res = run(tmp_path, sandbox_returning(stdout))
    assert res.status is CheckStatus.ERROR and not res.findings


def test_per_file_failure_is_incomplete(tmp_path):
    killed = line(file="b.js", status=None, signal="SIGTERM", failed=True, err="")
    res = run(tmp_path, sandbox_returning(out(OK, killed, DONE2)))
    assert res.status is CheckStatus.INCOMPLETE and "b.js" in res.errors[0]


def test_file_cap_is_incomplete(tmp_path):
    res = run(tmp_path, sandbox_returning(out(OK, line(done=True, count=1, truncated=True))), files=["a.js"])
    assert res.status is CheckStatus.INCOMPLETE


def test_sandbox_failure_modes(tmp_path):
    assert run(tmp_path, sandbox_returning(timed_out=True, exit_code=137)).status is CheckStatus.TIMEOUT
    for kw in ({"oom_killed": True}, {"output_truncated": True}, {"exit_code": 1, "stderr": "x"}, {"exit_code": 125}):
        assert run(tmp_path, sandbox_returning(out(OK, BAD, DONE2), **kw)).status is CheckStatus.ERROR

    def boom(*a, **k):
        raise SandboxError("verification failed")
    res = run(tmp_path, boom)
    assert res.status is CheckStatus.ERROR and "verification failed" in res.detail


def test_unavailable_docker_or_image(tmp_path):
    def nope(image):
        raise SandboxError("docker daemon down")
    sb = sandbox_returning(out(OK, BAD, DONE2))
    res = run(tmp_path, sb, available=nope)
    assert res.status is CheckStatus.UNAVAILABLE and not sb.calls and not res.findings


def test_not_applicable_without_js(tmp_path):
    sb = sandbox_returning()
    assert run(tmp_path, sb, files=["x.py", "node_modules/p/i.js"]).status is CheckStatus.NOT_APPLICABLE and not sb.calls


def test_runs_in_node_image_with_fixed_driver_and_no_project_data_in_argv(tmp_path):
    sb = sandbox_returning(out(OK, BAD, DONE2))
    run(tmp_path, sb, files=["a.js", "b.js", "evil; rm -rf $HOME.js"])
    c = sb.calls[0]
    assert c["image"] == NODE.image and c["command"] == ["node", "-e", node.DRIVER]
    assert "evil" not in " ".join(c["command"]) and c["limits"].timeout_s == 120.0


def test_driver_never_executes_project_code():
    # only `--check` is ever passed to a spawned node; no require()/import of project files
    assert "'--check'" in node.DRIVER and "require(f" not in node.DRIVER and "import(" not in node.DRIVER


# --- real sandbox (needs Docker + node:22-slim) ---
@pytest.mark.docker
def test_real_sandbox_syntax_check(tmp_path, ws_root):
    require_image(NODE.image)
    from saferun.engine import ValidationOptions, validate_project
    proj = tmp_path / "p"
    (proj / "sub").mkdir(parents=True)
    (proj / "ok.js").write_text("console.log('hi')\n")
    (proj / "esm.mjs").write_text("export const a = 1\n")
    (proj / "sub" / "bad.js").write_text("const x = 1;\nconst y = ;\n")
    (proj / "node_modules").mkdir()
    (proj / "node_modules" / "broken.js").write_text("this is not js")
    (proj / "marker.js").write_text("require('fs').writeFileSync('/tmp/executed', 'x'); process.exit(7);\n")
    rep = validate_project(proj, ValidationOptions(python_analysis=False, python_syntax=False, dependency_scan=False))
    (chk,) = [c for c in rep.checks if c.name == node.NAME]
    assert chk.status is CheckStatus.FINDINGS, chk.detail
    assert [(f.path, f.line) for f in chk.findings] == [("sub/bad.js", 2)]
    assert "4 JavaScript file(s)" in chk.notes[0]          # node_modules not walked
    assert list(ws_root.iterdir()) == []                   # workspaces cleaned up


@pytest.mark.docker
def test_real_sandbox_all_valid_js_passes(tmp_path, ws_root):
    require_image(NODE.image)
    from saferun.engine import ValidationOptions, validate_project
    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "a.js").write_text("module.exports = () => 1\n")
    rep = validate_project(tmp_path / "p", ValidationOptions(python_analysis=False, python_syntax=False, dependency_scan=False))
    assert [c.status for c in rep.checks if c.name == node.NAME] == [CheckStatus.PASSED]


def test_tool_string_is_the_unpinned_label_in_every_path(tmp_path):
    """Compatibility: report `tool` values must stay `node --check (node:22-slim[, sandboxed])`, not carry the digest."""
    def nope(image):
        raise SandboxError("no docker")
    assert run(tmp_path, sandbox_returning(), available=nope).tool == "node --check (node:22-slim)"
    assert run(tmp_path, sandbox_returning(out(line(file="a.js", ok=True), line(file="b.js", ok=True),
                                                 line(done=True, count=2, truncated=False)))).tool == "node --check (node:22-slim, sandboxed)"
    assert run(tmp_path, sandbox_returning("junk")).tool == "node --check (node:22-slim, sandboxed)"
    assert NODE.label == "node:22-slim" and "@" in NODE.image
