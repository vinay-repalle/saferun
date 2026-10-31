import os
import stat
import sys
import time

import pytest

from saferun.engine import tools


def script(tmp_path, body, name="tool", py=None):
    """argv prefix of a test tool: an sh script on POSIX; on Windows (no sh) the Python source `py`, run by this interpreter."""
    if sys.platform == "win32":
        p = tmp_path / (name + ".py")
        p.write_text(py)
        return [sys.executable, str(p)]
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return [str(p)]


def run(argv, tmp_path, **kw):
    kw.setdefault("timeout_s", 10)
    return tools.run_tool(argv, cwd=tmp_path, env=tools.build_env(tmp_path), **kw)


def test_output_and_exit_code(tmp_path):
    r = run(script(tmp_path, "echo out; echo err >&2; exit 3",
                   py="import sys\nprint('out')\nprint('err', file=sys.stderr)\nsys.exit(3)\n"), tmp_path)
    assert (r.exit_code, r.stdout.strip(), r.stderr.strip(), r.timed_out, r.output_truncated) == (3, "out", "err", False, False)


def test_missing_executable_is_unavailable(tmp_path):
    with pytest.raises(tools.ToolUnavailable):
        run([str(tmp_path / "nope")], tmp_path)


def test_timeout_kills_whole_process_group(tmp_path):
    marker = tmp_path / "child_alive"
    child = f"import time, pathlib; time.sleep(30); pathlib.Path({str(marker)!r}).touch()"
    exe = script(tmp_path, f"(sleep 30; touch {marker}) &\nsleep 30\n",
                 py=f"import subprocess, sys, time\nsubprocess.Popen([sys.executable, '-c', {child!r}])\ntime.sleep(30)\n")
    t0 = time.monotonic()
    r = run(exe, tmp_path, timeout_s=0.5)
    assert r.timed_out and r.exit_code is None and time.monotonic() - t0 < 5


def test_output_cap_kills_and_flags(tmp_path):
    r = run(script(tmp_path, "yes aaaaaaaaaaaaaaaa", py="while True:\n    print('a' * 16, flush=True)\n"), tmp_path, max_output=10_000, timeout_s=20)
    assert r.output_truncated and r.exit_code is None and len(r.stdout) <= 10_000 and not r.timed_out


@pytest.mark.parametrize("argv", [[], "tool", ["relative"], [""], ["/bin/true", "a\0b"], ["/bin/true", 5], ["/bin/true"] * 300])
def test_argv_validation(argv, tmp_path):
    with pytest.raises(ValueError):
        run(argv, tmp_path)


def test_no_shell_interpretation(tmp_path):
    out = tmp_path / "pwned"
    r = run([*script(tmp_path, 'echo "$1"', py="import sys\nprint(sys.argv[1])\n"), f"; touch {out} #"], tmp_path)
    assert not out.exists() and "touch" in r.stdout


def test_env_is_minimal_and_has_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s3cret")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy")
    env = tools.build_env(tmp_path)
    assert "AWS_SECRET_ACCESS_KEY" not in env and "HTTPS_PROXY" not in env and env["HOME"] == str(tmp_path)
    assert tools.build_env(tmp_path, network=True)["HTTPS_PROXY"] == "http://proxy"
    r = run(script(tmp_path, "env", py="import os\nfor k, v in os.environ.items():\n    print(k + '=' + v)\n"), tmp_path)
    assert "s3cret" not in r.stdout


def test_invalid_timeout(tmp_path):
    with pytest.raises(ValueError):
        run([sys.executable], tmp_path, timeout_s=0)


def test_find_tool_returns_absolute_or_none(monkeypatch):
    assert os.path.isabs(tools.find_tool("sh"))
    assert tools.find_tool("definitely-not-a-real-tool-xyz") is None
