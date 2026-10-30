"""Node.js profile: JavaScript programs run in the SAME hardened sandbox as Python ones.

This verifies that the sandbox can execute a JavaScript file in a separate image under identical
restrictions. It does not cover npm/dependencies, package.json handling or JS analyzers (later phases).
Requires the pinned image to be present locally: `saferun init --only node` (SafeRun never pulls during a scan).
"""
import textwrap

import pytest

from saferun.sandbox import SandboxLimits, run_sandboxed
from saferun.sandbox.attestation import attest
from saferun.sandbox.profiles import NODE, PYTHON, get_profile
from saferun.sandbox import SandboxError

from conftest import require_image

pytestmark = pytest.mark.docker


@pytest.fixture(autouse=True)
def _node_image_present():
    require_image(NODE.image)


@pytest.fixture
def js(tmp_path, ws_root):
    def _run(code: str, **limit_kw):
        proj = tmp_path / "jsproj"; proj.mkdir(exist_ok=True)
        (proj / "main.js").write_text(textwrap.dedent(code))
        return run_sandboxed(proj, [NODE.interpreter, "main.js"], SandboxLimits(**limit_kw), image=NODE.image)
    return _run


def test_profiles_are_registered_and_distinct():
    assert get_profile("node") is NODE and get_profile("python") is PYTHON and NODE.image != PYTHON.image
    with pytest.raises(SandboxError, match="unknown runtime profile"):
        get_profile("ruby")


def test_node_sandbox_passes_the_kernel_view_attestation():
    rep = attest(NODE.image)
    assert rep.ok and rep.image_id.startswith("sha256:")
    unverified = {c.name: c.state for c in rep.controls if c.state != "verified"}
    assert unverified in ({}, {"daemon-apparmor": "unavailable", "kernel-apparmor-profile": "unavailable"})


def test_javascript_runs_and_its_output_is_captured(js):
    r = js("console.log(JSON.stringify({sum: [1,2,3].reduce((a,b)=>a+b), node: process.version.split('.')[0]}));"
           "console.error('warn'); process.exit(4)")
    assert (r.exit_code, r.stderr.strip()) == (4, "warn")
    assert r.stdout.strip() == '{"sum":6,"node":"v22"}'
    assert r.image_id == __import__("saferun.sandbox.docker", fromlist=["x"]).resolve_image(NODE.image)


def test_node_runs_unprivileged_with_a_clean_environment(js, monkeypatch):
    monkeypatch.setenv("SAFERUN_TEST_SECRET", "hunter2")
    r = js("console.log(process.getuid(), process.getgid(), 'SAFERUN_TEST_SECRET' in process.env,"
           " require('fs').existsSync('/var/run/docker.sock'), process.env.HOME)")
    assert r.stdout.split() == ["65534", "65534", "false", "false", "/tmp"]


def test_node_has_no_network(js):
    r = js("""
        const net = require('net'); const dns = require('dns');
        console.log(JSON.stringify(Object.keys(require('os').networkInterfaces())));
        const s = net.connect({host: '1.1.1.1', port: 53, timeout: 3000});
        s.on('connect', () => { console.log('CONNECTED'); s.destroy(); });
        s.on('error', e => { console.log('blocked', e.code);
          dns.lookup('example.com', (err) => console.log(err ? 'dns-blocked' : 'DNS-OK')); });
        s.on('timeout', () => { console.log('blocked timeout'); s.destroy(); });
    """)
    assert "CONNECTED" not in r.stdout and "DNS-OK" not in r.stdout
    assert r.stdout.splitlines()[0] == '["lo"]' and "blocked" in r.stdout


def test_node_filesystem_is_read_only_except_tmp(js):
    r = js("""
        const fs = require('fs');
        const w = p => { try { fs.writeFileSync(p, 'x'); return true; } catch (e) { return e.code; } };
        console.log(w('/workspace/pwn'), w('/pwn'), w('/tmp/ok'));
        try { fs.unlinkSync('/workspace/main.js'); console.log('removed'); } catch (e) { console.log(e.code); }
    """)
    assert r.stdout.split("\n")[:2] == ["EROFS EROFS true", "EROFS"]


def test_node_tmp_is_noexec(js):
    r = js("""
        const fs = require('fs'), cp = require('child_process');
        fs.writeFileSync('/tmp/x.sh', '#!/bin/sh\\necho ran\\n', {mode: 0o755});
        const res = cp.spawnSync('/tmp/x.sh'); console.log(res.error ? res.error.code : 'EXEC:' + res.stdout);
    """)
    assert r.stdout.strip() == "EACCES"


def test_node_memory_limit_oom_kills(js):
    r = js("const b = Buffer.alloc(1024 * 1024 * 1024); b.fill(1); console.log('ALLOCATED');", memory_mb=96)
    assert "ALLOCATED" not in r.stdout and r.oom_killed is True and r.exit_code == 137


def test_node_infinite_loop_is_stopped_by_the_wall_clock_limit(js):
    r = js("for (;;) {}", timeout_s=2)
    assert r.timed_out and r.duration_s < 15


def test_node_output_flood_is_capped(js):
    r = js("for (let i = 0; i < 2000; i++) console.log('A'.repeat(1000));", max_output_bytes=4096)
    assert r.output_truncated and len(r.stdout) <= 4096


def test_node_symlink_and_secret_handling_is_runtime_independent(tmp_path, ws_root):
    proj = tmp_path / "p"; proj.mkdir()
    (proj / "main.js").write_text("console.log(require('fs').readdirSync('.').sort().join(','))")
    (proj / "evil").symlink_to("/etc/passwd")
    (proj / "private.txt").write_text("secret"); (proj / "private.txt").chmod(0o600)
    r = run_sandboxed(proj, ["node", "main.js"], image=NODE.image)
    assert r.stdout.strip() == "main.js"
    assert {s.path for s in r.skipped} == {"evil"} and {w.path for w in r.withheld} == {"private.txt"}
