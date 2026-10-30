"""Controlled probes of each sandbox restriction. Each test runs hostile-ish code
inside the container and asserts the restriction held (or fails loudly)."""
import json
from pathlib import Path

import pytest

from saferun.sandbox import SandboxError, SandboxLimits, run_sandboxed
from saferun.sandbox import docker as dk
from saferun.sandbox.runner import build_create_args

pytestmark = pytest.mark.docker

STATUS = """
import os
st = dict(l.split(':\\t') for l in open('/proc/self/status').read().splitlines() if ':\\t' in l)
"""


def test_runs_code_and_captures_output(probe):
    r = probe("print('hello'); import sys; sys.stderr.write('err'); sys.exit(3)")
    assert (r.exit_code, r.stdout.strip(), r.stderr.strip()) == (3, "hello", "err")
    assert not r.timed_out and not r.oom_killed


def test_runs_unprivileged_with_no_capabilities(probe):
    r = probe(STATUS + "print(os.getuid(), os.getgid(), st['CapEff'].strip(), st['CapBnd'].strip(), st['NoNewPrivs'].strip())")
    assert r.stdout.split() == ["65534", "65534", "0000000000000000", "0000000000000000", "1"]


def test_seccomp_filter_is_active_in_container(probe):
    """Seccomp: 2 == filter mode. Evidence from the kernel's view of the sandboxed process."""
    r = probe(STATUS + "print(st['Seccomp'].strip(), st.get('Seccomp_filters', '?').strip())")
    mode, filters = r.stdout.split()
    assert mode == "2"
    assert filters == "?" or int(filters) >= 1


def test_apparmor_profile_is_applied_when_host_has_apparmor(probe):
    sec = dk.docker("info", "--format", "{{json .SecurityOptions}}").stdout
    if not any("name=apparmor" in o for o in json.loads(sec)):
        pytest.skip("host Docker daemon has no AppArmor support: not verifiable here")
    r = probe("print(open('/proc/self/attr/current').read().strip())")
    assert r.stdout.strip() == "docker-default (enforce)"


def test_swap_is_disabled_and_memory_limit_in_cgroup(probe):
    r = probe("""
        for f in ('memory.max', 'memory.swap.max', 'pids.max'):
            print(f, open('/sys/fs/cgroup/' + f).read().strip())
    """, memory_mb=128, pids=20)
    assert r.stdout.split("\n")[:3] == [
        f"memory.max {128 * 1024 * 1024}", "memory.swap.max 0", "pids.max 20"]


def test_hardening_as_applied_by_docker(probe):
    hc = probe("pass").hardening
    assert hc["Privileged"] is False
    assert hc["NetworkMode"] == "none"
    assert hc["ReadonlyRootfs"] is True
    assert hc["CapDrop"] == ["ALL"] and not hc.get("CapAdd")
    assert "no-new-privileges" in " ".join(hc["SecurityOpt"])
    assert not any("unconfined" in o for o in hc["SecurityOpt"])
    assert hc["Memory"] == hc["MemorySwap"] == 256 * 1024 * 1024
    assert hc["NanoCpus"] == 1_000_000_000
    assert hc["PidsLimit"] == 64
    assert not hc["Binds"] or all(b.endswith(":ro") for b in hc["Binds"])
    assert hc["Mounts"][0]["ReadOnly"] is True


def test_no_network_interfaces_and_connect_fails(probe):
    r = probe("""
        import socket
        ifaces = [l.split(':')[0].strip() for l in open('/proc/net/dev').read().splitlines()[2:]]
        print(ifaces)
        s = socket.socket(); s.settimeout(3)
        try:
            s.connect(('1.1.1.1', 53)); print('CONNECTED')
        except OSError as e:
            print('blocked', type(e).__name__)
        try:
            print(socket.gethostbyname('example.com'))
        except OSError:
            print('dns-blocked')
    """)
    assert "['lo']" in r.stdout and "blocked" in r.stdout and "dns-blocked" in r.stdout
    assert "CONNECTED" not in r.stdout


def test_filesystem_read_only_except_tmp(probe):
    r = probe("""
        import os
        def can_write(p):
            try:
                open(p, 'w').write('x'); return True
            except OSError:
                return False
        print('workspace', can_write('/workspace/pwn'))
        print('root', can_write('/pwn'))
        print('etc', can_write('/etc/pwn'))
        print('tmp', can_write('/tmp/ok'))
        try:
            os.remove('/workspace/main.py'); print('rm', True)
        except OSError:
            print('rm', False)
    """)
    assert r.stdout.split("\n")[:5] == [
        "workspace False", "root False", "etc False", "tmp True", "rm False"]


def test_tmp_is_noexec_and_size_limited(probe):
    r = probe("""
        import os, subprocess
        open('/tmp/x.sh', 'w').write('#!/bin/sh\\necho ran\\n'); os.chmod('/tmp/x.sh', 0o755)
        try:
            subprocess.run(['/tmp/x.sh'], check=True); print('EXEC')
        except (OSError, subprocess.CalledProcessError):
            print('noexec')
        try:
            with open('/tmp/big', 'wb') as f:
                for _ in range(64): f.write(b'0' * 1024 * 1024)
            print('FILLED')
        except OSError as e:
            print('full', e.errno)
    """, tmpfs_mb=8)
    assert "noexec" in r.stdout and "full 28" in r.stdout


def test_no_host_secrets_or_docker_socket(probe, monkeypatch):
    monkeypatch.setenv("SAFERUN_TEST_SECRET", "hunter2")
    home = str(Path.home())
    r = probe(f"""
        import os
        print('secret', 'SAFERUN_TEST_SECRET' in os.environ, any('hunter2' in v for v in os.environ.values()))
        print('sock', os.path.exists('/var/run/docker.sock'), os.path.exists('/run/docker.sock'))
        print('home', os.path.exists({home!r}), os.path.exists('/root/.docker'))
        print('mounts', [l.split()[1] for l in open('/proc/mounts') if {home!r} in l or '.sock' in l or l.split()[1] == '/run'])
        print('init', [l.split()[1] for l in open('/proc/mounts') if 'docker-init' in l])
    """)
    assert r.stdout.split("\n")[:5] == [
        "secret False False", "sock False False", "home False False", "mounts []",
        "init ['/usr/sbin/docker-init']"]  # Docker's own --init shim is the only extra mount


def test_memory_limit_oom_kills_allocator(probe):
    r = probe("b = bytearray(1024 * 1024 * 1024); print('ALLOCATED')", memory_mb=64)
    assert "ALLOCATED" not in r.stdout
    assert r.oom_killed is True and r.exit_code == 137 and not r.timed_out


def test_pid_limit_is_exact(probe):
    """The container may hold exactly `pids` tasks: forks succeed until that, then EAGAIN."""
    r = probe("""
        import os, time
        base = len([d for d in os.listdir('/proc') if d.isdigit()])  # init + timeout + python
        n = 0
        try:
            while True:
                if os.fork() == 0:
                    time.sleep(10); os._exit(0)
                n += 1
        except OSError:
            print('limited', base, n)
    """, pids=16, timeout_s=20)
    _, base, n = r.stdout.split()
    assert int(n) == 16 - int(base) > 0


def test_cpu_quota_set_in_cgroup(probe):
    r = probe("print(open('/sys/fs/cgroup/cpu.max').read().strip())", cpus=0.5)
    assert r.stdout.split() == ["50000", "100000"]


def test_host_timeout_kills_container_and_cleans_up(probe):
    r = probe("import time; time.sleep(60)", timeout_s=2)
    assert r.timed_out and r.duration_s < 15
    assert dk.inspect(r.container_name) == {}


def test_output_is_capped_and_cannot_block(probe):
    r = probe("""
        import sys
        for _ in range(200): sys.stdout.write('A' * 10000 + '\\n')
        print('done')
    """, max_output_bytes=4096)
    assert r.output_truncated and len(r.stdout) <= 4096 and r.exit_code == 0


def test_file_size_ulimit_is_the_cause(probe):
    r = probe("""
        import resource
        print('rlimit', resource.getrlimit(resource.RLIMIT_FSIZE)[0])
        with open('/tmp/small', 'wb') as f:
            f.write(b'0' * 512 * 1024)       # under the limit: proves /tmp itself is fine
        print('small ok')
        try:
            with open('/tmp/f', 'wb') as f:
                f.write(b'0' * 4 * 1024 * 1024); f.flush()
            print('WROTE')
        except OSError as e:
            print('efbig', e.errno)           # 27 == EFBIG (Python ignores SIGXFSZ)
    """, fsize_mb=1)
    assert r.stdout.split("\n")[:4] == ["rlimit 1048576", "small ok", "efbig 27", ""]
    assert r.exit_code == 0


def test_no_labeled_containers_left_after_runs(probe):
    before = set(dk.leftover_containers())
    probe("print(1)")
    probe("import time; time.sleep(30)", timeout_s=1)
    assert set(dk.leftover_containers()) == before


def test_missing_image_is_error_not_pull(tmp_path):
    (tmp_path / "a.py").write_text("")
    with pytest.raises(SandboxError, match="not present locally"):
        run_sandboxed(tmp_path, ["true"], image="saferun-nonexistent:0")


def test_create_args_never_contain_dangerous_flags(tmp_path):
    args = " ".join(build_create_args("n", tmp_path, ["x"], "img", SandboxLimits()))
    for bad in ("--privileged", "docker.sock", "seccomp=unconfined", "--cap-add",
                "--network host", "--pid host", "--net=host"):
        assert bad not in args


def test_command_is_wrapped_in_container_side_timeout(tmp_path):
    a = build_create_args("n", tmp_path, ["python", "x.py"], "img",
                          SandboxLimits(timeout_s=10, container_grace_s=5))
    assert a[a.index("img") + 1:] == ["timeout", "-s", "KILL", "15", "python", "x.py"]


@pytest.mark.parametrize("bad", ["a,b", 'a"b', "a\nb"])
def test_mount_path_with_csv_metacharacters_rejected(tmp_path, bad):
    with pytest.raises(SandboxError, match="unsupported characters"):
        build_create_args("n", tmp_path / bad, ["x"], "img", SandboxLimits())


def test_invalid_limits_rejected():
    for kw in ({"timeout_s": 0}, {"memory_mb": -1}, {"cpus": float("nan")}, {"pids": 0}):
        with pytest.raises(ValueError):
            SandboxLimits(**kw)
