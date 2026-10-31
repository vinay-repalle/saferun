"""Run-time hardening: pre-start verification of the applied config, daemon preflight, input
validation, and robustness against unexpected Docker behaviour. Most tests need no Docker."""
import copy
import io
import json
import os
import stat
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from saferun.sandbox import SandboxError, SandboxLimits, run_sandboxed
from saferun.sandbox import docker as dk
from saferun.sandbox import runner
from saferun.sandbox.attestation import PROBE, evaluate
from saferun.sandbox.config import SANDBOX_UID
from saferun.sandbox.controls import MIB, REQUIRED_DAEMON, daemon_controls, verify_applied_config
from saferun.sandbox.runner import build_create_args, validate_command
from saferun.sandbox.workspace import create_workspace

LIM = SandboxLimits()
IMAGE_ID = "sha256:" + "ab" * 32


def golden(lim=LIM) -> dict:
    """`docker inspect` of a correctly hardened, not yet started container (shape taken from Docker 29)."""
    return {
        "Image": IMAGE_ID,
        "Config": {"User": f"{SANDBOX_UID}:{SANDBOX_UID}", "Volumes": None, "Entrypoint": [""], "Labels": {"saferun.sandbox": "1"}},
        "HostConfig": {
            "Privileged": False, "NetworkMode": "none", "ReadonlyRootfs": True, "CapDrop": ["ALL"], "CapAdd": None,
            "SecurityOpt": ["no-new-privileges"], "Memory": lim.memory_mb * MIB, "MemorySwap": lim.memory_mb * MIB,
            "NanoCpus": int(lim.cpus * 1e9), "PidsLimit": lim.pids,
            "Ulimits": [{"Name": "core", "Hard": 0, "Soft": 0},
                        {"Name": "fsize", "Hard": lim.fsize_mb * MIB, "Soft": lim.fsize_mb * MIB},
                        {"Name": "nofile", "Hard": lim.nofile, "Soft": lim.nofile}],
            "Tmpfs": {"/tmp": f"rw,noexec,nosuid,nodev,size={lim.tmpfs_mb}m"}, "ShmSize": lim.shm_mb * MIB,
            "Mounts": [{"Type": "bind", "Source": "/tmp/x", "Target": "/workspace", "ReadOnly": True}],
            "Binds": None, "LogConfig": {"Type": "none", "Config": {}}, "Init": True, "IpcMode": "private",
            "PidMode": "", "UsernsMode": "", "UTSMode": "", "Devices": [], "PortBindings": {},
            "PublishAllPorts": False, "OomKillDisable": False, "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        },
    }


def _violated(info, lim=LIM):
    return {c.name for c in verify_applied_config(info, lim, IMAGE_ID) if c.state != "verified"}


def test_golden_config_is_fully_verified():
    assert _violated(golden()) == set()


def _mut(fn):
    def apply(info):
        info = copy.deepcopy(info); fn(info); return info
    return apply


MUTATIONS = {
    "not-privileged": lambda i: i["HostConfig"].update(Privileged=True),
    "network-none": lambda i: i["HostConfig"].update(NetworkMode="bridge"),
    "rootfs-read-only": lambda i: i["HostConfig"].update(ReadonlyRootfs=False),
    "capabilities-dropped": lambda i: i["HostConfig"].update(CapDrop=None),
    "no-new-privileges": lambda i: i["HostConfig"].update(SecurityOpt=[]),
    "no-unconfined-profile": lambda i: i["HostConfig"].update(SecurityOpt=["no-new-privileges", "seccomp=unconfined"]),
    "entrypoint-reset": lambda i: i["Config"].update(Entrypoint=["docker-entrypoint.sh"]),
    "non-root-user": lambda i: i["Config"].update(User=""),
    "memory-limit": lambda i: i["HostConfig"].update(Memory=0),
    "swap-disabled": lambda i: i["HostConfig"].update(MemorySwap=2 * LIM.memory_mb * MIB),
    "cpu-quota": lambda i: i["HostConfig"].update(NanoCpus=0),
    "pids-limit": lambda i: i["HostConfig"].update(PidsLimit=-1),
    "fd-limit": lambda i: i["HostConfig"].update(Ulimits=[u for u in i["HostConfig"]["Ulimits"] if u["Name"] != "nofile"]),
    "file-size-limit": lambda i: i["HostConfig"].update(Ulimits=[u for u in i["HostConfig"]["Ulimits"] if u["Name"] != "fsize"]),
    "core-dumps-off": lambda i: i["HostConfig"].update(Ulimits=[u for u in i["HostConfig"]["Ulimits"] if u["Name"] != "core"]),
    "tmp-tmpfs": lambda i: i["HostConfig"].update(Tmpfs={"/tmp": "rw,nosuid,nodev,size=64m"}),   # exec allowed
    "shm-limit": lambda i: i["HostConfig"].update(ShmSize=64 * MIB),
    "workspace-mount-read-only": lambda i: i["HostConfig"]["Mounts"][0].update(ReadOnly=False),
    "no-image-volumes": lambda i: i["Config"].update(Volumes={"/data": {}}),
    "no-devices": lambda i: i["HostConfig"].update(Devices=[{"PathOnHost": "/dev/kvm"}]),
    "no-published-ports": lambda i: i["HostConfig"].update(PortBindings={"80/tcp": [{}]}),
    "private-namespaces": lambda i: i["HostConfig"].update(IpcMode="host"),
    "init-process": lambda i: i["HostConfig"].update(Init=False),
    "logging-off": lambda i: i["HostConfig"].update(LogConfig={"Type": "json-file"}),
    "oom-kill-enabled": lambda i: i["HostConfig"].update(OomKillDisable=True),
    "no-restart": lambda i: i["HostConfig"].update(RestartPolicy={"Name": "always"}),
    "created-from-resolved-image": lambda i: i.update(Image="sha256:" + "cd" * 32),
    "saferun-label": lambda i: i["Config"].update(Labels={}),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_every_verified_control_is_actually_checked(name):
    """Each control flips to violated when Docker reports the opposite, so none is a rubber stamp."""
    assert name in _violated(_mut(MUTATIONS[name])(golden()))


def test_extra_mount_is_a_violation():
    info = golden(); info["HostConfig"]["Mounts"].append({"Type": "bind", "Source": "/home", "Target": "/h", "ReadOnly": True})
    assert "workspace-mount-read-only" in _violated(info)
    info = golden(); info["HostConfig"]["Binds"] = ["/var/run/docker.sock:/s"]
    assert "workspace-mount-read-only" in _violated(info)


def test_garbage_inspect_data_is_a_violation_not_a_crash():
    assert _violated({}) and _violated({"HostConfig": None, "Config": None})


# ---- daemon preflight ----------------------------------------------------------

def _daemon(**kw):
    base = {"OSType": "linux", "SecurityOptions": ["name=apparmor,profile=default", "name=seccomp,profile=builtin"],
            "MemoryLimit": True, "SwapLimit": True, "PidsLimit": True, "CpuCfsQuota": True}
    base.update(kw)
    return base


def _states(info):
    return {c.name: c.state for c in daemon_controls(info)}


def test_daemon_controls_report_each_state_honestly():
    assert set(_states(_daemon()).values()) == {"verified"}
    assert _states(_daemon(SecurityOptions=["name=seccomp,profile=unconfined"]))["daemon-seccomp"] == "violated"
    assert _states(_daemon(SecurityOptions=[]))["daemon-seccomp"] == "unavailable"
    assert _states(_daemon(SecurityOptions=["name=seccomp,profile=builtin"]))["daemon-apparmor"] == "unavailable"
    assert _states(_daemon(SwapLimit=False))["daemon-swap-limit"] == "unavailable"
    assert _states({**_daemon(), "PidsLimit": None})["daemon-pids-limit"] == "unverified"


@pytest.fixture
def fake_daemon(monkeypatch):
    def install(info):
        monkeypatch.setattr(dk, "check_local_daemon", lambda: None)
        monkeypatch.setattr(dk, "daemon_info", lambda: info)
        monkeypatch.setattr(dk, "resolve_image", lambda image: IMAGE_ID)
    return install


@pytest.mark.parametrize("bad", [
    {"SecurityOptions": ["name=seccomp,profile=unconfined"]}, {"SecurityOptions": []},
    {"SwapLimit": False}, {"MemoryLimit": False}, {"PidsLimit": False}, {"CpuCfsQuota": None},
])
def test_preflight_refuses_when_a_required_control_is_missing(fake_daemon, bad):
    fake_daemon(_daemon(**bad))
    with pytest.raises(SandboxError, match="required control daemon-"):
        dk.preflight("python:3.12-slim")


def test_preflight_degradation_must_be_explicit_and_stays_visible(fake_daemon):
    fake_daemon(_daemon(SwapLimit=False))
    image_id, statuses = dk.preflight("img", frozenset({"daemon-swap-limit"}))
    assert image_id == IMAGE_ID
    assert {c.name: c.state for c in statuses}["daemon-swap-limit"] == "unavailable"


def test_missing_apparmor_is_reported_but_not_fatal(fake_daemon):
    fake_daemon(_daemon(SecurityOptions=["name=seccomp,profile=builtin"]))
    _, statuses = dk.preflight("img")
    assert {c.name: c.state for c in statuses}["daemon-apparmor"] == "unavailable"
    assert "daemon-apparmor" not in REQUIRED_DAEMON


@pytest.mark.parametrize("os_type", ["windows", "", None])
def test_preflight_requires_a_linux_container_daemon(fake_daemon, os_type):
    info = _daemon()
    info["OSType"] = os_type
    fake_daemon(info)
    with pytest.raises(SandboxError, match="needs Linux containers"):
        dk.preflight("python:3.12-slim")


def test_preflight_without_an_ostype_at_all_is_refused(fake_daemon):
    info = _daemon()
    del info["OSType"]
    fake_daemon(info)
    with pytest.raises(SandboxError, match="needs Linux containers"):
        dk.preflight("python:3.12-slim")


@pytest.mark.skipif(sys.platform == "win32", reason="on Windows a local named pipe is the accepted endpoint (tests/test_windows_platform.py)")
@pytest.mark.parametrize("host", ["tcp://127.0.0.1:2375", "ssh://user@example.org", "npipe:////./pipe/docker_engine", ""])
def test_remote_or_odd_docker_endpoints_are_refused(monkeypatch, host):
    monkeypatch.setenv("DOCKER_HOST", host)
    with pytest.raises(SandboxError, match="non-local docker endpoint"):
        dk.check_local_daemon()


@pytest.mark.skipif(sys.platform == "win32", reason="Windows accepts named pipes, not unix sockets")
def test_local_socket_endpoint_is_accepted(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    dk.check_local_daemon()


def test_run_with_remote_docker_host_creates_nothing(tmp_path, ws_root, monkeypatch):
    (tmp_path / "a.py").write_text("")
    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
    with pytest.raises(SandboxError, match="non-local"):
        run_sandboxed(tmp_path, ["true"])
    assert list(ws_root.iterdir()) == []


# ---- input validation ------------------------------------------------------------

@pytest.mark.parametrize("image", ["", "--privileged", "-v", " python", "py thon", "a\nb", "a;b", "x" * 300, None, 5])
def test_bad_image_references_are_rejected(image):
    with pytest.raises(SandboxError, match="invalid image"):
        dk.validate_image(image)


@pytest.mark.parametrize("image", ["python:3.12-slim", "node@sha256:" + "a" * 64, "ghcr.io/org/img:1.2-rc.1", "a"])
def test_ordinary_image_references_are_accepted(image):
    assert dk.validate_image(image) == image


@pytest.mark.parametrize("cmd", [[], "ls", None, [""], ["ls", 1], ["a\0b"], ["x"] * 5000, ["x" * 70000], ("",)])
def test_bad_commands_are_rejected(cmd):
    with pytest.raises(SandboxError, match="command must be"):
        validate_command(cmd)


def test_commands_are_never_shell_interpreted(tmp_path):
    args = build_create_args("n", tmp_path, ["echo", "$(id) ; rm -rf /"], "img", SandboxLimits())
    assert args[-2:] == ["echo", "$(id) ; rm -rf /"] and "sh" not in args and "-c" not in args


def test_create_args_use_pull_never_and_a_bounded_shm(tmp_path):
    a = build_create_args("n", tmp_path, ["x"], "img", SandboxLimits(shm_mb=8))
    assert a[a.index("--pull") + 1] == "never" and a[a.index("--shm-size") + 1] == "8m"


@pytest.mark.parametrize("bad", ["\0evil", 12345])
def test_malformed_project_paths_are_sandbox_errors(ws_root, bad):
    with pytest.raises(SandboxError, match="invalid project path"):
        create_workspace(bad)
    assert list(ws_root.iterdir()) == []


# ---- unexpected docker behaviour ---------------------------------------------------

def _cp(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


@pytest.mark.parametrize("out", ["not json", "[]", "{}", "[1]", "null", ""])
def test_malformed_inspect_output_is_a_sandbox_error(monkeypatch, out):
    monkeypatch.setattr(dk, "docker", lambda *a, **k: _cp(0, out))
    with pytest.raises(SandboxError, match="unexpected `docker inspect` output"):
        dk.inspect("x")


def test_inspect_distinguishes_missing_container_from_daemon_failure(monkeypatch):
    monkeypatch.setattr(dk, "docker", lambda *a, **k: _cp(1, "", "Error: No such object: x"))
    assert dk.inspect("x") == {}
    monkeypatch.setattr(dk, "docker", lambda *a, **k: _cp(1, "", "Cannot connect to the Docker daemon"))
    with pytest.raises(SandboxError, match="docker inspect x failed"):
        dk.inspect("x")


def test_force_remove_does_not_report_success_when_the_daemon_is_down(monkeypatch):
    """Regression: any inspect failure used to count as 'container gone'."""
    monkeypatch.setattr(dk, "docker", lambda *a, **k: _cp(1, "", "Cannot connect to the Docker daemon"))
    with pytest.raises(SandboxError, match="cannot determine whether container"):
        dk.force_remove("x")


def test_unexpected_daemon_info_and_image_id_are_sandbox_errors(monkeypatch):
    monkeypatch.setattr(dk, "docker", lambda *a, **k: _cp(0, "[1]"))
    with pytest.raises(SandboxError, match="not an object"):
        dk.daemon_info()
    monkeypatch.setattr(dk, "docker", lambda *a, **k: _cp(0, "nonsense"))
    with pytest.raises(SandboxError, match="unexpected image id"):
        dk.resolve_image("img")
    monkeypatch.setattr(dk, "docker", lambda *a, **k: _cp(1, "", "boom"))
    with pytest.raises(SandboxError, match="not present locally"):
        dk.resolve_image("img")


def _fake_docker_on_path(tmp_path, monkeypatch, body):
    d = tmp_path / "bin"; d.mkdir()
    f = d / "docker"; f.write_text("#!/bin/sh\n" + body); f.chmod(0o755)
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")  # the fake comes first, real tools stay usable


def test_hung_docker_cli_times_out_instead_of_hanging(tmp_path, monkeypatch):
    _fake_docker_on_path(tmp_path, monkeypatch, "sleep 30\n")
    monkeypatch.setattr(dk, "DEFAULT_TIMEOUT", 1)
    with pytest.raises(SandboxError, match="timed out"):
        dk.docker("version")


def test_missing_docker_binary_is_a_sandbox_error(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(SandboxError, match="docker executable not found"):
        dk.docker("version")


def test_docker_binary_is_resolved_to_an_absolute_path(tmp_path, monkeypatch):
    _fake_docker_on_path(tmp_path, monkeypatch, "echo hi\n")
    assert os.path.isabs(dk.docker_bin()) and dk.docker("x").stdout.strip() == "hi"


def test_non_utf8_docker_output_does_not_crash(tmp_path, monkeypatch):
    _fake_docker_on_path(tmp_path, monkeypatch, "printf '\\377\\376 bad bytes'\n")
    assert "bad bytes" in dk.docker("x").stdout


# ---- attestation evaluation (pure) -------------------------------------------------

GOOD_PROBE = {
    "uid": "65534", "NoNewPrivs": "1", "Seccomp": "2", "CapEff": "0" * 16, "CapBnd": "0" * 16, "CapAmb": "0" * 16,
    "apparmor": "docker-default (enforce)", "memory.max": str(LIM.memory_mb * MIB), "memory.swap.max": "0",
    "pids.max": str(LIM.pids), "cpu.max": "100000 100000", "ifaces": "lo,",
    "write:/workspace/.w": "no", "write:/.w": "no", "write:/tmp/.w": "yes",
}


def _ev(**override):
    kv = {**GOOD_PROBE, **override}
    kv = {k: v for k, v in kv.items() if v is not None}
    return {c.name: c.state for c in evaluate(kv, LIM, daemon_has_apparmor=True)}


def test_attestation_evaluation_verifies_only_with_evidence():
    assert set(_ev().values()) == {"verified"}
    assert _ev(Seccomp="0")["kernel-seccomp-filter"] == "violated"
    assert _ev(NoNewPrivs="0")["kernel-no-new-privileges"] == "violated"
    assert _ev(CapEff="0000000000000400")["kernel-capabilities-empty"] == "violated"
    assert _ev(uid="0")["kernel-non-root"] == "violated"
    assert _ev(ifaces="lo,eth0,")["kernel-network-loopback-only"] == "violated"
    assert _ev(**{"memory.swap.max": "max"})["kernel-swap-disabled"] == "violated"
    assert _ev(**{"write:/.w": "yes"})["fs-root-read-only"] == "violated"
    # missing evidence is "unverified", never "verified"
    assert _ev(Seccomp=None)["kernel-seccomp-filter"] == "unverified"
    assert _ev(**{"memory.swap.max": "none"})["kernel-swap-disabled"] == "unverified"
    assert _ev(CapEff=None)["kernel-capabilities-empty"] == "unverified"


def test_attestation_apparmor_states():
    assert _ev(apparmor="unconfined")["kernel-apparmor-profile"] == "violated"
    assert _ev(apparmor="none")["kernel-apparmor-profile"] == "unavailable"
    states = {c.name: c.state for c in evaluate(GOOD_PROBE | {"apparmor": "unconfined"}, LIM, daemon_has_apparmor=False)}
    assert states["kernel-apparmor-profile"] == "unavailable"


def test_probe_script_is_posix_sh_readonly_reads():
    assert "rm " not in PROBE and "curl" not in PROBE and "$((" not in PROBE


# ---- end to end (Docker) --------------------------------------------------------------

pytestmark_docker = pytest.mark.docker


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"; p.mkdir(); (p / "main.py").write_text("print('ran')")
    return p


def run(proj, **kw):
    return run_sandboxed(proj, ["python", "-I", "main.py"], **kw)


@pytest.mark.docker
def test_result_carries_verified_controls_and_the_exact_image(proj, ws_root):
    r = run(proj)
    states = {c.name: c.state for c in r.controls}
    assert r.stdout.strip() == "ran" and set(states.values()) <= {"verified", "unavailable"}
    assert states["created-from-resolved-image"] == states["rootfs-read-only"] == states["daemon-seccomp"] == "verified"
    from saferun.sandbox.profiles import PYTHON
    ident = dk.docker("image", "inspect", "--format", "{{.Id}}", PYTHON.image).stdout.strip()      # the pinned digest, not a floating tag
    assert r.image_id == ident


@pytest.mark.docker
@pytest.mark.parametrize("weaken,flagged", [
    (lambda a: [x for x in a if x != "--read-only"], "rootfs-read-only"),
    (lambda a: [("bridge" if a[i - 1] == "--network" else x) for i, x in enumerate(a)], "network-none"),
    (lambda a: [x for i, x in enumerate(a) if x != "--cap-drop" and a[i - 1] != "--cap-drop"], "capabilities-dropped"),
    (lambda a: [x for i, x in enumerate(a) if x != "--user" and a[i - 1] != "--user"], "non-root-user"),
    (lambda a: [("1024m" if x == "256m" else x) for x in a], "swap-disabled"),
], ids=["read-only-rootfs", "network", "cap-drop", "user", "memory"])
def test_container_is_never_started_if_docker_applies_a_weaker_config(proj, ws_root, monkeypatch, weaken, flagged):
    """Fail closed: simulate a create that produces a weaker container than policy; the code must not run."""
    real = runner.build_create_args
    monkeypatch.setattr(runner, "build_create_args", lambda *a, **k: weaken(real(*a, **k)))

    def no_start(*a, **k):
        raise AssertionError("container was started despite a policy violation")
    monkeypatch.setattr(runner, "subprocess", SimpleNamespace(
        Popen=no_start, PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL, TimeoutExpired=subprocess.TimeoutExpired))
    before = set(dk.leftover_containers())
    with pytest.raises(SandboxError, match=f"not started.*{flagged}"):
        run(proj)
    assert list(ws_root.iterdir()) == [] and set(dk.leftover_containers()) == before


@pytest.mark.docker
def test_unreadable_final_state_is_an_error_not_a_missing_exit_code(proj, ws_root, monkeypatch):
    real, calls = dk.inspect, []

    def flaky(name):
        calls.append(1)
        return real(name) if len(calls) == 1 else {}  # 1st: verification after create; 2nd: after the run
    monkeypatch.setattr(dk, "inspect", flaky)
    with pytest.raises(SandboxError, match="outcome unknown"):
        run(proj)
    assert list(ws_root.iterdir()) == []


@pytest.mark.docker
def test_container_that_will_not_die_after_kill_is_reported_and_cleaned_up(proj, ws_root, monkeypatch):
    class StuckClient:
        stdout, stderr = io.BytesIO(), io.BytesIO()
        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("docker", timeout)
        def poll(self):
            return None
        def kill(self):
            pass
    monkeypatch.setattr(runner, "subprocess", SimpleNamespace(
        Popen=lambda *a, **k: StuckClient(), PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL,
        TimeoutExpired=subprocess.TimeoutExpired))
    before = set(dk.leftover_containers())
    with pytest.raises(SandboxError, match="did not stop"):
        run(proj, limits=SandboxLimits(timeout_s=1))
    assert list(ws_root.iterdir()) == [] and set(dk.leftover_containers()) == before


@pytest.mark.docker
def test_dev_shm_is_size_limited(tmp_path, ws_root):
    (tmp_path / "main.py").write_text(
        "try:\n    open('/dev/shm/f','wb').write(b'0'*8*1024*1024); print('WROTE')\n"
        "except OSError as e:\n    print('full', e.errno)\n")
    r = run_sandboxed(tmp_path, ["python", "-I", "main.py"], SandboxLimits(shm_mb=4))
    assert r.stdout.strip() == "full 28"


@pytest.mark.docker
def test_concurrent_runs_are_isolated_and_all_cleaned_up(tmp_path, ws_root):
    before, results, errors = set(dk.leftover_containers()), {}, []

    def work(i):
        try:
            d = tmp_path / f"p{i}"; d.mkdir(); (d / "main.py").write_text(f"print({i} * 11)")
            results[i] = run_sandboxed(d, ["python", "-I", "main.py"])
        except BaseException as e:  # noqa: BLE001
            errors.append(e)
    threads = [threading.Thread(target=work, args=(i,)) for i in range(6)]
    [t.start() for t in threads]; [t.join(120) for t in threads]
    assert not errors and {i: r.stdout.strip() for i, r in results.items()} == {i: str(i * 11) for i in range(6)}
    assert len({r.container_name for r in results.values()}) == 6
    assert list(ws_root.iterdir()) == [] and set(dk.leftover_containers()) == before


def test_a_missing_required_image_skips_visibly_or_fails_when_docker_is_required(monkeypatch):
    import conftest
    monkeypatch.setattr(dk, "resolve_image", lambda image: (_ for _ in ()).throw(SandboxError("not present locally")))
    monkeypatch.setattr(conftest, "REQUIRE_DOCKER", False)
    with pytest.raises(pytest.skip.Exception, match="docker pull some:image"):
        conftest.require_image("some:image")
    monkeypatch.setattr(conftest, "REQUIRE_DOCKER", True)
    with pytest.raises(pytest.fail.Exception, match="docker pull some:image"):
        conftest.require_image("some:image")


def test_reaper_reports_a_daemon_failure_instead_of_an_empty_success(tmp_path, monkeypatch):
    from saferun.sandbox import reap_orphans
    monkeypatch.setattr(dk, "docker", lambda *a, **k: _cp(1, "", "Cannot connect to the Docker daemon"))
    rep = reap_orphans(tmp_root=tmp_path)
    assert rep.containers == [] and any("could not list containers" in e for e in rep.errors)


@pytest.mark.docker
def test_python_sandbox_passes_the_kernel_view_attestation(ws_root):
    """What the kernel reports inside a real sandbox (the Node image has the same test)."""
    from saferun.sandbox.attestation import attest
    from saferun.sandbox.profiles import PYTHON
    rep = attest(PYTHON.image)
    states = {c.name: c.state for c in rep.controls}
    assert rep.ok and rep.image_id == dk.resolve_image(PYTHON.image)
    for name in ("kernel-seccomp-filter", "kernel-no-new-privileges", "kernel-capabilities-empty", "kernel-non-root",
                 "kernel-network-loopback-only", "kernel-swap-disabled", "kernel-memory-max", "kernel-pids-max",
                 "kernel-cpu-quota", "fs-workspace-read-only", "fs-root-read-only", "fs-tmp-writable"):
        assert states[name] == "verified", (name, states[name])
    assert list(ws_root.iterdir()) == []
