"""Native Windows behaviour on a REAL NTFS volume. Skipped everywhere else; the Windows CI job runs it (see docs/platforms.md).

Nothing in this file can be run on Linux or macOS. These tests are the evidence (or the absence of it) for each Windows claim in the docs.
"""
import ctypes
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows tests")

if sys.platform == "win32":
    from saferun import hostos
    from saferun.engine.tools import build_env, run_tool
    from saferun.hostos import _win, acl
    from saferun.hostos.winfs import WinOps
    from saferun.sandbox import analyzer as sa
    from saferun.sandbox.config import SandboxError, SensitivePolicy, WorkspaceChangedError, WorkspaceLimits
    from saferun.sandbox.copy_windows import copy_tree
    from saferun.sandbox.reaper import reap_orphans
    from saferun.sandbox.workspace import WS_PREFIX, create_workspace


def sh(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check)


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"
    (p / "pkg").mkdir(parents=True)
    (p / "a.py").write_text("print('a')\n")
    (p / "pkg" / "b.py").write_text("x = 1\n")
    return p


@pytest.fixture
def ws_root(tmp_path, monkeypatch):
    import tempfile
    root = tmp_path / "wsroot"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


def reasons(ws):
    return {s.path: s.reason for s in ws.skipped}


def withheld(ws):
    return {w.path: w.reason for w in ws.withheld}


# ---------------------------------------------------------------- workspace copy: the basics and the reparse-point rules
def test_workspace_copy_accounts_for_every_entry_and_cleans_up(proj, ws_root):
    ws = create_workspace(proj)
    try:
        assert (ws.project / "pkg" / "b.py").read_text() == "x = 1\n"
        assert ws.entries_scanned == ws.copied_files + ws.copied_dirs + len(ws.skipped) + len(ws.withheld) == 3
        assert hostos.private_path_problem(ws.root, directory=True) is None   # owner-only ACL
    finally:
        ws.cleanup()
    assert not ws.root.exists()


def test_file_content_is_copied_byte_for_byte_without_newline_translation(proj, ws_root):
    data = bytes(range(256)) * 50 + b"\r\n\n\r"
    (proj / "bin.dat").write_bytes(data)
    ws = create_workspace(proj)
    try:
        assert (ws.project / "bin.dat").read_bytes() == data
    finally:
        ws.cleanup()


def test_junction_is_skipped_as_a_reparse_point_and_its_target_never_read(proj, ws_root, tmp_path):
    target = tmp_path / "outside"
    target.mkdir()
    (target / "secret.txt").write_text("outside the project")
    sh("cmd", "/c", "mklink", "/J", str(proj / "jn"), str(target))
    ws = create_workspace(proj)
    try:
        assert reasons(ws) == {"jn": "reparse-point"}
        assert not (ws.project / "jn").exists() and "outside the project" not in "".join(
            p.read_text() for p in ws.project.rglob("*") if p.is_file())
    finally:
        ws.cleanup()


def test_symlinks_are_skipped_and_never_followed(proj, ws_root, tmp_path):
    (tmp_path / "secret.txt").write_text("outside the project")
    try:
        os.symlink(tmp_path / "secret.txt", proj / "flink")
        os.symlink(tmp_path, proj / "dlink", target_is_directory=True)
    except OSError as e:
        pytest.skip(f"symlinks need Developer Mode or elevation: {e}")
    ws = create_workspace(proj)
    try:
        assert reasons(ws) == {"flink": "symlink", "dlink": "symlink"}
    finally:
        ws.cleanup()


def test_hardlink_with_a_name_outside_the_tree_is_skipped(proj, ws_root, tmp_path):
    (tmp_path / "outside.txt").write_text("shared")
    os.link(tmp_path / "outside.txt", proj / "linked")
    os.link(proj / "a.py", proj / "pkg" / "a_again.py")   # all names inside the tree: copied
    ws = create_workspace(proj)
    try:
        assert reasons(ws) == {"linked": "hardlink-external"} and (ws.project / "pkg" / "a_again.py").exists()
    finally:
        ws.cleanup()


def test_alternate_data_streams_are_reported_but_zone_identifier_is_not_a_reason_to_skip(proj, ws_root):
    with open(str(proj / "a.py") + ":payload", "w") as f:
        f.write("hidden")
    with open(str(proj / "pkg" / "b.py") + ":Zone.Identifier", "w") as f:
        f.write("[ZoneTransfer]\nZoneId=3\n")
    ws = create_workspace(proj)
    try:
        assert reasons(ws) == {"a.py": "alternate-data-stream"}
        assert (ws.project / "pkg" / "b.py").read_text() == "x = 1\n"
        assert not os.path.exists(str(ws.project / "pkg" / "b.py") + ":Zone.Identifier")   # never carried into the copy
    finally:
        ws.cleanup()


def test_reserved_device_names_and_long_paths_are_handled_and_cleaned_up(proj, ws_root):
    d = proj
    for i in range(20):
        d = d / ("long_directory_name_%02d" % i)
    os.makedirs(hostos.long_path(d))
    with open(hostos.long_path(d / "deep.py"), "w") as f:
        f.write("pass\n")
    with open(hostos.long_path(proj / "CON"), "w") as f:      # only creatable through the extended-length form
        f.write("odd name\n")
    ws = create_workspace(proj, WorkspaceLimits(max_depth=32))
    try:
        assert ws.copied_files >= 3
    finally:
        ws.cleanup()
    assert not ws.root.exists()


def test_read_only_files_in_the_workspace_do_not_block_cleanup(proj, ws_root):
    ws = create_workspace(proj)
    victim = ws.project / "a.py"
    sh("attrib", "+R", str(victim))
    ws.cleanup()
    assert not ws.root.exists()


# ---------------------------------------------------------------- private-file withholding (ACLs)
def me():
    return os.environ["USERNAME"]


def acl_debug(*paths):
    """What the evaluator was looking at, shown with a failed ACL assertion (the first Windows runs have no other way to see it)."""
    out = [f"whoami /groups:\n{sh('whoami', '/groups', check=False).stdout}"]
    out += [f"icacls {p}:\n{sh('icacls', str(p), check=False).stdout}" for p in paths]
    return "\n".join(out)


def narrow_to_me(path, rights):
    """Leave only the current user on `path`. On the CI runner the project directory grants SYSTEM, Administrators and OWNER RIGHTS full
    control, and `/inheritance:r` leaves such entries on the file (seen in the first diagnostic run), so a "narrowed" file was in fact
    as readable as its parent. Remove those principals explicitly: only then is the entry narrower than the project root."""
    sh("icacls", str(path), "/inheritance:r", "/grant:r", f"{me()}:{rights}")
    sh("icacls", str(path), "/remove", "*S-1-5-18", "*S-1-5-32-544", "*S-1-3-4")


def test_acl_narrowed_file_is_withheld_and_inherited_file_is_not(proj, ws_root):
    (proj / "id_key").write_text("harmless text")
    narrow_to_me(proj / "id_key", "R")
    ws = create_workspace(proj)
    try:
        assert withheld(ws) == {"id_key": "private-mode"}, acl_debug(proj, proj / "id_key")
        assert (ws.project / "a.py").exists() and not (ws.project / "id_key").exists()
    finally:
        ws.cleanup()


def test_an_entry_as_readable_as_its_parent_is_not_withheld(proj, ws_root):
    (proj / "id_key").write_text("harmless text")
    sh("icacls", str(proj / "id_key"), "/grant", f"{me()}:R")   # adds to the inherited access; narrows nothing
    ws = create_workspace(proj)
    try:
        assert withheld(ws) == {} and (ws.project / "id_key").exists(), acl_debug(proj, proj / "id_key")
    finally:
        ws.cleanup()


def test_explicit_deny_makes_a_file_private(proj, ws_root):
    sh("icacls", str(proj / "a.py"), "/deny", f"{me()}:(RD)")   # read data only: the file can still be examined, so it can be classified
    try:
        ws = create_workspace(proj)
    finally:
        sh("icacls", str(proj / "a.py"), "/remove:d", me(), check=False)
    try:
        assert withheld(ws) == {"a.py": "private-mode"}, f"{reasons(ws)}\n{acl_debug(proj, proj / 'a.py')}"
        assert not (ws.project / "a.py").exists()
    finally:
        ws.cleanup()


def test_a_file_that_cannot_even_be_examined_is_never_copied(proj, ws_root):
    sh("icacls", str(proj / "a.py"), "/deny", f"{me()}:R")   # generic read includes READ_CONTROL and the attributes: not even stat() works
    try:
        ws = create_workspace(proj)
    finally:
        sh("icacls", str(proj / "a.py"), "/remove:d", me(), check=False)
    try:
        assert not (ws.project / "a.py").exists()
        assert "a.py" in withheld(ws) or reasons(ws).get("a.py") == "unreadable", f"{withheld(ws)} {reasons(ws)}"   # reported, fail closed
    finally:
        ws.cleanup()


def test_acl_narrowed_directory_is_withheld_and_never_entered(proj, ws_root):
    narrow_to_me(proj / "pkg", "(OI)(CI)F")
    ws = create_workspace(proj)
    try:
        assert withheld(ws) == {"pkg": "private-mode"} and not (ws.project / "pkg").exists(), acl_debug(proj, proj / "pkg")
    finally:
        ws.cleanup()


def test_allow_paths_overrides_private_withholding(proj, ws_root):
    (proj / "id_key").write_text("harmless text")
    narrow_to_me(proj / "id_key", "R")
    ws = create_workspace(proj, policy=SensitivePolicy(allow_paths=frozenset({"id_key"})))
    try:
        assert (ws.project / "id_key").exists() and not ws.withheld
    finally:
        ws.cleanup()


def test_credential_content_is_withheld_regardless_of_the_acl(proj, ws_root):
    (proj / "creds").write_text("AKIA" + "ABCDEFGHIJKLMNOP")
    ws = create_workspace(proj)
    try:
        assert withheld(ws) == {"creds": "token:aws-access-key"}
    finally:
        ws.cleanup()


def test_real_descriptor_parses_and_the_caller_token_has_its_user(proj):
    h = _win.open_handle(str(proj / "a.py"), _win.READ_CONTROL, _win.SHARE_READ | _win.SHARE_WRITE | _win.SHARE_DELETE)
    try:
        desc = acl.parse_descriptor(_win.security_descriptor(h))
    finally:
        _win.close(h)
    token, user, owner = _win.current_token()
    assert desc.dacl is not None and user in token.sids and acl.EVERYONE in token.sids and owner in (user, acl.ADMINISTRATORS)
    assert acl.can(desc.dacl, token, acl.READ_FILE)


# ---------------------------------------------------------------- what the share modes really prevent (evidence for the docs)
def test_an_open_directory_cannot_be_renamed_or_deleted_and_neither_can_its_ancestors(proj):
    ops = WinOps()
    root = ops.open_root(str(proj))
    pkg = ops.open_dir(root, "pkg")
    try:
        with pytest.raises(OSError):
            os.rename(proj / "pkg", proj / "pkg2")
        with pytest.raises(OSError):
            os.rename(proj, proj.with_name("proj2"))
        with pytest.raises(OSError):
            os.rmdir(proj / "pkg")
    finally:
        ops.close(pkg)
        ops.close(root)
    os.rename(proj / "pkg", proj / "pkg2")   # released


def test_a_file_being_read_cannot_be_written_or_deleted(proj):
    ops = WinOps()
    root = ops.open_root(str(proj))
    f = ops.open_file(root, "a.py")
    try:
        with pytest.raises(OSError):
            open(proj / "a.py", "w").close()
        with pytest.raises(OSError):
            os.unlink(proj / "a.py")
    finally:
        ops.close(f)
        ops.close(root)
    (proj / "a.py").write_text("ok")


def test_change_time_and_identity_move_when_a_file_is_replaced_or_modified(proj):
    ops = WinOps()
    root = ops.open_root(str(proj))
    held = True
    try:
        before = ops.probe(root, "a.py", False)
        (proj / "a.py").write_text("print('changed')\n")
        assert ops.probe(root, "a.py", False).sig != before.sig
        before = ops.probe(root, "a.py", False)
        (proj / "new").write_text("x")
        # While SafeRun holds the directory handle (share mode READ only), replacing an entry of it is refused: the first Windows CI run saw
        # WinError 32 here for 3 s. That is the protection the copy engine relies on, so it is asserted, not retried away.
        with pytest.raises(PermissionError):
            os.replace(proj / "new", proj / "a.py")
        ops.close(root)
        held = False
        os.replace(proj / "new", proj / "a.py")      # with the handle released the very same replace works: the handle was the cause
        root = ops.open_root(str(proj))
        held = True
        after = ops.probe(root, "a.py", False)
        assert after.sig != before.sig and after.ident != before.ident
    finally:
        if held:
            ops.close(root)


def hooked(hook):
    """WinOps that runs `hook(name)` right before each file is opened (where a race would strike)."""
    class Hooked(WinOps):
        def open_file(self, d, name):
            hook(name)
            return super().open_file(d, name)
    return Hooked()


@pytest.mark.parametrize("attack", ["modify", "replace", "symlink", "junction-dir", "add", "remove"])
def test_changes_between_the_passes_are_detected_on_ntfs(proj, tmp_path, attack):
    dest = tmp_path / "dest"
    dest.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("TOPSECRET")
    done = []

    def hook(name):
        if name != "a.py" or done:
            return
        done.append(1)
        p = proj / "a.py"
        if attack == "modify":
            p.write_text("print('changed and longer')\n")
        elif attack == "replace":
            (proj / "n").write_text("x"); os.replace(proj / "n", p)
        elif attack == "symlink":
            p.unlink()
            try:
                os.symlink(outside, p)
            except OSError as e:
                pytest.skip(f"symlinks need Developer Mode or elevation: {e}")
        elif attack == "junction-dir":
            p.unlink()
            sh("cmd", "/c", "mklink", "/J", str(p), str(outside.parent))
        elif attack == "add":
            (proj / "new.py").write_text("x")
        else:
            (proj / "pkg" / "b.py").unlink()

    with pytest.raises(WorkspaceChangedError):
        copy_tree(str(proj), str(dest), WorkspaceLimits(), None, ops=hooked(hook))
    assert not any("TOPSECRET" in p.read_text() for p in dest.rglob("*") if p.is_file())


def test_remote_or_unc_roots_are_refused(tmp_path):
    with pytest.raises(OSError):
        WinOps().open_root(r"\\localhost\c$\Windows")


def test_project_root_that_is_a_junction_is_resolved_not_followed_blindly(proj, ws_root, tmp_path):
    link = tmp_path / "link_to_proj"
    sh("cmd", "/c", "mklink", "/J", str(link), str(proj))
    ws = create_workspace(link)    # create_workspace resolves the path the user typed, then opens the real directory
    try:
        assert (ws.project / "a.py").exists()
    finally:
        ws.cleanup()


# ---------------------------------------------------------------- process trees
def alive(pid: int) -> bool:
    h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return False
    try:
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
        return code.value == 259   # STILL_ACTIVE
    finally:
        ctypes.windll.kernel32.CloseHandle(h)


TREE = ("import subprocess, sys, time\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        "open(sys.argv[1], 'w').write(str(p.pid))\n"
        "time.sleep(120)\n")


def wait_for(path, secs=20):
    end = time.time() + secs
    while time.time() < end:
        if path.exists() and path.read_text().strip():
            return int(path.read_text())
        time.sleep(0.05)
    raise AssertionError("grandchild never started")


def test_timeout_kills_the_whole_process_tree(tmp_path):
    pidfile = tmp_path / "pid"
    script = tmp_path / "tree.py"
    script.write_text(TREE)
    res = run_tool([sys.executable, str(script), str(pidfile)], cwd=tmp_path, env=build_env(tmp_path), timeout_s=3)
    gc = wait_for(pidfile)
    assert res.timed_out and res.exit_code is None
    time.sleep(0.5)
    assert not alive(gc)


def test_cancel_interrupts_then_kills_the_whole_tree(tmp_path):
    pidfile = tmp_path / "pid"
    script = tmp_path / "tree.py"
    script.write_text(TREE)
    cancel = threading.Event()
    threading.Timer(2.5, cancel.set).start()
    res = run_tool([sys.executable, str(script), str(pidfile)], cwd=tmp_path, env=build_env(tmp_path), timeout_s=60,
                   cancel=cancel, cancel_grace_s=2)
    gc = wait_for(pidfile)
    assert res.cancelled and res.exit_code is None
    time.sleep(0.5)
    assert not alive(gc)


def test_children_left_behind_by_a_finished_tool_are_ended_with_its_job(tmp_path):
    pidfile = tmp_path / "pid"
    script = tmp_path / "orphan.py"
    script.write_text("import subprocess, sys\n"
                      "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
                      "open(sys.argv[1], 'w').write(str(p.pid))\n")
    res = run_tool([sys.executable, str(script), str(pidfile)], cwd=tmp_path, env=build_env(tmp_path), timeout_s=30)
    gc = wait_for(pidfile)
    assert res.exit_code == 0
    time.sleep(0.5)
    assert not alive(gc)


def test_a_normal_tool_run_returns_its_output(tmp_path):
    res = run_tool([sys.executable, "-c", "print('hello')"], cwd=tmp_path, env=build_env(tmp_path), timeout_s=30)
    assert (res.exit_code, res.stdout.strip()) == (0, "hello")


def test_tool_environment_has_what_windows_needs_and_no_inherited_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "should-not-leak")
    env = build_env(tmp_path)
    assert "GITHUB_TOKEN" not in env and env["USERPROFILE"] == str(tmp_path) and "SYSTEMROOT" in env


# ---------------------------------------------------------------- liveness lock, reaper, analyzer lock
def test_reaper_leaves_a_live_workspace_and_removes_one_whose_owner_died(proj, ws_root, tmp_path):
    live = create_workspace(proj)
    try:
        assert live.root.name not in reap_orphans(tmp_root=ws_root).workspaces and live.root.exists()
    finally:
        live.cleanup()
    code = ("import os, sys\nfrom pathlib import Path\nfrom saferun.sandbox.workspace import create_workspace\n"
            "ws = create_workspace(Path(sys.argv[1]))\nprint(ws.root, flush=True)\nos._exit(0)\n")
    env = {**os.environ, "TMP": str(ws_root), "TEMP": str(ws_root)}
    out = subprocess.run([sys.executable, "-I", "-c", code, str(proj)], capture_output=True, text=True, env=env,
                         cwd=str(Path(__file__).resolve().parents[1]))
    dead = Path(out.stdout.strip())
    assert dead.exists(), out.stderr
    report = reap_orphans(tmp_root=ws_root)
    assert dead.name in report.workspaces and not dead.exists()


def test_reaper_ignores_foreign_names_and_junctions(ws_root, tmp_path):
    (ws_root / "other-dir").mkdir()
    target = tmp_path / "precious"
    target.mkdir()
    (target / "keep.txt").write_text("keep")
    sh("cmd", "/c", "mklink", "/J", str(ws_root / (WS_PREFIX + "evil")), str(target))
    report = reap_orphans(tmp_root=ws_root)
    assert (ws_root / "other-dir").exists() and (target / "keep.txt").exists() and not report.workspaces


@pytest.fixture
def lock(tmp_path, monkeypatch):
    p = tmp_path / "lockdir" / "analyzer-image-id"
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(p))
    return p


IMAGE_ID = "sha256:" + "ab" * 32


def test_analyzer_lock_roundtrip_is_owner_only(lock):
    assert sa.write_lock(IMAGE_ID) == lock
    assert sa._read_lock() == IMAGE_ID
    assert hostos.private_path_problem(lock, directory=False) is None and hostos.private_path_problem(lock.parent, directory=True) is None


def test_analyzer_lock_readable_by_others_is_not_trusted(lock):
    sa.write_lock(IMAGE_ID)
    sh("icacls", str(lock), "/grant", "Everyone:R")
    with pytest.raises(sa.AnalyzerIntegrityError, match="not trusted"):
        sa._read_lock()


def test_analyzer_lock_directory_open_to_others_is_not_trusted_and_not_written(lock):
    sa.write_lock(IMAGE_ID)
    sh("icacls", str(lock.parent), "/grant", "Users:(OI)(CI)R")
    with pytest.raises(sa.AnalyzerIntegrityError):
        sa._read_lock()
    with pytest.raises(SandboxError, match="not writing"):
        sa.write_lock(IMAGE_ID)


def test_analyzer_lock_through_a_junctioned_directory_is_refused(lock, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "analyzer-image-id").write_text(IMAGE_ID + "\n")
    sh("cmd", "/c", "mklink", "/J", str(lock.parent), str(real))
    with pytest.raises(sa.AnalyzerIntegrityError):
        sa._read_lock()


def test_missing_lock_is_reported_as_not_installed(lock):
    with pytest.raises(sa.AnalyzerUnavailable):
        sa._read_lock()


# ---------------------------------------------------------------- docker endpoint, console, CLI
def test_docker_named_pipe_endpoints(monkeypatch):
    from saferun.sandbox import docker as dk
    monkeypatch.setenv("DOCKER_HOST", "npipe:////./pipe/docker_engine")
    dk.check_local_daemon()
    for bad in ("tcp://127.0.0.1:2375", "npipe:////other-host/pipe/docker_engine", "unix:///var/run/docker.sock"):
        monkeypatch.setenv("DOCKER_HOST", bad)
        with pytest.raises(SandboxError, match="non-local docker endpoint"):
            dk.check_local_daemon()


def test_mount_sources_are_validated_with_real_drive_types(tmp_path):
    assert hostos.mount_source_problem(str(tmp_path)) is None
    assert hostos.mount_source_problem(r"\\server\share\x")
    assert hostos.mount_source_problem("\\\\?\\" + str(tmp_path))


def test_enable_ansi_never_raises_even_without_a_console():
    hostos.enable_ansi()


def test_cli_starts_from_powershell_and_cmd_style_invocations(tmp_path):
    for argv in (["--help"], ["scan", "--help"]):
        r = subprocess.run([sys.executable, "-m", "saferun", *argv], capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[1]))
        assert r.returncode == 0 and "Traceback" not in r.stderr, r.stderr


def test_scan_without_a_usable_environment_fails_cleanly_not_with_a_traceback(proj):
    r = subprocess.run([sys.executable, "-m", "saferun", "scan", str(proj)], capture_output=True, text=True,
                       cwd=str(Path(__file__).resolve().parents[1]), env={**os.environ, "DOCKER_HOST": "tcp://127.0.0.1:1"})
    assert "Traceback" not in r.stderr and r.returncode != 0


def test_data_directory_is_under_localappdata():
    assert hostos.user_data_base() == Path(os.environ["LOCALAPPDATA"])
