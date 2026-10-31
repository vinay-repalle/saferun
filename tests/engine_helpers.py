"""Shared helpers for engine tests (canned tool output; no network, no real tools needed)."""
import json
from pathlib import Path

from saferun.engine.context import CheckContext
from saferun.engine.tools import ToolRun


def tool_run(stdout="", exit_code=0, stderr="", timed_out=False, truncated=False):
    return ToolRun(argv=["/x"], exit_code=None if timed_out or truncated else exit_code, stdout=stdout,
                   stderr=stderr, timed_out=timed_out, output_truncated=truncated)


class FakeRunner:
    """Records calls; returns a canned ToolRun (or raises)."""
    def __init__(self, result=None, exc=None):
        self.result, self.exc, self.calls = result, exc, []

    def __call__(self, argv, *, cwd, env=None, timeout_s, max_output, mounts=()):
        self.calls.append({"argv": argv, "cwd": cwd, "env": env, "timeout_s": timeout_s, "mounts": mounts})
        if self.exc:
            raise self.exc
        return self.result


def make_ctx(tmp_path: Path, files, runner=None, **kw) -> CheckContext:
    proj = tmp_path / "project"
    proj.mkdir(exist_ok=True)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for f in files:
        p = proj / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")
    args = dict(project=proj, home=home, files=list(files), analyzer_available=lambda: "sha256:" + "0" * 64)
    if runner is not None:
        args["analyzer"] = runner
    args.update(kw)
    return CheckContext(**args)


SEMGREP_JSON = json.dumps({
    "version": "1.0", "errors": [], "paths": {"scanned": ["app.py", "lib/h.py"]},
    "results": [
        {"check_id": "saferun.python.dynamic-code-execution", "path": "app.py",
         "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 12},
         "extra": {"message": "eval() is dangerous", "severity": "ERROR",
                   "metadata": {"saferun_severity": "high", "cwe": ["CWE-95"]}}},
        {"check_id": "saferun.python.weak-hash", "path": "lib/h.py", "start": {"line": 9}, "end": {"line": 9},
         "extra": {"message": "md5", "severity": "WARNING", "metadata": {"saferun_severity": "medium"}}},
    ]})

OSV_JSON = json.dumps({"results": [{
    "source": {"path": "/IGNORED/package-lock.json", "type": "lockfile"},
    "packages": [{
        "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
        "vulnerabilities": [
            {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "summary": "Command injection in lodash",
             "database_specific": {"severity": "HIGH"},
             "affected": [{"package": {"name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
            {"id": "CVE-2021-23337", "aliases": ["GHSA-35jh-r3h4-6jhm"], "summary": "dup under another id"},
            {"id": "GHSA-xxxx-low", "aliases": [], "summary": "minor", "database_specific": {"severity": "LOW"}},
        ],
        "groups": [{"ids": ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"], "max_severity": "7.2"}],
    }]}]})


def smart_sandbox(node_stdout=None):
    """Fake sandbox: answers the Python syntax driver by listing .py files (all valid), and the Node driver
    with `node_stdout` (default: all valid .js files)."""
    import json as _json

    def fake(project, command, limits=None, image=None, **_):
        from types import SimpleNamespace
        proj = Path(project)
        if command[0] == "python":
            files = sorted(p.relative_to(proj).as_posix() for p in proj.rglob("*") if p.suffix in (".py", ".pyi") and p.is_file())
            lines = [_json.dumps({"file": f, "ok": True}) for f in files] + [_json.dumps({"done": True, "count": len(files), "truncated": False})]
        elif node_stdout is not None:
            lines = [node_stdout]
        else:
            files = sorted(p.relative_to(proj).as_posix() for p in proj.rglob("*") if p.suffix in (".js", ".mjs", ".cjs") and p.is_file())
            lines = [_json.dumps({"file": f, "status": 0, "signal": None, "failed": False, "err": ""}) for f in files]
            lines.append(_json.dumps({"done": True, "count": len(files), "truncated": False}))
        return SimpleNamespace(exit_code=0, stdout="\n".join(lines) + "\n", stderr="", timed_out=False, oom_killed=False, output_truncated=False)
    return fake


def overrides(run=None, node_stdout=None):
    d = {"sandbox": smart_sandbox(node_stdout), "image_available": lambda image: None,
         "analyzer_available": lambda: "sha256:" + "0" * 64}
    if run is not None:
        d["analyzer"] = run
    return d


def sg_json(results=(), scanned=("app.py", "lib/h.py"), errors=()):
    """Semgrep-shaped JSON; `scanned=None` omits paths entirely."""
    d = {"results": list(results), "errors": list(errors)}
    if scanned is not None:
        d["paths"] = {"scanned": list(scanned)}
    return json.dumps(d)


def make_osv_db(root, ecosystems=("PyPI", "npm"), entries=3, age_days=0.0, md5="verified", now=None):
    """A REAL, internally consistent offline OSV database in `root` (zip files with `entries` advisories + manifest).
    Tests must lower osvdb.MIN_ENTRIES (see the `low_osv_floor` fixture) for small databases."""
    import hashlib
    import io
    import json
    import os
    import time
    import zipfile
    from pathlib import Path
    root = Path(root)
    now = time.time() if now is None else now
    manifest = {"schema": 1, "source": "https://example.invalid", "ecosystems": {}}
    for eco in ecosystems:
        d = root / "osv-scalibr" / eco
        d.mkdir(parents=True, exist_ok=True)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for i in range(entries):
                z.writestr(f"GHSA-test-{i}.json", "{}")
        data = buf.getvalue()
        (d / "all.zip").write_bytes(data)
        os.chmod(d / "all.zip", 0o644)
        manifest["ecosystems"][eco] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "entries": entries,
                                       "updated_epoch": int(now - age_days * 86400), "updated_at": "test", "md5": md5}
    for d in (root, root / "osv-scalibr", *[root / "osv-scalibr" / e for e in ecosystems]):
        os.chmod(d, 0o755)
    (root / "manifest.json").write_text(json.dumps(manifest))
    os.chmod(root / "manifest.json", 0o644)
    return root
