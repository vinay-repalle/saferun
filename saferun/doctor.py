"""`saferun doctor`: read-only diagnostics with PASS / WARNING / FAIL per check. It changes nothing and installs nothing.

Every verdict about an image, the analyzer or the OSV data comes from the same verification `saferun status` and every scan use
(`setup.component_status`); doctor adds the surrounding facts (Python, OS, Docker state, cosign, directories) and a fix for each problem.
A check that cannot be carried out is a FAIL or WARNING, never a PASS.
Exit status: 0 = no FAIL (warnings allowed), 1 = at least one FAIL.
"""
from __future__ import annotations

import json
import os
import platform
import sys
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

from . import dockerdiag, hostos
from . import setup as st
from .engine import osvdb
from .engine.model import clean_text
from .sandbox import SandboxError
from .sandbox import cosign_tool
from .sandbox import images as im
from .sandbox import signature as sig

PASS, WARN, FAIL = "PASS", "WARNING", "FAIL"
MIN_PYTHON = (3, 12)


@dataclass(frozen=True)
class Check:
    name: str
    level: str
    detail: str
    fix: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "level": self.level, "detail": self.detail, "fix": self.fix}


def _version() -> str:
    from . import __version__
    try:
        installed = metadata.version("saferun-cli")
    except metadata.PackageNotFoundError:
        return f"{__version__} (not installed as a package)"
    return installed if installed == __version__ else f"{__version__} (package metadata says {installed})"


def check_install() -> Check:
    p = Path(__file__).resolve().parent
    return Check("SafeRun installation", PASS, f"version {_version()} at {p}")


def check_python(v=None) -> Check:
    v = v or sys.version_info
    if tuple(v[:2]) >= MIN_PYTHON:
        return Check("Python", PASS, f"{v[0]}.{v[1]}.{v[2]} ({platform.python_implementation()})")
    return Check("Python", FAIL, f"{v[0]}.{v[1]} is too old", f"SafeRun needs Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer")


def check_os(system: str | None = None, machine: str | None = None) -> Check:
    s = (system or platform.system()).lower()
    m = machine or platform.machine()
    if s in ("linux", "darwin", "windows"):
        note = "" if s == "linux" else " (native Windows and macOS support is newer than Linux; see docs/platforms.md)"
        return Check("Operating system", PASS, f"{platform.system()} {m}{note}")
    return Check("Operating system", FAIL, f"{platform.system()} is not supported", "SafeRun supports Linux, macOS and Windows")


def check_docker(d: dockerdiag.DockerDiagnosis) -> Check:
    return Check("Docker", PASS if d.ok else FAIL, d.detail, "" if d.ok else d.guidance)


def _from_status(name: str, s: st.Status, fix: str) -> Check:
    level = {st.READY: PASS, st.OUTDATED: WARN}.get(s.state, FAIL)
    return Check(name, level, clean_text(s.detail, 300) if s.detail else s.state, "" if level == PASS else fix)


def check_cosign() -> Check:
    managed = cosign_tool.managed_cosign()
    if managed:
        return Check("Cosign", PASS, f"SafeRun's pinned copy {cosign_tool.COSIGN_VERSION} (SHA-256 verified) at {managed}")
    path = sig.find_cosign()
    if path:
        return Check("Cosign", PASS, f"found on PATH at {path} (not SafeRun's pinned copy)")
    return Check("Cosign", WARN, "not installed yet; only needed to install the signed analyzer image", "run: saferun init --only analyzer (fetches a verified copy)")


def check_directories() -> list[Check]:
    out = []
    base = hostos.user_data_base() / "saferun"
    probe = base
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    ok = os.access(probe, os.W_OK)
    out.append(Check("Data directory", PASS if ok else FAIL, f"{base} ({'exists' if base.exists() else 'will be created'}; writable: {ok})",
                     "" if ok else f"make {probe} writable by your user"))
    env = [k for k in ("SAFERUN_OSV_DB", "SAFERUN_ANALYZER_LOCK") if os.environ.get(k)]
    if env:
        out.append(Check("Configuration", PASS, "overridden by environment: " + ", ".join(f"{k}={os.environ[k]}" for k in env)))
    else:
        out.append(Check("Configuration", PASS, "defaults (no SAFERUN_* overrides)"))
    return out


def check_signature_online(*, verify=sig.verify_release_signature) -> Check:
    rel = im.ANALYZER_RELEASE
    if rel is None:
        return Check("Analyzer release signature", WARN, "no published analyzer release is recorded; the analyzer is built locally")
    try:
        n = verify(rel)
    except SandboxError as e:
        return Check("Analyzer release signature", FAIL, clean_text(e, 300), "run: saferun init --only analyzer")
    return Check("Analyzer release signature", PASS, f"{n} valid signature(s) for {rel.reference}")


def run_checks(*, online: bool = False, status=st.component_status, diagnose=dockerdiag.diagnose) -> list[Check]:
    """Run every check. Never raises: a broken probe becomes a FAIL."""
    checks = [check_install(), check_python(), check_os()]
    d = diagnose()
    checks.append(check_docker(d))
    for key, label in (("python", "Python sandbox image"), ("node", "Node.js sandbox image"), ("analyzer", "Analyzer image")):
        if not d.ok:
            checks.append(Check(label, FAIL, "cannot be verified while Docker is unusable", "fix Docker first"))
        else:
            checks.append(_from_status(label, status(key), f"run: saferun init --only {key}" + (" --repair" if key == "analyzer" else "")))
    checks.append(check_cosign())
    osv = _from_status("OSV database", status("osv-db"), "run: saferun osv-db update")
    checks.append(osv)
    checks.extend(check_directories())
    if online:
        try:
            checks.append(check_signature_online())
        except Exception as e:  # noqa: BLE001
            checks.append(Check("Analyzer release signature", FAIL, f"{type(e).__name__}: {clean_text(e, 200)}"))
    return checks


def exit_code(checks: list[Check]) -> int:
    return 1 if any(c.level == FAIL for c in checks) else 0


def render_text(checks: list[Check]) -> str:
    lines = []
    for c in checks:
        lines.append(f"[{c.level:<7}] {c.name}: {c.detail}")
        if c.fix:
            lines.append(f"{'':11}fix: {c.fix}")
    n = {lvl: sum(1 for c in checks if c.level == lvl) for lvl in (PASS, WARN, FAIL)}
    lines.append("")
    lines.append(f"{n[PASS]} passed, {n[WARN]} warning(s), {n[FAIL]} failed" + (" - SafeRun is ready" if not n[FAIL] and not n[WARN] else
                 " - SafeRun can run, but review the warnings" if not n[FAIL] else " - SafeRun is NOT ready; apply the fixes above"))
    return "\n".join(lines)


def render_json(checks: list[Check]) -> str:
    return json.dumps({"schema_version": 1, "ok": exit_code(checks) == 0, "checks": [c.to_dict() for c in checks]}, indent=2, sort_keys=True)
