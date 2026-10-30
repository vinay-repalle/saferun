"""First-run setup (`saferun init`) and installation status (`saferun status`).

This module only ORCHESTRATES things that already exist: the pinned images and their digest check (`sandbox.images`, `sandbox.verify`),
the analyzer image/lock/label/rules verification (`sandbox.analyzer`), the local build recipe (`docker/analyzer/build.sh`) and the
validated OSV data (`engine.osvdb`). It adds no new trust: a component is READY only if that existing verification passes now, never
because a tag or a directory happens to exist, and nothing is installed that cannot then be verified.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import ui
from .engine import osvdb
from .engine.model import clean_text
from .sandbox import SandboxError
from .sandbox import analyzer as sa
from .sandbox import docker as dk
from .sandbox import images as im
from .sandbox import verify as vf
from .sandbox.signature import CosignMissing, SignatureError, verify_release_signature

ROOT = Path(__file__).resolve().parent.parent
BUILD_SCRIPT = ROOT / "docker" / "analyzer" / "build.sh"

READY, MISSING, INVALID, OUTDATED, UNKNOWN = "ready", "missing", "invalid", "outdated", "unknown"
MB = 1_000_000


@dataclass(frozen=True)
class Component:
    key: str
    title: str
    purpose: str
    checks: tuple[str, ...]      # report check names that need it
    size: str                    # approximate download / disk use, shown before anything is fetched


COMPONENTS: tuple[Component, ...] = (
    Component("python", "Python sandbox image", "Runs the Python syntax check in a locked-down container.", ("python-syntax",), "about 190 MB"),
    Component("node", "Node.js sandbox image", "Runs the JavaScript syntax check in a locked-down container.", ("javascript-syntax",), "about 330 MB"),
    Component("analyzer", "Analyzer image (Semgrep, OSV-Scanner, rules)", "Runs the static code analysis, and holds the dependency scanner.",
              ("python-static-analysis", "dependency-vulnerabilities"), "about 740 MB, built locally in a few minutes"),
    Component("osv-db", "OSV vulnerability database", "Local vulnerability data so dependency scans run offline.", ("dependency-vulnerabilities",),
              "about 260 MB download"),
)
KEYS = tuple(c.key for c in COMPONENTS)
BY_KEY = {c.key: c for c in COMPONENTS}
CHECK_NEEDS = {"python-syntax": ("python",), "javascript-syntax": ("node",), "python-static-analysis": ("analyzer",),
               "dependency-vulnerabilities": ("analyzer", "osv-db")}
IMAGE_FOR = {"python": im.PYTHON_IMAGE, "node": im.NODE_IMAGE}
HOSTS = {"image": ("registry-1.docker.io",), "build": ("pypi.org", "github.com"), "osv": ("osv-vulnerabilities.storage.googleapis.com",),
         # a published analyzer: the registry, plus the Sigstore trust root and transparency log that `cosign verify` contacts
         "release": ("ghcr.io", "tuf-repo-cdn.sigstore.dev", "rekor.sigstore.dev")}

INTRO = ("SafeRun checks a project WITHOUT running it: Python/JavaScript syntax, static analysis (Semgrep) and known-vulnerable dependencies (OSV).\n"
         "Every check runs in a locked-down container and scans work offline; setup fetches what each check needs, once.")

def banner_lines(th: "ui.Theme") -> list[str]:
    """The SafeRun logo, only on a colour-capable terminal: plain, piped and CI output stays exactly as it was."""
    if not th.on:
        return []
    return [th.paint(line, "bold", "cyan") for line in ui.BANNER] + [th.paint(ui.BANNER_TAGLINE, "dim"), ""]


PRELOAD_HELP = """\
To set up without internet access, prepare the missing parts on a connected machine and copy them over:
  * OSV data:   saferun osv-db update --dir /path/to/osv-db      (copy the whole directory, then: export SAFERUN_OSV_DB=/path/to/osv-db  or  place it at {osv_dir})
                verify it with:  saferun osv-db status
  * Docker images:  docker pull <image>@<digest>  (see: saferun verify-images), then docker save / docker load on the target machine. SafeRun only trusts an image
                whose registry digest matches the pin (`saferun status` shows this); an image loaded without that digest is reported as invalid, never trusted.
  * Analyzer:   build it where docker/analyzer/build.sh can run (needs internet once), or, if you have built it elsewhere, docker save / docker load it (or, without --build-local, install the signed release analyzer-v1.0.1; see docs/release-images.md)."""


@dataclass(frozen=True)
class Status:
    key: str
    state: str          # ready | missing | invalid | outdated | unknown
    detail: str = ""

    @property
    def ready(self) -> bool:
        return self.state == READY

    def to_dict(self) -> dict:
        c = BY_KEY[self.key]
        return {"component": self.key, "title": c.title, "state": self.state, "detail": self.detail, "enables": list(c.checks)}


# ---------------------------------------------------------------------------------------------------------- detection
def _osv_dir() -> Path:
    return osvdb.default_dir()


def component_status(key: str, *, max_age_days: float = osvdb.DEFAULT_MAX_AGE_DAYS) -> Status:
    """Verify one component NOW with the existing checks. Never raises."""
    try:
        if key in IMAGE_FOR:
            c = vf.check_image(IMAGE_FOR[key])
            return Status(key, {vf.VERIFIED: READY, vf.MISSING: MISSING, vf.MISMATCH: INVALID}.get(c.status, UNKNOWN),
                          c.detail or f"digest {c.pinned_digest[:19]}… verified")
        if key == "analyzer":
            try:
                image_id = sa.verify_analyzer_image()
            except sa.AnalyzerUnavailable as e:
                return Status(key, MISSING, str(e))
            except sa.AnalyzerIntegrityError as e:
                return Status(key, INVALID, str(e))
            except SandboxError as e:
                return Status(key, UNKNOWN, str(e))
            return Status(key, READY, f"{image_id[:19]}… matches the lock; tool versions and rules hash verified")
        if key == "osv-db":
            d = _osv_dir()
            if not (d / osvdb.MANIFEST_NAME).exists() and not (d / "osv-scalibr").exists():
                return Status(key, MISSING, f"no OSV data in {d}")
            rep = osvdb.validate(d, list(osvdb.ECOSYSTEMS), max_age_days=max_age_days)
            if not rep.ok:
                return Status(key, INVALID, "; ".join(rep.problems))
            if rep.stale:
                return Status(key, OUTDATED, rep.stale)
            return Status(key, READY, f"{rep.age_days:.1f} days old, integrity manifest verified")
    except Exception as e:  # noqa: BLE001 - a broken probe must read as "not ready", never as ready
        return Status(key, UNKNOWN, f"could not verify: {type(e).__name__}: {e}")
    raise KeyError(key)


def all_status(keys=KEYS) -> list[Status]:
    return [component_status(k) for k in keys]


def check_requirements(check_name: str, statuses: dict[str, Status]) -> list[Status]:
    return [statuses[k] for k in CHECK_NEEDS.get(check_name, ()) if k in statuses and not statuses[k].ready]


def scan_hints(report) -> list[str]:
    """After a scan: for every check that could not do its job, say which component is missing/invalid/outdated and the exact fix.
    Reads component state only when some check is unavailable/error/incomplete; prints nothing for a healthy installation."""
    trouble = [c.name for c in report.checks if c.name in CHECK_NEEDS and c.status.value in ("unavailable", "error", "incomplete")]
    if not trouble:
        return []
    needed = sorted({k for n in trouble for k in CHECK_NEEDS[n]}, key=KEYS.index)
    bad = [s for s in all_status(needed) if not s.ready]
    return [f"setup: {BY_KEY[s.key].title} is {s.state}: {clean_text(s.detail, 220)}  ->  fix: saferun init --only {s.key}"
            + (" --repair" if s.key == "analyzer" and s.state == INVALID else "") for s in bad]


# ---------------------------------------------------------------------------------------------------------- selection
def parse_selection(text: str) -> list[str]:
    """'all' / '5' / 'a', numbers or names separated by commas or spaces; a leading '-' or '!' excludes ("all -osv-db", "-2,3").
    Returns component keys in canonical order. Raises ValueError for anything unrecognised or an empty result."""
    tokens = [t for t in text.replace(",", " ").split() if t]
    if not tokens:
        raise ValueError("nothing selected")
    inc, exc = set(), set()
    for t in tokens:
        neg = t[0] in "-!"
        name = t[1:] if neg else t
        low = name.lower()
        if low in ("all", "a", str(len(KEYS) + 1)):
            keys = set(KEYS)
        elif low.isdigit() and 1 <= int(low) <= len(KEYS):
            keys = {KEYS[int(low) - 1]}
        elif low in KEYS:
            keys = {low}
        else:
            raise ValueError(f"not a component: {t!r} (choose from {', '.join(f'{i + 1}={k}' for i, k in enumerate(KEYS))}, or all)")
        (exc if neg else inc).update(keys)
    chosen = (inc or set(KEYS)) - exc
    if not chosen:
        raise ValueError("nothing selected")
    return [k for k in KEYS if k in chosen]


def parse_list(value: str | None) -> list[str]:
    out = []
    for t in (value or "").replace(",", " ").split():
        if t not in KEYS:
            raise ValueError(f"unknown component {t!r}; choose from: {', '.join(KEYS)}")
        out.append(t)
    return out


def select(all_flag: bool, only: str | None, skip: str | None) -> list[str] | None:
    """Selection from command-line flags, or None when no flag was given (interactive)."""
    if not (all_flag or only or skip):
        return None
    base = parse_list(only) if only else list(KEYS)
    drop = set(parse_list(skip))
    chosen = [k for k in KEYS if k in base and k not in drop]
    if not chosen:
        raise ValueError("nothing selected")
    return chosen


# ---------------------------------------------------------------------------------------------------------- actions
def network_ok(host: str, port: int = 443, timeout: float = 5.0) -> bool:
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def docker_pull(ref: str) -> int:
    """`docker pull <ref>` with Docker's own progress output on the terminal."""
    return subprocess.run([dk.docker_bin(), "pull", ref], stdin=subprocess.DEVNULL).returncode


def build_analyzer(log) -> int:
    """Run docker/analyzer/build.sh (the existing local build workflow), showing a heartbeat and keeping the log."""
    fd, path = tempfile.mkstemp(prefix="saferun-analyzer-build-", suffix=".log")
    start = time.monotonic()
    with os.fdopen(fd, "w") as out:
        proc = subprocess.Popen(["sh", str(BUILD_SCRIPT)], stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                env={**os.environ, "PYTHON": sys.executable}, cwd=str(ROOT))
        try:
            while proc.poll() is None:
                time.sleep(5)
                log(f"    building… {int(time.monotonic() - start)} s (log: {path})")
        except BaseException:
            proc.terminate()
            raise
    if proc.returncode != 0:
        tail = Path(path).read_text(errors="replace").splitlines()[-15:]
        log("    build failed; last lines of the log:")
        for line in tail:
            log("      " + clean_text(line, 200))
    return proc.returncode


class ProgressPrinter:
    """OSV download progress: a rewritten line on a terminal, a line per 10 % otherwise."""

    def __init__(self, out, tty: bool, theme: "ui.Theme | None" = None):
        self.out, self.tty, self._last, self.th = out, tty, {}, theme or ui.PLAIN

    def __call__(self, eco: str, done: int, total: int | None) -> None:
        pct = int(done * 100 / total) if total else None
        step = (pct // 10) if pct is not None else done // (50 * MB)
        if self.tty:
            amount = f"{done / MB:.0f}" + (f" / {total / MB:.0f} MB" if total else " MB")
            self.out.write(f"\r\033[K    {eco:<5} {ui.bar(done, total, self.th)} {amount}" if total else f"\r\033[K    {eco:<5} {amount}")
            if total and done >= total:
                self.out.write("\n")
            self.out.flush()
        elif self._last.get(eco) != step:
            self._last[eco] = step
            self.out.write(f"    {eco}: {done / MB:.0f}" + (f" / {total / MB:.0f} MB ({pct}%)" if total else " MB") + "\n")


# ---------------------------------------------------------------------------------------------------------- the workflow
class Setup:
    """`saferun init`. All side effects go through injectable callables so the workflow is testable without Docker or a network."""

    def __init__(self, *, out=None, err=None, ask=input, interactive=False, tty=False, status=component_status, online=network_ok,
                 pull=docker_pull, build=build_analyzer, osv_update=None, free_bytes=None, daemon_check=None, theme=None,
                 verify_signature=verify_release_signature, build_local=False):
        self.out, self.err = out or sys.stdout, err or sys.stderr
        self.th = theme or ui.PLAIN
        self.ask, self.interactive, self.tty = ask, interactive, tty
        self.status, self.online, self.pull, self.build = status, online, pull, build
        self.verify_signature, self.build_local = verify_signature, build_local   # build_local: --build-local, never chosen automatically
        self.osv_update = osv_update or self._osv_update
        self.free_bytes = free_bytes or (lambda p: shutil.disk_usage(p).free)
        self.daemon_check = daemon_check or dk.check_local_daemon

    def show_banner(self) -> None:
        for line in banner_lines(self.th):
            self.say(line)

    def say(self, text: str = "") -> None:
        self.out.write(text + "\n")
        self.out.flush()

    # -- individual installers: return an error string, or "" on success (the caller re-verifies afterwards)
    def _osv_update(self, directory: Path, progress) -> None:
        osvdb.update(directory, progress=progress)

    def _install_image(self, key: str) -> str:
        img = IMAGE_FOR[key]
        self.say(f"    pulling {img.pull_reference} (verified by digest) …")
        rc = self.pull(img.pull_reference)
        return "" if rc == 0 else f"docker pull failed (exit {rc})"

    def _install_analyzer(self) -> str:
        rel = self._release()
        if rel is not None:
            return self._install_analyzer_release(rel)
        self.say("    building the analyzer image locally with docker/analyzer/build.sh" if im.ANALYZER_RELEASE is not None else
                 "    no signed prebuilt analyzer image has been published yet (docs/release-images.md): building it locally with docker/analyzer/build.sh")
        if not BUILD_SCRIPT.is_file():
            return ("this installation does not include the build recipe (docker/ is not part of the pip package): "
                    "use a SafeRun repository checkout, or run `saferun init --only analyzer` without --build-local to install the signed release")
        quiet = lambda t: None if t.lstrip().startswith("building…") else self.say(t)  # noqa: E731 - the spinner replaces the heartbeat lines
        with ui.Spinner(sys.stderr, "Building the analyzer image (a few minutes)", self.th) as sp:
            rc = self.build(quiet if sp.enabled else self.say)
        return "" if rc == 0 else f"the analyzer build failed (exit {rc})"

    def _release(self) -> "im.AnalyzerRelease | None":
        """The published analyzer to install, or None when the local build is to be used (no release is recorded, or --build-local)."""
        return None if self.build_local else im.ANALYZER_RELEASE

    def _install_analyzer_release(self, rel: im.AnalyzerRelease) -> str:
        """Used when a release is recorded in ANALYZER_RELEASE (and not --build-local). Verify the cosign signature of `repository@digest` BEFORE anything
        is pulled, then pull by digest, check the digest again, verify labels/tools/rules like a local build, then lock. Any failure leaves
        the image untrusted; there is no unsigned install and no automatic fallback to the local build."""
        ref = rel.reference
        self.say(f"    verifying the cosign signature of {ref} (expected signer: this repository's release workflow) …")
        try:
            self.verify_signature(rel)
        except CosignMissing as e:
            return (f"{clean_text(e, 300)}. Nothing was pulled. Install cosign, or build the analyzer yourself with "
                    "`saferun init --only analyzer --build-local`")
        except SignatureError as e:
            return f"signature verification failed, the image was NOT pulled or trusted: {clean_text(e, 300)}"
        self.say("    signature verified")
        self.say(f"    pulling the published analyzer image {ref} …")
        rc = self.pull(ref)
        if rc != 0:
            return f"docker pull failed (exit {rc})"
        r = dk.docker("image", "inspect", "--format", "{{json .RepoDigests}}", dk.validate_image(ref))
        try:
            ok = r.returncode == 0 and rel.digest in im.repo_digests(r.stdout.strip())
        except ValueError:
            ok = False
        if not ok:
            return "the pulled image does not carry the published digest; it was NOT trusted"
        t = dk.docker("tag", ref, sa.ANALYZER_REPO_TAG)
        if t.returncode != 0:
            return f"could not tag the pulled image: {t.stderr.strip()[:200]}"
        try:
            image_id, labels = sa.inspect_analyzer_tag()
            sa.check_labels(labels)
            sa.write_lock(image_id)
        except SandboxError as e:
            return f"the pulled image failed verification and was NOT trusted: {e}"
        return ""

    def _install_osv(self) -> str:
        d = _osv_dir()
        probe = d
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        free = self.free_bytes(probe)
        if free < 700 * MB:
            return f"not enough free disk space at {probe}: {free // MB} MB free, about 700 MB needed during the download"
        self.say(f"    downloading PyPI and npm advisories to {d} (about 260 MB, ~{free // MB // 1000} GB free) …")
        try:
            self.osv_update(d, ProgressPrinter(self.out, self.tty, self.th))
        except KeyboardInterrupt:
            raise
        except Exception as e:  # noqa: BLE001 - old data stays in place; say why
            return f"{type(e).__name__}: {clean_text(e, 300)} (existing data, if any, was left untouched)"
        return ""

    # -- the loop
    def run(self, selected: list[str], *, repair: bool = False, assume_yes: bool = False) -> int:
        statuses = {k: self.status(k) for k in selected}
        needs_docker = any(k in IMAGE_FOR or k == "analyzer" for k in selected)
        docker_error = ""
        if needs_docker:
            try:
                self.daemon_check()
            except SandboxError as e:
                docker_error = str(e)
        if self.interactive:
            self.say()                                   # space after the answer the user just typed
        self.say(self.th.paint("Checking what is already installed:", "bold", "cyan"))
        for k in selected:
            s = statuses[k]
            self.say(f"  {self._tag(s.state)} {BY_KEY[k].title}" + (self.th.paint(f": {clean_text(s.detail, 160)}", "dim") if s.state != READY else ""))
        results: dict[str, str] = {}
        offline: list[str] = []
        for k in selected:
            s = statuses[k]
            c = BY_KEY[k]
            if s.ready:
                results[k] = "skipped (already installed and verified)"
                continue
            if k != "osv-db" and docker_error:
                results[k] = f"not installed: Docker is unusable ({clean_text(docker_error, 160)})"
                continue
            if s.state == UNKNOWN:
                results[k] = f"not installed: could not be examined ({clean_text(s.detail, 160)})"
                continue
            self.say()                                   # a blank line separates every component's block
            if k == "analyzer" and s.state == INVALID and not (repair or self._confirm(
                    "  The analyzer image is present but FAILED verification. Rebuilding replaces the local image and its lock. Rebuild?", assume_yes)):
                results[k] = "left alone: it failed verification; re-run with --repair to rebuild it (investigate first if you did not expect this)"
                continue
            verb = {MISSING: "Install", INVALID: "Repair", OUTDATED: "Update"}[s.state]
            asked = self.interactive and not assume_yes and not (k == "analyzer" and s.state == INVALID)
            if asked and not self._confirm(f"  {verb} {c.title} ({c.size})?", assume_yes):
                results[k] = "not installed (declined)"
                self.say("  " + self._outcome(results[k]))
                continue
            hosts = (HOSTS["osv"] if k == "osv-db"
                     else (HOSTS["release"] if self._release() is not None else HOSTS["build"]) if k == "analyzer" else HOSTS["image"])
            if not all(self.online(h) for h in hosts):
                offline.append(k)
                results[k] = "not installed: no internet access"
                self.say("  " + self._outcome(results[k]))
                continue
            if not asked:                                # after a "[Y/n]" question the same line would only repeat it
                self.say(self.th.paint(f"  {verb} {c.title} ({c.size}):", "bold"))
            try:
                err = self._install_osv() if k == "osv-db" else self._install_analyzer() if k == "analyzer" else self._install_image(k)
            except KeyboardInterrupt:
                self.say("  interrupted; nothing partial was trusted (run `saferun status`).")
                return 130
            if err:
                results[k] = f"FAILED: {err}"
                self.say("  " + self._outcome(results[k]))
                continue
            after = self.status(k)
            results[k] = "installed and verified" if after.ready else f"FAILED: installed but still {after.state}: {clean_text(after.detail, 200)}"
            self.say("  " + self._outcome(results[k]))
        self.say()
        self.say(self.th.paint("Result:", "bold", "cyan"))
        for k in selected:
            self.say(f"  {BY_KEY[k].title}: {self._outcome(results[k])}")
        bad = [k for k in selected if not results[k].startswith(("installed", "skipped"))]
        if offline:
            self.say()
            self.say(PRELOAD_HELP.format(osv_dir=_osv_dir()))
        if bad:
            self.say()
            self.say(self.th.paint("Not ready: " + ", ".join(bad) + ". Checks that need them are reported as unavailable/incomplete and a scan can never be PASS.", "yellow", "bold"))
            return 1
        self.say()
        self.say(self.th.paint("Ready.", "green", "bold") + " Scan a project with: saferun scan ./my-project")
        return 0

    def _tag(self, state: str, pad: bool = True) -> str:
        """`[   ready]` in plain mode; an icon and a coloured upper-case word on a terminal (`pad=False`: no trailing spaces)."""
        if not self.th.on:
            return f"[{state:>8}]"
        icon, col = {READY: ("ok", "green"), MISSING: ("warn", "yellow"), OUTDATED: ("warn", "yellow"), INVALID: ("bad", "red")}.get(state, ("warn", "yellow"))
        word = state.upper().ljust(8) if pad else state.upper()
        return f"{self.th.icon(icon, col, 'bold')} {self.th.paint(word, col, 'bold')}"

    def _outcome(self, text: str) -> str:
        if not self.th.on:
            return text
        if text.startswith("installed"):
            return self.th.paint(f"{self.th.icons['ok']} {text}", "green", "bold")
        if text.startswith("skipped"):
            return self.th.paint(f"{self.th.icons['ok']} {text}", "green")
        if text.startswith("FAILED"):
            return self.th.paint(f"{self.th.icons['bad']} {text}", "red", "bold")
        return self.th.paint(f"{self.th.icons['warn']} {text}", "yellow")

    def _confirm(self, question: str, assume_yes: bool) -> bool:
        if assume_yes:
            return True
        if not self.interactive:
            return False
        try:
            return self.ask(f"{question} [Y/n] ").strip().lower() in ("", "y", "yes")
        except EOFError:
            return False

    def choose(self) -> list[str]:
        """Interactive menu. Returns the selected keys; raises ValueError after three invalid answers."""
        self.show_banner()
        self.say(INTRO)
        self.say()
        statuses = {k: self.status(k) for k in KEYS}
        self.say(self.th.paint("Components:", "bold", "cyan"))
        for i, c in enumerate(COMPONENTS, 1):
            tag = f"[{statuses[c.key].state}]" if not self.th.on else self._tag(statuses[c.key].state, pad=False)
            self.say(f"  {i}. {c.title}  {tag}\n       " + self.th.paint(f"{c.purpose} ({c.size})", "dim"))
        self.say(f"  {len(KEYS) + 1}. All components")
        self.say()
        self.say("Choose by number or name, comma-separated; 'all -osv-db' installs everything except osv-db. Enter = all.")
        for _ in range(3):
            try:
                answer = self.ask("Install which? ").strip()
            except EOFError:
                break
            try:
                return parse_selection(answer or "all")
            except ValueError as e:
                self.say(f"  {e}")
        raise ValueError("no valid selection")


def status_report(statuses: list[Status], th: "ui.Theme | None" = None) -> str:
    th = th or ui.PLAIN
    lines = []
    for s in statuses:
        c = BY_KEY[s.key]
        if th.on:
            icon, col = {READY: ("ok", "green"), INVALID: ("bad", "red")}.get(s.state, ("warn", "yellow"))
            head = f"{th.icon(icon, col, 'bold')} {th.paint(s.state.upper().ljust(8), col, 'bold')} {th.paint(c.title, 'bold')}"
            body = f"\n           enables: {', '.join(c.checks)}" + (f"\n           {th.paint(clean_text(s.detail, 240), 'dim')}" if s.detail else "")
            fix = f"\n           {th.paint('fix:', 'cyan', 'bold')} saferun init --only {s.key}" + (" --repair" if s.key == "analyzer" and s.state == INVALID else "")
            lines.append(head + body + (fix if not s.ready else ""))
            continue
        lines.append(f"{s.state.upper():<9} {c.title}\n          enables: {', '.join(c.checks)}"
                     + (f"\n          {clean_text(s.detail, 240)}" if s.detail else ""))
        if not s.ready:
            lines.append(f"          fix: saferun init --only {s.key}" + (" --repair" if s.key == "analyzer" and s.state == INVALID else ""))
    return "\n".join(lines)


def status_json(statuses: list[Status]) -> str:
    return json.dumps({"schema_version": 1, "ok": all(s.ready for s in statuses), "components": [s.to_dict() for s in statuses]},
                      indent=2, sort_keys=True)
