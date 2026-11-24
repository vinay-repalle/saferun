"""Offline OSV vulnerability databases (Phase 5B, validated since the Phase 5B review).

OSV-Scanner runs inside the analyzer container with the network disabled, so it needs a local copy of the OSV data. The
data lives in `<db_dir>/osv-scalibr/<Ecosystem>/all.zip` (the layout OSV-Scanner reads when XDG_CACHE_HOME=<db_dir>) and is
mounted read-only. `saferun osv-db update` is the only code that downloads it: an explicit, user-run, host-side HTTPS download of
public vulnerability data. The request contains only the ecosystem name; nothing about any project is sent.

Integrity model (read this before trusting a scan result):
* At download time: HTTPS (certificate-verified by urllib), the server-provided MD5 (`x-goog-hash`) must be present and match
  (a missing header is refused unless the operator passes `--allow-unverified`, and the manifest then records "unverified"),
  the file must be a readable zip whose central directory lists at least MIN_ENTRIES[ecosystem] advisory files. The host reads only
  the zip's central directory (stdlib `zipfile`, nothing is extracted); the advisories themselves are only ever opened by OSV-Scanner
  inside the container.
* A `manifest.json` records, per ecosystem, the SHA-256, size, entry count and update time of what was installed.
* Before every scan `validate()` re-hashes the files and compares them with the manifest, re-checks size/entry-count floors, refuses
  symlinks and unreadable files, rejects timestamps from the future, and reports the data's age. Any problem makes the dependency
  check an ERROR; data older than the age limit makes it INCOMPLETE. Neither can produce a clean result.
What this does NOT give you: the MD5 comes from the same server over the same connection, so it detects accidental corruption, not a
malicious or compromised server; the SHA-256 is computed locally after download, so it detects LATER modification of the files but does
not authenticate the original download; the manifest lives next to the data, so someone who can write the directory can rewrite both
(same trust level as the user's own files and Docker); the entry-count floor is a sanity check, not proof of completeness; and OSV
publishes no signature that SafeRun checks.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import stat
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .. import hostos

ECOSYSTEMS = ("PyPI",)
# Ecosystems SafeRun downloaded in the past but no longer supports (npm until the JavaScript removal). Only these names, and only when
# SafeRun's own manifest records them, are ever removed by `prune_unsupported`.
RETIRED_ECOSYSTEMS = ("npm",)
BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
MAX_BYTES = 2 * 1024 ** 3
MANIFEST_NAME = "manifest.json"
MANIFEST_SCHEMA = 1
# Sanity floors (about a fifth of what OSV listed in October 2026: PyPI 26 726 advisories). They catch empty, stub and badly
# truncated archives; they are not proof that an archive is complete.
MIN_ENTRIES = {"PyPI": 5_000}
DEFAULT_MAX_AGE_DAYS = 30.0
WARN_BEFORE_DAYS = 5.0   # early warning this many days before the age limit (day 25 by default); it never changes a verdict
FUTURE_SKEW_S = 24 * 3600
_HEX64 = frozenset("0123456789abcdef")


def default_dir() -> Path:
    env = os.environ.get("SAFERUN_OSV_DB")
    if env:
        return Path(env)
    return hostos.user_data_base() / "saferun" / "osv-db"


def available_ecosystems(db_dir: Path) -> list[str]:
    """Ecosystems that have a data file (existence only; use `validate` for trust)."""
    root = db_dir / "osv-scalibr"
    try:
        return sorted(e for e in ECOSYSTEMS if (root / e / "all.zip").is_file())
    except OSError:
        return []


# ---------------------------------------------------------------------------------------------------- validation
@dataclass
class DbReport:
    problems: list[str] = field(default_factory=list)   # any entry: the data cannot be trusted -> the check is an ERROR
    stale: str = ""                                      # non-empty: valid but older than the limit -> the check is INCOMPLETE
    expires_soon: str = ""                               # non-empty: valid and fresh, but stale within WARN_BEFORE_DAYS (a warning only)
    notes: list[str] = field(default_factory=list)       # freshness and integrity facts, always reported
    ecosystems: dict = field(default_factory=dict)       # manifest entries of the validated ecosystems
    age_days: float | None = None                        # age of the OLDEST validated ecosystem

    @property
    def ok(self) -> bool:
        return not self.problems


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def count_entries(path: Path) -> int:
    """Number of advisory (`*.json`) files listed in the zip's central directory. Nothing is extracted. Raises ValueError."""
    try:
        with zipfile.ZipFile(path) as z:
            return sum(1 for n in z.namelist() if n.endswith(".json"))
    except (zipfile.BadZipFile, OSError, NotImplementedError, RuntimeError, EOFError) as e:
        raise ValueError(f"not a readable zip archive: {e}") from None


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _load_manifest(db_dir: Path) -> dict:
    p = db_dir / MANIFEST_NAME
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        raise ValueError(f"no {MANIFEST_NAME} (the data was not installed by `saferun osv-db update`, or by an older version)") from None
    except OSError as e:
        raise ValueError(f"cannot read {MANIFEST_NAME}: {e}") from None
    if not stat.S_ISREG(st.st_mode) or st.st_size > 1 << 20:
        raise ValueError(f"{MANIFEST_NAME} is not a regular file of sane size")
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError, RecursionError) as e:
        raise ValueError(f"{MANIFEST_NAME} is not valid JSON: {e}") from None
    if not isinstance(data, dict) or data.get("schema") != MANIFEST_SCHEMA or not isinstance(data.get("ecosystems"), dict):
        raise ValueError(f"{MANIFEST_NAME} has an unexpected structure or schema version")
    return data


def _entry_problem(eco: str, e) -> str | None:
    if not isinstance(e, dict):
        return "manifest entry is not an object"
    sha, size, entries, ts = e.get("sha256"), e.get("size"), e.get("entries"), e.get("updated_epoch")
    if not (isinstance(sha, str) and len(sha) == 64 and set(sha) <= _HEX64):
        return "manifest sha256 is malformed"
    if not (isinstance(size, int) and not isinstance(size, bool) and size > 0):
        return "manifest size is malformed"
    if not (isinstance(entries, int) and not isinstance(entries, bool) and entries >= 0):
        return "manifest entry count is malformed"
    if not (isinstance(ts, (int, float)) and not isinstance(ts, bool) and math.isfinite(ts) and ts > 0):
        return "manifest update time is malformed"
    if e.get("md5") not in ("verified", "unverified"):
        return "manifest md5 status is malformed"
    return None


def validate(db_dir: Path, needed=None, *, max_age_days: float = DEFAULT_MAX_AGE_DAYS, now: float | None = None) -> DbReport:
    """Decide whether the data in `db_dir` may be used for `needed` ecosystems (default: everything in the manifest).
    Never raises; every doubt becomes a problem."""
    rep = DbReport()
    now = time.time() if now is None else now
    try:
        st = os.lstat(db_dir)
    except OSError:
        rep.problems.append(f"{db_dir} does not exist")
        return rep
    if not stat.S_ISDIR(st.st_mode):
        rep.problems.append(f"{db_dir} is not a directory (symlinks are refused)")
        return rep
    if not st.st_mode & 0o005 == 0o005:
        rep.problems.append(f"{db_dir} is not readable by other users; the analyzer container runs as uid 65534 (chmod o+rx it)")
    try:
        manifest = _load_manifest(db_dir)
    except ValueError as e:
        rep.problems.append(str(e))
        return rep
    names = sorted(needed) if needed is not None else sorted(manifest["ecosystems"])
    if not names:
        rep.problems.append("the manifest lists no ecosystem")
    oldest = None
    for eco in names:
        entry = manifest["ecosystems"].get(eco)
        if entry is None:
            rep.problems.append(f"no {eco} data in the manifest (run `saferun osv-db update`)")
            continue
        bad = _entry_problem(eco, entry)
        if bad:
            rep.problems.append(f"{eco}: {bad}")
            continue
        path = db_dir / "osv-scalibr" / eco / "all.zip"
        try:
            for d in (db_dir / "osv-scalibr", db_dir / "osv-scalibr" / eco):
                dst = os.lstat(d)
                if not stat.S_ISDIR(dst.st_mode) or not dst.st_mode & 0o005 == 0o005:
                    raise ValueError(f"{d} is a symlink/not a directory or not readable by other users")
            fst = os.lstat(path)
            if not stat.S_ISREG(fst.st_mode) or not fst.st_mode & 0o004:
                raise ValueError("data file is a symlink/not a regular file or not readable by other users")
            if fst.st_size != entry["size"]:
                raise ValueError(f"size {fst.st_size} differs from the recorded {entry['size']}")
            if _sha256_file(path) != entry["sha256"]:
                raise ValueError("SHA-256 differs from the recorded value (the file changed after installation)")
        except (OSError, ValueError) as e:
            rep.problems.append(f"{eco}: {e}")
            continue
        floor = MIN_ENTRIES.get(eco, 1)
        if entry["entries"] < floor:
            rep.problems.append(f"{eco}: only {entry['entries']} advisories recorded (minimum {floor}); the data is incomplete or a stub")
            continue
        if entry["updated_epoch"] > now + FUTURE_SKEW_S:
            rep.problems.append(f"{eco}: update time is in the future ({_iso(entry['updated_epoch'])}); the clock or the manifest is wrong")
            continue
        age = max(0.0, (now - entry["updated_epoch"]) / 86400)
        oldest = age if oldest is None else max(oldest, age)
        rep.ecosystems[eco] = entry
        rep.notes.append(f"OSV database {eco}: updated {_iso(entry['updated_epoch'])} ({age:.1f} days ago), {entry['entries']} advisories, "
                         f"sha256 {entry['sha256'][:16]}…, download MD5 {entry['md5']}")
    rep.age_days = oldest
    if rep.ok:
        rep.notes.append("OSV database integrity: hashes recorded locally at download time and re-checked now; this detects later changes, "
                         "it does not authenticate the original download")
        if any(e["md5"] == "unverified" for e in rep.ecosystems.values()):
            rep.notes.append("OSV database was installed WITHOUT a server-provided hash (--allow-unverified); its download was not integrity-checked")
        if oldest is not None and oldest > max_age_days:
            rep.stale = (f"the OSV database is {oldest:.0f} days old (limit {max_age_days:g}); vulnerabilities published since are not covered. "
                         "Refresh with: saferun osv-db update")
        else:
            rep.expires_soon = expiry_warning(oldest, max_age_days)
    return rep


def expiry_warning(age_days: float | None, max_age_days: float = DEFAULT_MAX_AGE_DAYS) -> str:
    """A warning when data of this age is still within the limit but becomes stale within WARN_BEFORE_DAYS days; otherwise ''."""
    if age_days is None or age_days > max_age_days or max_age_days - age_days > WARN_BEFORE_DAYS:
        return ""
    return (f"the OSV database is {age_days:.0f} days old and becomes stale in {max_age_days - age_days:.1f} day(s) (limit {max_age_days:g}); "
            "refresh it with: saferun osv-db update")


def manifest_age_days(db_dir: Path, *, now: float | None = None) -> float | None:
    """Age in days of the OLDEST supported ecosystem as recorded in the manifest, or None. Reads the manifest only (no hashing): for the
    early warning after a scan, which itself already validated the data. Never raises."""
    now = time.time() if now is None else now
    try:
        entries = _load_manifest(Path(db_dir))["ecosystems"]
    except (ValueError, OSError):
        return None
    ages = [max(0.0, (now - e["updated_epoch"]) / 86400) for eco in ECOSYSTEMS
            if (e := entries.get(eco)) is not None and _entry_problem(eco, e) is None]
    return max(ages) if ages else None


def stale_ecosystems(db_dir: Path, *, max_age_days: float = DEFAULT_MAX_AGE_DAYS, now: float | None = None) -> list[str]:
    """Ecosystems that must be (re)downloaded: missing, failing validation, or older than the limit. An ecosystem that is valid and
    fresh is not listed, so it is not downloaded again. Never raises."""
    out = []
    for eco in ECOSYSTEMS:
        rep = validate(Path(db_dir), [eco], max_age_days=max_age_days, now=now)
        if not rep.ok or rep.stale:
            out.append(eco)
    return out


# ---------------------------------------------------------------------------------------------------- update
def _ensure_dir(path: Path) -> bool:
    """Create `path` (mode 0755) if it is missing. Returns True if it was created. An EXISTING directory is never chmod'ed;
    a symlink is refused."""
    if path.is_symlink():
        raise ValueError(f"refusing to use a symlink as a database directory: {path}")
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"not a directory: {path}")
        return False
    if path == default_dir():
        hostos.ensure_private_dir(path.parent)   # <data>/saferun also holds the analyzer lock, which requires it to be owner-only
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(mode=0o755)
    os.chmod(path, 0o755)         # only a directory created just now; the umask may have narrowed it
    return True


def _write_manifest(db_dir: Path, base_url: str, eco: str, entry: dict) -> None:
    try:
        manifest = _load_manifest(db_dir)
    except ValueError:
        manifest = {"schema": MANIFEST_SCHEMA, "source": base_url, "ecosystems": {}}
    manifest["source"] = base_url
    manifest["ecosystems"][eco] = entry
    _save_manifest(db_dir, manifest)


def _save_manifest(db_dir: Path, manifest: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=db_dir, prefix=".manifest-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        os.chmod(tmp, 0o644)
        os.replace(tmp, db_dir / MANIFEST_NAME)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class OsvNetworkError(OSError):
    """The OSV server could not be reached (or kept failing). The existing data and manifest are untouched, and are NOT made fresher by this."""


OPEN_ATTEMPTS = 3
RETRY_STATUS = frozenset({408, 429, 500, 502, 503, 504})


def _open(opener, url: str, *, sleep=time.sleep, attempts: int = OPEN_ATTEMPTS):
    """Open `url`, retrying transient failures (no connection, timeout, 408/429/5xx) with a short back-off. Other HTTP errors fail at once."""
    last = None
    for i in range(attempts):
        try:
            return opener(url, timeout=120)
        except urllib.error.HTTPError as e:
            if e.code not in RETRY_STATUS:
                raise OsvNetworkError(f"the OSV server answered HTTP {e.code} for {url}") from None
            last = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last = str(getattr(e, "reason", e))
        if i + 1 < attempts:
            sleep(2 ** i)
    raise OsvNetworkError(f"cannot reach the OSV server ({last}) after {attempts} attempts; check your internet connection or proxy. "
                          "Existing data was left untouched and keeps its original age")


def update(db_dir: Path, ecosystems=ECOSYSTEMS, *, base_url: str = BASE_URL, opener=None,
           allow_unverified: bool = False, clock=time.time, progress=None, sleep=time.sleep) -> dict[str, dict]:
    """Download `all.zip` for each ecosystem into `db_dir` and record it in the manifest. Returns {ecosystem: manifest entry}.
    Atomic per file; raises on any problem (including an interrupted download) and leaves the previous file and manifest entry in place.
    Never changes the permissions of a directory that already existed. `progress(ecosystem, bytes_done, total_or_None)` is called about once per MiB."""
    if not base_url.startswith("https://"):
        raise ValueError("OSV database downloads must use https")
    opener = opener or urllib.request.urlopen
    for eco in ecosystems:
        if eco not in ECOSYSTEMS:
            raise ValueError(f"unsupported ecosystem {eco!r}; supported: {', '.join(ECOSYSTEMS)}")
    db_dir = Path(db_dir)
    _ensure_dir(db_dir)
    _ensure_dir(db_dir / "osv-scalibr")
    result = {}
    for eco in ecosystems:
        target_dir = db_dir / "osv-scalibr" / eco
        _ensure_dir(target_dir)
        fd, tmp = tempfile.mkstemp(dir=target_dir, prefix=".dl-")
        try:
            md5, sha, size = hashlib.md5(usedforsecurity=False), hashlib.sha256(), 0
            with os.fdopen(fd, "wb") as out, _open(opener, f"{base_url}/{eco}/all.zip", sleep=sleep) as resp:  # noqa: S310 - https enforced
                expected_md5 = _goog_md5(_header_values(resp.headers, "x-goog-hash"))
                if not expected_md5 and not allow_unverified:
                    raise ValueError(f"{eco}: the server sent no usable MD5 header, so the download cannot be integrity-checked; "
                                     "refusing (re-run with --allow-unverified to accept it and record it as unverified)")
                try:
                    total = int(resp.headers.get("Content-Length")) if resp.headers.get("Content-Length") else None
                except (TypeError, ValueError):
                    total = None
                while chunk := resp.read(1 << 20):
                    size += len(chunk)
                    if progress:
                        progress(eco, size, total)
                    if size > MAX_BYTES:
                        raise ValueError(f"{eco}: download exceeds {MAX_BYTES} bytes")
                    md5.update(chunk)
                    sha.update(chunk)
                    out.write(chunk)
            if expected_md5 and md5.hexdigest() != expected_md5:
                raise ValueError(f"{eco}: MD5 mismatch against the server-provided hash (corrupt download)")
            if size == 0:
                raise ValueError(f"{eco}: empty download")
            entries = count_entries(Path(tmp))
            if entries < MIN_ENTRIES[eco]:
                raise ValueError(f"{eco}: the archive lists only {entries} advisories (minimum {MIN_ENTRIES[eco]}); refusing an empty or incomplete database")
            os.chmod(tmp, 0o644)
            os.replace(tmp, target_dir / "all.zip")
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        now = clock()
        entry = {"sha256": sha.hexdigest(), "size": size, "entries": entries, "updated_epoch": int(now), "updated_at": _iso(now),
                 "md5": "verified" if expected_md5 else "unverified"}
        _write_manifest(db_dir, base_url, eco, entry)
        result[eco] = entry
    return result


# ---------------------------------------------------------------------------------------------------- unsupported data
def unsupported_data(db_dir: Path) -> list[tuple[str, int]]:
    """(ecosystem, bytes on disk) of data SafeRun downloaded earlier for an ecosystem it no longer supports (RETIRED_ECOSYSTEMS), as
    recorded in its own manifest. Existence only; never raises."""
    db_dir = Path(db_dir)
    try:
        recorded = _load_manifest(db_dir)["ecosystems"]
    except (ValueError, OSError):
        return []
    out = []
    for eco in RETIRED_ECOSYSTEMS:
        if eco in recorded:
            try:
                st = os.lstat(db_dir / "osv-scalibr" / eco / "all.zip")
                size = st.st_size if stat.S_ISREG(st.st_mode) else 0
            except OSError:
                size = 0
            out.append((eco, size))
    return out


def prune_unsupported(db_dir: Path) -> tuple[list[tuple[str, int]], list[str]]:
    """Remove the data `unsupported_data` lists: its `all.zip` and interrupted-download leftovers (`.dl-*`), the ecosystem folder only if
    that leaves it empty (never a recursive delete), then its manifest entry. Symlinks are never followed or removed, and a folder that
    is not a real directory is left alone. Returns ([(ecosystem, bytes removed)], [problems]). Never raises."""
    db_dir = Path(db_dir)
    removed, problems = [], []
    found = unsupported_data(db_dir)
    if not found:
        return removed, problems
    try:
        for d in (db_dir, db_dir / "osv-scalibr"):
            if not stat.S_ISDIR(os.lstat(d).st_mode):
                return removed, [f"{d} is not a real directory (a symlink?); nothing was removed"]
    except OSError as e:
        return removed, [f"cannot examine {db_dir}: {e}"]
    gone = []
    for eco, _ in found:
        folder = db_dir / "osv-scalibr" / eco
        freed = 0
        try:
            try:
                st = os.lstat(folder)
            except FileNotFoundError:
                st = None                                   # the data is already gone; only the manifest entry is left
            if st is not None:
                if not stat.S_ISDIR(st.st_mode):
                    problems.append(f"{folder} is not a real directory (a symlink?); left alone")
                    continue
                for entry in os.scandir(folder):
                    if (entry.name == "all.zip" or entry.name.startswith(".dl-")) and entry.is_file(follow_symlinks=False):
                        freed += entry.stat(follow_symlinks=False).st_size
                        os.unlink(entry.path)
                if os.path.lexists(folder / "all.zip"):
                    problems.append(f"{folder / 'all.zip'} is not a regular file (a symlink?); left alone")
                    continue
                try:
                    os.rmdir(folder)
                except OSError:
                    problems.append(f"{folder} still holds other files; the folder was left in place")
        except OSError as e:
            problems.append(f"{eco}: {e}")
            continue
        gone.append(eco)
        removed.append((eco, freed))
    if gone:
        try:
            manifest = _load_manifest(db_dir)
            for eco in gone:
                manifest["ecosystems"].pop(eco, None)
            _save_manifest(db_dir, manifest)
        except (ValueError, OSError) as e:
            problems.append(f"the data was removed but {MANIFEST_NAME} could not be updated: {e}")
    return removed, problems


def _header_values(headers, name: str) -> str:
    """All values of a header joined with commas. The real server sends `x-goog-hash` as TWO separate headers (crc32c, md5);
    `headers.get()` returns only the first, which made the original MD5 check a silent no-op."""
    if hasattr(headers, "get_all"):
        return ",".join(headers.get_all(name) or [])
    return str(headers.get(name, "") or "")


def _goog_md5(header: str) -> str:
    """x-goog-hash value(s): crc32c=...,md5=<base64>; returns the md5 as hex, or ''."""
    for part in (header or "").replace(" ", "").split(","):
        if part.startswith("md5="):
            try:
                raw = base64.b64decode(part[4:], validate=True)
            except ValueError:
                return ""
            return raw.hex() if len(raw) == 16 else ""
    return ""
