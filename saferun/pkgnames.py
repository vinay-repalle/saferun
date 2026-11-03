"""`saferun check-names`: look-alike package names, offline by default.

Offline (always): every declared Python package name is normalised (PEP 503) and compared with a bundled snapshot of the most
downloaded PyPI package names (`saferun/data/top_pypi.txt`). A name that is not in the snapshot but is one or two edits away from a
popular one is reported as "similar". This is a hint, not proof: it misses typosquats of packages outside the snapshot and can flag
innocent names. A name that is simply not in the snapshot is "unknown": it was not checked any further.

Online (only with --online): for names that are NOT in the snapshot, PyPI is asked whether the project exists and when its first
file was uploaded. Only the package name is sent (an HTTPS GET to pypi.org/simple/<name>/); no code, paths or file contents. If a
lookup fails for any reason the answer is "could not check", never a pass.

Reading a project: only requirements*.txt and pyproject.toml directly inside the given directory. Nothing is executed or installed,
symbolic links are not followed and file sizes are capped.
"""
from __future__ import annotations

import json
import re
import tomllib
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Callable

from . import __version__

SNAPSHOT_RESOURCE = "top_pypi.txt"
MAX_FILE_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 32_000_000
LOOKUP_TIMEOUT_S = 15.0
LOOKUP_WORKERS = 8
NEW_PACKAGE_DAYS = 30
MAX_NAMES = 2000          # one run never sends more lookups than this; the rest are reported as "could not check"
SIMPLE_URL = "https://pypi.org/simple/{name}/"

_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_NORMALIZED_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def normalize(name: str) -> str:
    """PEP 503 name normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------- snapshot

@dataclass(frozen=True, eq=False)
class Snapshot:
    names: tuple[str, ...]                 # most downloaded first
    source: str
    date: str
    rank: dict[str, int] = field(repr=False, default_factory=dict)

    def __contains__(self, name: str) -> bool:
        return name in self.rank


def parse_snapshot(text: str) -> Snapshot:
    names: list[str] = []
    seen: set[str] = set()
    meta: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            key, _, value = line[1:].partition(":")
            if value:
                meta.setdefault(key.strip().lower(), value.strip())
            continue
        if _NORMALIZED_RE.fullmatch(line) and line not in seen:
            seen.add(line)
            names.append(line)
    rank = {n: i for i, n in enumerate(names)}
    return Snapshot(tuple(names), meta.get("source", "unknown"), meta.get("date", "unknown"), rank)


@lru_cache(maxsize=1)
def load_snapshot() -> Snapshot:
    return parse_snapshot(resources.files("saferun").joinpath("data", SNAPSHOT_RESOURCE).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- similarity

def edit_distance(a: str, b: str, limit: int) -> int:
    """Damerau-Levenshtein distance (optimal string alignment: insert, delete, replace, swap two neighbours).
    Returns limit + 1 as soon as the distance is known to exceed `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def allowed_distance(name: str, popular: str) -> int:
    """How many edits still count as "similar". Short names are only matched at distance 1, and very short popular names
    (4 characters or fewer) are not used as a target at all: almost every short word is one edit away from one of them."""
    if len(popular) <= 4 or len(name) <= 4:
        return 0
    return 2 if min(len(name), len(popular)) >= 8 else 1


def _deletes(word: str, depth: int) -> set[str]:
    """`word` and every string made by deleting up to `depth` characters from it."""
    out = {word}
    frontier = {word}
    for _ in range(depth):
        frontier = {w[:i] + w[i + 1:] for w in frontier for i in range(len(w))}
        out |= frontier
    return out


@lru_cache(maxsize=4)
def _index(snap: Snapshot) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Delete-neighbourhood index (SymSpell): two names within `d` edits share a string reachable by deleting up to `d`
    characters from each. idx1 serves distance 1, idx2 distance 2 (only names of 8+ characters can match at 2)."""
    idx1: dict[str, list[str]] = {}
    idx2: dict[str, list[str]] = {}
    for name in snap.names:
        if len(name) <= 4:
            continue
        for v in _deletes(name, 1):
            idx1.setdefault(v, []).append(name)
        if len(name) >= 8:
            for v in _deletes(name, 2):
                idx2.setdefault(v, []).append(name)
    return idx1, idx2


def find_similar(name: str, snap: Snapshot) -> tuple[str, int] | None:
    """The closest, then most popular, snapshot name that `name` resembles, with its distance; None if there is none
    (or `name` is itself in the snapshot). Candidates from the index are always verified with the real edit distance."""
    if name in snap or len(name) <= 4:
        return None
    idx1, idx2 = _index(snap)
    candidates: set[str] = set()
    for v in _deletes(name, 1):
        candidates.update(idx1.get(v, ()))
    if len(name) >= 8:
        for v in _deletes(name, 2):
            candidates.update(idx2.get(v, ()))
    best: tuple[int, int, str] | None = None     # (distance, rank, popular)
    for popular in candidates:
        limit = allowed_distance(name, popular)
        if limit == 0:
            continue
        d = edit_distance(name, popular, limit)
        if d <= limit:
            key = (d, snap.rank[popular], popular)
            if best is None or key < best:
                best = key
    return (best[2], best[0]) if best else None


# ---------------------------------------------------------------- reading a project

@dataclass
class Declared:
    names: dict[str, list[str]] = field(default_factory=dict)      # normalised name -> files that declare it (or "command line")
    invalid: list[tuple[str, str]] = field(default_factory=list)   # (text, where): not a usable package name
    notes: list[str] = field(default_factory=list)                 # informational (URL lines, -e lines, ...)
    gaps: list[str] = field(default_factory=list)                  # things that were NOT read; the result cannot be a pass
    files_read: list[str] = field(default_factory=list)

    def add(self, raw: str, where: str) -> None:
        m = _NAME_RE.match(raw.strip())
        if not m or (m.end() < len(raw.strip()) and raw.strip()[m.end()] not in " \t[(<>=!~;@,"):
            self.invalid.append((raw.strip()[:80], where))
            return
        n = normalize(m.group(0))
        files = self.names.setdefault(n, [])
        if where not in files:
            files.append(where)


def _read_text(path: Path, declared: Declared) -> str | None:
    try:
        if path.is_symlink():
            declared.gaps.append(f"{path.name}: is a symbolic link, not read")
            return None
        if not path.is_file():
            return None
        if path.stat().st_size > MAX_FILE_BYTES:
            declared.gaps.append(f"{path.name}: larger than {MAX_FILE_BYTES} bytes, not read")
            return None
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError as e:
        declared.gaps.append(f"{path.name}: could not be read ({type(e).__name__})")
        return None


_REF_RE = re.compile(r"(?:-r|-c|--requirement|--constraint)(?:\s*=\s*|\s+)(\S+)")


def parse_requirements(text: str, where: str, declared: Declared, referenced: set[str]) -> None:
    for raw in text.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).rstrip(" \\\t").strip()
        if not line:
            continue
        if line.startswith("-"):
            ref = _REF_RE.fullmatch(line)
            if ref:
                referenced.add(ref.group(1))
            elif not line.startswith("--hash"):
                declared.notes.append(f"{where}: option line not checked: {line[:60]}")
            continue
        if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", line) or line.startswith((".", "/", "~")):
            declared.notes.append(f"{where}: URL or path requirement not checked: {line[:60]}")
            continue
        declared.add(line, where)


def _pyproject_requirements(doc: dict) -> list[str]:
    out: list[str] = []
    project = doc.get("project") if isinstance(doc.get("project"), dict) else {}
    out += [x for x in project.get("dependencies", []) if isinstance(x, str)]
    for group in (project.get("optional-dependencies") or {}).values():
        out += [x for x in group if isinstance(x, str)]
    for group in (doc.get("dependency-groups") or {}).values():
        out += [x for x in group if isinstance(x, str)]        # include-group entries are tables and are skipped
    out += [x for x in (doc.get("build-system") or {}).get("requires", []) if isinstance(x, str)]
    poetry = (doc.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}]
    tables += [g.get("dependencies") or {} for g in (poetry.get("group") or {}).values() if isinstance(g, dict)]
    for t in tables:
        out += [k for k in t if isinstance(k, str) and k.lower() != "python"]
    return out


def read_project(directory: Path) -> Declared:
    d = Declared()
    referenced: set[str] = set()
    try:
        candidates = sorted(p for p in directory.iterdir() if re.fullmatch(r"(?i)requirements.*\.txt", p.name) or p.name == "pyproject.toml")
    except OSError as e:
        d.gaps.append(f"{directory}: could not be listed ({type(e).__name__})")
        return d
    for p in candidates:
        text = _read_text(p, d)
        if text is None:
            continue
        d.files_read.append(p.name)
        if p.name == "pyproject.toml":
            try:
                for req in _pyproject_requirements(tomllib.loads(text)):
                    d.add(req, p.name)
            except (tomllib.TOMLDecodeError, AttributeError, TypeError) as e:
                d.gaps.append(f"pyproject.toml: could not be parsed ({type(e).__name__}); its dependencies were not checked")
        else:
            parse_requirements(text, p.name, d, referenced)
    for ref in sorted(referenced):
        if ref not in d.files_read:
            d.gaps.append(f"{ref}: referenced with -r/-c but not read (only requirements*.txt directly in the directory are read)")
    if not d.files_read and not d.gaps:
        d.gaps.append("no requirements*.txt or pyproject.toml found in the directory")
    return d


# ---------------------------------------------------------------- online lookup

@dataclass
class Lookup:
    status: str                    # "found" | "not_found" | "could_not_check"
    first_upload: str | None = None
    age_days: float | None = None
    detail: str = ""


Fetch = Callable[[str], tuple[int, bytes]]


def fetch_simple(name: str) -> tuple[int, bytes]:
    """HTTPS GET of the PyPI Simple API (JSON) for one project name. Returns (status, body); raises OSError on network problems."""
    req = urllib.request.Request(SIMPLE_URL.format(name=name), headers={
        "Accept": "application/vnd.pypi.simple.v1+json", "User-Agent": f"saferun/{__version__} (check-names; name lookup only)"})
    try:
        with urllib.request.urlopen(req, timeout=LOOKUP_TIMEOUT_S) as r:
            body = r.read(MAX_RESPONSE_BYTES + 1)
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, b""


def lookup_one(name: str, fetch: Fetch | None = None, now: datetime | None = None) -> Lookup:
    fetch = fetch or fetch_simple
    if not _NORMALIZED_RE.fullmatch(name):
        return Lookup("could_not_check", detail="not a valid package name, nothing was sent")
    try:
        status, body = fetch(name)
    except (OSError, TimeoutError, ValueError) as e:
        return Lookup("could_not_check", detail=f"{type(e).__name__}: {e}"[:200])
    if status == 404:
        return Lookup("not_found")
    if status != 200:
        return Lookup("could_not_check", detail=f"unexpected HTTP status {status}")
    if len(body) > MAX_RESPONSE_BYTES:
        return Lookup("could_not_check", detail="response too large")
    try:
        files = json.loads(body).get("files")
        times = [datetime.fromisoformat(f["upload-time"].replace("Z", "+00:00")) for f in files if isinstance(f, dict) and f.get("upload-time")]
    except (ValueError, AttributeError, TypeError, KeyError):
        return Lookup("could_not_check", detail="unexpected response format")
    if not times:
        return Lookup("found", detail="project exists but lists no uploaded files")
    first = min(times)
    now = now or datetime.now(timezone.utc)
    return Lookup("found", first_upload=first.date().isoformat(), age_days=max(0.0, (now - first).total_seconds() / 86400))


def lookup_many(names: list[str], fetch: Fetch | None = None, now: datetime | None = None) -> dict[str, Lookup]:
    out = {n: Lookup("could_not_check", detail=f"more than {MAX_NAMES} names; not looked up") for n in names[MAX_NAMES:]}
    todo = names[:MAX_NAMES]
    with ThreadPoolExecutor(max_workers=LOOKUP_WORKERS) as ex:
        for n, res in zip(todo, ex.map(lambda x: lookup_one(x, fetch, now), todo)):
            out[n] = res
    return out


# ---------------------------------------------------------------- the check

@dataclass
class NameResult:
    name: str
    declared_in: list[str]
    state: str                         # "popular" | "similar" | "unknown"
    similar_to: str | None = None
    distance: int | None = None
    lookup: Lookup | None = None

    @property
    def findings(self) -> list[str]:
        out = []
        if self.state == "similar":
            out.append(f"similar to the popular package '{self.similar_to}' (could be a typo or a look-alike)")
        lk = self.lookup
        if lk:
            if lk.status == "not_found":
                out.append("not found on PyPI")
            elif lk.status == "could_not_check":
                out.append(f"could not check online: {lk.detail}")
            elif lk.age_days is not None and lk.age_days < NEW_PACKAGE_DAYS:
                out.append(f"first uploaded {lk.first_upload}, only {lk.age_days:.0f} day(s) ago")
        return out


@dataclass
class NamesReport:
    results: list[NameResult]
    invalid: list[tuple[str, str]]
    notes: list[str]
    gaps: list[str]
    online: bool
    snapshot: Snapshot

    @property
    def flagged(self) -> list[NameResult]:
        return [r for r in self.results if r.findings]

    @property
    def complete(self) -> bool:
        return not self.gaps and not self.invalid

    @property
    def exit_code(self) -> int:
        """0 only when nothing was flagged AND everything that was asked for was checked; otherwise 2 (never a pass)."""
        return 0 if not self.flagged and self.complete else 2

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "exit_code": self.exit_code,
            "complete": self.complete,
            "online": self.online,
            "snapshot": {"source": self.snapshot.source, "date": self.snapshot.date, "names": len(self.snapshot.names)},
            "names": [{"name": r.name, "declared_in": r.declared_in, "state": r.state, "similar_to": r.similar_to,
                       "distance": r.distance, "findings": r.findings,
                       "lookup": None if r.lookup is None else {"status": r.lookup.status, "first_upload": r.lookup.first_upload,
                                                                "age_days": None if r.lookup.age_days is None else round(r.lookup.age_days, 1),
                                                                "detail": r.lookup.detail}} for r in self.results],
            "invalid": [{"text": t, "declared_in": w} for t, w in self.invalid],
            "notes": self.notes,
            "gaps": self.gaps,
        }


def check_names(declared: Declared, online: bool = False, snapshot: Snapshot | None = None, fetch: Fetch | None = None,
                now: datetime | None = None) -> NamesReport:
    snap = snapshot or load_snapshot()
    results = []
    for name in sorted(declared.names):
        if name in snap:
            results.append(NameResult(name, declared.names[name], "popular"))
            continue
        sim = find_similar(name, snap)
        results.append(NameResult(name, declared.names[name], "similar" if sim else "unknown",
                                  similar_to=sim[0] if sim else None, distance=sim[1] if sim else None))
    if online:
        todo = [r for r in results if r.state != "popular"]
        found = lookup_many([r.name for r in todo], fetch, now)
        for r in todo:
            r.lookup = found[r.name]
    return NamesReport(results, declared.invalid, declared.notes, declared.gaps, online, snap)
