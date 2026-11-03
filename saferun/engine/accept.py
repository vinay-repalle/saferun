"""Accepted risks: a file the OWNER of the scan writes to say "I know about this dependency vulnerability, and why it is fine for now".

    [[accept]]
    id = "GHSA-35jh-r3h4-6jhm"      # a vulnerability id or any of its aliases (CVE-...)
    package = "lodash"              # optional: only this package
    reason = "only used in a build script that never sees user input"
    expires = 2026-12-31            # required: the last day the acceptance holds

Rules (documented in docs/cli.md):
  * The file is read ONLY when passed with `saferun scan --accept-file PATH`. It is never picked up from the scanned project, because
    the project is untrusted and could otherwise hide its own vulnerable dependencies.
  * Only dependency findings can be accepted. `reason` and `expires` are mandatory; unknown keys are an error (a typo such as
    `expiry` must not silently turn into a permanent acceptance).
  * An accepted finding is moved out of the verdict but stays visible in the report with its reason and expiry. After the expiry
    date the entry stops applying: the finding counts again and the report says so. An entry that matches nothing is reported too.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .model import CheckStatus, Finding, clean_text

MAX_FILE_BYTES = 256 * 1024
MAX_ENTRIES = 1000
MAX_REASON = 500
_KEYS = {"id", "package", "reason", "expires"}


class AcceptFileError(ValueError):
    """The accept file cannot be used; nothing is accepted then (a broken file must never mean 'accept everything')."""


@dataclass(frozen=True)
class AcceptEntry:
    id: str
    reason: str
    expires: date
    package: str | None = None

    def label(self) -> str:
        return self.id + (f" ({self.package})" if self.package else "")


@dataclass(frozen=True)
class AcceptedFinding:
    finding: Finding
    entry: AcceptEntry

    def to_dict(self) -> dict:
        return {"finding": self.finding.to_dict(), "accepted_id": self.entry.id, "reason": self.entry.reason,
                "expires": self.entry.expires.isoformat()}


def _norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def parse(text: str) -> tuple[AcceptEntry, ...]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise AcceptFileError(f"not valid TOML: {e}") from None
    unknown = sorted(set(data) - {"accept"})
    if unknown:
        raise AcceptFileError(f"unknown top-level key(s): {', '.join(map(repr, unknown))} (only [[accept]] tables are allowed)")
    rows = data.get("accept", [])
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise AcceptFileError("'accept' must be a list of [[accept]] tables")
    if len(rows) > MAX_ENTRIES:
        raise AcceptFileError(f"more than {MAX_ENTRIES} entries")
    out = []
    for n, r in enumerate(rows, 1):
        where = f"[[accept]] #{n}"
        if set(r) - _KEYS:
            raise AcceptFileError(f"{where}: unknown key(s) {', '.join(map(repr, sorted(set(r) - _KEYS)))} (allowed: {', '.join(sorted(_KEYS))})")
        for k in ("id", "reason", "expires"):
            if k not in r:
                raise AcceptFileError(f"{where}: '{k}' is required")
        ident, reason, exp, pkg = r["id"], r["reason"], r["expires"], r.get("package")
        if not isinstance(ident, str) or not ident.strip():
            raise AcceptFileError(f"{where}: 'id' must be a non-empty string")
        if not isinstance(reason, str) or not reason.strip():
            raise AcceptFileError(f"{where}: 'reason' must say why the risk is accepted")
        if len(reason) > MAX_REASON:
            raise AcceptFileError(f"{where}: 'reason' is longer than {MAX_REASON} characters")
        if pkg is not None and (not isinstance(pkg, str) or not pkg.strip()):
            raise AcceptFileError(f"{where}: 'package' must be a non-empty string when given")
        if isinstance(exp, str):
            try:
                exp = date.fromisoformat(exp)
            except ValueError:
                raise AcceptFileError(f"{where}: 'expires' must be a date like 2026-12-31") from None
        if not isinstance(exp, date) or hasattr(exp, "hour"):      # a datetime is a date subclass; only whole days are meaningful
            raise AcceptFileError(f"{where}: 'expires' must be a date like 2026-12-31")
        out.append(AcceptEntry(ident.strip(), clean_text(reason.strip(), MAX_REASON), exp, pkg.strip() if pkg else None))
    return tuple(out)


def load(path) -> tuple[AcceptEntry, ...]:
    p = Path(path)
    try:
        if not p.is_file():
            raise AcceptFileError(f"not a file: {p}")
        if p.stat().st_size > MAX_FILE_BYTES:
            raise AcceptFileError(f"larger than {MAX_FILE_BYTES // 1024} KiB")
        text = p.read_text("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise AcceptFileError(f"cannot read {p}: {e}") from None
    return parse(text)


def _matches(e: AcceptEntry, f: Finding) -> bool:
    if f.category != "dependency":
        return False
    if e.package is not None and (f.package is None or _norm_pkg(e.package) != _norm_pkg(f.package.name)):
        return False
    return e.id.lower() in {i.lower() for i in (f.rule_id, *f.vulnerability_ids)}


def apply(checks, entries: tuple[AcceptEntry, ...], today: date) -> tuple[list[AcceptedFinding], list[str]]:
    """Move accepted dependency findings out of `checks` (in place). Returns (accepted, notes). Expired entries do not apply."""
    accepted: list[AcceptedFinding] = []
    used: set[AcceptEntry] = set()
    expired_hit: set[AcceptEntry] = set()
    for c in checks:
        kept = []
        for f in c.findings:
            hits = [e for e in entries if _matches(e, f)]
            hit = next((e for e in hits if e.expires >= today), hits[0] if hits else None)   # a current entry wins over an expired one
            if hit is None:
                kept.append(f)
                continue
            used.add(hit)
            if hit.expires < today:
                expired_hit.add(hit)
                kept.append(f)
            else:
                accepted.append(AcceptedFinding(f, hit))
        if len(kept) != len(c.findings):
            c.findings = kept
            if c.status is CheckStatus.FINDINGS and not kept:
                c.status = CheckStatus.PASSED
    notes = []
    for e in entries:
        if e in expired_hit:
            notes.append(f"accept entry {e.label()} expired on {e.expires.isoformat()}: the finding counts again; renew or remove the entry")
        elif e not in used:
            notes.append(f"accept entry {e.label()} did not apply to any finding in this scan (it can be removed)")
    return accepted, notes
