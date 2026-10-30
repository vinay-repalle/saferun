"""Content-based detection of credential material, and output redaction.

Detection is by *content signature*, never by filename. Signatures are high
precision on purpose (a PEM private key must have a base64 body, tokens must
match a vendor format); the list is not exhaustive. Redaction is best-effort
defence in depth: sandboxed code can encode or split a secret before printing.
"""
from __future__ import annotations

import re

MASK = "[REDACTED]"
OVERLAP = 1024          # bytes carried between chunks so a signature can span a boundary
LEARN_MAX = 256 * 1024  # only files up to this size are mined for secret-looking assignments
MAX_LEARNED = 500

_PEM_HDR = r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
_PEM_BODY = r"(?:[ \t]*\r?\n|\\n)(?:[A-Za-z0-9-]+:[^\n]*\n)*\s*[A-Za-z0-9+/=]{40,}"
_PEM_END = r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"

# (kind, byte anchors that must appear before the regex is even tried, pattern)
_SIGNATURES: list[tuple[str, tuple[bytes, ...], str]] = [
    ("private-key", (b"-----BEGIN",), _PEM_HDR + _PEM_BODY),
    ("token:aws-access-key", (b"AKIA", b"ASIA"), r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
    ("token:github", (b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_", b"github_pat_"),
     r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})"),
    ("token:slack", (b"xox",), r"(?<![A-Za-z0-9])xox[abprs]-[0-9A-Za-z-]{10,}"),
    ("token:google-api-key", (b"AIza",), r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}"),
    ("token:stripe-live", (b"_live_",), r"(?<![A-Za-z0-9])[sr]k_live_[0-9A-Za-z]{16,}"),
    ("token:pypi", (b"pypi-AgEI",), r"(?<![A-Za-z0-9])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"),
    ("token:anthropic", (b"sk-ant-",), r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{40,}"),
]
_BYTES = [(k, a, re.compile(p.encode())) for k, a, p in _SIGNATURES]

# Full-block redaction for output: header + body (lookahead) through END marker or end of text.
_REDACT = [re.compile(_PEM_HDR + "(?=" + _PEM_BODY + ").*?(?:" + _PEM_END + r"|\Z)", re.S)]
_REDACT += [re.compile(p) for k, _, p in _SIGNATURES if k != "private-key"]

_KEY = (r"^[ \t]*(?:export[ \t]+)?['\"]?[A-Za-z0-9_.\-]*"
        r"(?:secret|token|passw(?:or)?d|api[_\-]?key|private[_\-]?key|access[_\-]?key|credentials?)"
        r"[A-Za-z0-9_.\-]*['\"]?[ \t]*[=:][ \t]*")
_VALUE = r"(?P<q>['\"]?)(?P<v>[A-Za-z0-9_\-+/=.:@!%^*~]{8,})(?P=q)(?=[\s#,;]|$)"
_ASSIGN = re.compile((_KEY + _VALUE).encode(), re.I | re.M)


class SignatureScanner:
    """Feed a file's chunks in order; returns the first matching kind (never the value)."""

    def __init__(self) -> None:
        self._tail = b""

    def feed(self, chunk: bytes) -> str | None:
        data = self._tail + chunk
        self._tail = data[-OVERLAP:]
        for kind, anchors, rx in _BYTES:
            if any(a in data for a in anchors) and rx.search(data):
                return kind
        return None


class Redactor:
    """Masks secrets in sandbox output. Holds secret values in memory only."""

    def __init__(self) -> None:
        self._values: set[str] = set()

    def learn(self, data: bytes) -> None:
        """Remember values of secret-looking `KEY=value` lines in a file the sandbox can read."""
        if len(data) > LEARN_MAX or b"\0" in data:
            return
        for m in _ASSIGN.finditer(data):
            if len(self._values) >= MAX_LEARNED:
                return
            self._values.add(m.group("v").decode("utf-8", "ignore"))

    def redact(self, text: str) -> tuple[str, int]:
        n = 0
        for v in sorted(self._values, key=len, reverse=True):
            c = text.count(v)
            if c:
                text, n = text.replace(v, MASK), n + c
        for rx in _REDACT:
            text, c = rx.subn(MASK, text)
            n += c
        return text, n


def drop_partial_tail(text: str) -> str:
    """After truncation the last token may be a cut-off secret prefix: drop back to whitespace."""
    cut = max(text.rfind(c) for c in " \t\r\n")
    return text[: cut + 1] if cut >= 0 else ""
