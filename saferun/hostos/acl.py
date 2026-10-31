"""Windows security descriptors and effective-access evaluation, in pure Python (no Windows API), so the logic is unit-testable everywhere.

The Windows side (`_win.py`) only fetches the raw self-relative descriptor of an open handle and the caller's token; everything that
decides something lives here and FAILS CLOSED: a descriptor or ACE this module does not fully understand raises `AclUnverifiable`,
and callers treat that as "private / not trusted".

Access evaluation follows the Windows access-check algorithm for a DACL: ACEs are evaluated in stored order (the stored DACL already has
inherited ACEs in effective position); INHERIT_ONLY ACEs are ignored; an ACE applies when its SID is in the token; a deny ACE removes only
rights not yet granted by an earlier ACE; a NULL DACL grants everyone everything and an empty DACL grants nothing.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

EVERYONE = "S-1-1-0"
AUTHENTICATED_USERS = "S-1-5-11"
SYSTEM = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"
USERS = "S-1-5-32-545"

FILE_READ_DATA = FILE_LIST_DIRECTORY = 0x0001
FILE_TRAVERSE = 0x0020
READ_FILE = FILE_READ_DATA
READ_DIRECTORY = FILE_LIST_DIRECTORY | FILE_TRAVERSE   # the Windows counterpart of the POSIX "other r-x" test for directories
_GENERIC = ((0x80000000, 0x120089), (0x40000000, 0x120116), (0x20000000, 0x1200A0), (0x10000000, 0x1F01FF))  # read, write, execute, all
_ACCESS_ALLOWED, _ACCESS_DENIED = 0, 1
_INHERIT_ONLY = 0x08
SE_DACL_PRESENT, SE_DACL_PROTECTED = 0x0004, 0x1000


class AclUnverifiable(ValueError):
    """The security descriptor cannot be fully understood, so no conclusion may be drawn from it."""


@dataclass(frozen=True)
class Ace:
    allow: bool
    mask: int
    sid: str
    inherit_only: bool = False


@dataclass(frozen=True)
class Descriptor:
    owner: str | None
    dacl: tuple[Ace, ...] | None     # None: no DACL at all (everyone has full access)
    protected: bool = False          # inheritance from the parent is blocked


@dataclass(frozen=True)
class Token:
    """The SIDs of a (possibly hypothetical) security token. `deny_only` SIDs match deny ACEs only, as in a real filtered token."""
    sids: frozenset[str]
    deny_only: frozenset[str] = field(default_factory=frozenset)


def sid_to_str(data: bytes, offset: int = 0) -> tuple[str, int]:
    """(`S-1-...`, length in bytes) of the binary SID at `offset`."""
    try:
        revision, count = data[offset], data[offset + 1]
        if revision != 1 or count > 15:
            raise AclUnverifiable("unsupported SID revision or size")
        authority = int.from_bytes(data[offset + 2: offset + 8], "big")
        subs = struct.unpack_from(f"<{count}I", data, offset + 8)
    except (IndexError, struct.error):
        raise AclUnverifiable("truncated SID") from None
    return "S-1-" + "-".join(str(x) for x in (authority, *subs)), 8 + 4 * count


def _expand(mask: int) -> int:
    for generic, specific in _GENERIC:
        if mask & generic:
            mask = (mask & ~generic) | specific
    return mask


def parse_descriptor(data: bytes) -> Descriptor:
    """Parse a self-relative SECURITY_DESCRIPTOR. Raises AclUnverifiable for anything unexpected (conditional or object ACEs, bad offsets)."""
    try:
        revision, _sbz, control, off_owner, _off_group, _off_sacl, off_dacl = struct.unpack_from("<BBHIIII", data, 0)
    except struct.error:
        raise AclUnverifiable("security descriptor too short") from None
    if revision != 1 or not control & 0x8000:   # SE_SELF_RELATIVE
        raise AclUnverifiable("not a self-relative security descriptor")
    owner = sid_to_str(data, off_owner)[0] if off_owner else None
    if not control & SE_DACL_PRESENT or not off_dacl:
        return Descriptor(owner, None, bool(control & SE_DACL_PROTECTED))
    try:
        _rev, _sbz1, acl_size, count, _sbz2 = struct.unpack_from("<BBHHH", data, off_dacl)
    except struct.error:
        raise AclUnverifiable("truncated ACL") from None
    if off_dacl + acl_size > len(data):
        raise AclUnverifiable("ACL larger than the descriptor")
    aces, pos = [], off_dacl + 8
    for _ in range(count):
        try:
            kind, flags, size = struct.unpack_from("<BBH", data, pos)
            mask, = struct.unpack_from("<I", data, pos + 4)
        except struct.error:
            raise AclUnverifiable("truncated ACE") from None
        if kind not in (_ACCESS_ALLOWED, _ACCESS_DENIED) or size < 12 or pos + size > off_dacl + acl_size:
            raise AclUnverifiable(f"unsupported or malformed ACE (type {kind})")
        sid, sid_len = sid_to_str(data, pos + 8)
        if 8 + sid_len > size:
            raise AclUnverifiable("SID longer than its ACE")
        aces.append(Ace(kind == _ACCESS_ALLOWED, _expand(mask), sid, bool(flags & _INHERIT_ONLY)))
        pos += size
    return Descriptor(owner, tuple(aces), bool(control & SE_DACL_PROTECTED))


def effective_access(dacl: tuple[Ace, ...] | None, token: Token) -> int:
    """Rights `token` is granted by `dacl` (restricted to bits that appear in an ACE; callers test the bits they need)."""
    if dacl is None:
        return 0xFFFFFFFF
    granted = denied = 0
    for ace in dacl:
        if ace.inherit_only:
            continue
        if ace.allow:
            if ace.sid in token.sids:
                granted |= ace.mask & ~denied
        elif ace.sid in token.sids or ace.sid in token.deny_only:
            denied |= ace.mask & ~granted
    return granted


def can(dacl, token: Token, wanted: int) -> bool:
    return effective_access(dacl, token) & wanted == wanted


def _principal_token(sid: str) -> Token:
    """A hypothetical user holding `sid`, plus the groups every authenticated user is in."""
    if sid == EVERYONE:
        return Token(frozenset({EVERYONE}))
    return Token(frozenset({sid, EVERYONE, AUTHENTICATED_USERS}))


def readers(dacl, wanted: int) -> list[Token]:
    """Tokens that can read according to `dacl`: a hypothetical user for each SID with an allow ACE for the wanted rights."""
    if dacl is None:
        return [_principal_token(EVERYONE)]
    out = []
    for ace in dacl:
        if ace.allow and not ace.inherit_only and ace.mask & wanted:
            tok = _principal_token(ace.sid)
            if can(dacl, tok, wanted):
                out.append(tok)
    return out


def at_least_as_readable(file_dacl, baseline_dacl, caller: Token, *, directory: bool) -> bool:
    """True iff everyone who can read the project root (the caller, using the real token with its groups, and every principal the root's
    DACL grants read to) can also read this entry. A file narrower than the tree around it is deliberately private: the Windows
    counterpart of "not world-readable" on POSIX. Callers must treat AclUnverifiable (and any other failure) as private."""
    wanted = READ_DIRECTORY if directory else READ_FILE
    # The root itself is always evaluated with the directory rights, whatever the entry is.
    for tok in (caller, *readers(baseline_dacl, READ_DIRECTORY)):
        if can(baseline_dacl, tok, READ_DIRECTORY) and not can(file_dacl, tok, wanted):
            return False
    return True


def only_trusted_principals(desc: Descriptor, trusted: frozenset[str]) -> str | None:
    """None if no principal outside `trusted` is granted anything; else the first offending SID. A missing DACL grants everyone access."""
    if desc.dacl is None:
        return EVERYONE
    for ace in desc.dacl:
        if ace.allow and not ace.inherit_only and ace.mask and ace.sid not in trusted:
            return ace.sid
    return None
