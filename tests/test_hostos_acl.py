"""Windows security-descriptor parsing and effective-access evaluation (hostos/acl.py): pure Python, tested on every platform."""
import struct

import pytest

from saferun.hostos import acl
from saferun.hostos.acl import AclUnverifiable, Token

ME, OTHER, GROUP = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-513"
READ, RX, FULL = 0x120089, 0x1200A9, 0x1F01FF   # FILE_GENERIC_READ, read & execute, full control


def sid(s):
    parts = s.split("-")
    subs = [int(x) for x in parts[3:]]
    return bytes([1, len(subs)]) + int(parts[2]).to_bytes(6, "big") + b"".join(struct.pack("<I", x) for x in subs)


def ace(kind, mask, s, flags=0):
    body = struct.pack("<I", mask) + sid(s)
    return struct.pack("<BBH", kind, flags, 4 + len(body)) + body


def allow(s, mask=READ, flags=0):
    return ace(0, mask, s, flags)


def deny(s, mask=READ):
    return ace(1, mask, s)


def descriptor(aces, owner=ME, control=0x8000 | 0x0004, null_dacl=False):
    owner_sid = sid(owner)
    dacl = struct.pack("<BBHHH", 2, 0, 8 + sum(map(len, aces)), len(aces), 0) + b"".join(aces)
    off_owner = 20
    off_dacl = 0 if null_dacl else off_owner + len(owner_sid)
    if null_dacl:
        control &= ~0x0004
    hdr = struct.pack("<BBHIIII", 1, 0, control, off_owner, 0, 0, off_dacl)
    return hdr + owner_sid + (b"" if null_dacl else dacl)


def dacl_of(*aces):
    return acl.parse_descriptor(descriptor(list(aces))).dacl


def tok(*sids, deny_only=()):
    return Token(frozenset(sids), frozenset(deny_only))


def test_sid_roundtrip():
    assert acl.sid_to_str(sid("S-1-5-32-544")) == ("S-1-5-32-544", 16)
    assert acl.sid_to_str(sid("S-1-1-0"))[0] == "S-1-1-0"


def test_parse_reads_owner_aces_and_protection():
    d = acl.parse_descriptor(descriptor([allow(ME), deny(OTHER)], control=0x8000 | 0x4 | 0x1000))
    assert d.owner == ME and d.protected and [(a.allow, a.sid) for a in d.dacl] == [(True, ME), (False, OTHER)]


def test_generic_rights_are_expanded():
    d = acl.parse_descriptor(descriptor([allow(ME, 0x80000000)]))   # GENERIC_READ
    assert acl.can(d.dacl, tok(ME), acl.READ_FILE) and not acl.can(d.dacl, tok(ME), 0x2)   # no FILE_WRITE_DATA


@pytest.mark.parametrize("garbage", [b"", b"\x01" * 10, descriptor([allow(ME)])[:-3], b"\x02" + descriptor([allow(ME)])[1:]])
def test_malformed_descriptors_fail_closed(garbage):
    with pytest.raises(AclUnverifiable):
        acl.parse_descriptor(garbage)


@pytest.mark.parametrize("kind", [2, 5, 6, 9, 10, 0x11])   # audit, object and callback ACE types are not understood -> unverifiable
def test_unknown_ace_types_fail_closed(kind):
    with pytest.raises(AclUnverifiable):
        acl.parse_descriptor(descriptor([ace(kind, READ, ME)]))


def test_null_dacl_grants_everyone_and_empty_dacl_nobody():
    assert acl.can(acl.parse_descriptor(descriptor([], null_dacl=True)).dacl, tok(OTHER), acl.READ_FILE)
    assert not acl.can(dacl_of(), tok(ME), acl.READ_FILE)


def test_allow_through_a_group_membership():
    d = dacl_of(allow(GROUP))
    assert acl.can(d, tok(ME, GROUP), acl.READ_FILE) and not acl.can(d, tok(ME), acl.READ_FILE)


def test_deny_before_allow_wins_and_allow_before_deny_wins():
    assert not acl.can(dacl_of(deny(ME), allow(ME)), tok(ME), acl.READ_FILE)
    assert acl.can(dacl_of(allow(ME), deny(ME)), tok(ME), acl.READ_FILE)


def test_deny_applies_through_groups_and_deny_only_groups():
    assert not acl.can(dacl_of(deny(GROUP), allow(ME)), tok(ME, GROUP), acl.READ_FILE)
    assert not acl.can(dacl_of(deny(GROUP), allow(ME)), tok(ME, deny_only=[GROUP]), acl.READ_FILE)
    assert not acl.can(dacl_of(allow(GROUP)), tok(ME, deny_only=[GROUP]), acl.READ_FILE)   # a deny-only group never grants


def test_inherit_only_aces_do_not_apply_to_the_object_itself():
    assert not acl.can(dacl_of(allow(ME, flags=0x08)), tok(ME), acl.READ_FILE)
    assert acl.can(dacl_of(allow(ME, flags=0x08 | 0x03)), tok(ME), acl.READ_FILE) is False


def test_directories_need_list_and_traverse():
    only_list = dacl_of(allow(ME, 0x1))
    assert not acl.can(only_list, tok(ME), acl.READ_DIRECTORY) and acl.can(dacl_of(allow(ME, 0x21)), tok(ME), acl.READ_DIRECTORY)


ROOT_ACES = [allow(ME, FULL), allow(acl.SYSTEM, FULL), allow(acl.ADMINISTRATORS, FULL)]
ROOT = dacl_of(*ROOT_ACES)
CALLER = tok(ME, acl.ADMINISTRATORS, acl.EVERYONE, acl.AUTHENTICATED_USERS)


def readable(file_dacl, directory=False, root=ROOT, caller=CALLER):
    return acl.at_least_as_readable(file_dacl, root, caller, directory=directory)


def test_a_file_inheriting_the_root_acl_is_shareable():
    assert readable(ROOT)


def test_a_file_only_the_owner_can_read_is_private_even_if_the_caller_still_gets_in_via_a_group():
    only_me = dacl_of(allow(ME))
    assert not readable(only_me)              # SYSTEM, which can read the project root, cannot read this file


def test_explicit_deny_for_the_caller_makes_a_file_private():
    assert not readable(dacl_of(deny(ME), *ROOT_ACES))


def test_a_file_readable_by_more_than_the_root_is_shareable():
    assert readable(dacl_of(allow(acl.EVERYONE, READ), *ROOT_ACES))


def test_world_readable_root_requires_world_readable_files():
    world_root = dacl_of(allow(acl.EVERYONE, RX), allow(ME, FULL))
    assert readable(world_root, root=world_root)
    assert not readable(dacl_of(allow(ME, FULL)), root=world_root)


def test_null_root_dacl_means_everyone_must_be_able_to_read():
    assert readable(None, root=None) and not readable(dacl_of(allow(ME)), root=None)


def test_directory_rules_use_list_and_traverse():
    assert readable(ROOT, directory=True)
    assert not readable(dacl_of(allow(ME, FULL), allow(acl.SYSTEM, 0x1), allow(acl.ADMINISTRATORS, FULL)), directory=True)   # SYSTEM can list, not traverse


def test_only_trusted_principals():
    trusted = frozenset({ME, acl.SYSTEM, acl.ADMINISTRATORS})
    ok = acl.parse_descriptor(descriptor([allow(ME, FULL), allow(acl.SYSTEM, FULL)]))
    assert acl.only_trusted_principals(ok, trusted) is None
    bad = acl.parse_descriptor(descriptor([allow(ME, FULL), allow(acl.USERS, READ)]))
    assert acl.only_trusted_principals(bad, trusted) == acl.USERS
    assert acl.only_trusted_principals(acl.parse_descriptor(descriptor([], null_dacl=True)), trusted) == acl.EVERYONE
    denied_only = acl.parse_descriptor(descriptor([deny(OTHER), allow(ME, FULL)]))
    assert acl.only_trusted_principals(denied_only, trusted) is None
