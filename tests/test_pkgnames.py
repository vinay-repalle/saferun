"""`saferun check-names`: snapshot, similarity rule, project reading, online lookup (always mocked: no test touches the network)."""
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from saferun import cli, pkgnames as P

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)
SNAP = P.parse_snapshot("# source: test\n# date: 2026-01-01\nrequests\nnumpy\ndjango\npandas\nsix\nboto3\nsqlalchemy-utils\nbeautifulsoup4\n")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the network was used")
    monkeypatch.setattr(urllib.request, "urlopen", boom)


# ---------------------------------------------------------------- snapshot

def test_bundled_snapshot_is_well_formed():
    snap = P.load_snapshot()
    assert 8500 <= len(snap.names) <= 10000
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", snap.date) and snap.source.startswith("https://")
    assert all(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", n) for n in snap.names)
    assert len(set(snap.names)) == len(snap.names)
    assert {"requests", "numpy", "boto3"} <= set(snap.names[:50])


def test_snapshot_is_packaged():
    root = Path(__file__).resolve().parent.parent
    assert "data/*.txt" in (root / "pyproject.toml").read_text()
    assert (root / "saferun" / "data" / "top_pypi.txt").is_file()


def test_parse_snapshot_ignores_comments_blanks_invalid_and_duplicates():
    s = P.parse_snapshot("# source: x\n# date: d\n\nfoo\nBad Name\nfoo\nbar\n")
    assert s.names == ("foo", "bar") and s.source == "x" and s.date == "d" and s.rank["bar"] == 1


# ---------------------------------------------------------------- similarity

@pytest.mark.parametrize("a,b,limit,expected", [
    ("requests", "requests", 2, 0), ("reqeusts", "requests", 2, 1), ("reques", "requests", 2, 2),
    ("requestss", "requests", 2, 1), ("rexuests", "requests", 2, 1), ("abcdefgh", "requests", 2, 3), ("a", "abcdef", 2, 3),
])
def test_edit_distance_counts_swaps_as_one(a, b, limit, expected):
    assert P.edit_distance(a, b, limit) == expected


@pytest.mark.parametrize("name,popular,dist", [
    ("reqeusts", "requests", 1), ("djnago", "django", 1), ("pandsa", "pandas", 1), ("numpyy", "numpy", 1),
    ("sqlalchemy-utlis", "sqlalchemy-utils", 1), ("beautifulsoap4", "beautifulsoup4", 1), ("beautifulsoupp44", "beautifulsoup4", 2),
])
def test_similar_names_are_found(name, popular, dist):
    assert P.find_similar(name, SNAP) == (popular, dist)


@pytest.mark.parametrize("name", [
    "requests", "numpy",              # in the snapshot: never "similar" to another entry
    "sx", "sit", "sip", "sixx",       # 4 characters or fewer: never matched, not even to `six`
    "completely-different", "my-internal-lib",
])
def test_non_matches(name):
    assert P.find_similar(name, SNAP) is None


def test_two_edits_need_eight_characters():
    assert P.find_similar("reqeusta", SNAP) == ("requests", 2)       # 8 characters
    assert P.find_similar("djanggo2", SNAP) is None                  # 6-character target: only 1 edit allowed
    assert P.find_similar("pandsaa", SNAP) is None                   # 7 characters: only 1 edit allowed, this is 2


def test_closest_then_most_popular_wins():
    s = P.parse_snapshot("abcdefgh\nabcdefgx\nabcdefgy\n")
    assert P.find_similar("abcdefgz", s) == ("abcdefgh", 1)


def test_index_agrees_with_brute_force():
    snap = P.load_snapshot()
    names = [n for n in snap.names[:3000] if len(n) >= 5][::37]
    probes = [n[:-1] for n in names] + [n[1] + n[0] + n[2:] for n in names] + [n + "x" for n in names] + [n[:3] + "q" + n[4:] for n in names]
    for q in probes:
        fast = P.find_similar(q, snap)
        slow = None
        if q not in snap and len(q) > 4:
            for pop in snap.names:
                lim = P.allowed_distance(q, pop)
                if lim:
                    d = P.edit_distance(q, pop, lim)
                    if d <= lim and (slow is None or (d, snap.rank[pop]) < (slow[1], snap.rank[slow[0]])):
                        slow = (pop, d)
        assert fast == slow, q


# ---------------------------------------------------------------- reading a project

def test_requirements_parsing(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "Requests==2.31 --hash=sha256:abc\nflask[async]>=2 ; python_version>'3.8'  # note\nmy_lib @ https://x.org/a.whl\n"
        "-r base.txt\n--requirement=other.txt\n-e .\n--index-url https://x\nhttps://x.org/b.whl\n./local\n\n# only a comment\nnumpy \\\n    --hash=sha256:1\n")
    d = P.read_project(tmp_path)
    assert sorted(d.names) == ["flask", "my-lib", "numpy", "requests"]
    assert d.names["my-lib"] == ["requirements.txt"]
    assert sorted(g.split(":")[0] for g in d.gaps) == ["base.txt", "other.txt"]      # referenced files that were not read
    assert any("-e ." in n for n in d.notes) and any("--index-url" in n for n in d.notes) and any("https://x.org/b.whl" in n for n in d.notes)


def test_referenced_file_that_is_read_is_not_a_gap(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r requirements-dev.txt\nrequests\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest\n")
    d = P.read_project(tmp_path)
    assert d.gaps == [] and sorted(d.names) == ["pytest", "requests"]


def test_pyproject_parsing(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[build-system]\nrequires=["setuptools>=61"]\n[project]\nname="x"\ndependencies=["requests>=2","Zope.Interface"]\n'
        '[project.optional-dependencies]\ndev=["pytest"]\n[dependency-groups]\ntest=["coverage",{include-group="dev"}]\n'
        '[tool.poetry.dependencies]\npython="^3.12"\nflask="*"\n[tool.poetry.group.docs.dependencies]\nsphinx="*"\n')
    d = P.read_project(tmp_path)
    assert sorted(d.names) == ["coverage", "flask", "pytest", "requests", "setuptools", "sphinx", "zope-interface"]
    assert d.gaps == []


def test_bad_toml_is_a_gap_not_a_pass(tmp_path):
    (tmp_path / "pyproject.toml").write_text("this is [not toml")
    d = P.read_project(tmp_path)
    assert d.names == {} and any("pyproject.toml" in g for g in d.gaps)
    assert P.check_names(d, snapshot=SNAP).exit_code == 2


def test_symlink_and_oversized_files_are_not_read(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("flask\n")
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "requirements.txt").symlink_to(secret)
    (proj / "requirements-big.txt").write_text("a\n" * P.MAX_FILE_BYTES)
    d = P.read_project(proj)
    assert d.names == {} and len(d.gaps) == 2


def test_empty_directory_is_a_gap(tmp_path):
    d = P.read_project(tmp_path)
    assert d.gaps and P.check_names(d, snapshot=SNAP).exit_code == 2


def test_invalid_names_are_reported(tmp_path):
    d = P.Declared()
    d.add("bad/name", "command line")
    d.add("$(rm -rf)", "command line")
    assert d.names == {} and len(d.invalid) == 2
    assert P.check_names(d, snapshot=SNAP).exit_code == 2


# ---------------------------------------------------------------- online lookup

def sim(files):
    return 200, json.dumps({"name": "x", "files": files}).encode()


def test_lookup_found_computes_age_from_first_upload():
    lk = P.lookup_one("foo", lambda n: sim([{"upload-time": "2026-10-20T00:00:00.000000Z"}, {"upload-time": "2026-10-30T12:00:00Z"}]), NOW)
    assert lk.status == "found" and lk.first_upload == "2026-10-20" and round(lk.age_days) == 14


def test_lookup_not_found():
    assert P.lookup_one("foo", lambda n: (404, b""), NOW).status == "not_found"


@pytest.mark.parametrize("fetch", [
    lambda n: (500, b""), lambda n: (200, b"not json"), lambda n: (200, b'{"files": 5}'), lambda n: (200, b'{"files":[{"upload-time":"nope"}]}'),
    lambda n: (200, b"x" * (P.MAX_RESPONSE_BYTES + 1)), lambda n: (_ for _ in ()).throw(OSError("offline")),
    lambda n: (_ for _ in ()).throw(TimeoutError("slow")),
])
def test_every_failure_is_could_not_check(fetch):
    assert P.lookup_one("foo", fetch, NOW).status == "could_not_check"


def test_invalid_name_is_never_sent():
    sent = []
    assert P.lookup_one("../etc", lambda n: sent.append(n) or (200, b"{}"), NOW).status == "could_not_check" and not sent


def test_lookup_cap():
    names = [f"n{i}" for i in range(P.MAX_NAMES + 3)]
    res = P.lookup_many(names, lambda n: (404, b""), NOW)
    assert [res[n].status for n in names[-3:]] == ["could_not_check"] * 3 and res[names[0]].status == "not_found"


def declared(*names):
    d = P.Declared()
    for n in names:
        d.add(n, "requirements.txt")
    return d


def test_offline_never_calls_the_network_and_unknown_is_not_a_finding():
    rep = P.check_names(declared("requests", "my-internal-lib"), snapshot=SNAP, fetch=lambda n: pytest.fail("fetch called"))
    assert rep.exit_code == 0 and [r.state for r in rep.results] == ["unknown", "popular"] and rep.results[0].lookup is None


def test_similar_name_is_flagged_offline():
    rep = P.check_names(declared("reqeusts"), snapshot=SNAP)
    assert rep.exit_code == 2 and rep.flagged[0].similar_to == "requests"


def test_online_only_sends_names_outside_the_snapshot():
    sent = []

    def fetch(n):
        sent.append(n)
        return sim([{"upload-time": "2020-01-01T00:00:00Z"}])
    rep = P.check_names(declared("requests", "numpy", "some-lib"), online=True, snapshot=SNAP, fetch=fetch, now=NOW)
    assert sent == ["some-lib"] and rep.exit_code == 0


def test_online_new_package_not_found_and_failure_are_all_exit_2():
    results = {"new-lib": sim([{"upload-time": "2026-11-01T00:00:00Z"}]), "ghost-lib": (404, b"")}

    def fetch(n):
        if n == "down-lib":
            raise OSError("offline")
        return results[n]
    rep = P.check_names(declared("new-lib", "ghost-lib", "down-lib", "requests"), online=True, snapshot=SNAP, fetch=fetch, now=NOW)
    by = {r.name: r.findings[0] for r in rep.flagged}
    assert rep.exit_code == 2 and len(by) == 3
    assert "only 2 day(s) ago" in by["new-lib"] and by["ghost-lib"] == "not found on PyPI" and by["down-lib"].startswith("could not check online")


# ---------------------------------------------------------------- command line

def run(capsys, *argv):
    code = cli.main(["check-names", "--color", "never", *argv])
    return code, capsys.readouterr()


def test_cli_needs_input_and_a_real_directory(capsys, tmp_path):
    assert run(capsys)[0] == 64
    assert run(capsys, "--project", str(tmp_path / "missing"))[0] == 64


def test_cli_offline_text_and_exit_codes(capsys, tmp_path):
    (tmp_path / "requirements.txt").write_text("requests\nreqeusts\nmy-internal-lib\n")
    code, cap = run(capsys, "--project", str(tmp_path))
    assert code == 2 and "reqeusts" in cap.out and "similar to the popular package 'requests'" in cap.out
    assert "nothing was sent anywhere" in cap.out and "NOT a pass" in cap.out
    code, cap = run(capsys, "requests", "numpy")
    assert code == 0 and "Nothing flagged and everything checked." in cap.out


def test_cli_json(capsys):
    code, cap = run(capsys, "--format", "json", "djnago")
    doc = json.loads(cap.out)
    assert code == 2 == doc["exit_code"] and doc["schema_version"] == 1 and doc["online"] is False
    assert doc["names"][0]["similar_to"] == "django" and doc["snapshot"]["names"] >= 8500


def test_cli_online_failure_is_never_a_pass(capsys, monkeypatch):
    def offline(name):
        raise OSError("no network")
    monkeypatch.setattr(P, "fetch_simple", offline)
    code, cap = run(capsys, "--online", "some-unlisted-lib-zzq")
    assert code == 2 and "could not check online" in cap.out and "pypi.org" in cap.out


def test_cli_hostile_text_cannot_inject_escape_sequences(capsys, tmp_path):
    (tmp_path / "requirements.txt").write_text("\x1b[31mred\nok\x07name\n-e \x1b]0;pwn\x07\n")
    code, cap = run(capsys, "--project", str(tmp_path))
    assert "\x1b" not in cap.out and "\x07" not in cap.out
