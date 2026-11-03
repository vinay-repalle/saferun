"""Stage 10: patch/minor/major label on dependency fixes, and the accept-risk file (--accept-file)."""
import json
from datetime import date

import pytest

from engine_helpers import OSV_JSON, make_osv_db, overrides, tool_run
from saferun import cli
from saferun.engine import (CheckResult, CheckStatus, Finding, PackageRef, Severity, ValidationOptions, ValidationReport, Verdict,
                            accept, compute_verdict, osv, validate_project)
from test_engine_integration import project

TODAY = date(2026, 11, 3)


def dep(rule="GHSA-aaaa", name="lodash", version="4.17.15", fixed=("4.17.21",), sev=Severity.HIGH, ids=("CVE-2021-1",)):
    return Finding(check="dependency-vulnerabilities", rule_id=rule, severity=sev, message="m", category="dependency", path="requirements.txt",
                   package=PackageRef(name, version, "PyPI"), vulnerability_ids=(rule, *ids), fixed_versions=fixed,
                   fix_kind=osv.fix_kind(version, fixed))


def check(*findings):
    return CheckResult("dependency-vulnerabilities", CheckStatus.FINDINGS, findings=list(findings))


def entries(text):
    return accept.parse(text)


GOOD = '[[accept]]\nid = "GHSA-aaaa"\nreason = "build script only"\nexpires = 2026-12-31\n'


# ---- patch / minor / major ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("installed, fixed, kind", [
    ("4.17.15", ("4.17.21",), "patch"),
    ("1.0", ("1.0.1",), "patch"),
    ("1.2.3", ("1.3.0",), "minor"),
    ("1.2.3", ("2.0.0",), "major"),
    ("2.0", ("3",), "major"),
    ("1.2.3", ("1.2.9", "2.0.0"), "patch"),          # the nearest fix above the installed version decides
    ("1.2.3", ("0.9.0", "2.0.0"), "major"),          # fixes below the installed version are not an upgrade
    ("1.2.3", ("1.2.3",), ""),                       # already at the fixed version: nothing to upgrade to
    ("1.2.3", (), ""),
    ("1.2.3", ("a" * 40,), ""),                      # a commit hash is not a release number
    ("abc", ("1.0.0",), ""),
    ("", ("1.0.0",), ""),
])
def test_fix_kind(installed, fixed, kind):
    assert osv.fix_kind(installed, fixed) == kind


def test_parse_output_sets_fix_kind_and_json_omits_it_when_unknown(tmp_path):
    f = osv.parse_output(OSV_JSON, tmp_path)[0]
    assert (f.package.version, f.fixed_versions, f.fix_kind) == ("4.17.15", ("4.17.21",), "patch")
    assert f.to_dict()["fix_kind"] == "patch"
    assert "fix_kind" not in dep(fixed=()).to_dict()          # reports for unlabelled findings are unchanged


def test_text_report_shows_the_label_in_plan_and_finding():
    rep = ValidationReport(Verdict.FAIL, [], True, [check(dep(), dep("PYSEC-2", "flask", "1.0", ("2.0.0",)))], {"skipped": [], "withheld": []})
    plan = {r["name"]: r for r in cli.upgrade_plan(rep)}
    assert plan["lodash"]["kind"] == "patch" and plan["flask"]["kind"] == "major"
    text = cli.render_text(rep, "p")
    assert "≥ 4.17.21 (patch)" in text and "≥ 2.0.0 (major)" in text
    assert "fixed in: 4.17.21  (nearest fix: patch upgrade)" in text


# ---- accept file parsing --------------------------------------------------------------------------------------------------

def test_parse_valid_entry_and_optional_package():
    (e,) = entries(GOOD + 'package = "Lodash"\n')
    assert (e.id, e.reason, e.expires, e.package) == ("GHSA-aaaa", "build script only", date(2026, 12, 31), "Lodash")
    assert entries('[[accept]]\nid = "X"\nreason = "r"\nexpires = "2027-01-01"\n')[0].expires == date(2027, 1, 1)   # quoted date also fine
    assert entries("") == ()


@pytest.mark.parametrize("text, msg", [
    ("not toml [", "not valid TOML"),
    ('foo = 1\n', "unknown top-level"),
    ('[[accept]]\nid = "X"\nexpires = 2027-01-01\n', "'reason' is required"),
    ('[[accept]]\nid = "X"\nreason = "r"\n', "'expires' is required"),
    ('[[accept]]\nreason = "r"\nexpires = 2027-01-01\n', "'id' is required"),
    ('[[accept]]\nid = "X"\nreason = "  "\nexpires = 2027-01-01\n', "must say why"),
    ('[[accept]]\nid = "X"\nreason = "r"\nexpiry = 2027-01-01\nexpires = 2027-01-01\n', "unknown key"),     # typo must not pass silently
    ('[[accept]]\nid = "X"\nreason = "r"\nexpires = "soon"\n', "date like"),
    ('[[accept]]\nid = "X"\nreason = "r"\nexpires = 2027-01-01T10:00:00\n', "date like"),
    ('[[accept]]\nid = "X"\nreason = "r"\nexpires = 5\n', "date like"),
    ('[[accept]]\nid = ""\nreason = "r"\nexpires = 2027-01-01\n', "non-empty"),
    ('[[accept]]\nid = "X"\nreason = "r"\nexpires = 2027-01-01\npackage = ""\n', "non-empty"),
    ('[[accept]]\nid = "X"\nreason = "' + "x" * 501 + '"\nexpires = 2027-01-01\n', "longer than"),
    ('accept = 3\n', "list of"),
])
def test_parse_rejects_bad_files(text, msg):
    with pytest.raises(accept.AcceptFileError, match=msg):
        accept.parse(text)


def test_load_missing_directory_and_oversized(tmp_path):
    with pytest.raises(accept.AcceptFileError):
        accept.load(tmp_path / "nope.toml")
    with pytest.raises(accept.AcceptFileError):
        accept.load(tmp_path)
    big = tmp_path / "big.toml"
    big.write_text("#" * (accept.MAX_FILE_BYTES + 1))
    with pytest.raises(accept.AcceptFileError, match="larger"):
        accept.load(big)
    ok = tmp_path / "ok.toml"
    ok.write_text(GOOD)
    assert len(accept.load(ok)) == 1


# ---- applying -------------------------------------------------------------------------------------------------------------

def test_accepts_by_id_or_alias_and_package_filter():
    c = check(dep(), dep("GHSA-bbbb", "flask", "1.0", ("2.0.0",), ids=("CVE-2022-9",)))
    acc, notes = accept.apply([c], entries(GOOD + '[[accept]]\nid = "cve-2022-9"\npackage = "FLASK"\nreason = "r"\nexpires = 2027-01-01\n'), TODAY)
    assert [a.finding.rule_id for a in acc] == ["GHSA-aaaa", "GHSA-bbbb"] and notes == []
    assert c.findings == [] and c.status is CheckStatus.PASSED


def test_package_filter_must_match():
    c = check(dep())
    acc, notes = accept.apply([c], entries(GOOD + 'package = "other"\n'), TODAY)
    assert acc == [] and len(c.findings) == 1 and "did not apply to any finding" in notes[0]


def test_expired_entry_does_not_apply_and_is_reported():
    c = check(dep())
    acc, notes = accept.apply([c], entries('[[accept]]\nid = "GHSA-aaaa"\nreason = "r"\nexpires = 2026-11-02\n'), TODAY)
    assert acc == [] and len(c.findings) == 1 and c.status is CheckStatus.FINDINGS
    assert "expired on 2026-11-02" in notes[0]


def test_expiry_day_itself_still_counts_and_a_current_entry_beats_an_expired_one():
    c = check(dep())
    both = entries('[[accept]]\nid = "GHSA-aaaa"\nreason = "old"\nexpires = 2026-01-01\n[[accept]]\nid = "GHSA-aaaa"\nreason = "new"\nexpires = 2026-11-03\n')
    acc, notes = accept.apply([c], both, TODAY)
    assert [a.entry.reason for a in acc] == ["new"] and notes == ["accept entry GHSA-aaaa did not apply to any finding in this scan (it can be removed)"]


def test_only_dependency_findings_can_be_accepted():
    code = Finding(check="python-static-analysis", rule_id="GHSA-aaaa", severity=Severity.HIGH, message="m", path="a.py", line=1)
    c = CheckResult("python-static-analysis", CheckStatus.FINDINGS, findings=[code])
    acc, notes = accept.apply([c], entries(GOOD), TODAY)
    assert acc == [] and c.findings == [code] and "did not apply to any finding" in notes[0]


def test_other_findings_stay_and_status_stays_findings():
    c = check(dep(), dep("PYSEC-9", "flask", "1.0", ("2.0.0",)))
    accept.apply([c], entries(GOOD), TODAY)
    assert [f.rule_id for f in c.findings] == ["PYSEC-9"] and c.status is CheckStatus.FINDINGS


# ---- through the real engine ----------------------------------------------------------------------------------------------

@pytest.fixture
def lodash_project(tmp_path, ws_root, monkeypatch, low_osv_floor):
    make_osv_db(tmp_path / "osvdb")
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "osvdb"))
    return project(tmp_path, {"package.json": "{}", "package-lock.json": "{}"})


def scan(p, ents):
    return validate_project(p, ValidationOptions(accept=ents), ctx_overrides=overrides(
        lambda argv, **kw: tool_run("[]") if argv[0].endswith("gitleaks") else tool_run(OSV_JSON, exit_code=1)))


LODASH = '[[accept]]\nid = "CVE-2021-23337"\npackage = "lodash"\nreason = "dev tooling only"\nexpires = 2999-01-01\n'


def test_without_accept_the_vulnerability_fails_the_scan(lodash_project):
    rep = scan(lodash_project, ())
    assert rep.verdict is Verdict.FAIL and rep.accepted == [] and "accepted" not in rep.to_dict()


def test_accepted_finding_leaves_the_verdict_but_stays_in_the_report(lodash_project):
    rep = scan(lodash_project, entries(LODASH))
    assert [f.rule_id for f in rep.findings] == ["GHSA-xxxx-low"]       # the other finding is not accepted and still counts
    assert rep.verdict is Verdict.WARNING                                # was FAIL: only the accepted HIGH left the verdict
    assert [a.finding.rule_id for a in rep.accepted] == ["GHSA-35jh-r3h4-6jhm"]
    assert any("accepted via --accept-file" in r for r in rep.reasons)
    d = rep.to_dict()
    assert d["accepted"][0]["reason"] == "dev tooling only" and d["accepted"][0]["expires"] == "2999-01-01"
    assert d["accepted"][0]["finding"]["package"]["name"] == "lodash" and d["schema_version"] == 1
    text = cli.render_text(rep, "p")
    assert "Accepted risks (1)" in text and "accepted until 2999-01-01: dev tooling only" in text


def test_accepting_every_finding_gives_pass(lodash_project):
    rep = scan(lodash_project, entries(LODASH + LODASH.replace("CVE-2021-23337", "GHSA-xxxx-low")))
    assert rep.verdict is Verdict.PASS and rep.findings == [] and len(rep.accepted) == 2 and rep.complete


def test_expired_accept_means_the_scan_fails_again(lodash_project):
    rep = scan(lodash_project, entries(LODASH.replace("2999-01-01", "2000-01-01")))
    assert rep.verdict is Verdict.FAIL and rep.accepted == [] and "expired" in rep.accept_notes[0]
    assert "expired" in cli.render_text(rep, "p")


# ---- CLI ------------------------------------------------------------------------------------------------------------------

def stub(monkeypatch):
    seen = []
    rep = ValidationReport(*compute_verdict([]), checks=[], workspace={"skipped": [], "withheld": []})
    monkeypatch.setattr(cli, "validate_project", lambda path, options: seen.append(options) or rep)
    return seen


def test_cli_passes_entries_from_accept_file(tmp_path, monkeypatch):
    seen = stub(monkeypatch)
    f = tmp_path / "acc.toml"
    f.write_text(GOOD)
    proj = tmp_path / "p"
    proj.mkdir()
    cli.main(["scan", str(proj), "--accept-file", str(f)])
    assert [e.id for e in seen[0].accept] == ["GHSA-aaaa"]


@pytest.mark.parametrize("content", [None, "[[accept]]\nid = 'X'\n"])
def test_cli_bad_or_missing_accept_file_is_a_usage_error_and_nothing_is_scanned(tmp_path, monkeypatch, capsys, content):
    seen = stub(monkeypatch)
    f = tmp_path / "acc.toml"
    if content:
        f.write_text(content)
    proj = tmp_path / "p"
    proj.mkdir()
    assert cli.main(["scan", str(proj), "--accept-file", str(f)]) == cli.EXIT_USAGE
    assert seen == [] and "--accept-file" in capsys.readouterr().err


def test_cli_ignores_an_accept_file_inside_the_project_and_says_so(tmp_path, monkeypatch, capsys):
    seen = stub(monkeypatch)
    (tmp_path / ".saferun-accept.toml").write_text(GOOD)
    cli.main(["scan", str(tmp_path)])
    assert seen[0].accept == () and "ignored" in capsys.readouterr().err
