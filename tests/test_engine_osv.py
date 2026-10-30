import json

import pytest

from engine_helpers import OSV_JSON, FakeRunner, make_ctx, make_osv_db, tool_run
from saferun.engine import CheckStatus, Severity, osv
from saferun.sandbox import SandboxError
from saferun.sandbox.analyzer import AnalyzerIntegrityError, AnalyzerUnavailable
from saferun.engine.tools import ToolUnavailable


@pytest.fixture(autouse=True)
def have_osv_db(tmp_path, monkeypatch, low_osv_floor):
    """A small but internally consistent offline database so the check proceeds to the runner; the runner itself is faked in these tests."""
    make_osv_db(tmp_path / "osvdb")
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "osvdb"))


def run(tmp_path, runner, files=("package-lock.json", "package.json"), **kw):
    return osv.run_check(make_ctx(tmp_path, files, runner, **kw))


def test_discover_supported_files_and_gaps():
    files = ["requirements.txt", "web/package-lock.json", "web/package.json", "api/package.json", "poetry.lock",
             "node_modules/x/package-lock.json", ".venv/lib/requirements.txt", "tool/pyproject.toml", "Pipfile"]
    locks, unsafe, gaps = osv.discover(files)
    assert locks == ["poetry.lock", "requirements.txt", "web/package-lock.json"] and unsafe == []
    assert any(g.startswith("api/package.json") for g in gaps) and any(g.startswith("tool/pyproject.toml") for g in gaps)
    assert any(g.startswith("Pipfile:") for g in gaps) and not any("web/package.json" in g for g in gaps)


def test_discover_refuses_unsafe_names():
    locks, unsafe, _ = osv.discover(["a:b/package-lock.json", "ok/requirements.txt", "bad\nname/yarn.lock", "-x/uv.lock"])
    assert locks == ["-x/uv.lock", "ok/requirements.txt"]   # leading '-' is safe: passed as --lockfile=./<path>
    assert sorted(unsafe) == sorted(["a:b/package-lock.json", "bad\nname/yarn.lock"])   # ':' would read as a type prefix


def test_parse_normalizes_dedupes_and_maps_severity(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(OSV_JSON, exit_code=1)))
    assert res.status is CheckStatus.FINDINGS
    hi, lo = res.findings          # duplicate (CVE alias of the GHSA) reported once
    assert hi.rule_id == "GHSA-35jh-r3h4-6jhm" and hi.severity is Severity.HIGH      # group score 7.2
    assert hi.vulnerability_ids == ("GHSA-35jh-r3h4-6jhm", "CVE-2021-23337") and hi.fixed_versions == ("4.17.21",)
    assert (hi.package.name, hi.package.version, hi.package.ecosystem) == ("lodash", "4.17.15", "npm")
    assert hi.path is None          # tool-reported path outside the project is not trusted
    assert lo.severity is Severity.LOW and hi.category == "dependency"


def test_finding_path_is_relative_lockfile(tmp_path):
    out = json.loads(OSV_JSON)
    out["results"][0]["source"]["path"] = str(tmp_path / "project" / "package-lock.json")
    res = run(tmp_path, FakeRunner(tool_run(json.dumps(out), exit_code=1)), files=["package-lock.json"])
    assert res.status is CheckStatus.FINDINGS and res.findings[0].path == "package-lock.json"


@pytest.mark.parametrize("score,sev", [("9.8", Severity.CRITICAL), ("7.0", Severity.HIGH), ("4.0", Severity.MEDIUM),
                                       ("0.1", Severity.LOW), ("0", Severity.UNKNOWN)])
def test_score_thresholds(score, sev):
    assert osv._severity({"id": "A"}, {"A": score}) is sev


def test_severity_labels_and_unknown():
    assert osv._severity({"id": "A", "database_specific": {"severity": "MODERATE"}}, {}) is Severity.MEDIUM
    assert osv._severity({"id": "A"}, {}) is Severity.UNKNOWN


def test_clean_scan_passed_and_names_scanned_files(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(json.dumps({"results": []}))), files=["package-lock.json"])
    assert res.status is CheckStatus.PASSED and "package-lock.json" in res.notes[0]


@pytest.mark.parametrize("bad", ["", "nope", "{}", '{"results": 3}', '{"results": [{"packages": 3}]}',
                                 '{"results": [{"packages": [{"package": {}}]}]}',
                                 '{"results": [{"packages": [{"package": {"name": "a"}, "vulnerabilities": [1]}]}]}'])
def test_malformed_output_is_error(tmp_path, bad):
    res = run(tmp_path, FakeRunner(tool_run(bad)), files=["package-lock.json"])
    assert res.status is CheckStatus.ERROR and not res.findings


def test_exit_1_without_readable_findings_is_error(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(json.dumps({"results": []}), exit_code=1)), files=["package-lock.json"])
    assert res.status is CheckStatus.ERROR


@pytest.mark.parametrize("code", [127, 2, 255])
def test_scan_errors(tmp_path, code):
    res = run(tmp_path, FakeRunner(tool_run("", exit_code=code, stderr="network down")), files=["package-lock.json"])
    assert res.status is CheckStatus.ERROR and "network down" in res.detail and not res.findings


def test_no_packages_found_is_incomplete_not_clean(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run("", exit_code=128)), files=["package-lock.json"])
    assert res.status is CheckStatus.INCOMPLETE


def test_timeout_and_output_cap(tmp_path):
    assert run(tmp_path, FakeRunner(tool_run(timed_out=True)), files=["yarn.lock"]).status is CheckStatus.TIMEOUT
    assert run(tmp_path, FakeRunner(tool_run(truncated=True)), files=["yarn.lock"]).status is CheckStatus.ERROR


def _unavailable():
    raise AnalyzerUnavailable("the analyzer image has not been built")


def _tampered():
    raise AnalyzerIntegrityError("analyzer image ID mismatch")


def test_missing_analyzer_image_is_unavailable_never_clean_and_nothing_runs(tmp_path):
    r = FakeRunner(tool_run("{}"))
    res = run(tmp_path, r, files=["package-lock.json"], analyzer_available=_unavailable)
    assert res.status is CheckStatus.UNAVAILABLE and not res.findings and not r.calls and "no host fallback" in res.detail


def test_tampered_analyzer_image_is_error_and_nothing_runs(tmp_path):
    r = FakeRunner(tool_run("{}"))
    res = run(tmp_path, r, files=["package-lock.json"], analyzer_available=_tampered)
    assert res.status is CheckStatus.ERROR and not res.findings and not r.calls and "mismatch" in res.detail


def test_sandbox_failure_is_error_never_clean(tmp_path):
    res = run(tmp_path, FakeRunner(exc=SandboxError("isolation could not be established")), files=["package-lock.json"])
    assert res.status is CheckStatus.ERROR and not res.findings and "no host fallback" in res.detail


def test_missing_database_is_error_with_the_fix_and_nothing_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "nowhere"))
    r = FakeRunner(tool_run("{}"))
    res = run(tmp_path, r, files=["package-lock.json"])
    assert res.status is CheckStatus.ERROR and not r.calls and "saferun osv-db update" in res.detail and not res.findings


def test_tool_vanishing(tmp_path):
    assert run(tmp_path, FakeRunner(exc=ToolUnavailable("x")), files=["uv.lock"]).status is CheckStatus.UNAVAILABLE


def test_manifest_without_lockfile_is_skipped_not_clean(tmp_path):
    r = FakeRunner(tool_run("{}"))
    res = run(tmp_path, r, files=["package.json"])
    assert res.status is CheckStatus.SKIPPED and not r.calls and "package.json" in res.notes[0]


def test_lockfile_plus_uncovered_manifest_is_incomplete(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(json.dumps({"results": []}))), files=["package-lock.json", "api/package.json"])
    assert res.status is CheckStatus.INCOMPLETE and "api/package.json" in res.detail


def test_no_dependency_files(tmp_path):
    assert run(tmp_path, FakeRunner(tool_run("{}")), files=["main.py"]).status is CheckStatus.NOT_APPLICABLE


def test_unpinned_requirements_noted(tmp_path):
    ctx = make_ctx(tmp_path, ["requirements.txt"], FakeRunner(tool_run(json.dumps({"results": []}))))
    (ctx.project / "requirements.txt").write_text("flask==2.0\nrequests>=2\n# c\n-r other.txt\nnumpy\n")
    res = osv.run_check(ctx)
    assert res.status is CheckStatus.PASSED and any("2 requirement(s) not pinned" in n for n in res.notes)


def test_invocation_is_controlled(tmp_path):
    r = FakeRunner(tool_run(json.dumps({"results": []})))
    run(tmp_path, r, files=["package-lock.json", "sub/yarn.lock"], timeout_s=9)
    c = r.calls[0]
    assert c["argv"][:4] == ["/usr/bin/env", "XDG_CACHE_HOME=/osv-db", "/usr/local/bin/osv-scanner", "scan"]
    assert "--offline" in c["argv"] and "--offline-vulnerabilities" in c["argv"]   # always offline
    assert [m[1] for m in c["mounts"]] == ["/osv-db"] and c["env"] is None
    assert c["argv"][-2:] == ["--lockfile=./package-lock.json", "--lockfile=./sub/yarn.lock"] and c["timeout_s"] == 9
    assert "--no-resolve" in c["argv"]


def test_scans_are_offline_whatever_the_options_say(tmp_path, monkeypatch):
    """Phase 5B: there is no online mode; a stray proxy variable or osv_offline=False cannot enable the network."""
    monkeypatch.setenv("HTTPS_PROXY", "http://p")
    for opts in ({}, {"osv_offline": True}, {"osv_offline": False}):
        r = FakeRunner(tool_run(json.dumps({"results": []})))
        run(tmp_path, r, files=["package-lock.json"], options=opts)
        argv = r.calls[0]["argv"]
        assert "--offline" in argv and "--offline-vulnerabilities" in argv and r.calls[0]["env"] is None


def test_lockfile_cap(tmp_path):
    files = [f"d{i}/package-lock.json" for i in range(osv.MAX_LOCKFILES + 3)]
    res = run(tmp_path, FakeRunner(tool_run(json.dumps({"results": []}))), files=files)
    assert res.status is CheckStatus.INCOMPLETE and "beyond the limit" in res.detail


def test_requirements_txt_is_a_manifest_not_a_lockfile():
    assert "requirements.txt" not in osv.PY_LOCKFILES and "requirements.txt" in osv.PY_REQUIREMENTS
    assert set(osv.PY_LOCKFILES) == {"poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock"}
    assert "requirements.txt" in osv.SUPPORTED and "requirements-dev.txt" not in osv.SUPPORTED
    locks, _, gaps = osv.discover(["requirements.txt", "pyproject.toml"])
    assert locks == ["requirements.txt"] and "no Python lockfile" in gaps[0] and "scanned separately" in gaps[0]


def test_unpinned_note_says_manifest_and_lower_bound(tmp_path):
    ctx = make_ctx(tmp_path, ["requirements.txt"], FakeRunner(tool_run(json.dumps({"results": []}))))
    (ctx.project / "requirements.txt").write_text("flask>=1.0\n")
    notes = osv.run_check(ctx).notes           # database freshness notes follow the existing ones, so search by content, not position
    assert any("not a lockfile" in n and "lower bound" in n for n in notes)


def test_error_detail_prefers_error_lines_over_progress(tmp_path):
    stderr = ("Starting filesystem walk for root: /\nScanned /x/requirements.txt file and found 1 package\n"
              "End status: 0 dirs visited\nError during extraction: request failed: connection refused\n")
    res = run(tmp_path, FakeRunner(tool_run("", exit_code=127, stderr=stderr)), files=["package-lock.json"])
    assert "connection refused" in res.detail and "End status" not in res.detail


def test_exit_127_with_clean_looking_json_is_still_an_error(tmp_path):
    """Real osv-scanner 2.7.0 prints {"results": []} with exit 127 when the network is down."""
    res = run(tmp_path, FakeRunner(tool_run(json.dumps({"results": []}), exit_code=127, stderr="request failed")),
              files=["package-lock.json"])
    assert res.status is CheckStatus.ERROR


def _lock(tmp_path, body, name="package-lock.json"):
    ctx = make_ctx(tmp_path, [name], FakeRunner(tool_run(json.dumps({"results": []}))))
    (ctx.project / name).write_text(body)
    return ctx


V3 = '{"lockfileVersion":3,"packages":{"":{"name":"t"},"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}%s}}'


def test_npm_entries_osv_cannot_match_make_check_incomplete(tmp_path):
    """Real osv-scanner 2.7.0: no `resolved` URL -> 'found 1 package', no results, exit 0 (a silent miss)."""
    assert osv.run_check(_lock(tmp_path, V3 % "")).status is CheckStatus.PASSED
    res = osv.run_check(_lock(tmp_path, V3 % ',"node_modules/lodash":{"version":"4.17.15"}'))
    assert res.status is CheckStatus.INCOMPLETE and "1 package(s) without a registry URL" in res.detail


@pytest.mark.parametrize("entry,expected", [
    ('"node_modules/x":{"version":"1.0.0","resolved":"git+ssh://git@github.com/x/x.git#abc"}', 1),
    ('"node_modules/x":{"version":"1.0.0","link":true}', 0),
    ('"node_modules/x":{"version":"1.0.0","resolved":"https://r/x.tgz"}', 0),
    ('"node_modules/x":{"resolved":"file:../x"}', 0),
])
def test_npm_unmatched_counting(tmp_path, entry, expected):
    p = tmp_path / "package-lock.json"
    p.write_text(V3 % ("," + entry))
    assert osv.npm_unmatched(p) == expected


def test_npm_unmatched_v1_and_garbage(tmp_path):
    p = tmp_path / "l.json"
    p.write_text('{"lockfileVersion":1,"dependencies":{"a":{"version":"1","resolved":"https://r/a","dependencies":{"b":{"version":"2"}}}}}')
    assert osv.npm_unmatched(p) == 1
    for bad in ("nope", "[]", ""):
        p.write_text(bad)
        assert osv.npm_unmatched(p) is None
    assert osv.npm_unmatched(tmp_path / "missing") is None


def test_requirements_variants_are_a_reported_gap_not_silently_ignored(tmp_path):
    _, _, gaps = osv.discover(["requirements-dev.txt", "reqs/dev-requirements.txt", "requirements.txt"])
    assert len(gaps) == 2 and all("not scanned" in g for g in gaps)
    res = run(tmp_path, FakeRunner(tool_run("{}")), files=["requirements-dev.txt"])
    assert res.status is CheckStatus.SKIPPED
