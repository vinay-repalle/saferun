"""Tests that run the REAL Semgrep / OSV-Scanner INSIDE the analyzer container (Phase 5B).
Skipped, visibly, when the analyzer image is not built (docker/analyzer/build.sh) or, for OSV result tests, when no offline
OSV database (`saferun osv-db update`, or SAFERUN_OSV_DB) is available. Nothing needs the network; nothing installs or runs project code."""
import pytest

from saferun.engine import CheckStatus, ValidationOptions, Verdict, osv, osvdb, semgrep, validate_project
from saferun.sandbox.analyzer import verify_analyzer_image


def _analyzer() -> bool:
    try:
        verify_analyzer_image()
        return True
    except Exception:  # noqa: BLE001
        return False


HAVE_ANALYZER = _analyzer()
HAVE_DB = HAVE_ANALYZER and osvdb.validate(osvdb.default_dir(), ["PyPI"]).ok
OSV_ONLY = ValidationOptions(python_analysis=False, python_syntax=False)
SEMGREP_ONLY = ValidationOptions(python_syntax=False, dependency_scan=False)


needs_analyzer = pytest.mark.docker(pytest.mark.skipif(not HAVE_ANALYZER, reason="analyzer image not built"))
needs_osv = needs_semgrep = pytest.mark.skipif(not HAVE_ANALYZER, reason="analyzer image not built (docker/analyzer/build.sh)")
needs_net = pytest.mark.skipif(not HAVE_DB, reason="no offline OSV database for PyPI (saferun osv-db update / SAFERUN_OSV_DB)")


def proj(tmp_path, files):
    p = tmp_path / "p"
    for n, t in files.items():
        (p / n).parent.mkdir(parents=True, exist_ok=True)
        (p / n).write_text(t)
    return p


def osv_check(rep):
    return next(c for c in rep.checks if c.name == osv.NAME)


NPM_LOCK = '{"lockfileVersion":3,"packages":{"":{"name":"t"},"node_modules/%s":{"version":"%s","resolved":"https://registry.npmjs.org/%s/-/%s-%s.tgz"}}}'


@needs_net
def test_real_osv_vulnerable_python_requirement(tmp_path, ws_root):
    rep = validate_project(proj(tmp_path, {"requirements.txt": "django==2.2.0\n"}), OSV_ONLY)
    c = osv_check(rep)
    assert c.status is CheckStatus.FINDINGS and rep.verdict is Verdict.FAIL
    assert {f.package.ecosystem for f in c.findings} == {"PyPI"} and all(f.path == "requirements.txt" for f in c.findings)
    assert any(f.severity.value == "critical" for f in c.findings) and all(f.vulnerability_ids for f in c.findings)
    assert len({f.vulnerability_ids for f in c.findings}) == len(c.findings)      # aliases de-duplicated


@needs_net
def test_real_npm_lockfile_is_not_scanned_and_is_never_a_clean_pass(tmp_path, ws_root):
    rep = validate_project(proj(tmp_path, {"web/package-lock.json": NPM_LOCK % ("lodash", "4.17.15", "lodash", "lodash", "4.17.15")}), OSV_ONLY)
    c = osv_check(rep)
    assert c.status is CheckStatus.NOT_APPLICABLE and not c.findings and osv.JS_NOTE in c.notes and osv.JS_NOTE in c.detail
    assert rep.verdict is not Verdict.PASS


@needs_net
def test_real_osv_clean_result(tmp_path, ws_root):
    c = osv_check(validate_project(proj(tmp_path, {"requirements.txt": "six==1.17.0\n"}), OSV_ONLY))
    assert c.status is CheckStatus.PASSED and not c.findings


@needs_net
def test_real_osv_empty_lockfile_is_incomplete(tmp_path, ws_root):       # exit 128
    c = osv_check(validate_project(proj(tmp_path, {"Pipfile.lock": '{"_meta":{},"default":{},"develop":{}}'}), OSV_ONLY))
    assert c.status is CheckStatus.INCOMPLETE


@needs_net
def test_real_osv_malformed_lockfile_is_error(tmp_path, ws_root):        # exit 127
    rep = validate_project(proj(tmp_path, {"Pipfile.lock": "not json{"}), OSV_ONLY)
    assert osv_check(rep).status is CheckStatus.ERROR and rep.verdict is Verdict.WARNING


@needs_osv
def test_real_osv_without_database_is_error_and_never_clean(tmp_path, ws_root, monkeypatch):
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "no-db-here"))
    rep = validate_project(proj(tmp_path, {"requirements.txt": "django==2.2.0\n"}), OSV_ONLY)
    c = osv_check(rep)
    assert c.status is CheckStatus.ERROR and "osv-db update" in c.detail and not c.findings and rep.verdict is Verdict.WARNING


@needs_net
def test_real_osv_proxy_settings_cannot_make_it_go_online(tmp_path, ws_root, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")              # irrelevant: the container has no network and no host env
    c = osv_check(validate_project(proj(tmp_path, {"requirements.txt": "django==2.2.0\n"}), OSV_ONLY))
    assert c.status is CheckStatus.FINDINGS


@needs_net
def test_real_osv_timeout(tmp_path, ws_root):
    rep = validate_project(proj(tmp_path, {"requirements.txt": "django==2.2.0\n"}), ValidationOptions(**{**vars(OSV_ONLY), "tool_timeout_s": 0.01}))
    assert osv_check(rep).status is CheckStatus.TIMEOUT


@needs_semgrep
def test_real_semgrep_project_semgrepignore_cannot_hide_code(tmp_path, ws_root):
    p = proj(tmp_path, {"hid/h.py": "eval(x)\n", "ok.py": "x = 1\n", ".semgrepignore": "hid/\n"})
    c = next(c for c in validate_project(p, SEMGREP_ONLY).checks if c.name == semgrep.NAME)
    assert [f.path for f in c.findings] == ["hid/h.py"] and c.status is CheckStatus.FINDINGS
    assert (p / ".semgrepignore").exists()                                # the user's original is untouched


@needs_semgrep
def test_real_semgrep_oversized_file_is_reported_not_silently_skipped(tmp_path, ws_root):
    p = proj(tmp_path, {"big.py": "eval(x)\n" + "x = 1\n" * 300_000, "small.py": "x = 1\n"})
    rep = validate_project(p, SEMGREP_ONLY)
    c = next(c for c in rep.checks if c.name == semgrep.NAME)
    assert c.status is CheckStatus.INCOMPLETE and "big.py" in c.detail and rep.verdict is Verdict.WARNING and not rep.complete


@needs_semgrep
def test_real_semgrep_clean_project_is_complete_pass(tmp_path, ws_root):
    p = proj(tmp_path, {"a.py": "print(1)\n", "pkg/b.py": "y = 2\n", "stubs/c.pyi": "def f() -> int: ...\n"})
    c = next(c for c in validate_project(p, SEMGREP_ONLY).checks if c.name == semgrep.NAME)
    assert c.status is CheckStatus.PASSED, (c.status, c.detail)
