"""Plain-English explanations: the `explanation` field next to the unchanged `message`."""
import json
import re
from pathlib import Path

import pytest

from engine_helpers import SEMGREP_JSON, overrides, tool_run
from saferun import cli, ui
from saferun.engine import (CheckResult, CheckStatus, Finding, PackageRef, Severity, ValidationReport, Verdict,
                            compute_verdict, osv, validate_project)
from saferun.engine import explain as ex
from test_engine_integration import project, routed, tools_present  # noqa: F401  (fixture)

RULES = Path(__file__).resolve().parents[1] / "saferun" / "engine" / "rules" / "python.yml"
FORBIDDEN = re.compile(r"will steal|attacker will|attackers will|will hack|will be hacked|guarantee|completely safe|fully safe"
                       r"|(?:makes?|keeps?) (?:it|you|this|your \w+) (?:safe|secure)|proves? (?:an |that |the )?attack"
                       r"|will definitely|you are (?:safe|protected)", re.I)
TOKEN_KINDS = ("aws-access-key", "github", "slack", "google-api-key", "stripe-live", "pypi", "anthropic")


def finding(rule, category="code", **kw):
    return Finding(check="c", rule_id=rule, severity=Severity.HIGH, message="the original message", category=category, **kw)


def dep(version="4.17.15", fixed=("4.17.21",), name="lodash", rule="GHSA-aaaa"):
    return Finding(check="dependency-vulnerabilities", rule_id=rule, severity=Severity.HIGH, message="m", category="dependency",
                   package=PackageRef(name, version, "npm"), fixed_versions=fixed, fix_kind=osv.fix_kind(version, fixed))


def semgrep_ids():
    return re.findall(r"^  - id: (saferun\.python\.[\w-]+)$", RULES.read_text(), re.M)


KNOWN = ([finding(i) for i in semgrep_ids()]
         + [finding("withheld.private-key", "workspace"), finding("withheld.private-mode", "workspace"),
            finding("python.syntax-error", "syntax"), finding("javascript.syntax-error", "syntax")]
         + [finding(f"withheld.token:{k}", "workspace") for k in TOKEN_KINDS]
         + [finding("secrets.aws-access-token", "secret"), finding("secrets.some-new-vendor-rule", "secret")]
         + [dep(), dep("1.2.3", ("1.3.0",)), dep("1.2.3", ("2.0.0",)), dep(fixed=())])


# ---- coverage -------------------------------------------------------------------------------------------------------------

def test_the_rules_file_still_has_the_eleven_rules_this_table_covers():
    assert len(semgrep_ids()) == 11 and len(set(semgrep_ids())) == 11


@pytest.mark.parametrize("rule_id", semgrep_ids())
def test_every_semgrep_rule_has_an_explanation(rule_id):
    assert ex.explain(finding(rule_id))


def test_the_table_has_no_entries_for_rules_that_do_not_exist():
    assert set(ex._SEMGREP) == {i[len(ex._SEMGREP_PREFIX):] for i in semgrep_ids()}


def test_semgrep_ids_with_a_folder_prefix_still_match():
    assert ex.explain(finding("some.folder.saferun.python.weak-hash")) == ex.explain(finding("saferun.python.weak-hash"))


def test_withheld_secrets_syntax_and_dependency_findings_have_explanations():
    for f in KNOWN:
        assert ex.explain(f), f.rule_id


@pytest.mark.parametrize("f", [finding("saferun.python.not-a-rule"), finding("x"), finding("secretsX", "secret"),
                               finding("withheld.something-new", "workspace"), finding("java.syntax-error", "syntax"),
                               finding("GHSA-aaaa", "dependency")])      # a dependency finding without package data
def test_unknown_rule_ids_have_no_explanation(f):
    assert ex.explain(f) == ""
    assert ex.with_explanation(f) is f


def test_a_code_rule_name_in_another_category_is_not_explained():
    assert ex.explain(finding("saferun.python.weak-hash", "syntax")) == ""


# ---- wording --------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("f", KNOWN, ids=[f.rule_id + str(i) for i, f in enumerate(KNOWN)])
def test_wording_is_honest_short_and_one_line(f):
    text = ex.explain(f)
    assert not FORBIDDEN.search(text), text
    assert 20 < len(text) <= ex.MAX_LEN and "\n" not in text and "  " not in text
    assert text.endswith(".")


def test_no_text_in_the_module_uses_forbidden_certainty_phrases():
    texts = [*ex._SEMGREP.values(), *ex._EXACT.values(), ex._TOKEN, ex._SECRET]
    assert all(not FORBIDDEN.search(t) for t in texts)
    assert "attacker" not in " ".join(texts).lower()


def test_the_secret_text_never_contains_a_value_and_says_it_is_not_shown():
    assert "does not show" in ex._SECRET


# ---- the dependency template ----------------------------------------------------------------------------------------------

def test_dependency_patch():
    t = ex.explain(dep("4.17.15", ("4.17.21",)))
    assert t.startswith("lodash 4.17.15 has a known security problem (GHSA-aaaa)")
    assert "A small update (to 4.17.21 or newer)" in t and "usually low-risk" in t


def test_dependency_minor():
    t = ex.explain(dep("1.2.3", ("1.3.0",)))
    assert "Updating to 1.3.0 or newer" in t and "minor version step" in t


def test_dependency_major():
    t = ex.explain(dep("2.2.0", ("3.2.0",), name="django", rule="PYSEC-2021-9"))
    assert t.startswith("django 2.2.0 has a known security problem (PYSEC-2021-9)")
    assert "Updating to 3.2.0 or newer" in t and "major version jump that may break your code" in t


def test_dependency_no_fixed_version():
    t = ex.explain(dep("1.0.0", ()))
    assert "No fixed version is listed yet" in t and "newer" not in t


def test_dependency_uses_the_nearest_fix_above_the_installed_version():
    t = ex.explain(dep("1.0.0", ("3.0.0", "1.0.5", "0.9.0")))
    assert "to 1.0.5 or newer" in t and "3.0.0" not in t


def test_dependency_with_only_a_commit_hash_names_no_version():
    t = ex.explain(dep("1.0.0", ("a" * 40,)))
    assert "A fix is listed (see 'fixed in' below)" in t and "a" * 40 not in t


def test_dependency_text_does_not_use_the_advisory_text():
    f = Finding(check="dependency-vulnerabilities", rule_id="GHSA-aaaa", severity=Severity.HIGH, message="remote code execution!!",
                category="dependency", package=PackageRef("p", "1.0.0", "PyPI"), fixed_versions=("1.0.1",), fix_kind="patch")
    assert "remote code execution" not in ex.explain(f)


# ---- the JSON field -------------------------------------------------------------------------------------------------------

def test_json_key_is_present_only_when_an_explanation_exists_and_message_is_unchanged():
    f = ex.with_explanation(finding("saferun.python.weak-hash"))
    d = f.to_dict()
    assert d["explanation"] == ex.explain(finding("saferun.python.weak-hash")) and d["message"] == "the original message"
    assert "explanation" not in finding("saferun.python.weak-hash").to_dict()     # not filled in: key absent
    assert "explanation" not in ex.with_explanation(finding("unknown.rule")).to_dict()


def test_a_report_without_explanations_is_serialised_exactly_as_before():
    d = finding("x").to_dict()
    assert "explanation" not in d and set(d) == {"check", "rule_id", "severity", "message", "category", "path", "line", "end_line",
                                                 "package", "vulnerability_ids", "fixed_versions", "cwe"}


def test_schema_version_stays_one():
    rep = ValidationReport(Verdict.PASS, [], True, [])
    assert rep.to_dict()["schema_version"] == 1


def test_with_explanation_keeps_an_existing_one():
    f = finding("saferun.python.weak-hash", explanation="mine")
    assert ex.with_explanation(f).explanation == "mine"


# ---- the engine fills it in -----------------------------------------------------------------------------------------------

def test_validate_project_adds_explanations_and_keeps_messages(tmp_path, ws_root, tools_present):
    p = project(tmp_path, {"app.py": "eval(input())\n", "lib/h.py": "", "requirements.txt": "flask==2.0.0\n"})
    rep = validate_project(p, ctx_overrides=overrides(routed(tool_run(SEMGREP_JSON))))
    d = {f["rule_id"]: f for f in next(c for c in rep.to_dict()["checks"] if c["name"] == "python-static-analysis")["findings"]}
    assert d["saferun.python.dynamic-code-execution"]["message"] == "eval() is dangerous"
    assert "eval() and exec() run text as code" in d["saferun.python.dynamic-code-execution"]["explanation"]
    assert "explanation" in d["saferun.python.weak-hash"] and rep.to_dict()["schema_version"] == 1


# ---- the reports ----------------------------------------------------------------------------------------------------------

def report_with(*findings):
    checks = [CheckResult("python-static-analysis", CheckStatus.FINDINGS, findings=list(findings))]
    verdict, reasons, complete = compute_verdict(checks, "")
    return ValidationReport(verdict, reasons, complete, checks)


def test_text_report_shows_the_line_directly_under_the_message():
    f = ex.with_explanation(finding("saferun.python.weak-hash", path="a.py", line=3))
    lines = cli.render_text(report_with(f), "p").splitlines()
    i = next(n for n, ln in enumerate(lines) if ln == "      the original message")
    assert lines[i + 1] == "      In plain words: " + ex.explain(f)


def test_text_report_without_an_explanation_has_no_line():
    assert "In plain words" not in cli.render_text(report_with(finding("unknown.rule")), "p")


def test_text_report_for_dependency_findings_puts_it_before_package_and_fixed_in():
    out = cli.render_text(report_with(ex.with_explanation(dep())), "p").splitlines()
    i = next(n for n, ln in enumerate(out) if "In plain words" in ln)
    assert out[i + 1].strip().startswith("package:") and out[i + 2].strip().startswith("fixed in:")


@pytest.mark.parametrize("color", [False, True])
def test_styled_report_shows_the_line(color):
    f = ex.with_explanation(finding("saferun.python.weak-hash", path="a.py", line=3))
    out = cli.render_styled(report_with(f), "p", ui.Theme(color))
    flat = re.sub(r"\x1b\[[0-9;]*m", "", out)
    assert "In plain words:" in flat
    assert " ".join(flat.split()).count(ex.explain(f)) == 1       # wrapped, never cut


def test_styled_report_without_an_explanation_has_no_line():
    assert "In plain words" not in cli.render_styled(report_with(finding("unknown.rule")), "p", ui.Theme(False))


def test_explanation_goes_through_the_one_line_sanitiser():
    f = finding("x", explanation="line one\nline two \x1b[31mred\x1b[0m")
    text = cli.render_text(report_with(f), "p")
    styled = cli.render_styled(report_with(f), "p", ui.Theme(True))
    line = next(ln for ln in text.splitlines() if "In plain words" in ln)
    assert "line one line two" in line and "\x1b" not in text
    assert "\x1b[31mred" not in styled


def test_json_output_still_equals_the_report_dict():
    f = ex.with_explanation(finding("saferun.python.weak-hash", path="a.py", line=3))
    d = report_with(f).to_dict()
    assert json.loads(json.dumps(d)) == d and "explanation" in d["checks"][0]["findings"][0]
