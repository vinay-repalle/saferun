"""Secrets scan (gitleaks inside the analyzer container): canned-output unit tests, engine/CLI wiring, build pins, and real-container tests.
Every secret-looking value here is FAKE and is assembled at run time, never written as one literal."""
import ast
import json
import re
from pathlib import Path

import pytest

from engine_helpers import FakeRunner, make_ctx, tool_run
from saferun import cli
from saferun.engine import CheckStatus, ValidationOptions, Verdict, secretscan, validate_project
from saferun.engine.model import Severity
from saferun.sandbox import SandboxError, analyzer as sa, images
from saferun.sandbox.analyzer import AnalyzerIntegrityError

ROOT = Path(__file__).resolve().parent.parent
SENTINEL = "FAKE" + "-secret-value-" + "do-not-leak"        # what a misbehaving tool might put in Secret/Match


def entry(rule="npm-access-token", file="deploy.js", line=2, **extra):
    d = {"RuleID": rule, "Description": "Uncovered an npm access token.", "StartLine": line, "EndLine": line, "StartColumn": 1, "EndColumn": 40,
         "Match": f"token = {SENTINEL}", "Secret": SENTINEL, "File": file, "Fingerprint": f"{file}:{rule}:{line}", "Entropy": 4.2}
    d.update(extra)
    return d


def run(tmp_path, runner, files=("deploy.js",), **kw):
    return secretscan.run_check(make_ctx(tmp_path, list(files), runner, **kw))


# ---- parsing: only rule, path and line are taken ----

def test_finding_has_rule_path_line_and_no_secret_value(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run(json.dumps([entry()]))))
    assert res.status is CheckStatus.FINDINGS and res.tool == f"gitleaks {images.GITLEAKS_VERSION}"
    (f,) = res.findings
    assert (f.rule_id, f.severity, f.path, f.line, f.category, f.cwe) == ("secrets.npm-access-token", Severity.HIGH, "deploy.js", 2, "secret", ("CWE-798",))
    blob = json.dumps(res.to_dict()) + repr(f)
    assert SENTINEL not in blob and "Fingerprint" not in blob and "4.2" not in blob


def test_every_finding_is_high_so_the_verdict_fails():
    from saferun.engine.verdict import compute_verdict
    f = secretscan.parse_output(json.dumps([entry()]), Path("/p"))
    from saferun.engine.model import CheckResult
    verdict, reasons, _ = compute_verdict([CheckResult(secretscan.NAME, CheckStatus.FINDINGS, findings=f)])
    assert verdict is Verdict.FAIL and any("hardcoded-secrets" in r for r in reasons)


def test_duplicates_are_merged_and_the_cap_is_reported(tmp_path):
    out = json.dumps([entry(line=1), entry(line=1), entry(line=2), entry(line=3)])
    res = run(tmp_path, FakeRunner(tool_run(out)), max_findings=2)
    assert [f.line for f in res.findings] == [1, 2] and res.truncated_findings == 1


def test_hostile_values_are_sanitized_and_bounded(tmp_path):
    out = json.dumps([entry(rule="x\x1b[31m‮ y" + "A" * 500, file="../../etc/passwd", line=-5),
                      entry(rule="ok", file="/etc/shadow", line=True)])
    a, b = run(tmp_path, FakeRunner(tool_run(out))).findings
    assert a.path is None and b.path is None and a.line is None and b.line is None
    assert "\x1b" not in a.rule_id and "‮" not in a.rule_id and len(a.rule_id) <= 120 and "\x1b" not in a.message


@pytest.mark.parametrize("bad", ["", "not json", "{}", '{"results": []}', "[1]", '[{"File": "a"}]', '[{"RuleID": ""}]', "[" * 100000,
                                 json.dumps([{"RuleID": "x"}] * (secretscan.MAX_ENTRIES + 1))])
def test_malformed_output_is_error_not_clean(tmp_path, bad):
    res = run(tmp_path, FakeRunner(tool_run(bad)))
    assert res.status is CheckStatus.ERROR and not res.findings and "unusable" in res.detail


def test_clean_scan_is_passed(tmp_path):
    res = run(tmp_path, FakeRunner(tool_run("[]")))
    assert res.status is CheckStatus.PASSED and not res.findings and any("binary files" in n for n in res.notes)


# ---- operational outcomes are never clean ----

def test_not_applicable_without_files(tmp_path):
    assert run(tmp_path, FakeRunner(tool_run("[]")), files=["node_modules/a/x.js"]).status is CheckStatus.NOT_APPLICABLE


@pytest.mark.parametrize("exc,status", [(SandboxError("no docker"), CheckStatus.UNAVAILABLE), (AnalyzerIntegrityError("labels"), CheckStatus.ERROR)])
def test_analyzer_problems_stop_the_check_and_nothing_runs(tmp_path, exc, status):
    runner = FakeRunner(tool_run("[]"))
    def unavailable():
        raise exc
    res = run(tmp_path, runner, analyzer_available=unavailable)
    assert res.status is status and runner.calls == [] and "no host fallback" in res.detail


def test_run_failure_timeout_truncation_and_exit_code(tmp_path):
    assert run(tmp_path, FakeRunner(exc=SandboxError("x"))).status is CheckStatus.ERROR
    assert run(tmp_path, FakeRunner(tool_run("", timed_out=True))).status is CheckStatus.TIMEOUT
    assert run(tmp_path, FakeRunner(tool_run("[]", truncated=True))).status is CheckStatus.ERROR
    res = run(tmp_path, FakeRunner(tool_run("[]", exit_code=1, stderr="could not read " + SENTINEL)))
    assert res.status is CheckStatus.ERROR and SENTINEL not in res.detail        # stderr is never echoed


def test_file_over_the_size_limit_makes_the_check_incomplete(tmp_path):
    ctx = make_ctx(tmp_path, ["a.txt", "big.txt"], FakeRunner(tool_run("[]")))
    (ctx.project / "big.txt").write_bytes(b"x" * (secretscan.MAX_TARGET_MB * 1024 * 1024 + 1))
    res = secretscan.run_check(ctx)
    assert res.status is CheckStatus.INCOMPLETE and "big.txt" in res.detail and not res.findings


def test_project_ignore_files_are_removed_before_the_scan(tmp_path):
    ctx = make_ctx(tmp_path, ["a.txt", ".gitleaksignore", "sub/.gitleaksignore"], FakeRunner(tool_run("[]")))
    res = secretscan.run_check(ctx)
    assert not (ctx.project / ".gitleaksignore").exists() and not (ctx.project / "sub/.gitleaksignore").exists()
    assert res.status is CheckStatus.PASSED and any("2 .gitleaksignore" in n for n in res.notes)


def test_argv_uses_only_the_baked_config_offline_and_redacted():
    argv = secretscan.build_argv()
    assert argv[:3] == [sa.GITLEAKS_EXE, "dir", "."] and argv[argv.index("--config") + 1] == sa.SECRETS_RULES_PATH and argv.count("--config") == 1
    assert {"--ignore-gitleaks-allow", "--redact", "--no-banner"} <= set(argv) and argv[argv.index("--exit-code") + 1] == "0"
    assert argv[argv.index("--report-path") + 1] == "-"
    assert not {"--baseline-path", "-b", "--gitleaks-ignore-path", "-i", "--follow-symlinks", "--verbose", "-v"} & set(argv)


def test_check_module_has_no_host_execution_path():
    tree = ast.parse((ROOT / "saferun" / "engine" / "secretscan.py").read_text())
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) if n.module}
    assert not ({"run_tool", "find_tool", "Popen", "which", "system", "execv"} & names) and not ({"subprocess", "shutil"} & imported)


# ---- wiring: engine option, CLI flag, verdict ----



def test_engine_runs_the_check_and_a_disabled_check_is_skipped(tmp_path, ws_root):
    p = tmp_path / "p"
    p.mkdir()
    (p / "deploy.js").write_text("x\n")
    over = {"analyzer": FakeRunner(tool_run(json.dumps([entry()]))), "analyzer_available": lambda: "sha256:" + "0" * 64}
    only = dict(python_analysis=False, python_syntax=False, dependency_scan=False)
    rep = validate_project(p, ValidationOptions(**only), ctx_overrides=over)
    c = {x.name: x for x in rep.checks}[secretscan.NAME]
    assert c.status is CheckStatus.FINDINGS and rep.verdict is Verdict.FAIL
    assert SENTINEL not in json.dumps(rep.to_dict()) and SENTINEL not in cli.render_text(rep, "p")
    off = validate_project(p, ValidationOptions(secrets_check=False, **only), ctx_overrides=over)
    c = {x.name: x for x in off.checks}[secretscan.NAME]
    assert c.status is CheckStatus.SKIPPED and off.verdict is Verdict.WARNING and not off.complete


def test_cli_flag_and_next_step(monkeypatch, tmp_path, capsys):
    seen = []
    monkeypatch.setattr(cli, "validate_project", lambda path, opts: (seen.append(opts), (_ for _ in ()).throw(SandboxError("stop")))[1])
    cli.main(["scan", str(tmp_path)])
    cli.main(["scan", str(tmp_path), "--no-secrets-check"])
    assert [o.secrets_check for o in seen] == [True, False]
    f = secretscan.parse_output(json.dumps([entry()]), Path("/p"))
    from saferun.engine.model import CheckResult, ValidationReport
    rep = ValidationReport(Verdict.FAIL, ["r"], True, [CheckResult(secretscan.NAME, CheckStatus.FINDINGS, findings=f)])
    assert any("secrets" in s for s in cli._next_steps(rep))
    capsys.readouterr()


# ---- build recipe: pins agree everywhere ----

def test_dockerfile_pins_match_images_module():
    text = (ROOT / "docker" / "analyzer" / "Dockerfile").read_text()
    arg = lambda n: re.search(rf"^ARG {n}=(\S+)$", text, re.M).group(1)  # noqa: E731
    assert arg("GITLEAKS_VERSION") == images.GITLEAKS_VERSION and arg("GITLEAKS_TARBALL_SHA256") == images.GITLEAKS_LINUX_AMD64_TARBALL_SHA256
    assert re.fullmatch(r"[0-9a-f]{64}", images.GITLEAKS_LINUX_AMD64_TARBALL_SHA256)
    assert "ARG SECRETS_RULES_SHA256" in text and "COPY gitleaks.toml /opt/saferun/rules/gitleaks.toml" in text
    assert "sha256sum -c" in text and "--no-same-owner gitleaks" in text
    for label in ("saferun.gitleaks.version", "saferun.secrets-rules.sha256"):
        assert label in text
    build = (ROOT / "docker" / "analyzer" / "build.py").read_text()
    assert "gitleaks.toml" in build and "SECRETS_RULES_SHA256=" in build


def test_release_workflow_stages_checks_and_smoke_tests_gitleaks():
    wf = (ROOT / ".github" / "workflows" / "release-analyzer.yml").read_text()
    for needle in ("saferun/engine/rules/gitleaks.toml", "SECRETS_RULES_SHA256=", "saferun.gitleaks.version=$gitleaks_v", "saferun.secrets-rules.sha256=$SECRETS_RULES_SHA",
                   "gitleaks version", "/opt/saferun/rules/gitleaks.toml", "licenses/gitleaks-v8.30.1-go-module-licenses.txt"):
        assert needle in wf, needle


def test_gitleaks_rules_are_packaged_and_disable_the_generic_rule():
    import tomllib
    cfg = tomllib.loads(secretscan.RULES_FILE.read_text())
    assert cfg["extend"]["useDefault"] is True and cfg["extend"]["disabledRules"] == ["generic-api-key"] and "allowlists" in cfg
    assert "engine/rules/*.toml" in (ROOT / "pyproject.toml").read_text()
    assert "rules/gitleaks.toml" in (ROOT / ".github" / "workflows" / "ci.yml").read_text()


def test_gitleaks_licence_inventory_matches_its_texts():
    lic = ROOT / "docker" / "analyzer" / "licenses"
    assert "MIT License" in (lic / "gitleaks-v8.30.1-LICENSE").read_text(encoding="utf-8")
    inv = (lic / "gitleaks-v8.30.1-go-modules.md").read_text(encoding="utf-8")
    texts = (lic / "gitleaks-v8.30.1-go-module-licenses.txt").read_text(encoding="utf-8")
    rows = [l for l in inv.splitlines() if l.startswith("| ") and not l.startswith(("| Module", "|---"))]
    assert len(rows) == 65 and all(len(r.split("|")) == 6 and "UNDETERMINED" not in r and "NO LICENSE" not in r for r in rows)
    for r in rows:
        module, version = (c.strip() for c in r.split("|")[1:3])
        assert f"\n{module} {version} -- " in texts, module
    assert "Go standard library and runtime" in texts and "MPL-2.0" in inv
    notices = (ROOT / "docker" / "analyzer" / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert "gitleaks" in notices and "gitleaks-v8.30.1-go-modules.md" in notices


def test_labels_include_gitleaks_and_the_old_image_is_refused(monkeypatch):
    old = {"saferun.analyzer": "1", "saferun.semgrep.version": images.SEMGREP_VERSION, "saferun.osv-scanner.version": images.OSV_SCANNER_VERSION,
           "saferun.rules.sha256": sa.rules_sha256()}
    with pytest.raises(AnalyzerIntegrityError, match="gitleaks"):
        sa.check_labels(old)


# ---- real analyzer container ----

def _analyzer() -> bool:
    try:
        sa.verify_analyzer_image()
        return True
    except Exception:  # noqa: BLE001
        return False


HAVE_ANALYZER = _analyzer()
needs_analyzer = pytest.mark.docker(pytest.mark.skipif(not HAVE_ANALYZER, reason="analyzer image not built or not current (docker/analyzer/build.sh)"))
ONLY = dict(python_analysis=False, python_syntax=False, dependency_scan=False)


def fake_token() -> str:
    return "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def make_project(tmp_path, files):
    p = tmp_path / "p"
    for n, t in files.items():
        (p / n).parent.mkdir(parents=True, exist_ok=True)
        (p / n).write_text(t)
    return p


def secrets_result(rep):
    return next(c for c in rep.checks if c.name == secretscan.NAME)


@needs_analyzer
def test_real_gitleaks_finds_a_fake_token_and_never_reports_the_value(tmp_path, ws_root, capsys):
    tok = fake_token()
    p = make_project(tmp_path, {"app.py": "print(1)\n", "web/deploy.js": f'// demo only, fake\nconst token = "{tok}";\n'})
    rep = validate_project(p, ValidationOptions(**ONLY))
    c = secrets_result(rep)
    assert c.status is CheckStatus.FINDINGS and rep.verdict is Verdict.FAIL
    assert [(f.rule_id, f.path, f.line, f.severity) for f in c.findings] == [("secrets.npm-access-token", "web/deploy.js", 2, Severity.HIGH)]
    assert tok not in json.dumps(rep.to_dict()) and tok[4:] not in json.dumps(rep.to_dict())
    assert tok not in cli.render_text(rep, str(p))
    assert cli.main(["scan", str(p), "--format", "json", "--no-python-syntax", "--no-python-analysis", "--no-dependency-scan", "--no-javascript-check"]) == 1
    out = capsys.readouterr()
    assert tok not in out.out and tok not in out.err and json.loads(out.out)["checks"][-1]["findings"][0]["line"] == 2


@needs_analyzer
def test_real_gitleaks_clean_project_passes_and_vendored_folders_are_skipped(tmp_path, ws_root):
    p = make_project(tmp_path, {"app.py": "print(1)\n", "README.md": "hello\n", "node_modules/x/y.js": f'const t = "{fake_token()}";\n'})
    c = secrets_result(validate_project(p, ValidationOptions(**ONLY)))
    assert c.status is CheckStatus.PASSED and not c.findings


@needs_analyzer
def test_real_project_cannot_hide_a_secret_with_its_own_config_or_ignore_or_allow_comment(tmp_path, ws_root):
    tok = fake_token()
    p = make_project(tmp_path, {
        "a.js": f'const t = "{tok}";\n', "b.js": f'const t = "{tok}"; // gitleaks:allow\n',
        ".gitleaks.toml": "[allowlist]\npaths = ['''.*''']\n", ".gitleaksignore": "a.js:npm-access-token:1\nb.js:npm-access-token:1\n"})
    c = secrets_result(validate_project(p, ValidationOptions(**ONLY)))
    assert c.status is CheckStatus.FINDINGS and sorted(f.path for f in c.findings) == ["a.js", "b.js"]


@needs_analyzer
def test_real_large_file_is_reported_incomplete_not_clean(tmp_path, ws_root):
    p = make_project(tmp_path, {"small.txt": "x\n"})
    (p / "big.txt").write_bytes(b"a" * (2 * 1024 * 1024))
    c = secrets_result(validate_project(p, ValidationOptions(**ONLY)))
    assert c.status is CheckStatus.INCOMPLETE and "big.txt" in c.detail
