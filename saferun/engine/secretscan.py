"""Hardcoded-secret detection with gitleaks, run INSIDE the analyzer container. Never on the host.

Invocation (argv, no shell), run on the sanitized project copy mounted read-only at /workspace:
    /usr/local/bin/gitleaks dir . --config /opt/saferun/rules/gitleaks.toml --ignore-gitleaks-allow --redact
           --report-format json --report-path - --exit-code 0 --log-level error --max-target-megabytes 1 --no-banner --no-color
`dir` mode reads files only (no git history, no network, no online verification of any secret: gitleaks has none). Only the config baked
into the verified image is used (a project's own `.gitleaks.toml` is never read), `gitleaks:allow` comments in untrusted code are ignored,
and `.gitleaksignore` files are removed from SafeRun's private copy before the scan (the tool reads one from the scan root).
Exit codes: 0 = scan done (leaks do not change it, `--exit-code 0`); anything else = operational error.

SECRET VALUES NEVER LEAVE THE CONTAINER LOG-WISE: `--redact` makes gitleaks mask them, and this module additionally reads only the rule id,
file and line numbers from each entry. `Secret`, `Match`, `Fingerprint` and every other field are discarded, so even a tool that ignored
`--redact` could not put a value into a finding, the JSON report, the terminal or an error message (stderr is not echoed beyond a short,
cleaned excerpt, and only for failed runs).

Coverage is partly verified: files larger than the size limit are skipped by the tool without saying so, so they are found from the file
list and make the check INCOMPLETE. Binary files are skipped by the tool and cannot be listed; that is a documented limit (a note).
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from .context import CheckContext
from .model import CheckResult, CheckStatus, Finding, Severity, clean_text
from .paths import rel_path
from ..sandbox import SandboxError
from ..sandbox.analyzer import GITLEAKS_EXE, SECRETS_RULES_PATH, AnalyzerIntegrityError
from ..sandbox.images import GITLEAKS_VERSION
from .tools import ToolUnavailable

NAME = "hardcoded-secrets"
RULES_FILE = Path(__file__).parent / "rules" / "gitleaks.toml"
MAX_TARGET_MB = 1
EXCLUDES = ("node_modules", ".venv", "venv", "site-packages")     # the same vendored folders the Semgrep check skips; also in gitleaks.toml
IGNORE_FILES = (".gitleaksignore",)
MAX_ENTRIES = 100_000          # entries read from the tool's JSON before it is called unusable
_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,99}$")
MESSAGE = ("possible hardcoded secret ({rule}); the value is not shown or stored. Remove it from the project, "
           "rotate it if it was ever real, and load it from the environment or a secret manager instead")


def _vendored(rel: str) -> bool:
    return any(p in EXCLUDES for p in rel.split("/")[:-1])


def targets(files: list[str]) -> list[str]:
    return [f for f in files if not _vendored(f)]


def build_argv(exe: str = GITLEAKS_EXE, rules: str = SECRETS_RULES_PATH) -> list[str]:
    return [exe, "dir", ".", "--config", rules, "--ignore-gitleaks-allow", "--redact", "--report-format", "json", "--report-path", "-",
            "--exit-code", "0", "--log-level", "error", "--max-target-megabytes", str(MAX_TARGET_MB), "--no-banner", "--no-color"]


def _as_line(v) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def parse_output(text: str, root: Path) -> list[Finding]:
    """Findings from gitleaks JSON. Only rule id, path and line numbers are taken; no secret value can reach a Finding.
    Raises ValueError on anything that is not gitleaks' JSON report (a JSON list of objects)."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as e:
        raise ValueError(f"output is not valid JSON: {e}") from None
    if not isinstance(data, list):
        raise ValueError("JSON is not a list of findings")
    if len(data) > MAX_ENTRIES:
        raise ValueError(f"more than {MAX_ENTRIES} entries")
    out: list[Finding] = []
    seen: set[tuple] = set()
    for r in data:
        if not isinstance(r, dict) or not isinstance(r.get("RuleID"), str) or not r["RuleID"]:
            raise ValueError("malformed entry (no RuleID)")
        rule = r["RuleID"] if _RULE_ID.match(r["RuleID"]) else clean_text(r["RuleID"], 100).replace(" ", "_")
        path, line, end = rel_path(r.get("File"), root), _as_line(r.get("StartLine")), _as_line(r.get("EndLine"))
        key = (rule, path, line)
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(check=NAME, rule_id=f"secrets.{rule}", severity=Severity.HIGH, category="secret",
                           message=MESSAGE.format(rule=rule), path=path, line=line, end_line=end, cwe=("CWE-798",)))
    return out


def remove_ignore_files(ctx: CheckContext) -> int:
    """Delete .gitleaksignore files from the private analysis copy (the tool reads one from the scan root). Returns how many."""
    n = 0
    for f in ctx.files:
        if f.rsplit("/", 1)[-1] in IGNORE_FILES:
            try:
                os.unlink(ctx.project / f)
                n += 1
            except OSError:
                pass
    return n


def _too_large(ctx: CheckContext, files: list[str]) -> list[str]:
    limit = MAX_TARGET_MB * 1024 * 1024
    big = []
    for f in files:
        try:
            if os.stat(ctx.project / f).st_size > limit:
                big.append(f)
        except OSError:
            big.append(f)       # cannot be examined: do not claim it was covered
    return big


def run_check(ctx: CheckContext) -> CheckResult:
    files = targets(ctx.files)
    if not files:
        return CheckResult(NAME, CheckStatus.NOT_APPLICABLE, detail="no files to scan")
    tool = f"gitleaks {GITLEAKS_VERSION}"
    if not RULES_FILE.is_file():
        return CheckResult(NAME, CheckStatus.ERROR, detail=f"bundled rule file missing: {RULES_FILE.name}", tool=tool)
    try:
        ctx.analyzer_available()
    except AnalyzerIntegrityError as e:
        return CheckResult(NAME, CheckStatus.ERROR, tool=tool,
                           detail=clean_text(f"analyzer image failed verification; gitleaks was not run (no host fallback): {e}"))
    except SandboxError as e:
        return CheckResult(NAME, CheckStatus.UNAVAILABLE, tool=tool,
                           detail=clean_text(f"analyzer image unavailable; gitleaks was not run (no host fallback): {e}"))
    removed = remove_ignore_files(ctx)
    t0 = time.monotonic()
    try:
        run = ctx.analyzer(build_argv(), cwd=ctx.project, env=None, timeout_s=ctx.timeout_s, max_output=ctx.max_output)
    except ToolUnavailable as e:
        return CheckResult(NAME, CheckStatus.UNAVAILABLE, detail=clean_text(e), tool=tool)
    except SandboxError as e:
        return CheckResult(NAME, CheckStatus.ERROR, tool=tool, duration_s=time.monotonic() - t0,
                           detail=clean_text(f"isolated analyzer run failed; gitleaks results are not available (no host fallback): {e}"))
    res = CheckResult(NAME, CheckStatus.ERROR, tool=tool, duration_s=time.monotonic() - t0)
    if run.timed_out:
        res.status, res.detail = CheckStatus.TIMEOUT, f"gitleaks exceeded {ctx.timeout_s:g}s and was killed"
        return res
    if run.output_truncated:
        res.detail = "gitleaks output exceeded the size limit and the run was killed"
        return res
    if run.exit_code != 0:
        # stderr is deliberately not echoed: this check handles secrets, and nothing the tool prints about a file may reach a report.
        res.detail = f"gitleaks exited with code {run.exit_code} (its error text is not shown, so that no file content can reach the report)"
        return res
    try:
        findings = parse_output(run.stdout, ctx.project)
    except ValueError as e:
        res.detail = clean_text(f"gitleaks output unusable: {e}")
        return res
    res.findings = findings[: ctx.max_findings]
    res.truncated_findings = max(0, len(findings) - ctx.max_findings)
    res.notes = [f"{len(files)} file(s) targeted", "rules: gitleaks default rules without the generic-api-key rule (saferun/engine/rules/gitleaks.toml)",
                 "binary files are skipped by gitleaks and are not listed; secrets are never verified online"]
    if removed:
        res.notes.append(f"{removed} .gitleaksignore file(s) removed from the analysis copy")
    big = _too_large(ctx, [f for f in files if f.rsplit("/", 1)[-1] not in IGNORE_FILES])   # removed above: nothing left to scan
    if big:
        shown = ", ".join(clean_text(b, 80) for b in big[:5]) + (f" and {len(big) - 5} more" if len(big) > 5 else "")
        res.status = CheckStatus.INCOMPLETE
        res.detail = f"{len(big)} file(s) over {MAX_TARGET_MB} MB were not scanned by gitleaks: {shown}"
        res.errors = [f"not scanned: {clean_text(b, 200)}" for b in big[:50]]
    else:
        res.status = CheckStatus.FINDINGS if res.findings else CheckStatus.PASSED
    return res
