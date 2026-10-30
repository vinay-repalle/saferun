"""Python syntax validation INSIDE the sandbox (python:3.12-slim): `compile()` of every .py/.pyi file.

Semgrep recovers from syntax errors without reporting them (observed with Semgrep 1.182: a file with `def f(:` is
"scanned" with no error), so a separate check is needed or a broken file would look clean. One sandbox run executes
a fixed driver that only *compiles* each file (never imports or runs it) and prints one JSON line per file.
Syntax is that of the sandbox image's Python (3.12), not necessarily the project's target version.
"""
from __future__ import annotations

import json
import time

from ..sandbox import SandboxError, SandboxLimits
from ..sandbox.profiles import PYTHON
from .context import CheckContext
from .model import CheckResult, CheckStatus, Finding, Severity, clean_text
from .semgrep import python_files

NAME = "python-syntax"
MAX_FILES = 1000

DRIVER = """
import json, os
ROOT, MAX = '/workspace', %d
SKIP = {'node_modules', '.git', '.venv', 'venv', 'site-packages'}
files, truncated = [], False
for d, dirs, names in os.walk(ROOT):
    dirs[:] = sorted(x for x in dirs if x not in SKIP)
    for n in sorted(names):
        if n.endswith(('.py', '.pyi')):
            if len(files) >= MAX:
                truncated = True
            else:
                files.append(os.path.join(d, n))
def out(o):
    print(json.dumps(o), flush=True)
for f in files:
    rel = os.path.relpath(f, ROOT)
    try:
        with open(f, 'rb') as fh:
            src = fh.read()
        compile(src, rel, 'exec', dont_inherit=True)
        out({'file': rel, 'ok': True})
    except SyntaxError as e:
        out({'file': rel, 'ok': False, 'line': e.lineno, 'msg': str(e.msg)[:300]})
    except (ValueError, RecursionError, MemoryError, OSError) as e:
        out({'file': rel, 'failed': type(e).__name__})
out({'done': True, 'count': len(files), 'truncated': truncated})
""" % MAX_FILES


def build_command() -> list[str]:
    return ["python", "-I", "-c", DRIVER]


def parse_output(text: str, expected: list[str]) -> tuple[list[Finding], list[str], int]:
    """(findings, per-file problems, files checked). ValueError on malformed/incomplete output."""
    findings, problems, count, done, known = [], [], 0, None, set(expected)
    for raw in text.splitlines():
        if not raw.strip():
            continue
        try:
            o = json.loads(raw)
        except (json.JSONDecodeError, RecursionError):
            raise ValueError("driver output is not valid JSON lines") from None
        if not isinstance(o, dict):
            raise ValueError("driver output line is not an object")
        if o.get("done") is True:
            done = o
        elif isinstance(o.get("file"), str):
            f = o["file"]
            if f not in known:
                raise ValueError("driver reported a file that was not in the project")
            count += 1
            if "failed" in o:
                problems.append(f"{clean_text(f, 200)}: could not be compiled ({clean_text(o['failed'], 40)})")
            elif o.get("ok") is False:
                line = o.get("line")
                findings.append(Finding(
                    check=NAME, rule_id="python.syntax-error", severity=Severity.MEDIUM, category="syntax",
                    message=clean_text(f"SyntaxError: {o.get('msg', '')}", 300), path=clean_text(f, 300),
                    line=line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None))
            elif o.get("ok") is not True:
                raise ValueError("unrecognised driver output line")
        else:
            raise ValueError("unrecognised driver output line")
    if done is None:
        raise ValueError("driver output ended before its completion marker")
    if done.get("count") != count:
        raise ValueError("driver file count does not match its output")
    if done.get("truncated"):
        problems.append(f"more than {MAX_FILES} Python files; the rest were not checked")
    return findings, problems, count


def run_check(ctx: CheckContext) -> CheckResult:
    targets = python_files(ctx.files)
    if not targets:
        return CheckResult(NAME, CheckStatus.NOT_APPLICABLE, detail="no Python files")
    try:
        ctx.image_available(PYTHON.image)
    except SandboxError as e:
        return CheckResult(NAME, CheckStatus.UNAVAILABLE, tool=f"compile() ({PYTHON.label})",
                           detail=clean_text(f"sandbox or image unavailable: {e}"))
    t0 = time.monotonic()
    res = CheckResult(NAME, CheckStatus.ERROR, tool=f"compile() ({PYTHON.label}, sandboxed)")
    try:
        r = ctx.sandbox(ctx.project, build_command(), SandboxLimits(timeout_s=ctx.timeout_s, max_output_bytes=ctx.max_output),
                        image=PYTHON.image)
    except SandboxError as e:
        res.detail = clean_text(f"sandbox refused or failed to run: {e}")
        return res
    finally:
        res.duration_s = time.monotonic() - t0
    if r.timed_out:
        res.status, res.detail = CheckStatus.TIMEOUT, f"syntax check exceeded {ctx.timeout_s:g}s and was killed"
        return res
    if r.oom_killed or r.output_truncated or r.exit_code != 0:
        res.detail = clean_text(f"sandboxed run failed (exit {r.exit_code}, oom={r.oom_killed}, "
                                f"truncated={r.output_truncated}): {r.stderr.strip()[-200:]}")
        return res
    try:
        findings, problems, count = parse_output(r.stdout, targets)
    except ValueError as e:
        res.detail = clean_text(f"driver output unusable: {e}")
        return res
    res.findings = findings[: ctx.max_findings]
    res.truncated_findings = max(0, len(findings) - ctx.max_findings)
    res.errors = problems
    res.notes = [f"{count} Python file(s) compiled (not executed) with the sandbox image's Python 3.12"]
    if problems:
        res.status, res.detail = CheckStatus.INCOMPLETE, f"{len(problems)} problem(s): " + "; ".join(problems)[:300]
    else:
        res.status = CheckStatus.FINDINGS if findings else CheckStatus.PASSED
    return res
