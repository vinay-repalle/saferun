"""JavaScript syntax validation: `node --check` for every .js/.mjs/.cjs file, INSIDE the sandbox.

`node --check` only compiles a file, but the compiler still parses untrusted input, so it is not run on the
host: one sandbox run (node:22-slim, same verified restrictions as everything else: no network, read-only,
non-root, resource limits) executes a fixed driver script that walks /workspace and runs `node --check` on each
file, printing one JSON line per file. Project code is never executed. node_modules/.git are not walked.

Implemented: syntax validation. NOT implemented (deferred): npm install / dependency acquisition, test runners,
Semgrep JavaScript rules, ESLint, TypeScript. npm *vulnerability scanning* is done from lockfiles (see osv.py).
"""
from __future__ import annotations

import json
import re
import time

from ..sandbox import SandboxError, SandboxLimits
from ..sandbox.profiles import NODE
from .context import CheckContext
from .model import CheckResult, CheckStatus, Finding, Severity, clean_text

NAME = "javascript-syntax"
EXTS = (".js", ".mjs", ".cjs")
MAX_FILES = 1000
SKIP_DIRS = frozenset({"node_modules", ".git"})

DRIVER = r"""
const fs=require('fs'),cp=require('child_process'),path=require('path');
const ROOT='/workspace',MAX=%d,SKIP=new Set(['node_modules','.git']);
const out=o=>process.stdout.write(JSON.stringify(o)+'\n');
const files=[];let truncated=false;
(function walk(d,depth){
  if(depth>32)return;
  let ents;try{ents=fs.readdirSync(d,{withFileTypes:true});}catch(e){out({walk_error:path.relative(ROOT,d)});return;}
  for(const e of ents){
    if(e.isDirectory()){if(!SKIP.has(e.name))walk(path.join(d,e.name),depth+1);}
    else if(e.isFile()&&/\.(js|mjs|cjs)$/.test(e.name)){if(files.length>=MAX)truncated=true;else files.push(path.join(d,e.name));}
  }
})(ROOT,0);
files.sort();
for(const f of files){
  const r=cp.spawnSync(process.execPath,['--check',f],{encoding:'utf8',timeout:10000,maxBuffer:65536,env:{}});
  out({file:path.relative(ROOT,f),status:r.status,signal:r.signal,failed:!!r.error,err:(r.stderr||'').slice(0,2000)});
}
out({done:true,count:files.length,truncated});
""" % MAX_FILES


def js_files(files: list[str]) -> list[str]:
    return [f for f in files if f.endswith(EXTS) and not any(p in SKIP_DIRS for p in f.split("/")[:-1])]


def build_command() -> list[str]:
    return ["node", "-e", DRIVER]


_LINE = re.compile(r":(\d+)\s*$")


def _syntax_finding(file: str, err: str) -> Finding:
    lines = [ln for ln in err.splitlines() if ln.strip()]
    line = next((int(m.group(1)) for ln in lines[:3] if (m := _LINE.search(ln))), None)
    msg = next((ln for ln in lines if re.match(r"^\w*Error\b", ln)), lines[0] if lines else "syntax error")
    return Finding(check=NAME, rule_id="javascript.syntax-error", severity=Severity.MEDIUM,
                   message=clean_text(msg, 300), category="syntax", path=clean_text(file, 300), line=line)


def parse_output(text: str, expected: list[str]) -> tuple[list[Finding], list[str], int]:
    """Return (findings, per-file operational problems, files checked). Raises ValueError if the driver's
    output is malformed or incomplete (no 'done' marker), so a cut-off run cannot look clean."""
    findings, problems, count, done = [], [], 0, None
    known = set(expected)
    for raw in text.splitlines():
        if not raw.strip():
            continue
        try:
            o = json.loads(raw)
        except (json.JSONDecodeError, RecursionError):
            raise ValueError("driver output is not valid JSON lines") from None
        if not isinstance(o, dict):
            raise ValueError("driver output line is not an object")
        if "walk_error" in o:
            problems.append(f"{clean_text(o['walk_error'], 200)}: directory could not be read")
        elif o.get("done") is True:
            done = o
        elif isinstance(o.get("file"), str):
            f = o["file"]
            if f not in known:
                raise ValueError("driver reported a file that was not in the project")
            count += 1
            if o.get("failed") or o.get("signal") or not isinstance(o.get("status"), int):
                problems.append(f"{clean_text(f, 200)}: node --check could not complete")
            elif o["status"] != 0:
                findings.append(_syntax_finding(f, str(o.get("err", ""))))
        else:
            raise ValueError("unrecognised driver output line")
    if done is None:
        raise ValueError("driver output ended before its completion marker")
    if done.get("count") != count:
        raise ValueError("driver file count does not match its output")
    if done.get("truncated"):
        problems.append(f"more than {MAX_FILES} JavaScript files; the rest were not checked")
    return findings, problems, count


def run_check(ctx: CheckContext) -> CheckResult:
    targets = js_files(ctx.files)
    if not targets:
        return CheckResult(NAME, CheckStatus.NOT_APPLICABLE, detail="no JavaScript files")
    try:
        ctx.image_available(NODE.image)
    except SandboxError as e:
        return CheckResult(NAME, CheckStatus.UNAVAILABLE, tool=f"node --check ({NODE.label})",
                           detail=clean_text(f"sandbox or image unavailable: {e}"))
    t0 = time.monotonic()
    res = CheckResult(NAME, CheckStatus.ERROR, tool=f"node --check ({NODE.label}, sandboxed)")
    try:
        r = ctx.sandbox(ctx.project, build_command(), SandboxLimits(timeout_s=ctx.timeout_s, max_output_bytes=ctx.max_output),
                        image=NODE.image)
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
    res.notes = [f"{count} JavaScript file(s) syntax-checked with node --check; no code executed"]
    if problems:
        res.status, res.detail = CheckStatus.INCOMPLETE, f"{len(problems)} problem(s): " + "; ".join(problems)[:300]
    else:
        res.status = CheckStatus.FINDINGS if findings else CheckStatus.PASSED
    return res
