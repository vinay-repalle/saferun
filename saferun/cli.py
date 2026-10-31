"""SafeRun command line: `saferun scan PATH`. A thin front end over `saferun.engine.validate_project`.

Exit codes (deterministic, documented in docs/cli.md):
  0   PASS      all applicable checks completed with no findings above informational
  1   FAIL      at least one high or critical finding
  2   WARNING   lower-severity findings, or the project was not fully checked (never reported as PASS)
  64  usage     invalid command line, or the path is missing / not a directory
  70  fatal     the project could not be validated at all (e.g. the safe copy failed) or an internal error
  130 interrupted

`saferun verify-images` uses 0 (all pinned images verified), 1 (a pinned image is missing or its digest does not match),
64 (usage) and 70 (Docker unusable).
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
from pathlib import Path

from .engine import osvdb
from .engine import ValidationOptions, ValidationReport, Verdict, validate_project
from .engine.model import CheckResult, clean_text
from .sandbox import SandboxError
from .sandbox.verify import verify_images
from . import hostos
from . import setup as setup_mod
from . import ui

EXIT_PASS, EXIT_FAIL, EXIT_WARNING, EXIT_USAGE, EXIT_FATAL, EXIT_INTERRUPTED = 0, 1, 2, 64, 70, 130
VERDICT_EXIT = {Verdict.PASS: EXIT_PASS, Verdict.FAIL: EXIT_FAIL, Verdict.WARNING: EXIT_WARNING}
MAX_TIMEOUT_S = 3600.0

EPILOG = """\
examples:
  saferun scan ./my-project                 human-readable report
  saferun scan ./my-project --format json   machine-readable report (schema_version 1)
  saferun init                              first-run setup: install and verify what the checks need (--all for scripts/CI)
  saferun status                            show which components are installed and verified
  saferun osv-db update                     download the offline OSV vulnerability data used by the dependency scan
  saferun scan . --no-javascript-check --timeout 60

exit codes:
  0 PASS   1 FAIL (high/critical finding)   2 WARNING (lower-severity findings or incomplete scan)
  64 invalid usage / bad path   70 fatal error (no verdict possible)   130 interrupted

PASS means the checks that exist found nothing; it does not prove the code is safe. The project is copied
by the sandbox sanitizer first; project code is never executed on the host and dependencies are never installed.
"""


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse exits 2 by default, which here means WARNING
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _timeout(value: str) -> float:
    try:
        t = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {value!r}") from None
    if not math.isfinite(t) or not 0 < t <= MAX_TIMEOUT_S:
        raise argparse.ArgumentTypeError(f"must be greater than 0 and at most {MAX_TIMEOUT_S:g} seconds")
    return t


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="saferun", description="SafeRun: static validation of a local project, without running it.",
                epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", metavar="COMMAND", parser_class=_Parser)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="coloured output and progress animation: auto = only on a terminal (honours NO_COLOR), always, never")
    v = sub.add_parser("scan", help="validate a local project directory", description=(
        "Validate a local project directory with the SafeRun engine and print the verdict."),
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter, parents=[common])
    v.add_argument("path", help="project directory to validate")
    v.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    v.add_argument("--timeout", type=_timeout, default=120.0, metavar="SECONDS",
                   help="time limit per external tool / sandbox run (default: 120)")
    v.add_argument("--osv-offline", action="store_true",
                   help="accepted for compatibility: the dependency scan is always offline (nothing is sent to OSV.dev); "
                        "it needs the data from `saferun osv-db update`")
    v.add_argument("--no-python-syntax", action="store_true", help="skip the sandboxed Python syntax check")
    v.add_argument("--no-python-analysis", action="store_true", help="skip Semgrep analysis of Python files")
    v.add_argument("--no-dependency-scan", action="store_true", help="skip the OSV dependency scan (no network use)")
    v.add_argument("--no-javascript-check", action="store_true", help="skip the sandboxed `node --check`")
    w = sub.add_parser("verify-images", help="check that local Docker images match the pinned digests", description=(
        "Check that the container images SafeRun runs are present locally with the digests pinned in the code. "
        "Read-only: nothing is pulled or changed. Exit 0 when every image is verified, 1 when one is missing or "
        "does not match, 70 when Docker is unusable."), parents=[common])
    w.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    d = sub.add_parser("osv-db", help="manage the offline OSV vulnerability data", description=(
        "The dependency scan runs without network access, against local OSV data. `update` downloads it (public data from "
        "osv-vulnerabilities.storage.googleapis.com; nothing about any project is sent)."))
    dsub = d.add_subparsers(dest="osv_db_command", metavar="ACTION", parser_class=_Parser)
    u = dsub.add_parser("update", help="download/refresh the OSV data for PyPI and npm")
    u.add_argument("--dir", help="database directory (default: $SAFERUN_OSV_DB or ~/.local/share/saferun/osv-db)")
    u.add_argument("--allow-unverified", action="store_true",
                   help="accept a download for which the server sent no MD5 hash (refused by default); it is recorded as unverified")
    st = dsub.add_parser("status", help="validate the local OSV data and show its age; exit 0 if usable and fresh, 1 otherwise", parents=[common])
    st.add_argument("--dir", help="database directory (default: $SAFERUN_OSV_DB or ~/.local/share/saferun/osv-db)")
    st.add_argument("--max-age-days", type=float, default=osvdb.DEFAULT_MAX_AGE_DAYS, help="older data is reported as stale (default: 30)")
    w.add_argument("--base-only", action="store_true", help="only the python/node base images, not the locally built analyzer image")
    w.add_argument("--only", metavar="NAME[,NAME]", help="only these pinned images (python, node); implies --base-only")
    w.add_argument("--signature", action="store_true", help="ONLINE: also verify the cosign signature of the published analyzer release "
                   "(needs cosign and internet; fails if no release is configured)")
    ini = sub.add_parser("init", help="first-run setup: install and verify what the checks need", description=(
        "Interactive (or scripted) setup. Detects what is already installed and verified, skips it, and installs/repairs/updates the rest: "
        "the Python and Node.js sandbox images (pulled by pinned digest), the analyzer image (Semgrep, OSV-Scanner, rules) and the local OSV "
        "vulnerability data. Nothing is trusted because a tag or directory exists; everything is verified after installation."), parents=[common])
    ini.add_argument("--all", action="store_true", help="install/verify every component, without prompts")
    ini.add_argument("--only", metavar="COMPONENT[,COMPONENT]", help=f"only these components ({', '.join(setup_mod.KEYS)}), without prompts")
    ini.add_argument("--skip", metavar="COMPONENT[,COMPONENT]", help="exclude these components (everything else if --only is not given), without prompts")
    ini.add_argument("--yes", "-y", action="store_true", help="answer yes to confirmations in interactive mode")
    ini.add_argument("--build-local", action="store_true", help="build the analyzer image locally (docker/analyzer/build.py) instead of installing the "
                     "signed published image when a signed release exists (today init always builds locally); never done automatically")
    ini.add_argument("--repair", action="store_true", help="allow rebuilding an analyzer image that failed verification (it replaces the image and its lock)")
    st = sub.add_parser("status", help="show which components are installed and verified", description=(
        "Verifies every component now (image digests, analyzer lock/labels/rules, OSV data integrity and age). Exit 0 if all selected are ready, 1 otherwise."), parents=[common])
    st.add_argument("--only", metavar="COMPONENT[,COMPONENT]", help=f"only these components ({', '.join(setup_mod.KEYS)})")
    st.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    return p


_LINE_BREAKS = str.maketrans({c: " " for c in "\n\t\u2028\u2029\x85\x0b\x0c"})


def _s(value) -> str:
    """One printed field = one line: untrusted values (file names, messages) cannot add lines to the text report."""
    return clean_text(value, 300).translate(_LINE_BREAKS)


def _location(f) -> str:
    if f.path is None:
        return "-"
    loc = _s(f.path)
    if f.line is not None:
        loc += f":{f.line}"
    return loc


_HASH = re.compile(r"^[0-9a-f]{40}$", re.I)


def _vkey(v: str):
    """Sortable key for a release number ('1.26.17' -> (1, 26, 17)); None for commit hashes and anything non-numeric."""
    if _HASH.match(v) or not re.match(r"^\d+(\.\d+)*", v):
        return None
    return tuple(int(n) for n in re.match(r"^\d+(?:\.\d+)*", v).group(0).split("."))


def upgrade_plan(report: ValidationReport) -> list[dict]:
    """One row per vulnerable package: how many findings it has, the worst severity, and the lowest release that fixes
    every one of them (for each finding the nearest fixed release above the installed one; for the package the highest of
    those). `upgrade_to` is None when no finding names a usable release. Rows are worst-first."""
    rows: dict[tuple, dict] = {}
    for f in report.findings:
        if not f.package:
            continue
        key = (f.package.ecosystem, f.package.name, f.package.version)
        row = rows.setdefault(key, {"ecosystem": key[0], "name": key[1], "version": key[2], "findings": 0,
                                    "severity": f.severity, "upgrade_to": None, "_key": None})
        row["findings"] += 1
        if f.severity.rank > row["severity"].rank:
            row["severity"] = f.severity
        cur = _vkey(str(f.package.version))
        fixes = [(k, v) for v in f.fixed_versions if (k := _vkey(v)) is not None]
        above = [x for x in fixes if cur is None or x[0] > cur] or fixes
        if above:
            best = min(above)
            if row["_key"] is None or best[0] > row["_key"]:
                row["_key"], row["upgrade_to"] = best
    return sorted(rows.values(), key=lambda r: (-r["severity"].rank, r["name"]))


def _plan_lines(plan: list[dict], paint=None) -> list[str]:
    """The upgrade-plan table as aligned lines (shared by the plain and the styled report)."""
    paint = paint or (lambda t, *a: t)
    head = ("PACKAGE", "INSTALLED", "UPGRADE TO", "FINDINGS", "WORST")
    body = [(_s(r["name"]), _s(r["version"]), ("\u2265 " + _s(r["upgrade_to"])) if r["upgrade_to"] else "no fix listed",
             str(r["findings"]), r["severity"].value.upper()) for r in plan]
    w = [max(len(x[i]) for x in [head] + body) for i in range(5)]
    fmt = lambda row: "  " + "  ".join(c.ljust(w[i]) for i, c in enumerate(row)).rstrip()
    return [paint(fmt(head), "dim")] + [fmt(row) for row in body]


def render_text(report: ValidationReport, path: str) -> str:
    out = [f"SafeRun validation of {_s(path)}", "",
           f"Verdict: {report.verdict.value}    Scan complete: {'yes' if report.complete else 'NO - see coverage gaps'}",
           "Reasons:"]
    out += [f"  - {_s(r)}" for r in report.reasons]
    out += ["", "Checks:"]
    for c in report.checks:
        extra = f" - {_s(c.detail)}" if c.detail else ""
        out.append(f"  {c.status.value:<14} {_s(c.name)}  ({len(c.findings)} finding(s)){extra}")
    findings = sorted(report.findings, key=lambda f: (-f.severity.rank, f.check, f.path or "", f.line or 0, f.rule_id))
    plan = upgrade_plan(report)
    if plan:
        out += ["", f"Upgrade plan ({len(plan)} package(s)):"] + _plan_lines(plan)
    out += ["", f"Findings ({len(findings)}):" if findings else "Findings: none"]
    for f in findings:
        out.append(f"  [{f.severity.value.upper()}] {_s(f.rule_id)}  {_location(f)}")
        out.append(f"      {_s(f.message)}")
        if f.package:
            out.append(f"      package: {_s(f.package.name)} {_s(f.package.version)} ({_s(f.package.ecosystem)})")
        if f.fixed_versions:
            out.append(f"      fixed in: {', '.join(_s(v) for v in f.fixed_versions)}")
    gaps = _gaps(report)
    if gaps:
        out += ["", "Coverage gaps and operational problems:"] + [f"  - {g}" for g in gaps]
    out += ["", "PASS means the existing checks found nothing; it is not a proof that the code is safe."]
    return "\n".join(out) + "\n"


def _gaps(report: ValidationReport) -> list[str]:
    gaps = []
    for c in report.checks:
        if c.status.operational_problem or c.errors or c.truncated_findings:
            head = f"{_s(c.name)}: {c.status.value}" + (f" - {_s(c.detail)}" if c.detail else "")
            gaps.append(head)
            gaps += [f"    error: {_s(e)}" for e in c.errors]
            if c.truncated_findings:
                gaps.append(f"    {c.truncated_findings} further finding(s) not listed (cap reached)")
            gaps += [f"    note: {_s(n)}" for n in c.notes]
    for s in report.workspace.get("skipped", []):
        gaps.append(f"not analysed (skipped): {_s(s['path'])} ({_s(s['reason'])})")
    for w in report.workspace.get("withheld", []):
        gaps.append(f"not analysed (withheld): {_s(w['path'])} ({_s(w['reason'])})")
    return gaps


def _next_steps(report: ValidationReport) -> list[str]:
    cats = {f.category for f in report.findings}
    steps = []
    if "dependency" in cats:
        steps.append("Upgrade the vulnerable packages to the 'fixed in' versions, then scan again.")
    if "code" in cats:
        steps.append("Review or fix the flagged lines, then scan again.")
    if "syntax" in cats:
        steps.append("Fix the syntax errors, then scan again.")
    if "workspace" in cats:
        steps.append("Remove or rotate the credential-like files that were found.")
    if _gaps(report):
        steps.append("Some checks did not fully run: `saferun status` shows what is missing and the exact fix.")
    return steps


def render_styled(report: ValidationReport, path: str, th: "ui.Theme", elapsed: float | None = None) -> str:
    """The same information as render_text, laid out for quick reading on a terminal: coloured verdict banner, one icon per check,
    severity tags in colour, wrapped messages, a severity tally and the next steps. Every value goes through the same
    one-line sanitizer as render_text BEFORE it is painted, so untrusted text cannot inject escape sequences."""
    import shutil
    import textwrap
    width = max(60, min(110, shutil.get_terminal_size((100, 24)).columns - 8))
    p = th.paint
    out = [f"{p('SafeRun', 'bold', 'cyan')} validation of {p(_s(path), 'bold')}", ""]
    verdict = report.verdict.value
    banner = p(f" {th.icons['ok'] if verdict == 'PASS' else th.icons['bad'] if verdict == 'FAIL' else th.icons['warn']} {verdict} ", *ui.VERDICT_STYLE[verdict])
    done = p("scan complete", "green") if report.complete else p("scan NOT complete: see coverage gaps", "yellow", "bold")
    out.append(f"{banner}  {done}" + (p(f"   {elapsed:.1f} s", "dim") if elapsed is not None else ""))
    out += ["", p("Why this verdict", "bold", "cyan")]
    out += [f"  {th.icons['dot']} {_s(r)}" for r in report.reasons]
    out += ["", p("Checks", "bold", "cyan")]
    for c in report.checks:
        worst = max((f.severity.rank for f in c.findings), default=0)
        if c.status.value == "passed":
            icon, col = th.icon("ok", "green", "bold"), "green"
        elif c.status.value == "findings":
            icon, col = (th.icon("bad", "red", "bold"), "red") if worst >= 4 else (th.icon("warn", "yellow", "bold"), "yellow")
        elif c.status.value == "error":
            icon, col = th.icon("bad", "red", "bold"), "red"
        elif c.status.value in ("incomplete", "timeout", "unavailable"):
            icon, col = th.icon("warn", "yellow", "bold"), "yellow"
        else:
            icon, col = th.icon("skip", "dim"), "dim"
        n = len(c.findings)
        extra = f" {p('- ' + _s(c.detail), 'dim')}" if c.detail else ""
        out.append(f"  {icon} {p(f'{c.status.value:<14}', col)} {p(_s(c.name), 'bold')}  {p(f'({n} finding(s))', 'dim')}{extra}")
    findings = sorted(report.findings, key=lambda f: (-f.severity.rank, f.check, f.path or "", f.line or 0, f.rule_id))
    plan = upgrade_plan(report)
    if plan:
        out += ["", p(f"Upgrade plan ({len(plan)} package(s))", "bold", "cyan")]
        lines = _plan_lines(plan, p)
        out.append(lines[0])
        for r, line in zip(plan, lines[1:]):
            sev = r["severity"].value
            out.append(line[:-len(sev)] + p(sev.upper(), *ui.SEVERITY_STYLE[sev]))
    if findings:
        tally = {}
        for f in findings:
            tally[f.severity.value] = tally.get(f.severity.value, 0) + 1
        order = ("critical", "high", "medium", "unknown", "low", "info")
        out += ["", p(f"Findings ({len(findings)})", "bold", "cyan") + "  "
                + "  ".join(p(f"{k.upper()} {tally[k]}", *ui.SEVERITY_STYLE[k]) for k in order if k in tally)]
    else:
        out += ["", p("Findings: none", "green")]
    for f in findings:
        out.append("")
        tag = p(f"[{f.severity.value.upper()}]", *ui.SEVERITY_STYLE[f.severity.value])
        out.append(f"  {tag} {p(_s(f.rule_id), 'bold')}  {_location(f)}")
        for line in textwrap.wrap(_s(f.message), width=width) or [""]:
            out.append("      " + p(line, "dim"))
        if f.package:
            out.append(f"      package: {_s(f.package.name)} {_s(f.package.version)} ({_s(f.package.ecosystem)})")
        if f.fixed_versions:
            out.append("      " + p(f"fixed in: {', '.join(_s(v) for v in f.fixed_versions)}", "green"))
    gaps = _gaps(report)
    if gaps:
        out += ["", p("Coverage gaps and operational problems", "bold", "yellow")] + [f"  {th.icons['warn']} {g}" if not g.startswith("    ") else g for g in gaps]
    steps = _next_steps(report)
    if steps:
        out += ["", p("What to do next", "bold", "cyan")] + [f"  {th.icons['arrow']} {s}" for s in steps]
    out += ["", p("PASS means the existing checks found nothing; it is not a proof that the code is safe.", "dim")]
    return "\n".join(out) + "\n"


def _fail(message: str, code: int) -> int:
    print(f"saferun: error: {clean_text(message, 1000)}", file=sys.stderr)
    return code


def _osv_db(args) -> int:
    db_dir = Path(args.dir) if getattr(args, "dir", None) else osvdb.default_dir()
    if args.osv_db_command == "status":
        if not math.isfinite(args.max_age_days) or args.max_age_days <= 0:
            return _fail("--max-age-days must be a positive number", EXIT_USAGE)
        rep = osvdb.validate(db_dir, max_age_days=args.max_age_days)
        print(f"OSV database: {_s(db_dir)}")
        for line in rep.notes:
            print(f"  {_s(line)}")
        for line in rep.problems:
            print(f"  PROBLEM: {_s(line)}")
        if rep.stale:
            print(f"  STALE: {_s(rep.stale)}")
        print("  usable and fresh" if rep.ok and not rep.stale else "  NOT usable for a clean scan result")
        return EXIT_PASS if rep.ok and not rep.stale else EXIT_FAIL
    if args.osv_db_command != "update":
        return _fail("usage: saferun osv-db update|status [--dir DIR]", EXIT_USAGE)
    try:
        result = osvdb.update(db_dir, allow_unverified=args.allow_unverified)
    except KeyboardInterrupt:
        return _fail("interrupted", EXIT_INTERRUPTED)
    except Exception as e:  # noqa: BLE001 - report, never traceback
        return _fail(f"OSV database update failed (existing data left in place): {type(e).__name__}: {e}", EXIT_FATAL)
    for eco, e in result.items():
        print(f"{eco}: {e['size']} bytes, {e['entries']} advisories, sha256 {e['sha256'][:16]}…, MD5 {e['md5']} -> "
              f"{db_dir / 'osv-scalibr' / eco / 'all.zip'}")
    if any(e["md5"] != "verified" for e in result.values()):
        print("warning: at least one download was accepted WITHOUT a server-provided hash (--allow-unverified)", file=sys.stderr)
    return EXIT_PASS


def _init(args) -> int:
    try:
        chosen = setup_mod.select(args.all, args.only, args.skip)
    except ValueError as e:
        return _fail(str(e), EXIT_USAGE)
    tty = sys.stdin.isatty() and sys.stdout.isatty()
    if chosen is None and not tty:
        return _fail("not a terminal: choose components with --all, --only or --skip (e.g. `saferun init --all`)", EXIT_USAGE)
    theme = ui.theme_for(sys.stdout, args.color)
    s = setup_mod.Setup(interactive=chosen is None, tty=sys.stdout.isatty(), theme=theme, build_local=args.build_local)
    try:
        if chosen is None:
            try:
                chosen = s.choose()
            except ValueError as e:
                return _fail(str(e), EXIT_USAGE)
        else:
            for line in setup_mod.banner_lines(theme):
                s.say(line)
            s.say(setup_mod.INTRO)
            s.say()
        return s.run(chosen, repair=args.repair, assume_yes=args.yes)
    except KeyboardInterrupt:
        return _fail("interrupted", EXIT_INTERRUPTED)


def _status(args) -> int:
    try:
        keys = setup_mod.parse_list(args.only) or list(setup_mod.KEYS)
    except ValueError as e:
        return _fail(str(e), EXIT_USAGE)
    statuses = setup_mod.all_status(keys)
    sys.stdout.write((setup_mod.status_json(statuses) if args.format == "json"
                      else setup_mod.status_report(statuses, ui.theme_for(sys.stdout, args.color))) + "\n")
    return EXIT_PASS if all(x.ready for x in statuses) else EXIT_FAIL


def _check_signature() -> dict:
    """`verify-images --signature`: the cosign signature of the configured analyzer release (online). Fails closed."""
    from .sandbox import images as im
    from .sandbox.signature import SignatureError, verify_release_signature
    rel = im.ANALYZER_RELEASE
    if rel is None:
        return {"ok": False, "reference": "", "detail": "no analyzer release is configured (ANALYZER_RELEASE is not set), so there is nothing to verify"}
    try:
        n = verify_release_signature(rel)
    except SignatureError as e:
        return {"ok": False, "reference": rel.reference, "detail": str(e)}
    return {"ok": True, "reference": rel.reference, "detail": f"{rel.reference}: {n} valid signature(s) from the expected release workflow"}


def _verify_images(fmt: str, analyzer: bool = True, only: str | None = None, signature: bool = False) -> int:
    from .sandbox.images import PINNED_IMAGES
    names = [n for n in (only or "").replace(",", " ").split() if n]
    unknown = [n for n in names if n not in {i.name for i in PINNED_IMAGES}]
    if unknown:
        return _fail(f"unknown image name(s): {', '.join(unknown)} (choose from: {', '.join(i.name for i in PINNED_IMAGES)})", EXIT_USAGE)
    try:
        checks = (verify_images(tuple(i for i in PINNED_IMAGES if i.name in names), analyzer=analyzer) if names
                  else verify_images(analyzer=analyzer))
    except SandboxError as e:
        return _fail(f"cannot verify images: {e}", EXIT_FATAL)
    ok = all(c.ok for c in checks)
    sig = _check_signature() if signature else None
    if sig is not None:
        ok = ok and sig["ok"]
    if fmt == "json":
        doc = {"schema_version": 1, "ok": ok, "images": [c.to_dict() for c in checks]}
        if sig is not None:
            doc["signature"] = sig
        sys.stdout.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    else:
        for c in checks:
            sys.stdout.write(f"{c.status.upper():<9} {_s(c.reference)}\n")
            if c.detail:
                sys.stdout.write(f"          {_s(c.detail)}\n")
        if sig is not None:
            sys.stdout.write(f"{'VERIFIED' if sig['ok'] else 'FAILED':<9} cosign signature: {_s(sig['detail'])}\n")
        sys.stdout.write("all pinned images verified\n" if ok else "NOT VERIFIED: do not rely on these images\n")
    return EXIT_PASS if ok else EXIT_FAIL


def main(argv: list[str] | None = None) -> int:
    hostos.enable_ansi()   # Windows consoles: escape sequences and a code page that cannot crash on output; no-op elsewhere
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:  # --help -> 0; usage errors -> 64 (see _Parser.error)
        return e.code if isinstance(e.code, int) else EXIT_USAGE
    if args.command == "init":
        return _init(args)
    if args.command == "status":
        return _status(args)
    if args.command == "osv-db":
        return _osv_db(args)
    if args.command == "verify-images":
        return _verify_images(args.format, analyzer=not (args.base_only or args.only), only=args.only, signature=args.signature)
    if args.command != "scan":
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    project = Path(args.path)
    if not project.exists():
        return _fail(f"path does not exist: {args.path}", EXIT_USAGE)
    if not project.is_dir():
        return _fail(f"not a directory: {args.path}", EXIT_USAGE)
    options = ValidationOptions(
        python_analysis=not args.no_python_analysis, python_syntax=not args.no_python_syntax,
        dependency_scan=not args.no_dependency_scan, javascript_check=not args.no_javascript_check,
        tool_timeout_s=args.timeout, osv_offline=True)   # always offline; --osv-offline is a no-op
    t0 = time.monotonic()
    try:
        with ui.Spinner(sys.stderr, "Scanning: syntax, static analysis, dependencies (each in a locked-down container)", ui.theme_for(sys.stderr, args.color)):
            report = validate_project(project, options)
    except KeyboardInterrupt:
        return _fail("interrupted", EXIT_INTERRUPTED)
    except SandboxError as e:
        return _fail(f"cannot validate (no verdict): {e}", EXIT_FATAL)
    except Exception as e:  # noqa: BLE001 - never crash with a traceback or a misleading success code
        return _fail(f"internal error (no verdict): {type(e).__name__}: {e}", EXIT_FATAL)
    if args.format == "json":
        sys.stdout.write(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        th = ui.theme_for(sys.stdout, args.color)
        sys.stdout.write(render_styled(report, args.path, th, time.monotonic() - t0) if th.on else render_text(report, args.path))
    sys.stdout.flush()
    try:
        eth = ui.theme_for(sys.stderr, args.color)
        for hint in setup_mod.scan_hints(report):       # stderr only, after the report: stdout and exit codes are unaffected
            print(eth.paint(hint, "yellow") if eth.on else hint, file=sys.stderr)
    except Exception:  # noqa: BLE001 - a hint must never change the outcome of a scan
        pass
    return VERDICT_EXIT[report.verdict]


if __name__ == "__main__":
    sys.exit(main())
