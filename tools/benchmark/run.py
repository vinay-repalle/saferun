#!/usr/bin/env python3
"""Benchmark SafeRun against Bandit (code checks) and pip-audit (dependency checks). Dev environment only; standard library only.

Every sample in samples.toml is written into a fresh temp folder, scanned, and the folder is deleted again. Samples are NEVER executed:
SafeRun is only called with "scan" (and "check-names"), never "run"; Bandit and pip-audit only read files; pip-audit runs with
--no-deps --disable-pip, so nothing is installed.

    python tools/benchmark/run.py [--split dev|held-out|all] [--out-dir DIR]

The default split is "dev". The held-out split is run once, after the labels are frozen, and SafeRun is never tuned to its results.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import json
import platform
import subprocess
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SAMPLES = HERE / "samples.toml"

SAFERUN, BANDIT, PIP_AUDIT, PIP_AUDIT_OSV = "saferun", "bandit", "pip-audit", "pip-audit -s osv"
# Which tools take part in which kind of sample. "names" is SafeRun-only and is kept out of the head-to-head totals.
TOOLS_FOR = {"code": (SAFERUN, BANDIT), "deps": (SAFERUN, PIP_AUDIT, PIP_AUDIT_OSV), "names": (SAFERUN,)}
SPLITS = ("dev", "held-out")


# ------------------------------------------------------------------ samples
def load_samples(path: Path = SAMPLES) -> tuple[dict, list[dict]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    samples = data["sample"]
    ids = [s["id"] for s in samples]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate sample ids")
    for s in samples:
        if s["kind"] not in TOOLS_FOR or s["label"] not in ("bad", "clean") or s["split"] not in SPLITS:
            raise ValueError(f"bad sample definition: {s['id']}")
    return data["meta"], samples


def materialize(sample: dict, root: Path) -> Path:
    """Write one sample into its own folder under root and return the folder. Code goes to sample.py, dependencies to requirements.txt."""
    folder = root / sample["id"]
    folder.mkdir()
    if sample["kind"] == "code":
        (folder / "sample.py").write_text(sample["content"], encoding="utf-8")
    elif sample["kind"] == "deps":
        (folder / "requirements.txt").write_text(sample["content"], encoding="utf-8")
    return folder


# ------------------------------------------------------------------ tool calls (each returns an outcome dict, see _outcome)
def _outcome(status: str, findings: int = 0, strict: bool = False, detail: str = "", **extra) -> dict:
    """status: ok | error. loose = any finding; strict = the tool's own 'serious' bar (see the report text)."""
    return {"status": status, "findings": findings, "loose": status == "ok" and findings > 0, "strict": status == "ok" and strict,
            "detail": detail, **extra}


def _run(argv: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)   # never a shell
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout:.0f}s"
    except OSError as e:
        return -1, "", str(e)
    return p.returncode, p.stdout, p.stderr


def _json(out: str):
    try:
        return json.loads(out)
    except ValueError:
        return None


def scan_saferun(folder: Path, timeout: float) -> dict:
    rc, out, err = _run([sys.executable, "-m", "saferun", "scan", str(folder), "--format", "json"], timeout)   # scan only, never "run"
    doc = _json(out)
    if rc not in (0, 1, 2) or not isinstance(doc, dict) or "verdict" not in doc:
        return _outcome("error", detail=(err or out or f"exit {rc}").strip()[-300:])
    n = sum(len(c["findings"]) for c in doc["checks"])
    osv = next((note for c in doc["checks"] for note in c["notes"] if note.startswith("OSV database PyPI")), "")
    return _outcome("ok", n, doc["verdict"] == "FAIL", f"verdict {doc['verdict']}", incomplete=not doc["complete"], osv_note=osv)


def check_names_saferun(names: list[str], timeout: float) -> dict:
    rc, out, err = _run([sys.executable, "-m", "saferun", "check-names", *names, "--format", "json"], timeout)
    doc = _json(out)
    if rc not in (0, 2) or not isinstance(doc, dict) or "names" not in doc:
        return _outcome("error", detail=(err or out or f"exit {rc}").strip()[-300:])
    n = sum(len(x["findings"]) for x in doc["names"])
    return _outcome("ok", n, n > 0, "offline snapshot " + str(doc.get("snapshot", {}).get("date", "?")), incomplete=not doc["complete"])


def scan_bandit(folder: Path, timeout: float) -> dict:
    rc, out, err = _run([sys.executable, "-m", "bandit", "-q", "-f", "json", "-r", str(folder)], timeout)
    doc = _json(out)
    if rc not in (0, 1) or not isinstance(doc, dict) or "results" not in doc:
        return _outcome("error", detail=(err or out or f"exit {rc}").strip()[-300:])
    sev = [r["issue_severity"] for r in doc["results"]]
    return _outcome("ok", len(sev), any(s in ("MEDIUM", "HIGH") for s in sev), "severities " + ",".join(sorted(sev)) if sev else "")


def audit_pip(folder: Path, timeout: float, osv: bool) -> dict:
    argv = [sys.executable, "-m", "pip_audit", "-r", str(folder / "requirements.txt"), "--no-deps", "--disable-pip", "-f", "json",
            "--progress-spinner", "off"] + (["-s", "osv"] if osv else [])
    rc, out, err = _run(argv, timeout)
    doc = _json(out)
    if rc not in (0, 1) or not isinstance(doc, dict) or "dependencies" not in doc:
        return _outcome("error", detail=(err or out or f"exit {rc}").strip()[-300:])
    deps = doc["dependencies"]
    n = sum(len(d.get("vulns", [])) for d in deps)
    skipped = [d["name"] for d in deps if "skip_reason" in d]
    return _outcome("ok", n, n > 0, ("skipped: " + ",".join(skipped)) if skipped else "")   # pip-audit has no severity: strict == loose


def run_sample(sample: dict, root: Path, timeout: float, enabled: set[str]) -> dict[str, dict]:
    folder = materialize(sample, root)
    res: dict[str, dict] = {}
    for tool in TOOLS_FOR[sample["kind"]]:
        if tool not in enabled:
            continue
        if sample["kind"] == "names":
            res[tool] = check_names_saferun(sample["names"], timeout)
        elif tool == SAFERUN:
            res[tool] = scan_saferun(folder, timeout)
        elif tool == BANDIT:
            res[tool] = scan_bandit(folder, timeout)
        else:
            res[tool] = audit_pip(folder, timeout, osv=(tool == PIP_AUDIT_OSV))
    return res


# ------------------------------------------------------------------ scoring
def _rate(rows: list[dict], tool: str, label: str, bar: str) -> dict:
    sel = [r for r in rows if r["label"] == label and tool in r["results"]]
    return {"k": sum(1 for r in sel if r["results"][tool][bar]), "n": len(sel), "errors": sum(1 for r in sel if r["results"][tool]["status"] == "error")}


def aggregate(rows: list[dict], splits: tuple[str, ...]) -> dict:
    """Counts per kind and tool: catches among bad samples, false alarms among clean ones, each with the strict and the loose bar."""
    rows = [r for r in rows if r["split"] in splits]
    out: dict = {}
    for kind, tools in TOOLS_FOR.items():
        krows = [r for r in rows if r["kind"] == kind]
        out[kind] = {}
        for tool in tools:
            cats = {}
            for cat in sorted({r["category"] for r in krows}):
                crows = [r for r in krows if r["category"] == cat]
                cats[cat] = {"label": crows[0]["label"], **{bar: _rate(crows, tool, crows[0]["label"], bar) for bar in ("strict", "loose")}}
            out[kind][tool] = {
                "catch": {bar: _rate(krows, tool, "bad", bar) for bar in ("strict", "loose")},
                "false_alarm": {bar: _rate(krows, tool, "clean", bar) for bar in ("strict", "loose")},
                "categories": cats,
            }
    return out


def verdict_notes(rows: list[dict]) -> dict:
    """Samples where SafeRun's loose outcome is wrong, who got it right, and clean dependency samples that any tool flagged."""
    wrong = []
    for r in rows:
        sr = r["results"].get(SAFERUN)
        if not sr:
            continue
        flagged = sr["loose"]
        if (r["label"] == "bad" and not flagged) or (r["label"] == "clean" and flagged):
            others = [t for t, o in r["results"].items() if t != SAFERUN and o["loose"] == (r["label"] == "bad") and o["status"] == "ok"]
            wrong.append({"id": r["id"], "category": r["category"], "label": r["label"], "split": r["split"], "note": r["note"],
                          "saferun": "error" if sr["status"] == "error" else ("flagged" if flagged else "not flagged"), "others_right": others})
    exceptions = [{"id": r["id"], "note": r["note"], "flagged_by": [t for t, o in r["results"].items() if o["loose"]]}
                  for r in rows if r["kind"] == "deps" and r["label"] == "clean" and any(o["loose"] for o in r["results"].values())]
    return {"saferun_wrong": wrong, "clean_dependency_exceptions": exceptions}


# ------------------------------------------------------------------ report
def _kn(d: dict) -> str:
    return f"{d['k']}/{d['n']}" + (f" ({d['errors']} err)" if d["errors"] else "")


def render_markdown(rep: dict) -> str:
    m = rep["meta"]
    L = [f"# SafeRun benchmark report", "",
         f"- Run: {m['run_at']} on {m['platform']}, Python {m['python']}",
         f"- Samples: `{m['samples_file']}` sha256 `{m['samples_sha256'][:16]}…`, labels frozen {m['labels_frozen']}; split run: **{m['split']}**",
         "- Tools: " + ", ".join(f"{k} {v}" for k, v in m["tool_versions"].items()),
         "- Advisory data: SafeRun uses its local OSV snapshot (" + (m["saferun_osv_note"] or "not reported") + "). pip-audit defaults to PyPI's "
         "vulnerability service; \"pip-audit -s osv\" uses the OSV service. **Differences on dependency samples can come from the data, not the tools.**",
         "", "Counts are k/n (not percentages) because the sample set is small. \"Catch\" is among samples labeled bad; \"false alarm\" is among samples "
         "labeled clean. \"err\" counts scans that failed; a failed scan counts as not flagged.", "",
         "- **loose**: any finding. **strict**: SafeRun = verdict FAIL (high/critical finding); Bandit = a medium or high severity finding; "
         "pip-audit has no severity, so strict equals loose.", ""]
    for name, agg in rep["summary"].items():
        L += [f"## Results: {name} split", ""]
        for kind, title in (("code", "Code checks (head-to-head: SafeRun vs Bandit)"), ("deps", "Dependency checks (head-to-head: SafeRun vs pip-audit)"),
                            ("names", "SafeRun-only: look-alike package names (not in any head-to-head total)")):
            L += [f"### {title}", "", "| Tool | Catch (strict) | Catch (loose) | False alarm (strict) | False alarm (loose) |", "|---|---|---|---|---|"]
            for tool, a in agg[kind].items():
                L.append(f"| {tool} | {_kn(a['catch']['strict'])} | {_kn(a['catch']['loose'])} | {_kn(a['false_alarm']['strict'])} | {_kn(a['false_alarm']['loose'])} |")
            L += ["", "Per category (loose bar, k/n flagged; for clean categories k is false alarms):", "", "| Category | Label | " + " | ".join(agg[kind]) + " |",
                  "|---|---|" + "---|" * len(agg[kind])]
            cats = next(iter(agg[kind].values()))["categories"]
            for cat, c in cats.items():
                L.append(f"| {cat} | {c['label']} | " + " | ".join(_kn(agg[kind][t]["categories"][cat]["loose"]) for t in agg[kind]) + " |")
            L.append("")
    v = rep["notes"]
    L += ["## Where SafeRun is wrong (every sample that was run)", ""]
    if v["saferun_wrong"]:
        L += ["| Sample | Category | Expected | SafeRun | Tools that got it right | What it is |", "|---|---|---|---|---|---|"]
        for w in v["saferun_wrong"]:
            L.append(f"| {w['id']} ({w['split']}) | {w['category']} | {w['label']} | {w['saferun']} | {', '.join(w['others_right']) or 'none'} | {w['note']} |")
    else:
        L.append("None.")
    L += ["", "## Flagged exceptions: clean dependency samples that a tool flagged", ""]
    L += [f"- {e['id']}: flagged by {', '.join(e['flagged_by'])} ({e['note']})" for e in v["clean_dependency_exceptions"]] or ["None."]
    L += ["", "## Limits", "",
          "- The samples were written by the SafeRun authors, are few, and are simulations (nothing is real malware). Per-category counts are tiny.",
          "- Bandit looks for insecure coding practice and SafeRun looks for behaviour that should not be run unreviewed; the goals overlap but differ.",
          "- Only the scan is measured. The sandbox (`saferun run`) is not part of this benchmark and samples are never executed.",
          "- Dependency results depend on the advisory data on the run date. A PASS is not proof of safety.",
          "- SafeRun was not tuned to these results; fixes need a new sample set.", ""]
    return "\n".join(L)


def _version(pkg: str) -> str:
    try:
        return md.version(pkg)
    except md.PackageNotFoundError:
        return "not installed"


def build_report(rows: list[dict], splits: tuple[str, ...], meta: dict, sha: str) -> dict:
    summary = {s: aggregate(rows, (s,)) for s in splits}
    if len(splits) > 1:
        summary["all"] = aggregate(rows, splits)
    osv_note = next((o["osv_note"] for r in rows for t, o in r["results"].items() if t == SAFERUN and o.get("osv_note")), "")
    return {
        "meta": {"run_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "platform": platform.platform(), "python": platform.python_version(),
                 "samples_file": "tools/benchmark/samples.toml", "samples_sha256": sha, "labels_frozen": meta["frozen"],
                 "split": "+".join(splits), "saferun_osv_note": osv_note,
                 "tool_versions": {"saferun": _version("saferun-cli"), "bandit": _version("bandit"), "pip-audit": _version("pip-audit")}},
        "summary": summary, "notes": verdict_notes(rows), "samples": rows,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--split", choices=("dev", "held-out", "all"), default="dev", help="which samples to run (default: dev; run held-out once)")
    ap.add_argument("--out-dir", default="artifacts/benchmark", help="where benchmark.json and benchmark.md are written")
    ap.add_argument("--timeout", type=float, default=180, help="per tool call, seconds")
    ap.add_argument("--skip", default="", help="comma-separated tools to leave out: " + ", ".join((SAFERUN, BANDIT, PIP_AUDIT, PIP_AUDIT_OSV)))
    args = ap.parse_args(argv)
    splits = SPLITS if args.split == "all" else (args.split,)
    enabled = {SAFERUN, BANDIT, PIP_AUDIT, PIP_AUDIT_OSV} - {t.strip() for t in args.skip.split(",")}
    meta, samples = load_samples()
    samples = [s for s in samples if s["split"] in splits]
    rows = []
    with tempfile.TemporaryDirectory(prefix="saferun-bench-") as tmp:   # every generated file lives here and is removed on exit
        for i, s in enumerate(samples, 1):
            print(f"[{i}/{len(samples)}] {s['id']}", file=sys.stderr, flush=True)
            rows.append({k: s[k] for k in ("id", "kind", "category", "label", "split", "note")} | {"results": run_sample(s, Path(tmp), args.timeout, enabled)})
    rep = build_report(rows, splits, meta, hashlib.sha256(SAMPLES.read_bytes()).hexdigest())
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "benchmark.json").write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    text = render_markdown(rep)
    (out / "benchmark.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
