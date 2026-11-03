"""The benchmark harness (tools/benchmark): sample hygiene, scoring, and the promises that samples are never executed and always cleaned up.

Nothing here needs Docker, Bandit or pip-audit except the one test marked docker.
"""
import ast
import importlib.util
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUN_PY = ROOT / "tools" / "benchmark" / "run.py"


def _load():
    spec = importlib.util.spec_from_file_location("benchmark_run", RUN_PY)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_run"] = mod
    spec.loader.exec_module(mod)
    return mod


bench = _load()
META, SAMPLES = bench.load_samples()


def test_samples_have_unique_ids_valid_labels_and_both_splits_per_category():
    assert len({s["id"] for s in SAMPLES}) == len(SAMPLES)
    for cat in {s["category"] for s in SAMPLES}:
        assert {s["split"] for s in SAMPLES if s["category"] == cat} == {"dev", "held-out"}, cat
    assert {s["label"] for s in SAMPLES} == {"bad", "clean"}
    assert META["frozen"]


def test_required_categories_are_present():
    cats = {s["category"] for s in SAMPLES}
    assert {"obfuscated_payload", "evasion_variant", "hard_negative", "clean_normal", "dep_vulnerable", "dep_current", "name_lookalike"} <= cats


def test_code_samples_are_valid_python_and_are_only_parsed_never_run():
    for s in SAMPLES:
        if s["kind"] == "code":
            ast.parse(s["content"], s["id"])


def test_samples_stay_harmless_by_construction():
    for s in SAMPLES:
        if s["kind"] != "code":
            continue
        text = s["content"]
        if re.search(r"rmtree\(|system\(\"rm -rf|os\.remove\(|os\.rename\(", text):
            assert "tempfile" in text, f"{s['id']}: deletes must be confined to the temp folder"
        for host in re.findall(r"(?:https?|smtp)://([^/\"' ]+)|create_connection\(\(\"([^\"]+)\"|SMTP\(\"([^\"]+)\"", text):
            host = next(h for h in host if h)
            assert host.startswith(("127.0.0.1", "example.", "api.github.com", "db.example", "localhost")), (s["id"], host)


def test_materialize_writes_one_file_per_sample_into_its_own_folder(tmp_path):
    for s in SAMPLES:
        folder = bench.materialize(s, tmp_path)
        files = sorted(p.name for p in folder.iterdir())
        assert files == {"code": ["sample.py"], "deps": ["requirements.txt"], "names": []}[s["kind"]], s["id"]


def test_runner_only_ever_calls_scan_and_check_names_never_run(monkeypatch, tmp_path):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="{}", stderr="")

    monkeypatch.setattr(bench.subprocess, "run", fake_run)
    bench.scan_saferun(tmp_path, 5)
    bench.check_names_saferun(["x"], 5)
    sub = [a[a.index("saferun") + 1] for a in calls]
    assert sub == ["scan", "check-names"]
    assert not re.search(r"""["']saferun["']\s*,\s*["']run["']""", RUN_PY.read_text())


def test_pip_audit_never_installs_anything(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(bench.subprocess, "run", lambda argv, **kw: seen.append(argv) or subprocess.CompletedProcess(argv, 0, stdout="{}", stderr=""))
    bench.audit_pip(tmp_path, 5, osv=True)
    argv = seen[0]
    assert "--no-deps" in argv and "--disable-pip" in argv and argv[argv.index("-s") + 1] == "osv"


def _row(i, kind, cat, label, **tools):
    return {"id": i, "kind": kind, "category": cat, "label": label, "split": "dev", "note": i,
            "results": {t: bench._outcome("ok", n, st) for t, (n, st) in tools.items()}}


def test_aggregate_counts_catches_and_false_alarms_with_strict_and_loose_bars():
    rows = [
        _row("a", "code", "c1", "bad", saferun=(1, True), bandit=(1, False)),
        _row("b", "code", "c1", "bad", saferun=(0, False), bandit=(2, True)),
        _row("c", "code", "c2", "clean", saferun=(1, False), bandit=(0, False)),
        _row("d", "names", "name_lookalike", "bad", saferun=(1, True)),
    ]
    agg = bench.aggregate(rows, ("dev",))
    sr, bd = agg["code"]["saferun"], agg["code"]["bandit"]
    assert sr["catch"]["strict"] == {"k": 1, "n": 2, "errors": 0} and sr["catch"]["loose"]["k"] == 1
    assert bd["catch"]["strict"]["k"] == 1 and bd["catch"]["loose"]["k"] == 2
    assert sr["false_alarm"]["loose"] == {"k": 1, "n": 1, "errors": 0} and sr["false_alarm"]["strict"]["k"] == 0
    assert agg["names"]["saferun"]["catch"]["loose"]["n"] == 1
    assert "names" not in agg["code"]       # look-alike rows never enter the head-to-head totals


def test_a_failed_scan_counts_as_not_flagged_and_is_reported_as_an_error():
    rows = [{"id": "a", "kind": "code", "category": "c", "label": "bad", "split": "dev", "note": "n",
             "results": {"saferun": bench._outcome("error", detail="boom"), "bandit": bench._outcome("ok", 1, True)}}]
    agg = bench.aggregate(rows, ("dev",))
    assert agg["code"]["saferun"]["catch"]["loose"] == {"k": 0, "n": 1, "errors": 1}
    wrong = bench.verdict_notes(rows)["saferun_wrong"]
    assert wrong[0]["saferun"] == "error" and wrong[0]["others_right"] == ["bandit"]


def test_losses_and_clean_dependency_exceptions_are_listed():
    rows = [
        _row("miss", "code", "c", "bad", saferun=(0, False), bandit=(1, True)),
        _row("fa", "code", "c", "clean", saferun=(1, True), bandit=(0, False)),
        _row("win", "code", "c", "bad", saferun=(1, True), bandit=(0, False)),
        _row("dep", "deps", "dep_current", "clean", saferun=(0, False), **{"pip-audit": (1, True)}),
    ]
    notes = bench.verdict_notes(rows)
    assert [w["id"] for w in notes["saferun_wrong"]] == ["miss", "fa"]
    assert notes["clean_dependency_exceptions"] == [{"id": "dep", "note": "dep", "flagged_by": ["pip-audit"]}]


def test_report_uses_counts_states_limits_and_data_source_caveat():
    rows = [_row("a", "code", "c1", "bad", saferun=(1, True), bandit=(0, False))]
    rep = bench.build_report(rows, ("dev",), META, "0" * 64)
    text = bench.render_markdown(rep)
    assert "1/1" in text and "0/1" in text
    assert "Differences on dependency samples can come from the data, not the tools" in text
    assert "## Limits" in text and "written by the SafeRun authors" in text and "not tuned" in text
    assert rep["meta"]["labels_frozen"] == META["frozen"]


def test_main_deletes_every_generated_file(monkeypatch, tmp_path):
    seen = []

    def fake_run_sample(sample, root, timeout, enabled):
        folder = bench.materialize(sample, root)
        seen.append(folder)
        assert folder.exists()
        return {t: bench._outcome("ok") for t in bench.TOOLS_FOR[sample["kind"]]}

    monkeypatch.setattr(bench, "run_sample", fake_run_sample)
    assert bench.main(["--split", "dev", "--out-dir", str(tmp_path / "out")]) == 0
    assert seen and not any(p.exists() for p in seen) and not any(p.parent.exists() for p in seen)
    assert (tmp_path / "out" / "benchmark.json").is_file() and (tmp_path / "out" / "benchmark.md").is_file()


def test_bench_extra_is_pinned_exactly_and_kept_out_of_dev_and_the_default_install():
    extras = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]
    assert all(re.fullmatch(r"[\w-]+==\d+(\.\d+)*", d) for d in extras["bench"]), extras["bench"]
    assert {d.split("==")[0] for d in extras["bench"]} == {"bandit", "pip-audit"}
    assert not any(d.startswith(("bandit", "pip-audit")) for d in extras["dev"])
    assert not tomllib.loads((ROOT / "pyproject.toml").read_text())["project"].get("dependencies")


@pytest.mark.docker
def test_real_scan_of_one_dev_sample_with_saferun_and_bandit(tmp_path):
    pytest.importorskip("bandit")
    sample = next(s for s in SAMPLES if s["id"] == "dc-03")
    folder = bench.materialize(sample, tmp_path)
    sr = bench.scan_saferun(folder, 300)
    assert sr["status"] == "ok" and sr["loose"], sr
    bd = bench.scan_bandit(folder, 120)
    assert bd["status"] == "ok" and bd["loose"], bd
