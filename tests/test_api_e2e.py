"""End to end through the REAL worker: HTTP upload -> extraction -> `python -I -m saferun scan` -> real Docker sandbox +
Semgrep -> report. The report must equal what the CLI prints for the same project (parity: the API adds no validation)."""
import io
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from saferun.api.app import create_app
from saferun.api.archive import extract_zip
from saferun.api.jobs import JobLimits, JobManager

pytestmark = pytest.mark.docker
H = {"X-SafeRun-Request": "1", "Content-Type": "application/zip"}
PROJECT = {
    "demo/app.py": b"import os\n\ndef run(x):\n    return eval(x)\n",
    "demo/broken.py": b"def f(:\n    pass\n",
    "demo/ok.py": b"print('hello')\n",
    "__MACOSX/demo/._app.py": b"junk",
}


def make_zip(files) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, d in files.items():
            zf.writestr(n, d)
    return buf.getvalue()


def poll(c, sid, timeout=240):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        j = c.get(f"/api/scans/{sid}").json()
        if j["status"] not in ("queued", "running"):
            return j
        time.sleep(0.5)
    raise AssertionError("job did not finish")


def strip_timing(report):
    for c in report["checks"]:
        c["duration_s"] = 0
    return report


@pytest.fixture
def client(ws_root):
    mgr = JobManager(JobLimits(job_deadline_s=400, tool_timeout_s=120))
    c = TestClient(create_app(mgr, run_startup_cleanup=False, static_dir=None), base_url="http://127.0.0.1:8765",
                   client=("127.0.0.1", 50000))
    with c:
        yield c


def test_report_through_the_api_equals_the_cli_report(client, ws_root, tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-matter")      # the worker never sees it; results must not depend on it
    data = make_zip(PROJECT)
    sid = client.post("/api/scans?osv=disabled", content=data, headers=H).json()["id"]
    job = poll(client, sid)
    assert job["status"] == "done", job
    assert job["archive"]["stripped_prefix"] == "demo" and job["archive"]["excluded_total"] == 1
    assert list(ws_root.iterdir()) == []                                  # nothing left behind
    blob = json.dumps(job)
    assert str(ws_root) not in blob and "saferun-ws-" not in blob and "saferun-up-" not in blob   # no host paths in the response

    # the same archive, extracted by the same code and scanned by the plain CLI
    archive_file = tmp_path / "same.zip"
    archive_file.write_bytes(data)
    ex = extract_zip(archive_file)
    try:
        p = subprocess.run([sys.executable, "-I", "-m", "saferun", "scan", str(ex.project), "--format", "json",
                            "--no-dependency-scan", "--timeout", "120"], capture_output=True, text=True, timeout=300,
                           env={**os.environ, "PATH": f"{Path(sys.executable).parent}:{os.environ['PATH']}"})
    finally:
        ex.cleanup()
    cli = json.loads(p.stdout)
    assert {0: "PASS", 1: "FAIL", 2: "WARNING"}[p.returncode] == cli["verdict"] == job["report"]["verdict"]
    assert strip_timing(job["report"]) == strip_timing(cli)               # schema, verdict, findings: identical
    assert job["report"]["schema_version"] == 1

    names = {c["name"]: c["status"] for c in job["report"]["checks"]}
    assert names["python-syntax"] == "findings"                           # broken.py was really checked, in the sandbox
    assert names["dependency-vulnerabilities"] == "skipped"
    assert job["report"]["verdict"] in ("FAIL", "WARNING") and job["report"]["complete"] is False


def test_clean_project_with_osv_disabled_is_never_a_plain_pass(client):
    sid = client.post("/api/scans?osv=disabled", content=make_zip({"a.py": b"print(1)\n"}), headers=H).json()["id"]
    job = poll(client, sid)
    assert job["status"] == "done" and job["report"]["verdict"] == "WARNING" and job["report"]["complete"] is False
    assert any("dependency-vulnerabilities: skipped" in r for r in job["report"]["reasons"])


def test_hostile_archive_is_rejected_before_anything_runs(client, ws_root):
    marker = ws_root.parent / "pwned"
    sid = client.post("/api/scans", content=make_zip({"../pwned": b"x", "a.py": b"1"}), headers=H).json()["id"]
    job = poll(client, sid)
    assert job["status"] == "rejected" and job["error"]["code"] == "unsafe-name"
    assert not marker.exists() and list(ws_root.iterdir()) == []


def test_no_containers_left_behind():
    r = subprocess.run(["docker", "ps", "-aq", "--filter", "label=saferun.sandbox=1"], capture_output=True, text=True, timeout=60)
    assert r.stdout.strip() == ""
