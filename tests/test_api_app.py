"""HTTP layer tests (Phase 4 unit 3): upload limits, job lifecycle, guards, headers. The worker is a stub subprocess;
the real CLI/Docker path is in test_api_e2e.py."""
import asyncio
import io
import json
import os
import sys
import threading
import time
import zipfile

import pytest
from starlette.testclient import TestClient

from saferun.api import app as app_module
from saferun.api.app import create_app
from saferun.api.archive import MiB, ArchiveLimits
from saferun.api.jobs import JobLimits, JobManager
from saferun.engine.tools import ToolRun

REPORT = {"schema_version": 1, "verdict": "WARNING", "reasons": ["r"], "complete": False, "workspace": {}, "checks": []}
H = {"X-SafeRun-Request": "1", "Content-Type": "application/zip"}


def zip_bytes(files=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, d in (files or {"a.py": b"x = 1\n"}).items():
            zf.writestr(n, d)
    return buf.getvalue()


def stub_builder(code):
    return lambda project, osv, t: [sys.executable, "-c", code, str(project)]


OK_CODE = f"import sys,json; print(json.dumps({REPORT!r})); sys.exit(2)"


def client_for(manager=None, *, client=("127.0.0.1", 50000), base="http://127.0.0.1:8765", **kw):
    mgr = manager or JobManager(command_builder=stub_builder(OK_CODE))
    app = create_app(mgr, run_startup_cleanup=False, static_dir=kw.pop("static_dir", None), **kw)
    return TestClient(app, base_url=base, client=client), mgr


@pytest.fixture
def client(ws_root):
    c, _ = client_for()
    with c:
        yield c


def poll(c, scan_id, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = c.get(f"/api/scans/{scan_id}")
        assert r.status_code == 200
        if r.json()["status"] not in ("queued", "running"):
            return r.json()
        time.sleep(0.02)
    raise AssertionError("timeout")


def leftovers(ws_root):
    return sorted(p.name for p in ws_root.iterdir())


# -------------------------------------------------------------------------------------------- lifecycle

def test_upload_poll_and_report_roundtrip(client, ws_root):
    r = client.post("/api/scans?osv=disabled", content=zip_bytes(), headers=H)
    assert r.status_code == 202 and set(r.json()) == {"id", "status"}
    job = poll(client, r.json()["id"])
    assert job["status"] == "done" and job["report"] == REPORT and job["osv_mode"] == "disabled"
    assert job["archive"]["files"] == 1
    assert leftovers(ws_root) == []
    assert str(ws_root) not in json.dumps(job)                 # no server path in any response


def test_default_osv_mode_is_offline_and_online_is_refused(client):
    r = client.post("/api/scans", content=zip_bytes(), headers=H)
    assert poll(client, r.json()["id"])["osv_mode"] == "offline"
    r = client.post("/api/scans?osv=online", content=zip_bytes(), headers=H)
    assert r.status_code == 422 and r.json()["error"]["code"] == "osv-online-unsupported"


def test_bad_archive_becomes_rejected_with_a_stable_code(client, ws_root):
    r = client.post("/api/scans", content=zip_bytes({"../x.py": b"1"}), headers=H)
    job = poll(client, r.json()["id"])
    assert job["status"] == "rejected" and job["error"]["code"] == "unsafe-name" and "report" not in job
    r = client.post("/api/scans", content=b"this is not a zip" * 10, headers=H)
    assert poll(client, r.json()["id"])["error"]["code"] == "not-a-zip"
    assert leftovers(ws_root) == []


def test_delete_lifecycle(client):
    sid = client.post("/api/scans", content=zip_bytes(), headers=H).json()["id"]
    poll(client, sid)
    assert client.delete(f"/api/scans/{sid}", headers={"X-SafeRun-Request": "1"}).status_code == 204
    assert client.get(f"/api/scans/{sid}").status_code == 404
    assert client.delete(f"/api/scans/{sid}", headers={"X-SafeRun-Request": "1"}).status_code == 404


def test_cannot_delete_a_running_scan(ws_root):
    gate = threading.Event()
    mgr = JobManager(command_builder=stub_builder(OK_CODE),
                     tool_runner=lambda argv, **kw: (gate.wait(20), ToolRun(argv, 2, json.dumps(REPORT), ""))[1])
    c, _ = client_for(mgr)
    with c:
        sid = c.post("/api/scans", content=zip_bytes(), headers=H).json()["id"]
        assert c.delete(f"/api/scans/{sid}", headers={"X-SafeRun-Request": "1"}).status_code == 409
        gate.set()
        poll(c, sid)


@pytest.mark.parametrize("sid", ["x", "../../etc/passwd", "a" * 200, "nonexistent_id_12345678", "%00"])
def test_unknown_or_malformed_ids_are_404(client, sid):
    assert client.get(f"/api/scans/{sid}").status_code == 404


def test_health_reports_tools_queue_and_limits_without_paths(client):
    h = client.get("/api/health").json()
    assert set(h) == {"docker_cli", "analyzer", "semgrep", "osv_scanner", "queue", "limits"}
    assert h["semgrep"] is h["osv_scanner"] is h["analyzer"]       # both tools live in the one verified analyzer image
    assert h["limits"]["max_archive_mib"] == 100 and h["limits"]["max_entries"] == 5000 and h["limits"]["job_deadline_s"] == 600
    assert "/" not in json.dumps({k: v for k, v in h.items() if k not in ("limits",)}).replace("\\/", "")


# -------------------------------------------------------------------------------------- request limits

def test_wrong_content_type_is_415(client):
    for ct in ("application/json", "multipart/form-data; boundary=x", "text/plain", ""):
        r = client.post("/api/scans", content=zip_bytes(), headers={"X-SafeRun-Request": "1", "Content-Type": ct})
        assert r.status_code == 415
    assert client.post("/api/scans", content=zip_bytes(), headers={**H, "Content-Type": "Application/ZIP; charset=x"}).status_code == 202


def test_invalid_osv_mode_is_422(client):
    assert client.post("/api/scans?osv=everything", content=zip_bytes(), headers=H).status_code == 422


def test_empty_body_is_400(client):
    assert client.post("/api/scans", content=b"", headers=H).status_code == 400


def test_oversized_content_length_is_413_before_reading(ws_root):
    c, _ = client_for(archive_limits=ArchiveLimits(max_archive_bytes=1000))
    with c:
        r = c.post("/api/scans", content=b"x" * 5000, headers=H)
        assert r.status_code == 413 and r.json()["error"]["code"] == "archive-too-large"
        assert leftovers(ws_root) == []


def test_chunked_upload_without_content_length_is_capped_while_streaming(ws_root):
    c, _ = client_for(archive_limits=ArchiveLimits(max_archive_bytes=1000))
    sent = []

    def gen():
        for _ in range(100):
            sent.append(1)
            yield b"x" * 100
    with c:
        r = c.post("/api/scans", content=gen(), headers=H)
        assert r.status_code == 413
        assert leftovers(ws_root) == []


def test_bad_content_length_is_400(client):
    r = client.post("/api/scans", content=b"x", headers={**H, "Content-Length": "abc"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad-content-length"


def test_busy_returns_429_and_leaves_no_upload(ws_root):
    gate = threading.Event()
    mgr = JobManager(JobLimits(max_queue=1), command_builder=stub_builder(OK_CODE),
                     tool_runner=lambda argv, **kw: (gate.wait(20), ToolRun(argv, 2, json.dumps(REPORT), ""))[1])
    c, _ = client_for(mgr)
    with c:
        ids = [c.post("/api/scans", content=zip_bytes(), headers=H).json()["id"] for _ in range(2)]
        r = c.post("/api/scans", content=zip_bytes(), headers=H)
        assert r.status_code == 429 and r.headers["retry-after"] == "30" and r.json()["error"]["code"] == "busy"
        gate.set()
        for i in ids:
            poll(c, i)
        assert leftovers(ws_root) == []


def test_slow_upload_times_out_and_is_cleaned_up(ws_root, monkeypatch):
    monkeypatch.setattr(app_module, "UPLOAD_TIMEOUT_S", 0.4)
    mgr = JobManager(command_builder=stub_builder(OK_CODE))
    app = create_app(mgr, run_startup_cleanup=False, static_dir=None)
    out = {}

    async def drive():
        sent = []
        step = {"n": 0}

        async def receive():
            step["n"] += 1
            if step["n"] == 1:
                return {"type": "http.request", "body": b"PK", "more_body": True}
            await asyncio.sleep(5)                             # the client stalls
            return {"type": "http.disconnect"}

        async def send(m):
            sent.append(m)
        scope = {"type": "http", "method": "POST", "path": "/api/scans", "raw_path": b"/api/scans", "query_string": b"",
                 "headers": [(b"host", b"127.0.0.1:8765"), (b"content-type", b"application/zip"), (b"x-saferun-request", b"1")],
                 "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8765), "scheme": "http", "http_version": "1.1", "root_path": ""}
        t0 = time.monotonic()
        await app(scope, receive, send)
        out["status"] = sent[0]["status"]
        out["elapsed"] = time.monotonic() - t0
    asyncio.run(drive())
    assert out["status"] == 408 and out["elapsed"] < 3
    assert leftovers(ws_root) == []


# ------------------------------------------------------------------------------------------- the guard

def test_non_loopback_peer_is_refused_everywhere(ws_root):
    for peer in ("203.0.113.9", "192.168.1.5", "::ffff:127.0.0.1", "2001:db8::1"):
        c, _ = client_for(client=(peer, 1234))
        with c:
            for path in ("/api/health", "/", "/api/scans/xxxxxxxxxxxxxxxxxxxxxx"):
                r = c.get(path)
                assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden-peer", (peer, path)
            assert c.post("/api/scans", content=zip_bytes(), headers=H).status_code == 403


def test_missing_peer_address_is_refused(ws_root):
    c, _ = client_for(client=None)
    app = c.app
    sent = []

    async def drive():
        async def receive(): return {"type": "http.request", "body": b"", "more_body": False}
        async def send(m): sent.append(m)
        await app({"type": "http", "method": "GET", "path": "/api/health", "raw_path": b"/api/health", "query_string": b"",
                   "headers": [(b"host", b"127.0.0.1")], "client": None, "server": None, "scheme": "http",
                   "http_version": "1.1", "root_path": ""}, receive, send)
    asyncio.run(drive())
    assert sent[0]["status"] == 403


@pytest.mark.parametrize("host", ["evil.com", "evil.com:8765", "127.0.0.1.evil.com", "192.168.1.5:8765", "0.0.0.0:8765"])
def test_foreign_host_header_is_rejected_dns_rebinding(client, host):
    r = client.get("/api/health", headers={"Host": host})
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad-host"


def test_state_changing_requests_need_the_custom_header(client):
    r = client.post("/api/scans", content=zip_bytes(), headers={"Content-Type": "application/zip"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "missing-header"
    assert client.delete("/api/scans/xxxxxxxxxxxxxxxxxxxxxx").status_code == 403
    assert client.post("/api/scans", content=zip_bytes(), headers={**H, "X-SafeRun-Request": "0"}).status_code == 403


def test_cross_origin_requests_are_refused_but_same_origin_passes(client):
    for origin in ("http://evil.com", "https://127.0.0.1:8765", "http://localhost:8765", "null", "http://127.0.0.1:1"):
        r = client.post("/api/scans", content=zip_bytes(), headers={**H, "Origin": origin})
        assert r.status_code == 403 and r.json()["error"]["code"] == "bad-origin", origin
    assert client.post("/api/scans?osv=disabled", content=zip_bytes(), headers={**H, "Origin": "http://127.0.0.1:8765"}).status_code == 202


def test_cors_preflight_is_never_answered(client):
    r = client.options("/api/scans", headers={"Origin": "http://evil.com", "Access-Control-Request-Method": "POST",
                                              "Access-Control-Request-Headers": "x-saferun-request"})
    assert r.status_code == 403 and "access-control-allow-origin" not in r.headers


def test_websockets_are_refused(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/scans"):
            pass


def test_security_headers_and_no_openapi_pages(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"] and "unsafe-inline" not in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store" and r.headers["referrer-policy"] == "no-referrer"
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_error_responses_also_carry_security_headers(client):
    r = client.get("/api/health", headers={"Host": "evil.com"})
    assert r.status_code == 400 and r.headers["x-content-type-options"] == "nosniff"


def test_no_endpoint_executes_anything_there_is_no_run_route(client):
    for method, path in (("post", "/api/run"), ("post", "/api/exec"), ("post", "/api/scans/x/run"), ("put", "/api/scans")):
        assert getattr(client, method)(path, headers=H, content=b"x").status_code in (404, 405)


# --------------------------------------------------------------------------------------- static files

def test_static_dashboard_is_served_with_security_headers(ws_root, tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>SafeRun</title><script type=module src=/assets/app.js></script>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    c, _ = client_for(static_dir=dist)
    with c:
        r = c.get("/")
        assert r.status_code == 200 and "SafeRun" in r.text and "content-security-policy" in r.headers
        assert c.get("/assets/app.js").status_code == 200
        (tmp_path / "secret.txt").write_text("SECRET")
        for p in ("/assets/../index.html", "/assets/..%2findex.html", "/assets/%2e%2e/secret.txt", "/assets//etc/passwd"):
            r = c.get(p)
            assert r.status_code == 404 and "SECRET" not in r.text, p
        assert c.get("/nope").status_code == 404


def test_without_a_build_there_is_only_the_api(client):
    assert client.get("/").status_code == 404


def test_oversized_content_length_is_refused_without_reading_the_body(ws_root):
    """The declared size is checked first: a hostile 10 GiB announcement never causes a single body read."""
    mgr = JobManager(command_builder=stub_builder(OK_CODE))
    app = create_app(mgr, run_startup_cleanup=False, static_dir=None)
    sent, reads = [], []

    async def drive():
        async def receive():
            reads.append(1)
            return {"type": "http.request", "body": b"x" * 10, "more_body": True}

        async def send(m):
            sent.append(m)
        await app({"type": "http", "method": "POST", "path": "/api/scans", "raw_path": b"/api/scans", "query_string": b"",
                   "headers": [(b"host", b"127.0.0.1:8765"), (b"content-type", b"application/zip"), (b"x-saferun-request", b"1"),
                               (b"content-length", str(10 * 1024**3).encode())],
                   "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8765), "scheme": "http", "http_version": "1.1", "root_path": ""},
                  receive, send)
    asyncio.run(drive())
    assert sent[0]["status"] == 413 and reads == []
    assert leftovers(ws_root) == []


# ------------------------------------------------------------- review regressions

def _scope(path="/api/scans", method="POST"):
    return {"type": "http", "method": method, "path": path, "raw_path": path.encode(), "query_string": b"",
            "headers": [(b"host", b"127.0.0.1:8765"), (b"content-type", b"application/zip"), (b"x-saferun-request", b"1")],
            "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8765), "scheme": "http", "http_version": "1.1", "root_path": ""}


def test_created_at_is_a_wall_clock_timestamp(client):
    sid = client.post("/api/scans", content=zip_bytes(), headers=H).json()["id"]
    created = poll(client, sid)["created_at"]
    assert abs(created - time.time()) < 60


def test_concurrent_stalled_uploads_are_bounded(ws_root, monkeypatch):
    """Slowloris: stalled uploads must count against capacity, otherwise N connections hold N x 25 MiB of temp files."""
    monkeypatch.setattr(app_module, "UPLOAD_TIMEOUT_S", 3)
    mgr = JobManager(JobLimits(max_queue=2), command_builder=stub_builder(OK_CODE))    # capacity 3
    app = create_app(mgr, run_startup_cleanup=False, static_dir=None)
    statuses = {}

    async def one(i):
        sent = []

        async def receive():
            await asyncio.sleep(2)                          # stalls (first read), then the client goes away
            return {"type": "http.disconnect"}

        async def send(m):
            sent.append(m)
        await app(_scope(), receive, send)
        statuses[i] = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)

    async def drive():
        tasks = [asyncio.create_task(one(i)) for i in range(3)]
        await asyncio.sleep(0.4)                            # the three are now in flight, stalled
        await one(99)                                       # a fourth must be refused immediately
        assert statuses[99] == 429
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.run(drive())
    assert statuses[99] == 429 and leftovers(ws_root) == []


def test_uploads_in_flight_are_released_after_errors(client):
    for _ in range(12):                                     # more than the capacity: each failed upload must free its slot
        assert client.post("/api/scans", content=b"", headers=H).status_code == 400
        assert client.post("/api/scans?osv=bad", content=b"x", headers=H).status_code == 422
    assert client.post("/api/scans?osv=disabled", content=zip_bytes(), headers=H).status_code == 202
