"""FastAPI application for the local SafeRun dashboard (Phase 4, unit 3).

A thin HTTP layer: upload a ZIP, poll the job, read the engine's report. All validation happens in the existing
CLI/engine (see jobs.py); nothing is executed here, and there is no endpoint that runs code or commands.

  POST   /api/scans?osv=offline|disabled   body: raw application/zip      -> 202 {id, status}
  GET    /api/scans/{id}                                                          -> job (+ report when done)
  DELETE /api/scans/{id}                                                          -> 204 (finished jobs only)
  GET    /api/health                                                              -> tool availability, limits
  GET    /                                                                        -> built dashboard (web/dist), if built

Auth: none, deliberately no claim of it. Access control is loopback-only (guard.py + server.py). The interactive
OpenAPI pages are disabled.
"""
from __future__ import annotations

import asyncio
import errno
import os
import re
import shutil
import tempfile
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from ..sandbox import reap_orphans
from .archive import MiB, UPLOAD_PREFIX, ArchiveLimits
from .guard import GuardMiddleware
from ..sandbox.analyzer import verify_analyzer_image
from .jobs import OSV_MODES, Busy, JobLimits, JobManager, startup_cleanup, worker_path

DEFAULT_STATIC_DIR = Path(__file__).resolve().parents[2] / "web" / "dist"
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
UPLOAD_TIMEOUT_S = 120.0
_CHUNK = 64 * 1024


def _error(status: int, code: str, message: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status, headers=headers)


def _safe_reap():
    return reap_orphans()


# An upload needs room for itself, and the job then needs about twice the extracted size (checked later by the extractor).
# Refuse early instead of filling the disk: free space must cover the declared size plus this reserve.
DISK_RESERVE_BYTES = 64 * MiB
HEALTH_PROBE_TIMEOUT_S = 10.0     # a hung Docker daemon must not hold health requests (each docker call may take up to 30 s)
HEALTH_PROBE_TTL_S = 5.0


def _no_space() -> JSONResponse:
    return _error(507, "insufficient-storage", "not enough free disk space for this upload")


def _free_bytes() -> int:
    return shutil.disk_usage(tempfile.gettempdir()).free


class _AnalyzerProbe:
    """`verify_analyzer_image` with a hard time limit and a short cache.

    The probe runs on a daemon thread; at most one runs at a time. If Docker hangs, callers get "not available" after
    `timeout_s` and later calls reuse the pending probe instead of piling up threads.
    """

    def __init__(self, check, timeout_s: float | None = None, ttl_s: float | None = None):
        self._check, self._timeout_s, self._ttl_s = check, timeout_s, ttl_s
        self._lock = threading.Lock()
        self._result: tuple[float, bool] | None = None
        self._pending: threading.Event | None = None

    @property
    def _timeout(self) -> float:
        return HEALTH_PROBE_TIMEOUT_S if self._timeout_s is None else self._timeout_s

    @property
    def _ttl(self) -> float:
        return HEALTH_PROBE_TTL_S if self._ttl_s is None else self._ttl_s

    def _run(self, done: threading.Event, box: list) -> None:
        try:
            self._check()
            ok = True
        except Exception:  # noqa: BLE001 - any problem means the analyzer cannot be relied on
            ok = False
        with self._lock:
            self._result = (time.monotonic(), ok)
            self._pending = None
        box.append(ok)
        done.set()

    def ok(self) -> bool:
        with self._lock:
            if self._result and time.monotonic() - self._result[0] < self._ttl:
                return self._result[1]
            done = self._pending
            if done is None:
                done, box = threading.Event(), []
                self._pending = done
                threading.Thread(target=self._run, args=(done, box), name="saferun-health", daemon=True).start()
        if done.wait(self._timeout):
            with self._lock:
                return bool(self._result and self._result[1])
        return False


def create_app(manager: JobManager | None = None, *, archive_limits: ArchiveLimits | None = None,
               static_dir: Path | None = DEFAULT_STATIC_DIR, run_startup_cleanup: bool = True) -> FastAPI:
    limits = archive_limits or ArchiveLimits()
    mgr = manager or JobManager(JobLimits(), limits, reaper=_safe_reap)

    probe = _AnalyzerProbe(lambda: verify_analyzer_image())
    lock_fd: list[int | None] = [None]

    @asynccontextmanager
    async def lifespan(_app):
        if run_startup_cleanup:
            # Crash recovery: leftovers (and orphaned workers) of a server that was SIGKILLed, then abandoned containers/workspaces.
            lock_fd[0] = startup_cleanup(mgr.limits.stale_after_s).lock_fd
            try:
                reap_orphans()
            except Exception:   # noqa: BLE001 - Docker may be down; scans will then fail visibly, not silently
                pass
        mgr.start()
        yield
        mgr.shutdown()
        if lock_fd[0] is not None:
            os.close(lock_fd[0])
            lock_fd[0] = None

    inflight = [0]   # uploads currently being read; they count against capacity like queued jobs

    app = FastAPI(title="SafeRun dashboard", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(GuardMiddleware)

    @app.post("/api/scans", status_code=202)
    async def create_scan(request: Request, osv: str = "offline"):
        if osv == "online":
            return _error(422, "osv-online-unsupported", "online OSV scanning is not supported: scans run offline in an isolated "
                          "container. Refresh the local data with `saferun osv-db update`")
        if osv not in OSV_MODES:
            return _error(422, "invalid-osv-mode", f"osv must be one of: {', '.join(OSV_MODES)}")
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/zip":
            return _error(415, "unsupported-media-type", "send the archive as the raw body with Content-Type: application/zip")
        cap = limits.max_archive_bytes
        cl = request.headers.get("content-length")
        if cl is not None:
            if not cl.isdigit():
                return _error(400, "bad-content-length", "invalid Content-Length")
            if int(cl) > cap:
                return _error(413, "archive-too-large", f"the archive exceeds {cap // MiB} MiB")
        if inflight[0] + mgr.counts()["active"] >= mgr.counts()["capacity"]:
            return _error(429, "busy", "too many scans in progress; try again shortly", {"Retry-After": "30"})
        try:
            if _free_bytes() < (int(cl) if cl is not None else 0) + DISK_RESERVE_BYTES:
                return _no_space()
        except OSError:
            return _no_space()
        inflight[0] += 1          # asyncio is single-threaded: no await between the check above and this increment
        try:
            fd, path = tempfile.mkstemp(prefix=UPLOAD_PREFIX, suffix=".zip")
        except OSError as e:
            inflight[0] -= 1
            if e.errno in (errno.ENOSPC, errno.EDQUOT):
                return _no_space()
            raise
        except BaseException:
            inflight[0] -= 1
            raise
        owned = True
        try:
            total = 0
            deadline = time.monotonic() + UPLOAD_TIMEOUT_S
            with os.fdopen(fd, "wb") as out:
                it = request.stream().__aiter__()
                while True:
                    try:
                        chunk = await asyncio.wait_for(it.__anext__(), max(0.001, deadline - time.monotonic()))
                    except StopAsyncIteration:
                        break
                    except asyncio.TimeoutError:
                        return _error(408, "upload-timeout", "the upload took too long")
                    total += len(chunk)
                    if total > cap:
                        return _error(413, "archive-too-large", f"the archive exceeds {cap // MiB} MiB")
                    out.write(chunk)
            if total == 0:
                return _error(400, "empty-body", "the request body is empty")
            try:
                job = mgr.submit(path, osv)
            except Busy:
                return _error(429, "busy", "too many scans in progress; try again shortly", {"Retry-After": "30"})
            owned = False
            return JSONResponse({"id": job.id, "status": job.status}, status_code=202)
        except OSError as e:
            if e.errno in (errno.ENOSPC, errno.EDQUOT):   # the disk filled up mid-upload: the partial file is removed below
                return _no_space()
            raise
        finally:
            inflight[0] -= 1
            if owned:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        job = mgr.get(scan_id) if _ID_RE.match(scan_id) else None
        return JSONResponse(job) if job else _error(404, "not-found", "no such scan")

    @app.delete("/api/scans/{scan_id}")
    def delete_scan(scan_id: str):
        if not _ID_RE.match(scan_id) or mgr.get(scan_id) is None:
            return _error(404, "not-found", "no such scan")
        if not mgr.delete(scan_id):
            return _error(409, "not-finished", "the scan is still queued or running")
        return Response(status_code=204)

    @app.get("/api/health")
    def health():
        path = worker_path()
        docker_cli = shutil.which("docker", path=path) is not None
        analyzer = probe.ok()
        # "semgrep" / "osv_scanner" keep their old keys: both now mean "available in the verified analyzer image"
        return {"docker_cli": docker_cli, "analyzer": analyzer, "semgrep": analyzer, "osv_scanner": analyzer,
                "queue": mgr.counts(),
                "limits": {"max_archive_mib": limits.max_archive_bytes // MiB, "max_uncompressed_mib": limits.max_total_bytes // MiB,
                           "max_entries": limits.max_entries, "max_file_mib": limits.max_file_bytes // MiB,
                           "job_deadline_s": mgr.limits.job_deadline_s, "result_ttl_s": mgr.limits.result_ttl_s}}

    if static_dir is not None and (Path(static_dir) / "index.html").is_file():
        static_dir = Path(static_dir)
        if (static_dir / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(static_dir / "index.html", media_type="text/html", headers={"Cache-Control": "no-store"})

    return app
