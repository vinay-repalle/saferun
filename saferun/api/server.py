"""Launcher for the local dashboard: `python -m saferun.api` / `saferun-web`.

Loopback-only is enforced here in code: the bind address is validated by `guard.resolve_bind` BEFORE anything is
imported or started, and there is no environment variable or option that bypasses it. A non-loopback `--host`
exits with status 64 and prints why. (GuardMiddleware additionally refuses non-loopback peers.)
"""
from __future__ import annotations

import argparse
import sys

from .guard import BindError, resolve_bind

DEFAULT_PORT = 8765


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="saferun-web", description=(
        "SafeRun local dashboard (loopback only). Uploaded archives are treated as hostile and are never executed; "
        "host-side Semgrep/OSV-Scanner still parse them, so do not expose this beyond your own machine."))
    p.add_argument("--host", default="127.0.0.1", help="loopback address only (127.0.0.1 or ::1); anything else is refused")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    return p


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 64
    try:
        host, port = resolve_bind(args.host, args.port)
    except BindError as e:
        print(f"saferun-web: error: {e}", file=sys.stderr)
        return 64
    try:
        import uvicorn
        from .app import create_app
    except ImportError:
        print("saferun-web: error: the web extra is not installed (pip install -e '.[web]')", file=sys.stderr)
        return 70
    print(f"SafeRun dashboard on http://{host if ':' not in host else '[' + host + ']'}:{port}/  (loopback only; Ctrl+C to stop)",
          file=sys.stderr)
    uvicorn.run(create_app(), host=host, port=port, log_level="warning", server_header=False, date_header=False,
                proxy_headers=False, forwarded_allow_ips="", timeout_keep_alive=5, access_log=False,
                limit_concurrency=32, h11_max_incomplete_event_size=16 * 1024)
    return 0


if __name__ == "__main__":
    sys.exit(main())
