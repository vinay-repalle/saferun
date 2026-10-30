"""Network-facing guards for the local dashboard (Phase 4): loopback-only access, Host/Origin checks, headers.

This is the application-level enforcement of "loopback only": `is_loopback_ip`/`resolve_bind` are used by the launcher
(server.py) to refuse non-loopback bind configurations, and `GuardMiddleware` independently refuses any request whose
TCP peer is not loopback - so the restriction holds even if the ASGI app is started some other way (e.g. `uvicorn
--host 0.0.0.0 saferun.api.app:app`). It does not make remote exposure safe; remote use is simply not supported
(host-side Semgrep/OSV-Scanner parse hostile files - see docs/api.md).
"""
from __future__ import annotations

import ipaddress
import json
import re

LOOPBACK_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "[::1]"})
CSRF_HEADER = "x-saferun-request"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = (
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
)


class BindError(ValueError):
    """The requested bind address is not a loopback address."""


def is_loopback_ip(value) -> bool:
    """True only for a literal IPv4 127.0.0.0/8 or IPv6 ::1 address. Hostnames, empty strings, wildcard addresses
    and IPv4-mapped IPv6 forms are not accepted (strict on purpose)."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        return ip == ipaddress.IPv6Address("::1")
    return ip in ipaddress.ip_network("127.0.0.0/8")


def resolve_bind(host, port) -> tuple[str, int]:
    """Validate a bind configuration. `localhost` is mapped to 127.0.0.1 (no DNS lookup); everything else must be a
    loopback IP literal. Raises BindError otherwise - the server is never started with a non-loopback address."""
    if isinstance(host, str) and host == "localhost":
        host = "127.0.0.1"
    if not is_loopback_ip(host):
        raise BindError(f"refusing to bind to {str(host)[:64]!r}: SafeRun's web dashboard is loopback-only "
                        "(127.0.0.1 or ::1). Remote access is not supported.")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise BindError(f"invalid port: {str(port)[:16]!r}")
    return host, port


_HOST_RE = re.compile(r"^(?P<h>localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::(?P<p>\d{1,5}))?$")


def host_header_ok(value: str | None) -> bool:
    """Host header must name a loopback host (DNS-rebinding defence): localhost, 127.x.x.x or [::1], optional port."""
    if not value:
        return False
    m = _HOST_RE.match(value.strip().lower())
    if not m:
        return False
    h = m.group("h")
    return h in ("localhost", "[::1]") or is_loopback_ip(h)


def _json_response(status: int, code: str, message: str):
    body = json.dumps({"error": {"code": code, "message": message}}).encode()
    return status, [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                    (b"cache-control", b"no-store")], body


class GuardMiddleware:
    """Pure ASGI middleware, applied to every request:
      * the TCP peer must be loopback (403 otherwise; no peer address = refused)
      * the Host header must be a loopback name (400)
      * state-changing methods need the custom header (forces a CORS preflight that is never answered) and, if an
        Origin header is present, it must be exactly this server's own origin (403)
      * security headers on every response; `Cache-Control: no-store` on the API
    WebSocket and other non-HTTP scopes are refused."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await receive()
                await send({"type": "websocket.close", "code": 1008})
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        client = scope.get("client")
        refusal = None
        if not client or not is_loopback_ip(client[0]):
            refusal = (403, "forbidden-peer", "only loopback clients are served")
        elif not host_header_ok(headers.get("host")):
            refusal = (400, "bad-host", "invalid Host header")
        elif scope["method"] not in ("GET", "HEAD"):
            origin = headers.get("origin")
            if headers.get(CSRF_HEADER) != "1":
                refusal = (403, "missing-header", "missing X-SafeRun-Request header")
            elif origin is not None and origin != f"http://{headers['host']}":
                refusal = (403, "bad-origin", "cross-origin request refused")
        if refusal:
            status, hdrs, body = _json_response(*refusal)
            hdrs += list(SECURITY_HEADERS)
            await send({"type": "http.response.start", "status": status, "headers": hdrs})
            await send({"type": "http.response.body", "body": body})
            return
        is_api = scope["path"].startswith("/api/")

        async def send_wrapped(message):
            if message["type"] == "http.response.start":
                names = {k.lower() for k, _ in message["headers"]}
                extra = [h for h in SECURITY_HEADERS if h[0] not in names]
                if is_api and b"cache-control" not in names:
                    extra.append((b"cache-control", b"no-store"))
                message = dict(message, headers=list(message["headers"]) + extra)
            await send(message)
        await self.app(scope, receive, send_wrapped)
