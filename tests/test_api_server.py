"""Loopback-only enforcement (Phase 4 unit 4): the launcher refuses non-loopback bind configurations, in code."""
import subprocess
import sys

import pytest

from saferun.api import server
from saferun.api.guard import BindError, host_header_ok, is_loopback_ip, resolve_bind

LOOPBACK = ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1", "0:0:0:0:0:0:0:1"]
NOT_LOOPBACK = ["0.0.0.0", "::", "", " ", "localhost ", "192.168.1.10", "10.0.0.1", "8.8.8.8", "example.com", "127.0.0.1.evil.com",
                "::ffff:127.0.0.1", "::ffff:7f00:1", "128.0.0.1", "1", "127.1", "0x7f.0.0.1", "2130706433", "fe80::1", "[::1]",
                "127.0.0.1\n", "127.0.0.1 ", None, 127, b"127.0.0.1"]


@pytest.mark.parametrize("host", LOOPBACK)
def test_loopback_literals_are_accepted(host):
    assert is_loopback_ip(host) and resolve_bind(host, 8765) == (host, 8765)


@pytest.mark.parametrize("host", NOT_LOOPBACK, ids=repr)
def test_everything_else_is_refused(host):
    assert not is_loopback_ip(host)
    with pytest.raises(BindError):
        resolve_bind(host, 8765)


def test_localhost_maps_to_ipv4_loopback_without_dns():
    assert resolve_bind("localhost", 80) == ("127.0.0.1", 80)


@pytest.mark.parametrize("port", [0, -1, 65536, "80", None, True, 1.5])
def test_invalid_ports_are_refused(port):
    with pytest.raises(BindError):
        resolve_bind("127.0.0.1", port)


@pytest.mark.parametrize("value,ok", [("127.0.0.1:8765", True), ("localhost", True), ("LOCALHOST:80", True), ("[::1]:9", True),
                                      ("127.0.0.1", True), ("evil.com", False), ("localhost.evil.com", False), ("127.0.0.1.evil.com", False),
                                      ("", False), (None, False), ("0.0.0.0:80", False), ("192.168.0.1", False), ("127.0.0.1:99999999", False),
                                      ("localhost:80@evil.com", False), ("a b", False)])
def test_host_header_allow_list(value, ok):
    assert host_header_ok(value) is ok


class FakeUvicorn:
    calls = []

    @staticmethod
    def run(app, **kw):
        FakeUvicorn.calls.append(kw)


@pytest.fixture
def fake_uvicorn(monkeypatch):
    import uvicorn
    FakeUvicorn.calls = []
    monkeypatch.setattr(uvicorn, "run", FakeUvicorn.run)
    return FakeUvicorn


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.5", "example.com", "", "::ffff:127.0.0.1"])
def test_launcher_refuses_non_loopback_hosts_and_never_starts_the_server(fake_uvicorn, capsys, host):
    assert server.main(["--host", host]) == 64
    assert fake_uvicorn.calls == []
    assert "loopback-only" in capsys.readouterr().err


def test_launcher_refuses_a_bad_port(fake_uvicorn):
    assert server.main(["--port", "0"]) == 64 and fake_uvicorn.calls == []


@pytest.mark.parametrize("host,expect", [(None, "127.0.0.1"), ("127.0.0.1", "127.0.0.1"), ("::1", "::1"), ("localhost", "127.0.0.1")])
def test_launcher_starts_on_loopback_with_hardened_options(fake_uvicorn, host, expect):
    assert server.main(["--port", "8123"] + (["--host", host] if host else [])) == 0
    kw, = fake_uvicorn.calls
    assert kw["host"] == expect and kw["port"] == 8123 and kw["proxy_headers"] is False and kw["server_header"] is False


def test_no_environment_variable_can_override_the_bind(fake_uvicorn, monkeypatch):
    for k in ("HOST", "UVICORN_HOST", "SAFERUN_HOST", "SAFERUN_BIND", "BIND"):
        monkeypatch.setenv(k, "0.0.0.0")
    assert server.main([]) == 0 and fake_uvicorn.calls[0]["host"] == "127.0.0.1"


def test_launcher_as_a_real_process_refuses_wildcard_bind_and_exits_immediately():
    r = subprocess.run([sys.executable, "-I", "-m", "saferun.api", "--host", "0.0.0.0", "--port", "18765"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 64 and "loopback-only" in r.stderr and "Traceback" not in r.stderr
