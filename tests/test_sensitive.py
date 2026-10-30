"""Sensitive-file handling: withholding by mode and content signature, and output redaction."""
import os

import pytest

from saferun.sandbox import SensitivePolicy, run_sandboxed, SandboxLimits
from saferun.sandbox import copy as cp
from saferun.sandbox.secrets import MASK, Redactor, drop_partial_tail
from saferun.sandbox.workspace import create_workspace

# Fake credentials are assembled at runtime so no real-looking secret sits in the repository.
PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n" * 3
PEM = "-----BEGIN " + "PRIVATE KEY-----\n" + PEM_BODY + "-----END " + "PRIVATE KEY-----\n"
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
TOKENS = {
    "private-key": PEM,
    "token:aws-access-key": f'KEY = "{AWS}"\n',
    "token:github": "t = 'gh" + "p_" + "a" * 36 + "'\n",
    "token:slack": "x" + "oxb-" + "1234567890-abcdefghij",
    "token:google-api-key": "AI" + "za" + "A" * 35,
    "token:stripe-live": "s" + "k_live_" + "a" * 24,
    "token:pypi": "py" + "pi-AgEIcHlwaS5vcmc" + "A" * 60,
    "token:anthropic": "sk" + "-ant-" + "a" * 50,
}


def _ws(tmp_path, files: dict, policy=None):
    src = tmp_path / "p"; src.mkdir()
    for name, (content, mode) in files.items():
        f = src / name; f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content); f.chmod(mode)
    return create_workspace(src, policy=policy)


def _tree_text(ws):
    return "".join(p.read_text(errors="replace") for p in ws.root.rglob("*") if p.is_file())


def test_mode_not_filename_decides(tmp_path, ws_root):
    """`.env` at 0644 is a normal file; an innocent-named 0600 file is withheld."""
    ws = _ws(tmp_path, {".env": ("MODE=dev\n", 0o644), "notes.txt": ("private", 0o600),
                        "group.txt": ("g", 0o640)})
    try:
        assert sorted(p.name for p in ws.project.iterdir()) == [".env"]
        assert {(w.path, w.reason) for w in ws.withheld} == {
            ("notes.txt", "private-mode"), ("group.txt", "private-mode")}
        assert "private" not in _tree_text(ws)
    finally:
        ws.cleanup()


def test_private_directory_is_withheld_but_root_is_exempt(tmp_path, ws_root):
    src = tmp_path / "p"; (src / ".ssh").mkdir(parents=True)
    (src / ".ssh" / "config").write_text("Host x")      # 0644 inside a 0700 dir
    (src / ".ssh").chmod(0o700); (src / "ok.py").write_text("x=1")
    src.chmod(0o700)  # the root the user pointed us at is never judged
    ws = create_workspace(src)
    try:
        assert [p.name for p in ws.project.iterdir()] == ["ok.py"]
        assert [(w.path, w.reason) for w in ws.withheld] == [(".ssh", "private-mode")]
    finally:
        ws.cleanup()


def test_allow_paths_and_opt_out_restore_private_files(tmp_path, ws_root):
    ws = _ws(tmp_path, {"a.txt": ("A", 0o600), "b.txt": ("B", 0o600)},
             SensitivePolicy(allow_paths={"a.txt"}))
    try:
        assert sorted(p.name for p in ws.project.iterdir()) == ["a.txt"]
        assert [w.path for w in ws.withheld] == ["b.txt"]
    finally:
        ws.cleanup()
    (tmp_path / "p" / "a.txt").chmod(0o600)
    ws = create_workspace(tmp_path / "p", policy=SensitivePolicy(honor_private_modes=False))
    try:
        assert sorted(p.name for p in ws.project.iterdir()) == ["a.txt", "b.txt"] and not ws.withheld
    finally:
        ws.cleanup()


@pytest.mark.parametrize("kind", sorted(TOKENS))
def test_signature_withholds_file_whatever_its_name(tmp_path, ws_root, kind):
    ws = _ws(tmp_path, {"innocent_name.py": (TOKENS[kind], 0o644), "fine.py": ("x = 1\n", 0o644)})
    try:
        assert [(w.path, w.reason) for w in ws.withheld] == [("innocent_name.py", kind)]
        assert [p.name for p in ws.project.iterdir()] == ["fine.py"]
        assert TOKENS[kind].strip()[-12:] not in _tree_text(ws)  # nothing of it left on disk
        assert TOKENS[kind].strip()[-12:] not in repr(ws.withheld) + repr(ws)
    finally:
        ws.cleanup()


@pytest.mark.parametrize("content", [
    'HEADER = "-----BEGIN PRIVATE KEY-----"  # format marker only, no key body\n',
    "def parse(pem):\n    return pem.startswith('-----BEGIN RSA PRIVATE KEY-----')\n",
    "see disk-" + "x" * 40 + " and task-" + "y" * 40 + "\n",
    "ghp_ is a prefix; AKIA alone; xox; AIza; sk-ant-short\n",
    "AKIA" + "IOSFODNN7EXAMPL" + "\n",                      # one character short
])
def test_similar_but_harmless_content_is_not_withheld(tmp_path, ws_root, content):
    ws = _ws(tmp_path, {"code.py": (content, 0o644)})
    try:
        assert ws.withheld == [] and (ws.project / "code.py").read_text() == content
    finally:
        ws.cleanup()


def test_signature_split_across_read_chunks_is_still_found(tmp_path, ws_root, monkeypatch):
    monkeypatch.setattr(cp, "CHUNK", 64)
    for pad in range(0, 70, 7):  # moves the token across several chunk boundaries
        d = tmp_path / f"t{pad}"; d.mkdir()
        ws = _ws(d, {"f.txt": ("x" * pad + " " + AWS + "\n", 0o644)})
        try:
            assert [w.reason for w in ws.withheld] == ["token:aws-access-key"], pad
        finally:
            ws.cleanup()


def test_allowed_path_with_signature_is_copied_intact(tmp_path, ws_root):
    ws = _ws(tmp_path, {"fixture.pem": (PEM, 0o644)}, SensitivePolicy(allow_paths={"fixture.pem"}))
    try:
        assert (ws.project / "fixture.pem").read_text() == PEM and ws.withheld == []
    finally:
        ws.cleanup()


# ---- redaction -------------------------------------------------------------

def test_redactor_learns_secret_assignments_not_code():
    r = Redactor()
    r.learn(b"DB_PASSWORD=hunter2hunter2\nexport API_TOKEN='abcd-1234-efgh'\n"
            b'"client_secret": "s3cr3t-value-xyz"\nDEBUG=true\nPASSWORD=short\n'
            b'API_KEY = os.environ["API_KEY"]\ntoken = get_token()\n')
    out, n = r.redact("a hunter2hunter2 b abcd-1234-efgh c s3cr3t-value-xyz d short e os.environ")
    assert out == f"a {MASK} b {MASK} c {MASK} d short e os.environ" and n == 3


def test_redactor_masks_signatures_in_output_even_if_not_in_any_file():
    out, n = Redactor().redact(f"id={AWS}\n{PEM}done")
    assert AWS not in out and "MIIEvQ" not in out and "BEGIN" not in out and out.endswith("done") and n == 2


def test_redactor_masks_truncated_key_block_to_end_and_escaped_form():
    out, _ = Redactor().redact("x " + PEM[: len(PEM) // 2])
    assert out == f"x {MASK}"
    out, _ = Redactor().redact(repr(PEM) + " tail")
    assert "MIIEvQ" not in out and out.endswith(" tail")


def test_redactor_leaves_unrelated_text_alone():
    text = "-----BEGIN PRIVATE KEY----- is a header\nAKIA is a prefix\n"
    assert Redactor().redact(text) == (text, 0)


def test_drop_partial_tail():
    assert drop_partial_tail("alpha beta gam") == "alpha beta "
    assert drop_partial_tail("alpha\nbeta") == "alpha\n"
    assert drop_partial_tail("noseparator") == ""


# ---- end to end through the sandbox ---------------------------------------

@pytest.mark.docker
class TestThroughSandbox:
    @pytest.fixture
    def run(self, tmp_path, ws_root):
        def _run(files: dict, code: str, **kw):
            proj = tmp_path / "proj"; proj.mkdir()
            for name, (content, mode) in files.items():
                (proj / name).write_text(content); (proj / name).chmod(mode)
            (proj / "main.py").write_text(code)
            return run_sandboxed(proj, ["python", "-I", "main.py"], SandboxLimits(**kw.pop("limits", {})), **kw)
        return _run

    def test_readable_secret_is_redacted_from_stdout_and_stderr(self, run):
        r = run({".env": ("DB_PASSWORD=hunter2hunter2\n", 0o644), "cert.txt": (PEM, 0o644)},
                "import sys\nd = open('.env').read()\nprint(d); sys.stderr.write(d)\n")
        assert r.exit_code == 0
        assert "hunter2hunter2" not in r.stdout + r.stderr and MASK in r.stdout and MASK in r.stderr
        assert r.redactions == 2 and [w.path for w in r.withheld] == ["cert.txt"]

    def test_withheld_files_do_not_exist_for_the_sandboxed_code(self, run):
        code = "import os\nprint(sorted(os.listdir('.')))\n"
        r = run({"id_key": ("TOP-SECRET-CONTENT", 0o600), "tok.py": (f"K='{AWS}'", 0o644)}, code)
        assert r.stdout.strip() == "['main.py']"
        assert (r.copied_files, r.copied_dirs, r.copied_bytes, r.entries_scanned) == (1, 0, len(code), 3)
        assert {(w.path, w.reason) for w in r.withheld} == {
            ("id_key", "private-mode"), ("tok.py", "token:aws-access-key")}
        assert "TOP-SECRET-CONTENT" not in repr(r) and AWS not in repr(r)

    def test_secret_cut_by_output_truncation_does_not_leak_a_prefix(self, run):
        secret = "hunter2hunter2-abcdef"
        r = run({".env": (f"API_TOKEN={secret}\n", 0o644)},
                f"print('A' * 100 + ' ' + {secret!r})\n", limits={"max_output_bytes": 100 + 1 + 8})
        assert r.output_truncated and secret[:6] not in r.stdout

    def test_known_limitation_encoded_secret_is_not_redacted(self, run):
        """Documents a gap: code can transform a secret before printing it. If this starts failing,
        redaction improved and PROJECT.md must be updated."""
        r = run({".env": ("API_TOKEN=hunter2hunter2\n", 0o644)},
                "import base64\nprint(base64.b64encode(open('.env').read().split('=')[1].strip().encode()).decode())\n")
        assert "aHVudGVyMmh1bnRlcjI=" in r.stdout
