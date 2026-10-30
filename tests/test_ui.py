"""Terminal presentation: colours, icons, spinner, progress bar. Plain output (pipes, CI, tests) must stay exactly what it was."""
import io
import json
import re
import threading
import time

import pytest

from saferun import cli, setup as su, ui
from saferun.engine import (CheckResult, CheckStatus, Finding, PackageRef, Severity, ValidationReport, Verdict, compute_verdict)

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class FakeTTY(io.StringIO):
    encoding = "utf-8"

    def isatty(self):
        return True


class AsciiTTY(FakeTTY):
    encoding = "ascii"


def finding(sev, **kw):
    base = dict(check="c", rule_id="r.1", severity=sev, message="msg", path="a/b.py", line=7, category="code")
    base.update(kw)
    return Finding(**base)


def report(*checks, partial=""):
    v, reasons, complete = compute_verdict(list(checks), partial)
    return ValidationReport(v, reasons, complete, list(checks), {"skipped": [], "withheld": []})


def sample():
    dep = finding(Severity.CRITICAL, check="dependency-vulnerabilities", rule_id="PYSEC-1", category="dependency", path="requirements.txt",
                  line=None, message="pyyaml 5.3: arbitrary code execution " + "x" * 400, package=PackageRef("pyyaml", "5.3", "PyPI"), fixed_versions=("5.3.1",))
    return report(CheckResult("python-syntax", CheckStatus.PASSED),
                  CheckResult("python-static-analysis", CheckStatus.FINDINGS, findings=[finding(Severity.MEDIUM), finding(Severity.LOW, rule_id="r.2")]),
                  CheckResult("dependency-vulnerabilities", CheckStatus.FINDINGS, findings=[dep]),
                  CheckResult("javascript-syntax", CheckStatus.NOT_APPLICABLE, detail="no JavaScript files"),
                  CheckResult("x-unavailable", CheckStatus.UNAVAILABLE, detail="image missing"))


# ---------------------------------------------------------------- colour policy
@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in ("NO_COLOR", "FORCE_COLOR", "SAFERUN_ASCII"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")


def test_colour_is_automatic_only_on_a_terminal():
    assert ui.theme_for(FakeTTY()).on is True
    assert ui.theme_for(io.StringIO()).on is False                       # pipes, files, CI logs
    assert ui.theme_for(FakeTTY(), "never").on is False
    assert ui.theme_for(io.StringIO(), "always").on is True


def test_no_color_force_color_and_dumb_terminals(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert ui.theme_for(FakeTTY()).on is False
    assert ui.theme_for(FakeTTY(), "always").on is True                  # an explicit flag beats the environment
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert ui.theme_for(io.StringIO()).on is True
    monkeypatch.setenv("FORCE_COLOR", "0")
    assert ui.theme_for(io.StringIO()).on is False
    monkeypatch.delenv("FORCE_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert ui.theme_for(FakeTTY()).on is False


def test_ascii_fallback_for_non_utf8_terminals(monkeypatch):
    t = ui.theme_for(AsciiTTY())
    assert t.icons["ok"] == "+" and t.icons["bad"] == "x" and t.spin == "|/-\\"
    monkeypatch.setenv("SAFERUN_ASCII", "1")
    assert ui.theme_for(FakeTTY()).icons["ok"] == "+"
    assert ui.theme_for(FakeTTY()).icons["ok"] != "✓"


def test_paint_is_plain_when_off_and_escaped_when_on():
    assert ui.PLAIN.paint("x", "red", "bold") == "x" and ui.Theme(False).icon("ok", "green") == "✓"
    assert ui.Theme(True).paint("x", "red", "bold") == "\x1b[31;1mx\x1b[0m"
    assert ui.Theme(True).paint("x") == "x"


# ---------------------------------------------------------------- spinner
def test_spinner_is_silent_when_the_stream_is_not_a_terminal():
    s = io.StringIO()
    with ui.Spinner(s, "Scanning") as sp:
        assert sp.enabled is False
    assert s.getvalue() == ""


def test_spinner_animates_then_clears_and_restores_the_cursor():
    s = FakeTTY()
    with ui.Spinner(s, "Scanning…", ui.Theme(True), interval=0.01):
        time.sleep(0.15)
    out = s.getvalue()
    assert out.startswith("\x1b[?25l") and out.endswith("\r\x1b[K\x1b[?25h")           # hidden first, restored last, line cleared
    frames = re.findall(r"[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]", out)
    assert len(frames) >= 3 and len(set(frames)) >= 2 and "Scanning…" in out


def test_spinner_restores_the_terminal_on_errors_and_ctrl_c():
    for exc in (RuntimeError("boom"), KeyboardInterrupt()):
        s = FakeTTY()
        sp = ui.Spinner(s, "Working", interval=0.01)
        with pytest.raises(type(exc)):
            with sp:
                time.sleep(0.05)
                raise exc
        assert s.getvalue().endswith("\x1b[?25h") and sp._thread is not None and not sp._thread.is_alive()


def test_spinner_message_is_cut_to_one_line_and_ascii_frames_work(monkeypatch):
    monkeypatch.setattr(ui.shutil, "get_terminal_size", lambda fallback=None: type("S", (), {"columns": 40})())
    s = AsciiTTY()
    with ui.Spinner(s, "m" * 200, ui.theme_for(s), interval=0.01):
        time.sleep(0.05)
    lines = [seg for seg in s.getvalue().split("\r\x1b[K") if "m" in seg]
    assert lines and all(len(ANSI.sub("", seg)) <= 40 for seg in lines) and any(c in s.getvalue() for c in "|/-\\")


def test_progress_bar():
    assert ui.bar(0, 100, ui.PLAIN, 10) == "[" + "░" * 10 + "]   0%"
    assert ui.bar(50, 100, ui.PLAIN, 10) == "[" + "█" * 5 + "░" * 5 + "]  50%"
    assert ui.bar(150, 100, ui.PLAIN, 10).endswith("100%") and ui.bar(-5, 100, ui.PLAIN, 10).endswith("  0%")
    assert ui.bar(5, None, ui.PLAIN) == "" and ui.bar(5, 0, ui.PLAIN) == ""
    assert "#" in ui.bar(1, 2, ui.Theme(False, False), 4)


# ---------------------------------------------------------------- the styled report
def test_styled_report_shows_verdict_icons_severity_tally_fix_and_next_steps():
    rep = sample()
    text = cli.render_styled(rep, "./proj", ui.Theme(True), elapsed=3.2)
    plain = ANSI.sub("", text)
    assert "✗ FAIL" in plain and "scan NOT complete" in plain and "3.2 s" in plain
    assert "✓ passed" in plain and "✗ findings" in plain and "– not_applicable" in plain and "! unavailable" in plain
    assert "CRITICAL 1" in plain and "MEDIUM 1" in plain and "LOW 1" in plain and "Findings (3)" in plain
    assert "[CRITICAL] PYSEC-1" in plain and "fixed in: 5.3.1" in plain and "package: pyyaml 5.3 (PyPI)" in plain
    assert "What to do next" in plain and "Upgrade the vulnerable packages" in plain and "saferun status" in plain
    assert "\x1b[1;35m[CRITICAL]" in text and "\x1b[33m[MEDIUM]" in text and "\x1b[36m[LOW]" in text   # one colour per severity
    assert "\x1b[32;1m✓" in text and "\x1b[31;1m✗" in text                                 # green tick for passed, red cross for findings
    assert "\x1b[32mfixed in: 5.3.1" in text                                               # the fix is green


def test_severity_and_status_colours_are_distinct():
    t = ui.Theme(True)
    tags = {s: t.paint(f"[{s}]", *ui.SEVERITY_STYLE[s]) for s in ui.SEVERITY_STYLE}
    assert len({v.split("m")[0] for v in tags.values()}) >= 4                              # critical, high, medium, low/info do not share a colour
    assert set(ui.VERDICT_STYLE) == {"PASS", "WARNING", "FAIL"} and len(set(ui.VERDICT_STYLE.values())) == 3


def test_styled_report_carries_the_same_facts_as_the_plain_report():
    rep = sample()
    plain = cli.render_text(rep, "./proj")
    styled = ANSI.sub("", cli.render_styled(rep, "./proj", ui.Theme(True)))
    for f in rep.findings:
        assert f.rule_id in plain and f.rule_id in styled
        assert (f.path or "") in styled
    for c in rep.checks:
        assert c.name in styled
    for r in rep.reasons:
        assert r in styled


def test_styled_report_with_the_theme_off_has_no_escape_sequences():
    assert "\x1b" not in cli.render_styled(sample(), "./proj", ui.PLAIN)


def test_hostile_text_cannot_inject_escape_sequences_or_forged_lines_into_the_styled_report():
    evil = "x\x1b[2J\x1b]0;pwned\x07\n  [LOW] forged  y.py:1   [LOW] forged2  z\x1b[31m"
    f = finding(Severity.HIGH, rule_id=evil, message=evil, path=evil, package=PackageRef(evil, evil, evil), fixed_versions=(evil,))
    rep = report(CheckResult(evil, CheckStatus.FINDINGS, findings=[f], detail=evil, errors=[evil], notes=[evil]))
    text = cli.render_styled(rep, evil, ui.Theme(True))
    leftover = ANSI.sub("", text)
    assert "\x1b" not in leftover and "\x07" not in leftover and " " not in leftover          # only SafeRun's own colour codes remain
    assert len(re.findall(r"^\s*\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN)\] ", leftover, re.M)) == 1


# ---------------------------------------------------------------- CLI wiring
@pytest.fixture
def stub(monkeypatch, tmp_path):
    rep = sample()
    monkeypatch.setattr(cli, "validate_project", lambda p, o: rep)
    monkeypatch.setattr(cli.setup_mod, "scan_hints", lambda r: [])
    return tmp_path


def test_scan_output_is_plain_when_piped_and_unchanged(stub, capsys):
    assert cli.main(["scan", str(stub)]) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out and out == cli.render_text(sample(), str(stub))


def test_scan_color_always_styles_text_but_never_json(stub, capsys):
    assert cli.main(["scan", str(stub), "--color", "always"]) == 1
    styled = capsys.readouterr().out
    assert "\x1b[" in styled and "What to do next" in styled and "[CRITICAL] PYSEC-1" in ANSI.sub("", styled)
    assert cli.main(["scan", str(stub), "--color", "always", "--format", "json"]) == 1
    data = capsys.readouterr().out
    assert "\x1b" not in data and json.loads(data)["verdict"] == "FAIL"                    # machine output is never decorated


def test_scan_color_never_and_no_color_env(stub, capsys, monkeypatch):
    assert cli.main(["scan", str(stub), "--color", "never"]) == 1 and "\x1b" not in capsys.readouterr().out
    monkeypatch.setenv("NO_COLOR", "1")
    assert cli.main(["scan", str(stub)]) == 1 and "\x1b" not in capsys.readouterr().out


def test_exit_codes_are_the_same_with_and_without_styling(monkeypatch, tmp_path, capsys):
    for rep, code in ((report(CheckResult("python-syntax", CheckStatus.PASSED)), 0), (sample(), 1),
                      (report(CheckResult("python-syntax", CheckStatus.UNAVAILABLE)), 2)):
        monkeypatch.setattr(cli, "validate_project", lambda p, o, rep=rep: rep)
        monkeypatch.setattr(cli.setup_mod, "scan_hints", lambda r: [])
        assert cli.main(["scan", str(tmp_path), "--color", "never"]) == code
        assert cli.main(["scan", str(tmp_path), "--color", "always"]) == code
        capsys.readouterr()


def test_setup_hints_follow_the_report_and_are_coloured_only_when_asked(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "validate_project", lambda p, o: report(CheckResult("python-syntax", CheckStatus.PASSED)))
    monkeypatch.setattr(cli.setup_mod, "scan_hints", lambda r: ["setup: X is missing  ->  fix: saferun init --only x"])
    assert cli.main(["scan", str(tmp_path)]) == 0
    cap = capsys.readouterr()
    assert cap.err.strip() == "setup: X is missing  ->  fix: saferun init --only x"
    assert cli.main(["scan", str(tmp_path), "--color", "always"]) == 0
    assert "\x1b[33m" in capsys.readouterr().err


def test_every_command_accepts_color():
    parser = cli.build_parser()
    for argv in (["scan", "."], ["init", "--all"], ["status"], ["verify-images"], ["osv-db", "status"]):
        assert parser.parse_args([*argv, "--color", "never"]).color == "never"
        assert parser.parse_args(argv).color == "auto"
    assert cli.main(["init", "--color", "bogus"]) == 64 and cli.main(["scan", ".", "--color", "rainbow"]) == 64


# ---------------------------------------------------------------- setup output
def test_status_report_is_coloured_with_icons_and_the_fix(monkeypatch):
    sts = [su.Status("python", su.READY, "ok"), su.Status("osv-db", su.OUTDATED, "45 days old"), su.Status("analyzer", su.INVALID, "ID mismatch")]
    plain = su.status_report(sts)
    assert "\x1b" not in plain and "READY     Python sandbox image" in plain                  # unchanged plain layout
    styled = su.status_report(sts, ui.Theme(True))
    stripped = ANSI.sub("", styled)
    assert "✓ READY" in stripped and "! OUTDATED" in stripped and "✗ INVALID" in stripped
    assert "fix: saferun init --only osv-db" in stripped and "fix: saferun init --only analyzer --repair" in stripped
    assert "\x1b[32;1m✓" in styled and "\x1b[31;1m✗" in styled and "\x1b[33;1m!" in styled


def test_init_workflow_output_is_coloured_on_a_terminal_and_plain_otherwise():
    class W:
        def status(self, k):
            return su.Status(k, su.READY if k != "osv-db" else su.MISSING, "")

    def run(theme):
        out = io.StringIO()
        s = su.Setup(out=out, status=W().status, online=lambda h: False, theme=theme, free_bytes=lambda p: 10**12)
        s.run(["python", "osv-db"])
        return out.getvalue()
    plain, styled = run(ui.PLAIN), run(ui.Theme(True))
    assert "\x1b" not in plain and "[   ready] Python sandbox image" in plain and "[ missing] OSV vulnerability database" in plain
    assert "\x1b[" in styled and "✓ READY" in ANSI.sub("", styled) and "! MISSING" in ANSI.sub("", styled)
    assert "no internet access" in ANSI.sub("", styled) and "skipped (already installed and verified)" in ANSI.sub("", styled)


def test_menu_shows_coloured_state_tags():
    out = io.StringIO()
    s = su.Setup(out=out, ask=lambda p: "1", interactive=True, status=lambda k: su.Status(k, su.READY), theme=ui.Theme(True))
    s.choose()
    assert "\x1b[" in out.getvalue() and "✓ READY" in ANSI.sub("", out.getvalue())


def test_download_progress_draws_a_bar_on_a_terminal_and_stays_line_based_otherwise():
    tty = io.StringIO()
    p = su.ProgressPrinter(tty, tty=True, theme=ui.PLAIN)
    p("npm", 50 * su.MB, 100 * su.MB)
    assert tty.getvalue().startswith("\r\x1b[K") and "█" in tty.getvalue() and "50 / 100 MB" in tty.getvalue()
    p("npm", 100 * su.MB, 100 * su.MB)
    assert tty.getvalue().endswith("\n")
    plain = io.StringIO()
    q = su.ProgressPrinter(plain, tty=False)
    for done in (0, 100):
        q("npm", done * su.MB, 100 * su.MB)
    assert "\r" not in plain.getvalue() and plain.getvalue().splitlines() == ["    npm: 0 / 100 MB (0%)", "    npm: 100 / 100 MB (100%)"]


def test_analyzer_build_uses_the_spinner_only_on_a_terminal(monkeypatch):
    heard = []

    def build(log):
        log("    building… 5 s (log: /tmp/x)")
        log("    build failed; last lines of the log:")
        return 0
    out = io.StringIO()
    s = su.Setup(out=out, build=build, theme=ui.PLAIN, build_local=True)     # the local build path (a signed release exists otherwise)
    s._install_analyzer()
    assert "building… 5 s" in out.getvalue()                                      # no terminal: the heartbeat lines are kept
    tty = FakeTTY()
    monkeypatch.setattr(su.sys, "stderr", tty)
    out2 = io.StringIO()
    s2 = su.Setup(out=out2, build=build, theme=ui.Theme(True), build_local=True)
    s2._install_analyzer()
    assert "building…" not in out2.getvalue() and "build failed" in out2.getvalue()  # the spinner replaces the heartbeat, failures still print
    assert "Building the analyzer image" in tty.getvalue() and tty.getvalue().endswith("\x1b[?25h")


def test_init_banner_only_on_colour_terminals():
    from saferun import setup as su
    import io
    out = io.StringIO()
    su.Setup(out=out, theme=ui.Theme(True, True)).show_banner()
    assert all(line in out.getvalue() for line in ui.BANNER) and ui.BANNER_TAGLINE in out.getvalue()
    plain = io.StringIO()
    su.Setup(out=plain, theme=ui.Theme(False, True)).show_banner()
    assert plain.getvalue() == ""
