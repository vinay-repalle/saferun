"""The three behaviour rules (sensitive-file-access, persistence-setup, hidden-function-lookup) run through real Semgrep.

The repository's rules file is mounted into the analyzer image, so these tests do not depend on which rules the image was built with
(only on its Semgrep). Snippets are small and written for this test, not taken from the benchmark sets.
"""
import json
import subprocess
import sys

import pytest

from saferun.engine.semgrep import RULES_FILE
from saferun.sandbox.analyzer import ANALYZER_REPO_TAG

pytestmark = [pytest.mark.docker, pytest.mark.skipif(sys.platform == "win32", reason="mounts a POSIX temp folder")]

SENS, PERS, HIDE = "sensitive-file-access", "persistence-setup", "hidden-function-lookup"

FLAGGED = {
    "ssh_key": ('import os\nopen(os.path.expanduser("~/.ssh/id_ed25519")).read()\n', SENS),
    "aws": ('from pathlib import Path\nPath.home().joinpath(".aws", "credentials").read_text()\n', SENS),
    "kube_chain": ('from pathlib import Path\nPath.home() / ".kube" / "config"\n', SENS),
    "history": ('import os\nopen(os.path.join(os.path.expanduser("~"), ".zsh_history"))\n', SENS),
    "shadow": ('open("/etc/shadow")\n', SENS),
    "firefox": ('import glob\nglob.glob("/home/u/.mozilla/firefox/*/cookies.sqlite")\n', SENS),
    "bashrc": ('import os\nopen(os.path.expanduser("~/.bashrc"), "a").write("x")\n', PERS),
    "systemd_text": ('UNIT = "[Service]\\nExecStart=/usr/bin/python3 /x.py\\n[Install]\\nWantedBy=default.target\\n"\n', PERS),
    "launchagent_text": ('PL = "<plist><dict><key>RunAtLoad</key><true/></dict></plist>"\n', PERS),
    "schtasks": ('import subprocess\nsubprocess.run(["schtasks", "/create", "/tn", "x"])\n', PERS),
    "crontab_edit": ('import subprocess\nsubprocess.run(["crontab", "/tmp/x"])\n', PERS),
    "cron_line": ('LINE = "@reboot python3 /x.py"\n', PERS),
    "getattr_builtins": ('import builtins\nn = "".join(["e", "v", "al"])\ngetattr(builtins, n)("1")\n', HIDE),
    "getattr_const_name": ('import builtins\nn = "ev" + "al"\ngetattr(builtins, n)("1")\n', HIDE),
    "getattr_split": ('import os\ngetattr(os, "sys" + "tem")("true")\n', HIDE),
    "vars_builtins": ('import builtins\nvars(builtins)["ex" + "ec"]("1")\n', HIDE),
    "dunder_import": ('m = __import__("o" + "s")\n', HIDE),
    "import_module": ('import importlib\nimportlib.import_module("sub" + "process")\n', HIDE),
}

CLEAN = {
    "help_text_mentions": 'HELP = "Do not keep keys in ~/.aws/credentials on shared machines."\nprint(HELP)\n',
    "crontab_print": 'script = "/opt/backup.py"\nprint("crontab -e, then add:")\nprint(f"0 3 * * * python3 {script}")\n',
    "crontab_list": 'import subprocess\nsubprocess.run(["crontab", "-l"])\n',
    "plain_read": 'import csv\nopen("data.csv").read()\nopen("notes.txt")\n',
    "home_documents": 'from pathlib import Path\nPath.home() / "Documents" / "report.txt"\n',
    "getattr_plugin": 'def run(obj, kind):\n    return getattr(obj, "handle_" + kind)()\n',
    "getattr_literal": 'import os\nx = getattr(os, "getcwd")\n',
    "getattr_plain": 'class C:\n    a = 1\nprint(getattr(C, "a"))\n',
    "import_literal": 'm = __import__("json")\n',
    "import_module_literal": 'import importlib\nimportlib.import_module("json")\n',
    "env_get": 'import os\nprint(os.environ.get("EDITOR", "nano"))\n',
}


@pytest.fixture(scope="module")
def hits(tmp_path_factory):
    d = tmp_path_factory.mktemp("rules_in")
    for name, (code, _) in FLAGGED.items():
        (d / f"f_{name}.py").write_text(code)
    for name, code in CLEAN.items():
        (d / f"c_{name}.py").write_text(code)
    d.chmod(0o755)
    p = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--user", "1000:1000", "-e", "HOME=/tmp", "--tmpfs", "/tmp",
         "-v", f"{RULES_FILE.parent}:/r:ro", "-v", f"{d}:/w:ro", ANALYZER_REPO_TAG,
         "/usr/local/bin/semgrep", "scan", "--metrics=off", "--disable-version-check", "--config", "/r/python.yml", "--json", "--quiet", "/w"],
        capture_output=True, text=True, timeout=300)
    out = json.loads(p.stdout)
    assert out["errors"] == [], out["errors"]
    found: dict[str, set[str]] = {}
    for r in out["results"]:
        found.setdefault(r["path"].rsplit("/", 1)[1][:-3], set()).add(r["check_id"].rsplit(".", 1)[1])
    return found


@pytest.mark.parametrize("name", FLAGGED)
def test_flagged_snippets_raise_their_rule_at_medium(hits, name):
    assert FLAGGED[name][1] in hits.get(f"f_{name}", set())


@pytest.mark.parametrize("name", CLEAN)
def test_ordinary_code_is_not_flagged_by_the_behaviour_rules(hits, name):
    assert not ({SENS, PERS, HIDE} & hits.get(f"c_{name}", set()))


def test_the_three_rules_are_medium_severity():
    import re
    text = RULES_FILE.read_text(encoding="utf-8")
    for rid in (SENS, PERS, HIDE):
        block = text.split(f"id: saferun.python.{rid}\n", 1)[1].split("\n  - id: ", 1)[0]
        assert re.search(r"saferun_severity: medium\b", block), rid
