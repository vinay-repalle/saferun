"""Plain-English explanations of findings (the `explanation` field; `message` is never changed).

One or two short sentences: what it is, why it matters, how to fix it. Written for a developer who is not a security
person, with the exact technical term kept next to the simple words. Honest by design: "can" / "could", never "an attacker
will", and no text claims a finding proves an attack or that a fix guarantees safety.

The texts live here (not in the Semgrep rules file or the analyzer image). A rule id with no entry has no explanation.
"""
from __future__ import annotations

import re
from dataclasses import replace

from .osv import version_key

MAX_LEN = 300     # the text report cuts one printed line at 300 characters; every text stays below it

_SEMGREP = {
    "dynamic-code-execution":
        "eval() and exec() run text as code. If that text can come from outside, it could run commands you did not write. "
        "Use ast.literal_eval or json for data, or call the code directly.",
    "subprocess-shell-true":
        "shell=True sends the command through a shell, so untrusted text in it can add extra commands (command injection). "
        "Pass a list instead, like [\"ls\", folder], and remove shell=True.",
    "os-command-execution":
        "os.system() and os.popen() send a text line to the shell, so untrusted text in it can add extra commands "
        "(command injection). Use subprocess.run with a list of arguments.",
    "unsafe-deserialization":
        "Loading pickle, marshal or shelve data can run code hidden in that data. Only load data you created yourself; "
        "use JSON for data from outside.",
    "yaml-unsafe-load":
        "yaml.load() without a safe loader can build any Python object, which can run code. Use yaml.safe_load() instead.",
    "tls-verification-disabled":
        "verify=False turns off the check that the server is the real one, so someone in between could read or change the "
        "traffic. Remove it, or set verify to your own certificate file.",
    "weak-hash":
        "MD5 and SHA-1 are weak and should not protect passwords or prove data is unchanged. Use SHA-256, or bcrypt or "
        "argon2 for passwords. Fine for non-security uses like cache keys.",
    "insecure-tempfile":
        "tempfile.mktemp() only picks a name, and another process could create that file first (race condition). "
        "Use tempfile.mkstemp() or NamedTemporaryFile().",
    "flask-debug":
        "Flask debug mode can give anyone who reaches the app a debugger that runs code. Fine on your own machine; "
        "turn it off before others can reach the app.",
    "hardcoded-secret":
        "A password-like variable is set to fixed text in the code, so anyone who can read the code can read it. "
        "Move it to an environment variable or secret manager, and change it if it was ever real.",
    "assert-for-validation":
        "assert lines are skipped when Python runs with -O, so the check could disappear. "
        "Use an if that raises an error for checks that must always run.",
}
_SEMGREP_PREFIX = "saferun.python."

_EXACT = {
    "withheld.private-key":
        "This file looks like it holds a private key. SafeRun did not read it or copy it into the sandbox. "
        "Keep keys outside the project and out of version control, and replace the key if it was ever shared.",
    "withheld.private-mode":
        "This file is readable only by its owner, so SafeRun left it out of the scan and the sandbox: it was not checked. "
        "If it is safe to share, loosen its permissions (for example chmod 644) and scan again.",
    "python.syntax-error":
        "Python could not read this file, so the other Python checks may have missed problems in it. "
        "Fix the syntax error at this line and scan again.",
}
_TOKEN = ("This file looks like it holds an access token. SafeRun did not read it or copy it into the sandbox. "
          "Keep tokens out of project files and version control, and revoke and replace it if it was ever shared.")
_SECRET = ("A value on this line looks like a password, key or token written into a file, so anyone who can read the project "
           "can read it. SafeRun does not show it. Remove it, load it from an environment variable or secret manager, "
           "and replace it if it was ever real.")


def _nearest_fix(installed: str, fixed) -> str | None:
    """The lowest fixed release above the installed one (the one `fix_kind` is judged on); None if there is none."""
    cur = version_key(installed)
    keyed = [(k, v) for v in fixed if (k := version_key(v)) is not None]
    above = [x for x in keyed if cur is None or x[0] > cur] or keyed
    return min(above)[1] if above else None


def _dependency(f) -> str:
    pk = f.package
    text = (f"{pk.name} {pk.version} has a known security problem ({f.rule_id}), which could affect your project "
            "if the vulnerable code is used. ")
    fix = _nearest_fix(pk.version, f.fixed_versions) if f.fixed_versions else None
    if not f.fixed_versions:
        return text + "No fixed version is listed yet. Check the advisory for workarounds, or consider a different package."
    if fix and f.fix_kind == "patch":
        return text + f"A small update (to {fix} or newer) is listed as fixing it and is usually low-risk; run your tests after upgrading."
    if fix and f.fix_kind == "minor":
        return text + f"Updating to {fix} or newer is listed as fixing it. It is a minor version step: check the changelog and run your tests."
    if fix and f.fix_kind == "major":
        return text + (f"Updating to {fix} or newer is listed as fixing it, but it is a major version jump that may break "
                       "your code: read the changelog and test before upgrading.")
    return text + "A fix is listed (see 'fixed in' below). Check it and run your tests."


def explain(f) -> str:
    """The plain-English text for a finding, or "" when there is none."""
    rid = f.rule_id
    if f.category == "dependency" and f.package is not None:
        return _dependency(f)[:MAX_LEN]
    if rid in _EXACT:
        return _EXACT[rid]
    if rid.startswith("withheld.token:"):
        return _TOKEN
    if rid.startswith("secrets."):
        return _SECRET
    if f.category == "code":
        # Semgrep may prefix the id with the rules file's folders; match on the part from "saferun.python." on
        i = rid.find(_SEMGREP_PREFIX)
        if i >= 0:
            return _SEMGREP.get(rid[i + len(_SEMGREP_PREFIX):], "")
    return ""


def with_explanation(f):
    """The finding with its `explanation` filled in (unchanged if it has one already or none exists)."""
    if f.explanation:
        return f
    text = explain(f)
    return replace(f, explanation=text) if text else f
