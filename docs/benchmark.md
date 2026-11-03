# Benchmark: SafeRun vs Bandit and pip-audit

A small, honest comparison of SafeRun's **scan** with two established tools:

| Part of SafeRun | Compared with | Kind |
|---|---|---|
| Python code checks (Semgrep with SafeRun's own rules) | [Bandit](https://bandit.readthedocs.io/) | static code analysis (SAST) |
| Dependency check (OSV-Scanner, local OSV data) | [pip-audit](https://pypi.org/project/pip-audit/), default PyPI service and `-s osv` | known-vulnerability check (SCA) |
| `saferun check-names` (look-alike package names) | nothing comparable | reported separately as SafeRun-only |

**Secrets scan.** The numbers below were taken on 2026-11-03 before `scan` gained its gitleaks secrets check (`hardcoded-secrets`); that check is not part of this comparison (Bandit's hardcoded-password rule is the only related one) and the results have not been re-run since.

The sandbox (`saferun run`) is **not** measured. The benchmark is a development tool: it is not part of the installed package, it runs only in the dev environment, and in CI it is advisory (it never blocks a merge).

## How it works

- **Samples** are plain text in [tools/benchmark/samples.toml](https://github.com/vinay-repalle/saferun/blob/main/tools/benchmark/samples.toml): 70 code samples (48 bad, 22 clean), 12 dependency samples (8 vulnerable pins, 4 current pins) and 6 look-alike-name samples. Each has an expected label, fixed **before any tool was run** (it is in git history), and a split: `dev` (used while writing the runner) or `held-out` (run once, never used to change anything).
- Samples are **harmless simulations**: obfuscated payloads only print, exfiltration samples point at the dead loopback address `127.0.0.1:9`, destructive and persistence samples touch only stand-in paths in the temp folder. Fake secrets are obviously fake. Samples are **never executed**; only `saferun scan` (never `saferun run`), Bandit and `pip-audit --no-deps --disable-pip` read them.
- The runner writes each sample into a fresh temp folder at run time and deletes it afterwards (no script files live in the repository, which avoids antivirus false alarms).
- Categories include evasion variants (string concatenation, `getattr` tricks), which are expected to be hard for any static scanner, and hard negatives (scary-looking but benign scripts).

## Run it yourself

```bash
pip install -e '.[bench]'            # pinned Bandit and pip-audit; needs network (pip-audit queries advisory services)
saferun init --all && saferun osv-db update
python tools/benchmark/run.py --split dev            # while developing the runner
python tools/benchmark/run.py --split all            # report: dev, held-out and combined; writes artifacts/benchmark/benchmark.{md,json}
```

CI (job `benchmark`, advisory) prints the same report in the log and uploads `benchmark.md` and `benchmark.json` as the `benchmark-report` artifact.

## What counts as a catch

| Tool | strict | loose |
|---|---|---|
| SafeRun | verdict FAIL (high or critical finding) | any finding |
| Bandit | a medium or high severity finding | any finding |
| pip-audit | any vulnerability (no severity; strict equals loose) | any vulnerability |

A **catch** is counted among samples labeled bad; a **false alarm** is the same definition applied to samples labeled clean. A failed scan counts as not flagged and is shown as an error. Numbers are counts (k/n), not percentages: the set is small.

## Result of the first run (2026-11-03)

SafeRun 0.0.2, Bandit 1.9.4, pip-audit 2.10.1. SafeRun's OSV snapshot: updated 2026-10-29, 26736 advisories. pip-audit default: PyPI's vulnerability service; second pass: `-s osv`. **Dependency differences can come from the data, not the tools.** No scan failed. The full per-sample report is `artifacts/benchmark/benchmark.md` after a run.

**Code checks, all 70 samples** (dev and held-out together; the two splits agreed closely, see the report):

| Tool | Catch strict | Catch loose | False alarm strict | False alarm loose |
|---|---|---|---|---|
| SafeRun | 21/48 | 26/48 | 1/22 | 2/22 |
| Bandit | 24/48 | 28/48 | 0/22 | 3/22 |

| Category (loose, flagged/total) | SafeRun | Bandit |
|---|---|---|
| dangerous calls (bad) | 6/6 | 6/6 |
| unsafe deserialization (bad) | 4/4 | 4/4 |
| obfuscated payload (bad) | 6/6 | 6/6 |
| hardcoded secret (bad) | 4/4 | 3/4 |
| weak practice (bad) | 5/6 | 6/6 |
| exfiltration (bad) | 0/4 | 2/4 |
| destructive (bad) | 1/4 | 1/4 |
| evasion variant (bad) | 0/6 | 0/6 |
| persistence (bad) | 0/4 | 0/4 |
| sensitive file read (bad) | 0/4 | 0/4 |
| normal scripts (clean, false alarms) | 0/12 | 1/12 |
| hard negatives (clean, false alarms) | 2/10 | 2/10 |

**Dependency checks, all 12 samples:** SafeRun, pip-audit and `pip-audit -s osv` each caught 8/8 vulnerable pins with 0/4 false alarms (strict and loose). No clean dependency sample was flagged by any tool.

**SafeRun-only look-alike names (not in any total above):** 4/4 look-alikes flagged, 0/2 false alarms.

### Where SafeRun loses or misses

- **Behind Bandit overall on this set**: 26/48 vs 28/48 loose, 21/48 vs 24/48 strict. SafeRun missed `random` used for a session token (`wp-02`), which Bandit flags.
- **Exfiltration**: SafeRun flagged 0/4 (a file or the environment sent over `urllib`, `requests`, a raw socket or SMTP); Bandit flagged 2/4 (the `urllib` and `requests` ones).
- **Not flagged by either tool**: all six evasion variants, all four persistence samples, all four sensitive-file reads, and most destructive samples. These are behaviours neither tool's rules cover; this is a gap in static scanning of this kind, not a SafeRun win.
- **False alarms**: SafeRun flagged `os.system("clear")` (`hn-01`, which Bandit also flagged) and MD5 used as a non-security cache key (`hn-06`, which Bandit did not flag). Bandit also flagged two others: `subprocess.run` with an argument list (`cn-07`) and `random.randint` in a dice game (`hn-09`).
- **Where SafeRun does as well or better**: the dependency check matches pip-audit on both data sources; SafeRun flagged all 4 hardcoded-secret samples (Bandit 3/4); fewer loose false alarms (2/22 vs 3/22), though Bandit has fewer strict ones (0/22 vs 1/22).

## Limits

- The samples were written by the SafeRun authors, are few (2-6 per category and split) and are simulations. A few categories moving by one sample changes the picture. This is not an independent evaluation and not a claim about real-world malware.
- Bandit looks for insecure coding practice; SafeRun is aimed at code you are about to run but do not trust. The goals overlap but differ, so a lower score for one tool is not a verdict on the other.
- Only the scan is measured. A PASS is not proof of safety.
- Dependency results depend on the advisory data on the run date; re-running later can change them. A new finding on a "clean" dependency sample is reported as a flagged exception, never silently accepted.
- **SafeRun's rules and settings were not tuned to these results.** Any rule change needs a new sample set and the owner's approval.
