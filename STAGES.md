# SafeRun stages (tracker)

Phases 1-5 and Phase 6 (init/doctor/run, CI, packaging, 0.0.1-0.0.3, website) are summarised in [PROJECT.md](PROJECT.md). New stages continue from 7. Old detail, per-stage test counts and the former long table: [docs/history.md](docs/history.md) Part B.
Status words: planned / in progress / done (local) / committed. Update this file after every stage.

## Working rules (owner: Vinay Repalle)
1. Claude never runs `git commit`, `git push`, `git tag`, makes branches/PRs/releases, publishes to PyPI, or signs with cosign. Claude gives the exact command or commit message; the owner runs it. Commit messages describe the feature or fix only (no stage numbers).
2. Never change or remove existing features or behaviour without asking first.
3. Do not assume or invent (stage numbers, file or rule names, results). If unclear, ask.
4. Honest claims only: PASS is not proof of safety; no claim the tests do not back (especially Windows/macOS sandbox).
5. Scans stay offline by default; online features are explicit and opt-in.
6. One stage at a time: short plan → owner approval → implement locally → local tests (full suite incl. Docker) → update docs and this file → hand over commit message → stop for review. Keep docs short.

## Stages
| # | Goal | Status |
|---|---|---|
| 7 | Docs clarity: `scan` vs `run`; syntax check = "can the scanner read this file"; stale-doc cleanup | committed |
| 8 | `saferun check-names` (offline top-10 000 PyPI snapshot, opt-in `--online`) | committed |
| 9 | Benchmark vs Bandit and pip-audit (88 simulated samples, advisory CI job) | committed |
| 10 | Dependency findings: `fix_kind` label, `--accept-file` accepted risks | committed |
| 11 | Secrets scanner `hardcoded-secrets` (gitleaks); analyzer `analyzer-v1.1.0` | committed; analyzer release published and signed 2026-11-04 |
| 12 | Plain-English `explanation` on findings | committed |
| 13 | JavaScript rules **cancelled**; all JavaScript/Node support removed (Python-only) | committed |
| 14 | Benchmark misses (Python rules): held-out set 2, 3 new behaviour rules; `analyzer-v1.2.0` | committed, closed (Checkpoints 1-4 done; `analyzer-v1.2.0` released) |

All stages 7-14 are committed (owner confirmed, up to the 0.0.3 PyPI release). The git log is authoritative.

## Stage notes (facts that are not obvious from the code)
- **7:** docs only; JavaScript was first labelled experimental, then removed in 13. Website text deliberately left out (see Deferred).
- **8:** `scan` is unchanged. Bundled snapshot dataset date 2026-11-01. Online lookup sends names only; downloads not included.
- **9:** Dataset: 88 harmless simulated samples stored as text, files generated in a temp folder at run time and never executed; labels and dev/held-out split frozen in git before any tool ran. `bench` extra pins bandit 1.9.4 and pip-audit 2.10.1; runner `tools/benchmark/run.py` (uses `saferun scan` only). First run 2026-11-03: SafeRun 26/48 vs Bandit 28/48 loose code catches; dependency checks tie 8/8. SafeRun was not tuned. Results in docs/benchmark.md.
- **10:** accept file read only from the flag, never from the scanned project; accepted findings stay listed but leave the verdict; expired entries count again.
- **11:** gitleaks 8.30.1 chosen by the owner over detect-secrets/trufflehog/custom Semgrep. Offline, read-only project, no online verification, values never printed/logged/in JSON (rule, file, line only), always HIGH, `--no-secrets-check`, generic entropy rule disabled, project config/ignore/allow comments neutralised. Older analyzer images fail label verification until `saferun init`. `analyzer-v1.1.0`: tag commit `f47d65f`, digest `sha256:5642a101…7682d07`, recorded in `ANALYZER_RELEASE`. Superseded by `analyzer-v1.2.0`; the owner check `saferun verify-images --signature` should be run against the current release.
- **12:** texts in `saferun/engine/explain.py`; no analyzer image or rules-file change; `schema_version` stays 1. Two existing tests that pin the exact JSON key set of a Semgrep finding (`tests/test_engine_integration.py`, `tests/test_adversarial.py`) got `explanation` added to the expected set (still exact comparisons).
- **13:** removed the `javascript-syntax` check, Node image/profile, npm OSV data and lockfile scan. npm files get the plain note "JavaScript/npm dependencies are not supported and were not scanned." (no change to status or verdict). `--no-javascript-check` stays as a hidden no-op. Analyzer image unchanged. Two test files deleted (`test_engine_node.py`, `test_node_profile.py`), about 20 edited.
- **14:** held-out set 2 = `tools/benchmark/samples_v2.toml` (68 code samples: 48 bad, 20 clean; 24 dev, 44 held-out); set 1 is now dev-only. Order was: freeze labels → baseline of unchanged rules committed → rule proposals shown first → re-run once → report k/n and losses. Known false alarms `os.system("clear")` and MD5 cache key are reported, not fixed. New rules default to medium; any HIGH is proposed separately.
  Checkpoint 3 (owner approved families 1, 3, 5, all medium): 3 new Semgrep rules in `saferun/engine/rules/python.yml` (`sensitive-file-access`, `persistence-setup`, `hidden-function-lookup`) with plain-English texts; written against dev samples only (19 bad dev samples caught, 0 clean dev samples flagged; pe-04 still missed).
  Checkpoint 4 (held-out re-run done ONCE): SafeRun loose 9/32 → 14/32, strict 7/32 unchanged (new rules are medium, so no new FAIL verdicts), false alarms 0/12 → 0/12, no sample lost; gained x2-pe-06, x2-sr-02, x2-sr-06, x2-ev-04, x2-ev-06. Bandit unchanged (17/32 loose, 14/32 strict). Saved in `tools/benchmark/baselines/set2-held-out-final.*`. **The held-out set must not be used to change rules any more.** Left out on purpose: plain file upload (ex-03), exfiltration and destructive families (not requested), weak-practice family.
  Release `analyzer-v1.2.0` published and signed 2026-11-04 (tag commit `2570952`, digest `sha256:33ed623e…bf277`), recorded in `ANALYZER_RELEASE`. Tests: parametrized `tests/test_behaviour_rules.py` (real Semgrep, repo rules mounted into the analyzer image); rule count in `test_explanations.py` 11 → 14. docs/benchmark.md has the set 2 results.

Full suite (latest): `SAFERUN_REQUIRE_DOCKER=1 .venv/bin/python -m pytest` → 1158 passed, 50 skipped (Windows/macOS-only), 0 failed.

## Next (optional, none urgent; each needs the owner's approval first)
- **Duplicate finding:** the `sensitive-file-access` rule reports the same finding twice on one line. Fix = rule change + new analyzer release + owner approval.
- **Benchmark misses:** exfiltration, destructive and weak-practice samples need a new held-out set and owner approval before any new rules.
- **Stage 12 follow-ups:** group dependency findings by package; drop git commit hashes from "fixed in".
- **Release practice:** 0.0.3 was built from a tree with no outstanding changes. The docs/cli.md and website mentions are already updated.
- **Clean-machine end-to-end test** (see PROJECT.md *Status and remaining work*).
- Benchmark README graphs and a website benchmarks docs page are pending (owner follow-up).

## Done since the last list
- Website text (`Faq.jsx`, `Features.jsx`, `GuidePage.jsx`, `site.js`) already says Python-only, explains `scan` vs `run` and "can the scanner read this file", and has no Node/`node --check` wording (checked 2026-11-05). The OSV download size was corrected from about 260 MB to about 36 MB (PyPI data only) in the Guide page, README, docs/install-and-test.md and docs/release-pypi.md. The owner redeploys Netlify.
