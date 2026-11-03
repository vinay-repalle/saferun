# SafeRun stages (new work)

Phases 1-5 are in PROJECT.md. Phase 6 = the unnumbered post-Phase-5 work (init/doctor/run, CI, packaging, 0.0.1/0.0.2 releases, website). New stages start at 7.
Status: planned / in progress / done (local) / pushed. Updated after every stage.

| Stage | Goal | Status | Tests | Docs updated |
|---|---|---|---|---|
| 7 | Docs clarity: `scan` vs `run`, syntax check as "can the scanner read this file", stale-doc cleanup (IMPLEMENTATION.md, PROJECT.md, docs; diff shown first), JavaScript labelled experimental (docs only; website excluded, see Deferred) | done (committed by owner) | docs only, no new tests; full suite incl. Docker: 925 passed, 50 skipped (Windows/macOS-only tests), 0 failed | README, PROJECT, IMPLEMENTATION, docs/cli.md, docs/engine.md |
| 8 | Package-name check: new `saferun check-names`, bundled offline top-PyPI snapshot (10 000 names, dataset 2026-11-01), opt-in `--online` lookup (existence and first-upload age from pypi.org; names only; downloads not included); `scan` unchanged | done (local, awaiting owner commit) | 55 new (`tests/test_pkgnames.py`); full suite incl. Docker with `SAFERUN_REQUIRE_DOCKER=1`: 980 passed, 50 skipped (Windows/macOS-only tests), 0 failed; wheel build checked (snapshot included) | README, PROJECT, IMPLEMENTATION, docs/cli.md |
| 9 | Benchmark vs Bandit and pip-audit: 88 harmless simulated samples (stored as text, files generated in a temp folder at run time, never executed; labels and dev/held-out split frozen in git before any tool ran), `bench` extra with pinned bandit 1.9.4 and pip-audit 2.10.1, runner `tools/benchmark/run.py` (`saferun scan` only), advisory CI job with report artifact. First run 2026-11-03: SafeRun 26/48 vs Bandit 28/48 loose code catches; dependency checks tie 8/8. SafeRun not tuned | done (local, awaiting owner commit) | 14 new in `tests/test_benchmark.py` (1 Docker); CI job-list test updated; full suite incl. Docker with `SAFERUN_REQUIRE_DOCKER=1`: 994 passed, 50 skipped (Windows/macOS-only tests), 0 failed; results in docs/benchmark.md | docs/benchmark.md, README, PROJECT, docs/install-and-test.md |
| 10 | Dependency findings: patch/major label, `.saferun-accept.toml` accept-risk with reason and expiry | planned | - | - |
| 11 | Secrets scanner: options proposed first; analyzer-image changes batched into one release | planned | - | - |
| 12 | Plain-English findings: new `explanation` field next to the unchanged `message` | planned | - | - |
| 13 | JavaScript rules (only after 7-12 are done and working) | planned | - | - |

## Deferred (ask the owner before doing; after the main stages are done)
- Website text (`web/src/content/site.js`, `Faq.jsx`, `Features.jsx`): `scan` vs `run` wording, "can the scanner read this file" syntax wording, JavaScript labelled experimental. Left out of Phase 7 by owner decision; must match the docs when added. Owner redeploys Netlify.
