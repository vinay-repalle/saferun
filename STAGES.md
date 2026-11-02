# SafeRun stages (new work)

Phases 1-5 are in PROJECT.md. Phase 6 = the unnumbered post-Phase-5 work (init/doctor/run, CI, packaging, 0.0.1/0.0.2 releases, website). New stages start at 7.
Status: planned / in progress / done (local) / pushed. Updated after every stage.

| Stage | Goal | Status | Tests | Docs updated |
|---|---|---|---|---|
| 7 | Docs clarity: `scan` vs `run`, syntax check as "can the scanner read this file", stale-doc cleanup (IMPLEMENTATION.md, PROJECT.md, docs; diff shown first), JavaScript labelled experimental (docs only; website excluded, see Deferred) | done (committed by owner) | docs only, no new tests; full suite incl. Docker: 925 passed, 50 skipped (Windows/macOS-only tests), 0 failed | README, PROJECT, IMPLEMENTATION, docs/cli.md, docs/engine.md |
| 8 | Package-name check: new `saferun check-names`, bundled offline top-PyPI snapshot, opt-in online lookup; `scan` unchanged | planned | - | - |
| 9 | Benchmark vs Bandit and pip-audit (harmless samples generated at run time); dev environment only; advisory in CI | planned | - | - |
| 10 | Dependency findings: patch/major label, `.saferun-accept.toml` accept-risk with reason and expiry | planned | - | - |
| 11 | Secrets scanner: options proposed first; analyzer-image changes batched into one release | planned | - | - |
| 12 | Plain-English findings: new `explanation` field next to the unchanged `message` | planned | - | - |
| 13 | JavaScript rules (only after 7-12 are done and working) | planned | - | - |

## Deferred (ask the owner before doing; after the main stages are done)
- Website text (`web/src/content/site.js`, `Faq.jsx`, `Features.jsx`): `scan` vs `run` wording, "can the scanner read this file" syntax wording, JavaScript labelled experimental. Left out of Phase 7 by owner decision; must match the docs when added. Owner redeploys Netlify.
