# SafeRun Improvement Plan (instructions for Claude)

Owner: Vinay Repalle. Laptop: Linux, Docker working. This is a short brief, not a spec. Keep every doc you write short.

## 0. Hard rules (never break)
1. **Never** run `git commit`, `git push`, `git tag`, create branches, or open PRs/releases. **Never** publish to PyPI or create GitHub releases. Only suggest the exact command or a commit message; the owner runs it.
2. **Never change or remove existing features or behavior.** If you think something should improve, **ask first** and wait for approval before touching it.
3. **Do not assume or invent.** If something is unclear or missing, ask. Do not guess stage numbers, file names, rule names or results.
4. Keep honest claims. A PASS is not proof of safety. Do not write claims the tests do not back (especially for Windows/macOS sandbox).
5. Scans stay **offline** by default (`scan` and `run` use no network). Online features must be explicit and opt-in.
6. Only the owner approves scope changes. Work one stage at a time and stop for review after each.

## 1. First step: investigate, then report (no code yet)
Read `PROJECT.md`, `STAGES.md`, `docs/`, `README.md`, tests and CI. Report to the owner:
- Existing stages/phases and their real numbers, and what is done.
- What each item below already has, partly has, or lacks.
- Needed inputs, risks, and open questions.

Then wait for approval. After approval, create a short tracking file (`STAGES.md`) continuing the **existing** numbering (if there are 8 phases, new ones start at 9). One line per stage: goal, status, tests, docs updated. Update it after every stage.

## 2. Wanted stages (in this priority order; owner may reorder)
1. **Package-name check.** Offline snapshot of top PyPI package names (a few thousand, small) to detect names that look like typos of popular packages. Optional online lookup (opt-in flag) for existence, age and downloads. Only package names are sent, never code. If the lookup fails or is offline, report "could not check", never a pass. Never inside plain `scan`.
2. **Benchmark.** Compare SafeRun against comparable tools: Bandit (code checks) and pip-audit (dependency checks). Publish honest numbers, including where SafeRun loses. Samples are **harmless simulations only** (print instead of stealing; temp-folder-only deletes), plus normal scripts, each with an expected verdict. Store samples as plain text and **generate the script files at run time** into a temp folder (avoids antivirus flags). Report catch rate and false-alarm rate. Run in CI.
3. **Dependency findings made actionable.** Show fixed version (and patch vs major jump), severity, one-line description. Add an "accept risk" file with a reason and expiry date. Only if existing OSV data supports it; ask if not.
4. **Secrets scanner** (hardcoded passwords/keys) inside the analyzer container, if the README/engine confirms it is missing. Ask before choosing the tool.
5. **Plain-English findings** for the most common rules.
6. **Docs clarity:** explain `scan` (executes nothing) vs `run` (scans, then executes in the sandbox); describe the syntax check as a "can the scanner read this file" step.
7. **JavaScript (last).** Label experimental or add real JS rules; ask first.

## 3. Per-stage workflow
Plan (short) -> owner approval -> implement locally -> local tests -> update docs and `STAGES.md` -> give owner the commit message and commands -> owner commits/pushes -> GitHub Actions result -> next stage.

## 4. Testing and CI
- Local: Linux with Docker; run the full tests including Docker ones.
- GitHub Actions: Windows and macOS runners prove the **host CLI code** only. They cannot run the Linux sandbox. Docs must say exactly this: Linux fully tested; Windows/macOS host code tested in CI.
- Packaging: check the build and a clean-environment install locally; tell the owner the release commands but do not run them.

## 5. Owner must clarify or approve
Stage list and numbering, tool choices (secrets scanner, any new dependency), any change to existing behavior, and every commit/push/release.
