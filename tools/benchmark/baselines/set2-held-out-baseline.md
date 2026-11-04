# SafeRun benchmark report

- Run: 2026-11-03 18:44 UTC on Linux-7.0.0-38-generic-x86_64-with-glibc2.39, Python 3.12.3
- Samples: `tools/benchmark/samples_v2.toml` sha256 `10f734e21ed9f82e…`, labels frozen 2026-11-03; split run: **held-out**
- Tools: saferun 0.0.2, bandit 1.9.4, pip-audit 2.10.1
- Advisory data: SafeRun uses its local OSV snapshot (not reported). pip-audit defaults to PyPI's vulnerability service; "pip-audit -s osv" uses the OSV service. **Differences on dependency samples can come from the data, not the tools.**

Counts are k/n (not percentages) because the sample set is small. "Catch" is among samples labeled bad; "false alarm" is among samples labeled clean. "err" counts scans that failed; a failed scan counts as not flagged.

- **loose**: any finding. **strict**: SafeRun = verdict FAIL (high/critical finding); Bandit = a medium or high severity finding; pip-audit has no severity, so strict equals loose.

## Results: held-out split

### Code checks (head-to-head: SafeRun vs Bandit)

| Tool | Catch (strict) | Catch (loose) | False alarm (strict) | False alarm (loose) |
|---|---|---|---|---|
| saferun | 7/32 | 9/32 | 0/12 | 0/12 |
| bandit | 14/32 | 17/32 | 1/12 | 2/12 |

Per category (loose bar, k/n flagged; for clean categories k is false alarms):

| Category | Label | saferun | bandit |
|---|---|---|---|
| dangerous_calls | bad | 2/2 | 2/2 |
| destructive | bad | 0/4 | 1/4 |
| evasion_variant | bad | 1/4 | 1/4 |
| exfiltration | bad | 0/4 | 2/4 |
| hard_negative | clean | 0/7 | 2/7 |
| hardcoded_secret | bad | 1/2 | 2/2 |
| normal_script | clean | 0/5 | 0/5 |
| obfuscated_payload | bad | 2/2 | 2/2 |
| persistence | bad | 0/4 | 1/4 |
| sensitive_file_read | bad | 0/4 | 0/4 |
| unsafe_deserialization | bad | 2/2 | 2/2 |
| weak_practice | bad | 1/4 | 4/4 |

## Where SafeRun is wrong (every sample that was run)

| Sample | Category | Expected | SafeRun | Tools that got it right | What it is |
|---|---|---|---|---|---|
| x2-ex-02 (held-out) | exfiltration | bad | not flagged | none | file contents sent with http.client |
| x2-ex-03 (held-out) | exfiltration | bad | not flagged | bandit | file uploaded over FTP |
| x2-ex-05 (held-out) | exfiltration | bad | not flagged | none | all text files sent over UDP |
| x2-ex-06 (held-out) | exfiltration | bad | not flagged | bandit | environment encoded into a URL |
| x2-pe-02 (held-out) | persistence | bad | not flagged | none | line appended to a shell profile (stand-in file in the temp folder) |
| x2-pe-03 (held-out) | persistence | bad | not flagged | none | cron.d style entry that runs every minute (stand-in folder) |
| x2-pe-04 (held-out) | persistence | bad | not flagged | none | Windows registry Run key (stand-in name) |
| x2-pe-06 (held-out) | persistence | bad | not flagged | bandit | systemd user unit written and enabled |
| x2-sr-02 (held-out) | sensitive_file_read | bad | not flagged | none | .netrc read (stored passwords) |
| x2-sr-03 (held-out) | sensitive_file_read | bad | not flagged | none | browser login database copied |
| x2-sr-04 (held-out) | sensitive_file_read | bad | not flagged | none | Docker credentials file parsed |
| x2-sr-06 (held-out) | sensitive_file_read | bad | not flagged | none | GnuPG private key folder listed and read |
| x2-ev-03 (held-out) | evasion_variant | bad | not flagged | none | os.system called through operator.methodcaller with a split name |
| x2-ev-04 (held-out) | evasion_variant | bad | not flagged | none | eval looked up in the builtins dictionary with a split name |
| x2-ev-06 (held-out) | evasion_variant | bad | not flagged | none | module name decoded from hex, then check_output |
| x2-de-02 (held-out) | destructive | bad | not flagged | none | files overwritten with zeros, then removed (stand-in folder) |
| x2-de-03 (held-out) | destructive | bad | not flagged | bandit | rm -rf with an argument list (stand-in folder) |
| x2-de-04 (held-out) | destructive | bad | not flagged | none | walk a tree and unlink every document (stand-in folder) |
| x2-de-06 (held-out) | destructive | bad | not flagged | none | every file truncated to zero length (stand-in folder) |
| x2-wp-03 (held-out) | weak_practice | bad | not flagged | bandit | certificate checks switched off |
| x2-wp-04 (held-out) | weak_practice | bad | not flagged | bandit | world-writable file permissions |
| x2-wp-06 (held-out) | weak_practice | bad | not flagged | bandit | server bound to all interfaces |
| x2-hs-03 (held-out) | hardcoded_secret | bad | not flagged | bandit | secret key in a settings dictionary (obviously fake) |

## Flagged exceptions: clean dependency samples that a tool flagged

None.

## Limits

- The samples were written by the SafeRun authors, are few, and are simulations (nothing is real malware). Per-category counts are tiny.
- Bandit looks for insecure coding practice and SafeRun looks for behaviour that should not be run unreviewed; the goals overlap but differ.
- Only the scan is measured. The sandbox (`saferun run`) is not part of this benchmark and samples are never executed.
- Dependency results depend on the advisory data on the run date. A PASS is not proof of safety.
- SafeRun was not tuned to these results; fixes need a new sample set.
- Set 2 was written by authors who already knew where set 1 was missed, so it can be unconsciously easier or harder than a stranger's set; the samples are structurally different from set 1, which reduces but does not remove that bias.
