// Numbers copied from docs/benchmark.md (held-out split of sample set 2, run 2026-11-03 and 2026-11-04). Not computed here; do not edit without a new run.

// [label, of how many, note, [[series, k, key]...]]
export const BENCH_ROWS = [
  ['Catches, loose', 32, 'any finding, among 32 bad samples', [['SafeRun, unchanged rules', 9, 'before'], ['SafeRun, new rules', 14, 'after'], ['Bandit', 17, 'bandit']]],
  ['Catches, strict', 32, 'SafeRun: FAIL verdict; Bandit: medium or high finding', [['SafeRun, unchanged rules', 7, 'before'], ['SafeRun, new rules', 7, 'after'], ['Bandit', 14, 'bandit']]],
  ['False alarms, loose', 12, 'any finding, among 12 clean samples (lower is better)', [['SafeRun, unchanged rules', 0, 'before'], ['SafeRun, new rules', 0, 'after'], ['Bandit', 2, 'bandit']]],
]

// [category, SafeRun before, SafeRun after, Bandit], loose, flagged / total
export const BENCH_CATEGORIES = [
  ['Sensitive file read', '0/4', '2/4', '0/4'],
  ['Evasion variant', '1/4', '3/4', '1/4'],
  ['Persistence', '0/4', '1/4', '1/4'],
  ['Exfiltration', '0/4', '0/4', '2/4'],
  ['Destructive', '0/4', '0/4', '1/4'],
  ['Weak practice', '1/4', '1/4', '4/4'],
  ['Hardcoded secret', '1/2', '1/2', '2/2'],
  ['Dangerous calls', '2/2', '2/2', '2/2'],
  ['Obfuscated payload', '2/2', '2/2', '2/2'],
  ['Unsafe deserialization', '2/2', '2/2', '2/2'],
]

export const BENCH_LIMITS = [
  'SafeRun is still behind Bandit: 14/32 vs 17/32 loose and 7/32 vs 14/32 strict. It flagged none of the exfiltration or destructive samples.',
  'Strict catches did not change: the three new rules are medium severity, so they add findings and a WARNING, not a FAIL verdict.',
  'The samples are few, simulated and written by the SafeRun authors, who already knew where the first set was missed. This is not an independent evaluation and not a claim about real-world malware.',
  'Bandit looks for insecure coding practice; SafeRun is aimed at code you are about to run but do not trust. A lower score for one tool is not a verdict on the other.',
  'The rules were written against the dev samples only. The held-out samples were run once and must not be used to change rules any more.',
  'Only the scan is measured, not the sandbox. A PASS is not proof of safety.',
]
