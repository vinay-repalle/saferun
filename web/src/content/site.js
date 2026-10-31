// Single source of truth for text shown on more than one page (website and setup guide), so the two cannot drift apart.

export const GITHUB = 'https://github.com/vinay-repalle/saferun'
export const DOCS = GITHUB + '/blob/main/docs/'

export const TRUST = [
  ['Your code is never run', 'Static checks only: nothing you submit is executed.'],
  ['Scans work offline', 'No network inside the analyzer container.'],
  ['Locked-down containers', 'Sandbox isolation: read-only copy, non-root, no capabilities.'],
  ['Pinned analyzer image', 'A cosign-signed image pinned by digest (built from a hash-locked recipe), locked locally and re-checked before every scan.'],
]

// [name, status, evidence]: what the tests have shown, nothing more.
export const PLATFORMS = [
  ['Ubuntu / Linux', 'Fully tested', 'The full test suite, including the Docker sandbox and analyzer tests, runs locally and in CI.'],
  ['Windows 10/11', 'Native, partly verified', 'A native implementation (no WSL needed for SafeRun itself). Non-Docker tests pass in CI on windows-2022; Docker Desktop integration has not yet been manually verified.'],
  ['macOS', 'Partly verified', 'Same code as Linux. Non-Docker tests pass in CI on Apple Silicon and Intel; Docker Desktop integration has not yet been manually verified.'],
]

// [title, text, command]
export const STEPS = [
  ['Set up', 'Run saferun init once. It installs only what is missing.', 'saferun init'],
  ['Verify', 'Check that every part is ready and verified.', 'saferun status'],
  ['Scan', 'Scan a project folder.', 'saferun scan ./my-project'],
]

export const REQUIREMENTS = [
  ['Operating system', 'Linux (Ubuntu), native Windows 10/11 or macOS. The analyzer image is linux/amd64 only, so on Apple Silicon and Windows ARM it runs under emulation.'],
  ['Python', '3.12 or newer, with venv and pip.'],
  ['Docker', 'A local Docker Engine that your user can reach, with memory, swap, pids and CPU limits and seccomp enabled. Remote Docker endpoints are refused. On Windows and macOS use Docker Desktop in Linux containers mode: that integration has not yet been manually verified.'],
  ['Cosign', 'Yes, for the default setup: Cosign 2.2 or newer on your PATH verifies the signed analyzer image before it is pulled. SafeRun does not install it for you. Not needed if you build the analyzer yourself with --build-local.'],
  ['Internet', 'Only for setup (Docker Hub, the signed analyzer from ghcr.io with its Sigstore check, and the OSV data; a local analyzer build uses PyPI and GitHub instead). Scans never use the network.'],
  ['Disk space', 'About 1.5 GB for images and vulnerability data.'],
]
export const requirement = (name) => REQUIREMENTS.find(([n]) => n === name)[1]

// [key, icon, label, meaning, what to do]
export const VERDICTS = [
  ['pass', '✓', 'PASS', 'Every check ran and found nothing.', 'Looks fine, but it is not a proof of safety.'],
  ['warn', '!', 'WARNING', 'Minor findings, or a check could not run (missing or outdated component).', 'Run saferun status, apply the fix, scan again.'],
  ['fail', '✕', 'FAIL', 'At least one high or critical finding.', 'Do not run the project until it is fixed.'],
]

// [title, text]
export const SAFETY = [
  ['Your project is never executed', 'It is copied read-only into a throwaway container: no network, non-root user, no Linux capabilities, memory, CPU and process limits.'],
  ['Images are pinned by digest', 'An image is trusted only if Docker reports the exact pinned digest. A tag that merely exists is not enough.'],
  ['The analyzer is a signed, digest-pinned image', 'Setup checks its cosign signature (this project\'s release workflow, a release tag) and the pinned digest before pulling it, then verifies its tool versions and rules hash. A signature would not prove the project itself was never compromised. You can build it yourself with --build-local instead.'],
  ['The analyzer is locked', 'Its image ID, tool versions and rules hash are re-checked before every scan. The lock file must be private to your user.'],
  ['Vulnerability data has an integrity record', 'SHA-256, size, advisory count and date are re-checked before every scan. Damaged, tampered or old data cannot produce PASS.'],
]

export const HONEST_LIMITS = 'Honest limits: these checks detect damage and later changes, but a locally recorded hash cannot prove the original download was genuine. PASS means the existing checks found nothing, not that the code is safe. Scans send nothing anywhere and are only as current as your last saferun osv-db update.'
