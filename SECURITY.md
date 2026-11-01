# Security policy

SafeRun is alpha software (current release: 0.0.2, published as `saferun-cli` on PyPI) and has not been independently audited or certified; see the README and [docs/sandbox.md](docs/sandbox.md) for its limits. Reports of security problems are welcome.

## Reporting a vulnerability

Please report privately, not in a public issue or pull request.

Use GitHub's private vulnerability reporting for this repository: open <https://github.com/vinay-repalle/saferun/security> and choose **Report a vulnerability** (the **Security** tab, then **Advisories**). If that option is not shown, private reporting is not enabled yet: open a public issue that says only that you need a private channel, **without any details of the problem**, and the maintainer will arrange one.

Helpful details: the SafeRun version (`saferun --version`), your OS and Docker version, the steps or a minimal sample that reproduces the problem, and what you expected versus what happened.

## Scope

In scope: ways to make `saferun scan` or `saferun run` execute code on the host, escape or weaken the sandbox, leak secrets, accept an unsigned or wrongly signed analyzer image, or accept tampered OSV data.

Out of scope: findings the scanner misses (detection quality is a known gap, a normal issue is fine), and problems in third-party tools (Semgrep, OSV-Scanner, cosign, Docker) that are not caused by how SafeRun uses them.

## Supported versions

Only the latest release receives fixes (currently 0.0.2). Upgrade with `pip install --upgrade saferun-cli`, then run `saferun init` and `saferun doctor`.

## Limitations you should know

A PASS is not proof that code is safe, and the sandbox limits the impact of code rather than making it harmless. Docker is the isolation boundary. Docker Desktop on Windows and macOS has not yet been manually verified. Details: [PROJECT.md](PROJECT.md) (known exposures) and [docs/platforms.md](docs/platforms.md).
