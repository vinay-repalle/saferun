# Manual verification on a real Docker Desktop machine (Windows or macOS)

CI cannot run Linux containers on Windows/macOS runners, so run this once per platform and record the result in the pull request.
Windows: use both PowerShell and Command Prompt for steps 1-4. Replace the python launcher as needed.

1. `docker version` shows a Server with `OS/Arch: linux/...`; `docker info --format "{{.OSType}}"` prints `linux`.
2. From a checkout: `python -m pip install -e ".[dev]"`, then `saferun --help`.
3. `saferun init --only python,node,analyzer --build-local` (or the signed analyzer if `cosign` is installed).
4. `saferun status` and `saferun verify-images`.
5. `python -m pytest -q -ra -m docker` — record passes, failures, skips and the exact error text of any failure (especially `required control ... is unavailable`
   and mount errors).
6. `saferun scan <a small project>`; afterwards `docker ps -a --filter label=saferun.sandbox=1` is empty and no `saferun-ws-*` directory is left in the temp directory.
7. Press Ctrl+C during a scan: same cleanup expectations.
8. Windows only: switch Docker Desktop to Windows containers; `saferun scan` must refuse with "needs Linux containers".
