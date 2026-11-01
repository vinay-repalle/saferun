# Platform support (status)

SafeRun 0.0.2 (alpha) supports **Linux, Windows and macOS** and is installed the same way everywhere: `pip install saferun-cli`, then `saferun init`. **System requirements:** Python 3.12+, a local Docker running Linux containers, about 1.5 GB of disk space, and internet access for setup only. Linux is the fully tested platform; Windows and macOS are only partly verified (below).

SafeRun runs untrusted code only inside a Linux container, so **every platform needs a local Docker that runs Linux containers**.
Installing SafeRun does not install Docker.

| Platform | Docker you need | SafeRun host code | Evidence in this repository |
|---|---|---|---|
| Linux (x86-64) | Docker Engine, cgroup limits + seccomp | unchanged POSIX implementation | full test suite **including 101 Docker tests**, run locally (Ubuntu) and in CI |
| macOS (Apple Silicon and Intel) | Docker Desktop (Linux containers) | the same POSIX implementation | non-Docker tests **passed** on `macos-15` (arm64) and `macos-15-intel` in CI (the Intel leg is advisory in the workflow). **Docker Desktop integration not verified.** |
| Windows 10/11 | Docker Desktop, **Linux containers mode** (WSL 2 or Hyper-V backend) | native Windows implementation, no WSL needed for SafeRun itself | non-Docker unit, security and NTFS tests **passed** on `windows-2022` in CI. **Docker Desktop integration not verified.** |

"Verified" means a test that ran. The Windows code was written on Linux and first executed in CI. CI results are evidence for the
behaviours the tests exercise on GitHub's runner images; they do not prove every real-machine scenario (other Windows editions, file
systems, antivirus or backup software holding files open, unusual ACLs, other macOS versions). The manual checklist
([platform-test-checklist.md](platform-test-checklist.md)) is still required on a real Docker Desktop machine.

## CI results (commit `257f7aa`, all 8 jobs passed)
| Job | Result |
|---|---|
| Linux (Ubuntu): full test suite | passed |
| Linux (Ubuntu): Docker sandbox and analyzer integration tests | passed |
| Windows (`windows-2022`): native unit and security tests, Docker tests excluded | passed |
| macOS (`macos-15`, Apple Silicon): tests, Docker tests excluded | passed |
| macOS (`macos-15-intel`): tests, Docker tests excluded | passed |
| Website tests and build | passed |
| Package build and inspection | passed |
| Dependency audit | passed |

On Windows the native tests cover, among others: junctions, symlinks, hard links and alternate data streams; reserved device names and
long paths; ACL-based private-file withholding; the analyzer-lock trust rules; the workspace reaper; process-tree termination through job
objects; Docker endpoint and mount-path validation; and the NTFS sharing behaviour described below. Test modules that exercise the POSIX
implementation itself (`fcntl` locks, `O_NOFOLLOW`/`dir_fd` copy, permission bits, uid ownership) and the Docker-dependent modules are
skipped on Windows; their Windows equivalents are in `tests/test_windows_native.py`, `tests/test_copy_windows_engine.py` and
`tests/test_hostos_acl.py`.

**Not verified by any CI job:** running the sandbox or the analyzer through Docker Desktop on Windows or macOS (GitHub's Windows and macOS
runners have no Linux Docker daemon), the bind mount of a Windows/macOS path into a Linux container, the `docker info` capability fields as
reported by Docker Desktop's VM, and behaviour on a real developer machine.

## What GitHub's runners can and cannot show
Windows and macOS runners have no Linux Docker daemon, so the sandbox and analyzer tests are skipped there (the CI summary says so). To
verify a real Docker Desktop machine, follow [platform-test-checklist.md](platform-test-checklist.md).

## Prerequisites
* Python 3.12+. Windows: PowerShell or Command Prompt, `py -3.12 -m pip install saferun-cli` (preferably in a virtual environment).
* Docker reachable by your user and **local**: `unix://` socket on Linux/macOS, a **local named pipe** (`npipe:////./pipe/...`) on Windows.
  `tcp://`, `ssh://`, remote pipes and anything else are refused, because the workspace is bind-mounted by host path.
* The daemon must report `OSType: linux` (all platforms). Windows: right-click the Docker tray icon → *Switch to Linux containers*.
* cosign: nothing to install. `saferun init` fetches a pinned, SHA-256-verified cosign 2.4.3 into SafeRun's data directory when none is available (Linux and macOS amd64/arm64, Windows amd64); an existing cosign 2.2+ on `PATH` is used otherwise. Without any, or to avoid it, use `saferun init --build-local` (source checkout).
* Windows: the project and the temp directory (`%TEMP%`) must be on a **local drive that Docker Desktop shares** (default for `C:\Users`).
  UNC/network paths and `\\?\` paths are refused. macOS: default Docker Desktop shares `/Users`, `/private` and `/var/folders`.
* Per-user data (analyzer lock, OSV database): Linux `~/.local/share/saferun` (or `$XDG_DATA_HOME`), macOS
  `~/Library/Application Support/saferun`, Windows `%LOCALAPPDATA%\saferun`. Overrides: `SAFERUN_ANALYZER_LOCK`, `SAFERUN_OSV_DB`.
  The workspace location follows `TMPDIR` (POSIX) or `TEMP`/`TMP` (Windows).

## Architecture
`saferun/hostos/` is the only place that branches on the OS. Linux and macOS keep the original code paths (`fcntl` locks, `openat`-style
copy in `sandbox/copy.py`, permission bits). Windows adds: `sandbox/copy_windows.py` (the algorithm), `hostos/winfs.py` + `_win.py`
(Win32 handles via `ctypes`, no new dependency), `hostos/acl.py` (pure-Python security-descriptor evaluation, fail closed),
`hostos/process.py` (job objects). The sandbox container policy, the preflight, the signature check and the verdict logic are shared and unchanged.
The local analyzer build is now `docker/analyzer/build.py` (`build.sh` just runs it).

## Windows: how the guarantees are provided (and where they differ)
| Guarantee | Linux / macOS | Windows |
|---|---|---|
| Symlinks never followed | `O_NOFOLLOW` relative to open dir fds | every entry opened with `FILE_FLAG_OPEN_REPARSE_POINT`; attributes read from the open handle |
| Other reparse points (junctions, mount points, cloud placeholders) | n/a | skipped, reported as `reparse-point` |
| Alternate data streams | n/a | entry skipped, reported as `alternate-data-stream` (the benign `Zone.Identifier` mark is ignored and never copied) |
| Race detection | 3 passes: signature (type, mode, dev, ino, size, mtime, ctime) + directory listings | 3 passes: signature (type, attributes, 128-bit file id + volume, size, LastWrite, ChangeTime, link count) + listings |
| Race *prevention* | none (detection only) | directories and files are held open without rename/delete/write sharing. The native NTFS tests on `windows-2022` confirm that an open directory (and its ancestors) cannot be renamed or deleted and that a file being read cannot be written or deleted; adding or removing entries in a directory stays possible and is caught by the three-pass comparison. Tested on the GitHub runner's NTFS only |
| Hard links with outside names | link count vs names seen | same (`nlink` vs names seen) |
| Private-file withholding | "not world-readable" (mode bits) | **different rule:** withheld unless every principal that can read the project root can also read the file (real token + groups, deny ACEs, inheritance). Unreadable/unparseable ACLs, conditional/object ACEs: withheld |
| Credential-signature scan | yes | yes (identical) |
| Lock/trust files (analyzer lock) | owner uid, mode 0700/0600, no symlinks | owner SID, no reparse points, no ACE for anyone but the user, SYSTEM, Administrators |
| Orphan workspace liveness | `flock` | exclusive-share lock file (released by the OS if the process dies) |
| Process tree kill | process group + `SIGKILL`/`SIGINT` | job object (kill-on-close; started suspended, confined, then resumed); `CTRL_BREAK` for interrupt |
| Executable bit dropped | yes | not applicable |

Known Windows limitations: ADS and reparse points are skipped (so such projects are scanned partially, and the report says so); the
private-file rule is a *relative* heuristic (a project whose files are all equally restricted is treated as shareable, as on a umask-077 Linux tree
with `honor_private_modes=False`, but here without a switch); `ChangeTime` behaviour on every file system is not guaranteed (FAT/exFAT, network
shares are refused or weaker); Windows containers mode is refused.

## Docker Desktop caveats (unverified: CI cannot test them)
* `docker info` capability fields (`MemoryLimit`, `SwapLimit`, `PidsLimit`, `CpuCfsQuota`, seccomp) as reported by Docker Desktop's VM may differ from
  a Linux host. SafeRun treats them as required and refuses to run if they are missing; it will not be loosened without real output.
* Bind mounts go through Docker Desktop file sharing; ownership and modes inside the container may differ from Linux. The container user is
  still `65534`, the mount is still read-only, and `docker inspect` of the created container is still verified before it starts.
* The analyzer image is linux/amd64 only; on Apple Silicon and Windows ARM it would run under emulation (multi-arch is a packaging-phase topic).
* If the macOS temp directory is not shared with Docker Desktop (Colima/Lima setups), set `TMPDIR` to a shared location.
