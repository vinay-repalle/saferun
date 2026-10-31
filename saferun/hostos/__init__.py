"""The only place SafeRun branches on the operating system (apart from the Windows copy engine, sandbox/copy_windows.py).

POSIX (Linux, macOS) behaviour is the original behaviour of SafeRun and stays implemented where it always was (fcntl locks, O_NOFOLLOW /
dir_fd copy, permission bits). This package adds what a native Windows host needs, plus path and endpoint rules that differ per platform.
Nothing here weakens a check: where Windows cannot offer a POSIX guarantee, the function fails closed or says so (docs/platforms.md).
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

if IS_WINDOWS:
    from . import _win


def user_data_base() -> Path:
    """Directory that holds `saferun/…` (analyzer lock, OSV database). XDG_DATA_HOME wins on POSIX; Linux default is unchanged."""
    if IS_WINDOWS:
        return Path(os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local"))
    env = os.environ.get("XDG_DATA_HOME")
    if env:
        return Path(env)
    home = os.path.expanduser("~")
    if IS_MACOS:
        return Path(home) / "Library" / "Application Support"
    return Path(home) / ".local" / "share"


# Environment variables a child process needs on Windows (it cannot start, resolve DNS or load DLLs without them). Nothing secret.
WINDOWS_BASE_ENV = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE")


def base_env_names() -> tuple[str, ...]:
    return WINDOWS_BASE_ENV if IS_WINDOWS else ()


def private_home_env(home: str) -> dict[str, str]:
    """Variables that point a child's profile / temp locations at `home` (Windows names; POSIX uses HOME / XDG_* set by the callers)."""
    if not IS_WINDOWS:
        return {}
    return {"USERPROFILE": home, "APPDATA": home, "LOCALAPPDATA": home, "TEMP": home, "TMP": home}


def enable_ansi() -> None:
    """Make colour / cursor escapes work in cmd.exe and PowerShell consoles (Windows 10+), and never crash on a non-UTF-8 code page."""
    if not IS_WINDOWS:
        return
    for fd in (-11, -12):
        _win.enable_ansi(fd)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


# ---- Docker endpoint and mount rules ------------------------------------------------------------------------------
_NPIPE_RE = re.compile(r"^npipe:/{2,4}\./pipe/[A-Za-z0-9_.-]{1,128}$")   # host must be "." = this machine; no \\server\pipe\x


def docker_endpoint_is_local(host: str) -> bool:
    """POSIX: only a unix:// socket (unchanged). Windows: only a LOCAL named pipe; unix://, tcp://, ssh:// and remote pipes are refused."""
    if IS_WINDOWS:
        return bool(_NPIPE_RE.match(host))
    return host.startswith("unix://")


_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:\\")


def mount_source_problem(path: str) -> str | None:
    """Windows only: a bind-mount source must be a plain local drive path. UNC / device / extended paths could reach a remote machine."""
    if not IS_WINDOWS:
        return None
    if not _DRIVE_PATH_RE.match(path) or "\\\\?\\" in path or "\\\\.\\" in path:
        return "only a local drive path (C:\\...) can be mounted; network, device and extended-length paths are refused"
    if _win.is_remote_drive(path):
        return "the path is on a network drive; Docker would resolve it on another machine"
    return None


# ---- files owned and readable only by the current user (analyzer lock, workspace ownership) -------------------------
def _trusted_sids() -> tuple[frozenset[str], str]:
    from . import acl
    _tok, user, owner = _win.current_token()
    return frozenset({user, owner, acl.SYSTEM, acl.ADMINISTRATORS}), user


def private_path_problem(path: Path, *, directory: bool) -> str | None:
    """Windows counterpart of the POSIX "owned by me, mode 0700/0600, not a symlink" test; None if the path can be trusted.
    The object must not be a reparse point, must be owned by the current user (or the account's default owner / Administrators), and its
    DACL must grant nothing to any other principal than the user, SYSTEM and Administrators. Anything unreadable is NOT trusted."""
    from . import acl
    try:
        h = _win.open_handle(str(path), _win.READ_CONTROL | _win.FILE_READ_ATTRIBUTES, _win.SHARE_READ | _win.SHARE_WRITE | _win.SHARE_DELETE,
                             flags=_win.FLAG_BACKUP_SEMANTICS | _win.FLAG_OPEN_REPARSE_POINT)
    except OSError as e:
        return f"cannot examine {path}: {e}"
    try:
        info = _win.file_info(h)
        if info["attrs"] & _win.ATTR_REPARSE_POINT:
            return f"{path} is a reparse point (symlink or junction), not a real {'directory' if directory else 'file'}"
        if bool(info["attrs"] & _win.ATTR_DIRECTORY) != directory:
            return f"{path} is not a {'directory' if directory else 'regular file'}"
        trusted, _user = _trusted_sids()
        desc = acl.parse_descriptor(_win.security_descriptor(h))
        if desc.owner not in trusted:
            return f"{path} is owned by {desc.owner}, not by the current user"
        other = acl.only_trusted_principals(desc, trusted)
        if other:
            return f"{path} grants access to {other}; only the current user, SYSTEM and Administrators may have access (icacls {path} /inheritance:r /grant:r %USERNAME%:F)"
    except (OSError, acl.AclUnverifiable) as e:
        return f"cannot verify the permissions of {path}: {e}"
    finally:
        _win.close(h)
    return None


def restrict_to_owner(path: Path) -> None:
    """Windows: make `path` accessible to the current user and SYSTEM only (protected DACL). The POSIX code uses chmod 0700 / 0600."""
    _win.restrict_to_user(str(path), _win.current_token()[1])


def owned_by_current_user(path: Path) -> bool:
    """Windows counterpart of `st_uid == os.getuid()` (used before the reaper deletes a leftover workspace)."""
    from . import acl
    try:
        h = _win.open_handle(str(path), _win.READ_CONTROL, _win.SHARE_READ | _win.SHARE_WRITE | _win.SHARE_DELETE,
                             flags=_win.FLAG_BACKUP_SEMANTICS | _win.FLAG_OPEN_REPARSE_POINT)
    except OSError:
        return False
    try:
        _tok, user, owner = _win.current_token()   # `owner` is the account's default owner: Administrators for an elevated token
        return acl.parse_descriptor(_win.security_descriptor(h)).owner in (user, owner)
    except (OSError, acl.AclUnverifiable):
        return False
    finally:
        _win.close(h)


# ---- workspace liveness lock ---------------------------------------------------------------------------------------
def create_workspace_lock(path: Path) -> int:
    """Windows: file held with share mode 0 until the returned fd is closed (or the process dies)."""
    return _win.create_exclusive_lock(str(path))


def workspace_lock_state(path: str) -> str:
    return _win.lock_state(path)


def long_path(path) -> str:
    """Windows: the extended-length form, so deletion works for long paths and names such as CON / trailing dots. Elsewhere: unchanged."""
    return _win.ext(str(path)) if IS_WINDOWS else str(path)


def rmtree_onexc(func, path, exc):
    """shutil.rmtree error handler for Windows: clear the read-only flag and retry once. Any other failure is raised, never hidden."""
    import stat
    if isinstance(exc, PermissionError):
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
            return
        except OSError:
            pass
    raise exc
