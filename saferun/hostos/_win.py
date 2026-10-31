"""Thin ctypes layer over the Win32 / NT calls SafeRun needs. Imported only on Windows; nothing here decides policy (see acl.py).

Every function declares argtypes/restype: without them 64-bit handles are truncated to 32 bits.
"""
from __future__ import annotations

import ctypes
import msvcrt
import ntpath
import os
from ctypes import wintypes as wt

from . import acl

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_adv = ctypes.WinDLL("advapi32", use_last_error=True)
_nt = ctypes.WinDLL("ntdll", use_last_error=True)

HANDLE = ctypes.c_void_p
INVALID = ctypes.c_void_p(-1).value

GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, READ_CONTROL, DELETE = 0x1, 0x80, 0x20000, 0x10000
SHARE_READ, SHARE_WRITE, SHARE_DELETE = 1, 2, 4
CREATE_NEW, OPEN_EXISTING = 1, 3
FLAG_BACKUP_SEMANTICS, FLAG_OPEN_REPARSE_POINT, ATTR_NORMAL = 0x02000000, 0x00200000, 0x80
ATTR_DIRECTORY, ATTR_REPARSE_POINT = 0x10, 0x400
TAG_SYMLINK = 0xA000000C
ERROR_SHARING_VIOLATION, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF = 32, 2, 38
DRIVE_REMOTE = 4


class FILETIME(ctypes.Structure):
    _fields_ = [("lo", wt.DWORD), ("hi", wt.DWORD)]


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [("attrs", wt.DWORD), ("created", FILETIME), ("accessed", FILETIME), ("written", FILETIME),
                ("volume", wt.DWORD), ("size_hi", wt.DWORD), ("size_lo", wt.DWORD), ("nlink", wt.DWORD),
                ("index_hi", wt.DWORD), ("index_lo", wt.DWORD)]


class FILE_BASIC_INFO(ctypes.Structure):
    _fields_ = [("created", ctypes.c_int64), ("accessed", ctypes.c_int64), ("written", ctypes.c_int64),
                ("changed", ctypes.c_int64), ("attrs", wt.DWORD)]


class FILE_ID_INFO(ctypes.Structure):
    _fields_ = [("volume", ctypes.c_uint64), ("file_id", ctypes.c_ubyte * 16)]


class FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = [("attrs", wt.DWORD), ("tag", wt.DWORD)]


class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [("size", ctypes.c_int64), ("name", ctypes.c_wchar * (260 + 36))]


def _fn(dll, name, restype, *argtypes):
    f = getattr(dll, name)
    f.restype, f.argtypes = restype, list(argtypes)
    return f


CreateFileW = _fn(_k32, "CreateFileW", HANDLE, wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, HANDLE)
CloseHandle = _fn(_k32, "CloseHandle", wt.BOOL, HANDLE)
GetFileInformationByHandle = _fn(_k32, "GetFileInformationByHandle", wt.BOOL, HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION))
GetFileInformationByHandleEx = _fn(_k32, "GetFileInformationByHandleEx", wt.BOOL, HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD)
GetFinalPathNameByHandleW = _fn(_k32, "GetFinalPathNameByHandleW", wt.DWORD, HANDLE, wt.LPWSTR, wt.DWORD, wt.DWORD)
GetDriveTypeW = _fn(_k32, "GetDriveTypeW", wt.UINT, wt.LPCWSTR)
FindFirstStreamW = _fn(_k32, "FindFirstStreamW", HANDLE, wt.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wt.DWORD)
FindNextStreamW = _fn(_k32, "FindNextStreamW", wt.BOOL, HANDLE, ctypes.c_void_p)
FindClose = _fn(_k32, "FindClose", wt.BOOL, HANDLE)
CreateJobObjectW = _fn(_k32, "CreateJobObjectW", HANDLE, ctypes.c_void_p, wt.LPCWSTR)
SetInformationJobObject = _fn(_k32, "SetInformationJobObject", wt.BOOL, HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD)
AssignProcessToJobObject = _fn(_k32, "AssignProcessToJobObject", wt.BOOL, HANDLE, HANDLE)
TerminateJobObject = _fn(_k32, "TerminateJobObject", wt.BOOL, HANDLE, wt.UINT)
GetStdHandle = _fn(_k32, "GetStdHandle", HANDLE, wt.DWORD)
GetConsoleMode = _fn(_k32, "GetConsoleMode", wt.BOOL, HANDLE, ctypes.POINTER(wt.DWORD))
SetConsoleMode = _fn(_k32, "SetConsoleMode", wt.BOOL, HANDLE, wt.DWORD)
LocalFree = _fn(_k32, "LocalFree", HANDLE, HANDLE)
GetCurrentProcess = _fn(_k32, "GetCurrentProcess", HANDLE)
OpenProcessToken = _adv.OpenProcessToken
OpenProcessToken.restype, OpenProcessToken.argtypes = wt.BOOL, [HANDLE, wt.DWORD, ctypes.POINTER(HANDLE)]
GetTokenInformation = _fn(_adv, "GetTokenInformation", wt.BOOL, HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD))
GetKernelObjectSecurity = _fn(_adv, "GetKernelObjectSecurity", wt.BOOL, HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD))
ConvertStringSecurityDescriptorToSecurityDescriptorW = _fn(
    _adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", wt.BOOL, wt.LPCWSTR, wt.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p)
SetFileSecurityW = _fn(_adv, "SetFileSecurityW", wt.BOOL, wt.LPCWSTR, wt.DWORD, ctypes.c_void_p)
NtResumeProcess = _fn(_nt, "NtResumeProcess", ctypes.c_long, HANDLE)


def ext(path: str) -> str:
    """Extended-length form of an absolute path (no MAX_PATH limit, no Win32 name normalisation)."""
    # os.path.abspath() asks Win32 to normalise the name, which turns a final component such as CON into the device path \\.\CON.
    # An already absolute path is only cleaned up as a string; only a relative one needs the working directory.
    path = ntpath.normpath(path) if ntpath.isabs(path) else os.path.abspath(path)
    if path.startswith("\\\\?\\"):
        return path
    return "\\\\?\\UNC\\" + path[2:] if path.startswith("\\\\") else "\\\\?\\" + path


def oserror(code: int | None = None) -> OSError:
    code = ctypes.get_last_error() if code is None else code
    return ctypes.WinError(code)


def open_handle(path: str, access: int, share: int, disposition: int = OPEN_EXISTING, flags: int = 0) -> int:
    h = CreateFileW(ext(path), access, share, None, disposition, flags, None)
    if h is None or h == INVALID:
        raise oserror()
    return h


def close(handle: int | None) -> None:
    if handle:
        CloseHandle(handle)


def file_info(handle: int) -> dict:
    """Identity and metadata of an OPEN handle (never of a path): attributes, 128-bit file id, size, links, times, reparse tag."""
    bh = BY_HANDLE_FILE_INFORMATION()
    if not GetFileInformationByHandle(handle, ctypes.byref(bh)):
        raise oserror()
    basic = FILE_BASIC_INFO()
    if not GetFileInformationByHandleEx(handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)):
        raise oserror()
    fid = FILE_ID_INFO()
    if GetFileInformationByHandleEx(handle, 18, ctypes.byref(fid), ctypes.sizeof(fid)):
        ident = (fid.volume, bytes(fid.file_id))
    else:   # file systems without 128-bit ids: the 64-bit index
        ident = (bh.volume, (bh.index_hi << 32) | bh.index_lo)
    tag = 0
    if bh.attrs & ATTR_REPARSE_POINT:
        t = FILE_ATTRIBUTE_TAG_INFO()
        if not GetFileInformationByHandleEx(handle, 9, ctypes.byref(t), ctypes.sizeof(t)):
            raise oserror()
        tag = t.tag
    return {"attrs": bh.attrs, "ident": ident, "size": (bh.size_hi << 32) | bh.size_lo, "nlink": bh.nlink,
            "written": basic.written, "changed": basic.changed, "tag": tag}


def final_path(handle: int) -> str:
    buf = ctypes.create_unicode_buffer(32768)
    n = GetFinalPathNameByHandleW(handle, buf, len(buf), 0)
    if n == 0 or n >= len(buf):
        raise oserror()
    p = buf.value
    return p[4:] if p.startswith("\\\\?\\") and not p.startswith("\\\\?\\UNC\\") else p


def is_remote_drive(path: str) -> bool:
    p = os.path.abspath(path)
    return p.startswith("\\\\") or GetDriveTypeW(os.path.splitdrive(p)[0] + "\\") == DRIVE_REMOTE


def stream_names(path: str) -> list[str]:
    """Names of all data streams of a file or directory, e.g. ['::$DATA', ':Zone.Identifier:$DATA']."""
    data = WIN32_FIND_STREAM_DATA()
    h = FindFirstStreamW(ext(path), 0, ctypes.byref(data), 0)
    if h is None or h == INVALID:
        err = ctypes.get_last_error()
        if err == ERROR_HANDLE_EOF:
            return []
        raise oserror(err)
    try:
        names = [data.name]
        while FindNextStreamW(h, ctypes.byref(data)):
            names.append(data.name)
        if ctypes.get_last_error() not in (0, ERROR_HANDLE_EOF):   # enumeration ended on an error, not at the end
            pass
        return names
    finally:
        FindClose(h)


def security_descriptor(handle: int) -> bytes:
    """Owner + DACL of an open handle (needs READ_CONTROL), self-relative."""
    needed = wt.DWORD(0)
    GetKernelObjectSecurity(handle, 0x5, None, 0, ctypes.byref(needed))
    for _ in range(3):
        buf = ctypes.create_string_buffer(max(needed.value, 64))
        if GetKernelObjectSecurity(handle, 0x5, buf, len(buf), ctypes.byref(needed)):
            return buf.raw[:needed.value]
    raise oserror()


def _sid_at(address: int) -> str:
    count = ctypes.string_at(address + 1, 1)[0]
    return acl.sid_to_str(ctypes.string_at(address, 8 + 4 * count))[0]


def _token_info(token: int, cls: int) -> ctypes.Array:
    n = wt.DWORD(0)
    GetTokenInformation(token, cls, None, 0, ctypes.byref(n))
    buf = ctypes.create_string_buffer(n.value)
    if not GetTokenInformation(token, cls, buf, n.value, ctypes.byref(n)):
        raise oserror()
    return buf


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attrs", wt.DWORD)]


def current_token() -> tuple[acl.Token, str, str]:
    """(token with enabled / deny-only groups, user SID, default owner SID) of this process."""
    tok = HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), 0x8, ctypes.byref(tok)):   # TOKEN_QUERY
        raise oserror()
    try:
        user = _sid_at(ctypes.cast(_token_info(tok, 1), ctypes.POINTER(ctypes.c_void_p))[0])
        owner = _sid_at(ctypes.cast(_token_info(tok, 4), ctypes.POINTER(ctypes.c_void_p))[0])
        buf = _token_info(tok, 2)
        count = ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0]
        first = ctypes.addressof(buf) + ctypes.sizeof(ctypes.c_void_p)    # groups start after the count, padded to pointer size
        groups = (_SidAndAttributes * count).from_address(first)
        enabled = {_sid_at(g.sid) for g in groups if g.attrs & 0x4}
        deny_only = {_sid_at(g.sid) for g in groups if g.attrs & 0x10}
    finally:
        CloseHandle(tok)
    return (acl.Token(frozenset(enabled | {user, acl.EVERYONE, acl.AUTHENTICATED_USERS}), frozenset(deny_only)), user, owner)


def restrict_to_user(path: str, user_sid: str) -> None:
    """Replace the DACL of `path` with a protected one granting full control to `user_sid` and SYSTEM only."""
    sddl = f"D:P(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)"
    psd = ctypes.c_void_p()
    if not ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(psd), None):
        raise oserror()
    try:
        if not SetFileSecurityW(ext(path), 0x4, psd):   # DACL_SECURITY_INFORMATION
            raise oserror()
    finally:
        LocalFree(psd)


def create_exclusive_lock(path: str) -> int:
    """Create `path` held with share mode 0: no one else can open it while this fd lives; the OS releases it if we die. -> C fd"""
    h = open_handle(path, GENERIC_READ | GENERIC_WRITE, 0, CREATE_NEW, ATTR_NORMAL)
    try:
        return msvcrt.open_osfhandle(h, os.O_RDWR | os.O_NOINHERIT)
    except BaseException:
        CloseHandle(h)
        raise


def lock_state(path: str) -> str:
    """'busy' (a live owner holds it), 'free' (no holder) or 'absent'."""
    try:
        h = open_handle(path, GENERIC_READ, 0)
    except OSError as e:
        code = getattr(e, "winerror", None)
        if code == ERROR_SHARING_VIOLATION:
            return "busy"
        if code == ERROR_FILE_NOT_FOUND or isinstance(e, FileNotFoundError):
            return "absent"
        raise
    CloseHandle(h)
    return "free"


def enable_ansi(stream_fd: int) -> bool:
    """Turn on ANSI escape processing for the console behind std handle -11 (stdout) / -12 (stderr). False if not a console."""
    h = GetStdHandle(wt.DWORD(stream_fd))
    mode = wt.DWORD()
    if not h or h == INVALID or not GetConsoleMode(h, ctypes.byref(mode)):
        return False
    return bool(SetConsoleMode(h, mode.value | 0x0004))   # ENABLE_VIRTUAL_TERMINAL_PROCESSING


# ---- job objects -------------------------------------------------------------------------------------------------
class _BasicLimit(ctypes.Structure):
    _fields_ = [("per_process_time", ctypes.c_int64), ("per_job_time", ctypes.c_int64), ("flags", wt.DWORD),
                ("min_ws", ctypes.c_size_t), ("max_ws", ctypes.c_size_t), ("active", wt.DWORD), ("affinity", ctypes.c_size_t),
                ("priority", wt.DWORD), ("sched", wt.DWORD)]


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in ("ro", "wo", "oo", "rb", "wb", "ob")]


class _ExtendedLimit(ctypes.Structure):
    _fields_ = [("basic", _BasicLimit), ("io", _IoCounters), ("proc_mem", ctypes.c_size_t), ("job_mem", ctypes.c_size_t),
                ("peak_proc", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]


def create_kill_on_close_job() -> int:
    job = CreateJobObjectW(None, None)
    if not job:
        raise oserror()
    info = _ExtendedLimit()
    info.basic.flags = 0x2000   # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        err = oserror()
        CloseHandle(job)
        raise err
    return job


def assign_to_job(job: int, process_handle: int) -> None:
    if not AssignProcessToJobObject(job, process_handle):
        raise oserror()


def resume_process(process_handle: int) -> None:
    if NtResumeProcess(process_handle) < 0:
        raise OSError("could not resume the suspended process")


def terminate_job(job: int) -> None:
    TerminateJobObject(job, 1)
