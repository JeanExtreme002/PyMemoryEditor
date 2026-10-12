# -*- coding: utf-8 -*-

"""
Two facts about a process the policy needs and the core library does not
expose: its **parent** and its **identity** (when it started).

* The parent is how the server finds the MCP client to protect. ``getppid()``
  alone is not enough: under ``uvx`` (the launch command the MCP Registry
  entry uses) the server's parent is ``uv``, and the client is one or two
  levels further up. :func:`ancestor_pids` walks the whole chain.
* The start time is what turns a pid into an identity. A pid is recycled the
  moment its process exits; ``(pid, start time)`` is not, which is what a
  remembered approval scoped to *one running instance* has to be keyed by.

Both are best-effort and dependency-free, one small primitive per OS: Linux
reads ``/proc/<pid>/stat``, macOS asks ``proc_pidinfo(PROC_PIDTBSDINFO)``, and
Windows uses a Toolhelp snapshot plus ``GetProcessTimes``. Every failure —
a process that exited, one this user may not inspect — reads as "unknown"
(``None``) rather than raising: the callers fail safe on ``None``.
"""

import ctypes
import os
import sys
from typing import FrozenSet, Optional, Set

#: How far :func:`ancestor_pids` climbs. A real launch chain is a handful of
#: levels (terminal -> shell -> client -> uv -> server); the bound only exists
#: so a corrupt or cyclic answer cannot loop.
MAX_ANCESTOR_DEPTH = 32


def _linux_stat_fields(pid: int) -> Optional[list]:
    """The fields of ``/proc/<pid>/stat`` after ``comm``, or ``None``.

    ``comm`` is parenthesised and may itself contain spaces or parentheses, so
    the only safe split point is the last ``)`` (``man 5 proc``). Read as
    bytes: ``comm`` is whatever the process set, not necessarily UTF-8, and a
    decode error here would end the ancestor walk early and leave the client
    above unprotected. Every field after ``comm`` is ASCII.
    """
    try:
        with open("/proc/%d/stat" % pid, "rb") as handle:
            raw = handle.read()
    except OSError:
        return None
    close = raw.rfind(b")")
    if close == -1:
        return None
    return raw[close + 1 :].decode("ascii", "replace").split()


if sys.platform == "darwin":
    _PROC_PIDTBSDINFO = 3

    class _ProcBsdInfo(ctypes.Structure):
        """``struct proc_bsdinfo`` from ``<sys/proc_info.h>`` (136 bytes)."""

        _fields_ = [
            ("pbi_flags", ctypes.c_uint32),
            ("pbi_status", ctypes.c_uint32),
            ("pbi_xstatus", ctypes.c_uint32),
            ("pbi_pid", ctypes.c_uint32),
            ("pbi_ppid", ctypes.c_uint32),
            ("pbi_uid", ctypes.c_uint32),
            ("pbi_gid", ctypes.c_uint32),
            ("pbi_ruid", ctypes.c_uint32),
            ("pbi_rgid", ctypes.c_uint32),
            ("pbi_svuid", ctypes.c_uint32),
            ("pbi_svgid", ctypes.c_uint32),
            ("rfu_1", ctypes.c_uint32),
            ("pbi_comm", ctypes.c_char * 16),
            ("pbi_name", ctypes.c_char * 32),
            ("pbi_nfiles", ctypes.c_uint32),
            ("pbi_pgid", ctypes.c_uint32),
            ("pbi_pjobc", ctypes.c_uint32),
            ("e_tdev", ctypes.c_uint32),
            ("e_tpgid", ctypes.c_uint32),
            ("pbi_nice", ctypes.c_int32),
            ("pbi_start_tvsec", ctypes.c_uint64),
            ("pbi_start_tvusec", ctypes.c_uint64),
        ]

    # A private handle, so these prototypes cannot clash with the ones the
    # macOS backend declares on its own libSystem handle.
    _libproc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    _libproc.proc_pidinfo.argtypes = (
        ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int,
    )
    _libproc.proc_pidinfo.restype = ctypes.c_int

    def _bsdinfo(pid: int) -> Optional[_ProcBsdInfo]:
        info = _ProcBsdInfo()
        size = ctypes.sizeof(info)
        try:
            got = _libproc.proc_pidinfo(
                pid, _PROC_PIDTBSDINFO, 0, ctypes.byref(info), size
            )
        except (OverflowError, ctypes.ArgumentError):
            return None
        return info if got == size else None

    def parent_pid(pid: int) -> Optional[int]:
        """The parent of ``pid``, or ``None`` when it cannot be read."""
        info = _bsdinfo(pid)
        return None if info is None else int(info.pbi_ppid)

    def start_identity(pid: int) -> Optional[int]:
        """A value that changes when ``pid`` is reused: the start time in µs."""
        info = _bsdinfo(pid)
        if info is None:
            return None
        return int(info.pbi_start_tvsec) * 1_000_000 + int(info.pbi_start_tvusec)

elif sys.platform == "win32":  # pragma: no cover - exercised on Windows CI only
    from ctypes import wintypes

    from ..win32.types import PROCESSENTRY32W

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.c_void_p)
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.c_void_p)
    _kernel32.Process32NextW.restype = wintypes.BOOL
    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (
        ctypes.POINTER(wintypes.FILETIME),
    ) * 4
    _kernel32.GetProcessTimes.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _TH32CS_SNAPPROCESS = 0x2
    _INVALID_HANDLE = wintypes.HANDLE(-1).value
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    def parent_pid(pid: int) -> Optional[int]:
        """The parent of ``pid`` per a Toolhelp snapshot, or ``None``."""
        snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        if not snapshot or snapshot == _INVALID_HANDLE:
            return None
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            ok = _kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                if int(entry.th32ProcessID) == pid:
                    return int(entry.th32ParentProcessID)
                ok = _kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            _kernel32.CloseHandle(snapshot)
        return None

    def start_identity(pid: int) -> Optional[int]:
        """The process creation time (a ``FILETIME``), or ``None``."""
        try:
            handle = _kernel32.OpenProcess(
                _PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
        except (OverflowError, ctypes.ArgumentError):
            return None
        if not handle:
            return None
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not _kernel32.GetProcessTimes(
                handle, *(ctypes.byref(item) for item in times)
            ):
                return None
            created = times[0]
            return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
        finally:
            _kernel32.CloseHandle(handle)

else:

    def parent_pid(pid: int) -> Optional[int]:
        """The parent of ``pid`` from ``/proc``, or ``None``."""
        fields = _linux_stat_fields(pid)
        try:
            return int(fields[1]) if fields else None
        except (IndexError, ValueError):
            return None

    def start_identity(pid: int) -> Optional[int]:
        """``starttime`` (field 22 of ``/proc/<pid>/stat``), or ``None``.

        The Linux backend's PID-reuse guard reads the same field; sharing its
        parser keeps the two identities from ever disagreeing.
        """
        from ..linux.functions import read_start_time

        return read_start_time(pid)


def ancestor_pids(pid: Optional[int] = None) -> FrozenSet[int]:
    """Every ancestor of ``pid`` (default: this process), nearest first.

    Stops at the init process (pid 0 / 1, which the system denylist already
    covers), at a pid it has seen before, after :data:`MAX_ANCESTOR_DEPTH`
    hops, or where the parent cannot be read. ``os.getppid()`` is always
    included for this process, even when nothing above it can be read.

    A parent that started *after* its child is not the parent: on Windows the
    recorded parent id outlives the parent, and the number can since belong to
    an unrelated process. The walk stops there rather than protect a stranger.
    """
    ancestors: Set[int] = set()
    child = origin = os.getpid() if pid is None else pid
    parent: Optional[int]
    if pid is None and os.getppid() > 1:
        # The kernel's own answer for this process: trusted outright.
        child = os.getppid()
        ancestors.add(child)
        parent = _safe_parent(child)
    else:
        parent = _safe_parent(child)

    for _ in range(MAX_ANCESTOR_DEPTH):
        if parent is None or parent <= 1 or parent in ancestors or parent == origin:
            break
        child_started = _safe_identity(child)
        parent_started = _safe_identity(parent)
        if (
            child_started is not None
            and parent_started is not None
            and parent_started > child_started
        ):
            break
        ancestors.add(parent)
        child, parent = parent, _safe_parent(parent)

    return frozenset(ancestors)


def _safe_parent(pid: int) -> Optional[int]:
    try:
        return parent_pid(pid)
    except Exception:  # noqa: BLE001 — best effort; "unknown" fails safe
        return None


def _safe_identity(pid: int) -> Optional[int]:
    try:
        return start_identity(pid)
    except Exception:  # noqa: BLE001 — best effort; "unknown" fails safe
        return None


def process_identity(pid: int) -> Optional[int]:
    """``start_identity`` that never raises: ``None`` means "unknown"."""
    return _safe_identity(pid)


__all__ = ("MAX_ANCESTOR_DEPTH", "ancestor_pids", "parent_pid", "process_identity")
