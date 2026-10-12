# -*- coding: utf-8 -*-

# Read more about operations with processes by win32 api here:
# https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
# https://learn.microsoft.com/en-us/windows/win32/api/psapi/
# ...

import ctypes
import ctypes.wintypes
import logging
import time
from typing import Generator, Optional, Pattern, Sequence, Tuple, Type, TypeVar, Union, cast

from ..enums import ScanTypesEnum
from ..process.errors import ProcessIDNotExistsError
from ..process.module_info import ModuleInfo
from ..process.region import (
    MemoryRegion,
    MemoryRegionSnapshot,
    default_address_filter,
    default_scan_filter,
    make_region,
)
from ..process.scanning import (
    iter_pattern_results,
    iter_search_results,
    iter_values_for_addresses,
)
from ..process.thread_info import ThreadInfo
from ..util import (
    _validate_pytype,
    as_writable_c_buffer,
    get_c_type_of,
    sign_extend_narrow_int,
    values_to_bytes,
)
from ..util.pattern import PatternLike, compile_pattern

from .enums import MemoryAllocationStatesEnum, MemoryProtectionsEnum, MemoryTypesEnum
from .types import (
    MEMORY_BASIC_INFORMATION,
    MODULEENTRY32W,
    PROCESSENTRY32W,
    SYSTEM_INFO,
    TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
    TH32CS_SNAPPROCESS,
    TH32CS_SNAPTHREAD,
    THREADENTRY32,
)


_logger = logging.getLogger("PyMemoryEditor")


# Load the libraries with `use_last_error=True` so that `ctypes.get_last_error()`
# returns the per-call `GetLastError` set by the Win32 API. The default
# `ctypes.windll.kernel32` accessor uses the shared `WinError` state and
# `ctypes.get_last_error()` would always return 0, making the WinError path
# in `_raise_last_error` effectively dead.
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

# Configure argtypes/restype for each Windows API used.
# Skipping argtypes silently truncates 64-bit handles to 32-bit on x64 Python builds
# and lets Python misinterpret return values, hiding errors.

kernel32.OpenProcess.argtypes = (
    ctypes.wintypes.DWORD,
    ctypes.wintypes.BOOL,
    ctypes.wintypes.DWORD,
)
kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE

kernel32.CloseHandle.argtypes = (ctypes.wintypes.HANDLE,)
kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

# BOOL GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
# Needs PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION on the
# handle. Used to tell "the target exited" apart from "the handle lacks a
# right" when a memory call fails — a terminated process keeps its pid and
# its handle valid for as long as we hold the handle, so a pid probe alone
# cannot answer that question.
kernel32.GetExitCodeProcess.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.DWORD),
)
kernel32.GetExitCodeProcess.restype = ctypes.wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCVOID,
    ctypes.wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)
kernel32.ReadProcessMemory.restype = ctypes.wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)
kernel32.WriteProcessMemory.restype = ctypes.wintypes.BOOL

kernel32.VirtualQueryEx.argtypes = (
    # The buffer is the caller's native MEMORY_BASIC_INFORMATION (see
    # mbi_class_for_handle); it is declared as a raw void pointer so callers
    # (and tests) can pass any byref()'d struct of that size.
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCVOID,
    ctypes.c_void_p,
    ctypes.c_size_t,
)
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.GetSystemInfo.argtypes = (ctypes.POINTER(SYSTEM_INFO),)
kernel32.GetSystemInfo.restype = None

# void GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo);
# Unlike GetSystemInfo, this reports the *native* architecture even when the
# caller is a 32-bit (WOW64) process — so it tells us the true OS bitness
# regardless of how Python itself was built.
kernel32.GetNativeSystemInfo.argtypes = (ctypes.POINTER(SYSTEM_INFO),)
kernel32.GetNativeSystemInfo.restype = None

# BOOL IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);
# True when the target is a 32-bit process running on 64-bit Windows.
kernel32.IsWow64Process.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.BOOL),
)
kernel32.IsWow64Process.restype = ctypes.wintypes.BOOL

# HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
# Snapshot of system threads (with TH32CS_SNAPTHREAD); per the docs, the
# ProcessID arg is ignored when SNAPTHREAD is set — the snapshot is global.
kernel32.CreateToolhelp32Snapshot.argtypes = (
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
)
kernel32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE

kernel32.Thread32First.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(THREADENTRY32),
)
kernel32.Thread32First.restype = ctypes.wintypes.BOOL

kernel32.Thread32Next.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(THREADENTRY32),
)
kernel32.Thread32Next.restype = ctypes.wintypes.BOOL

# Toolhelp32 module/process walks use the Unicode ("W") entry points so names
# and paths arrive as UTF-16 instead of being squeezed through the ANSI code
# page. Module32First/Process32First (no suffix) are the ANSI variants.
kernel32.Module32FirstW.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(MODULEENTRY32W),
)
kernel32.Module32FirstW.restype = ctypes.wintypes.BOOL

kernel32.Module32NextW.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(MODULEENTRY32W),
)
kernel32.Module32NextW.restype = ctypes.wintypes.BOOL

kernel32.Process32FirstW.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
)
kernel32.Process32FirstW.restype = ctypes.wintypes.BOOL

kernel32.Process32NextW.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
)
kernel32.Process32NextW.restype = ctypes.wintypes.BOOL

# LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
#                       DWORD flAllocationType, DWORD flProtect);
kernel32.VirtualAllocEx.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
)
kernel32.VirtualAllocEx.restype = ctypes.wintypes.LPVOID

# BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
#                    DWORD dwFreeType);
kernel32.VirtualFreeEx.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.wintypes.DWORD,
)
kernel32.VirtualFreeEx.restype = ctypes.wintypes.BOOL


# VirtualAllocEx flAllocationType: reserve address space *and* back it with
# physical storage in one call.
_MEM_COMMIT_RESERVE = (
    MemoryAllocationStatesEnum.MEM_COMMIT.value
    | MemoryAllocationStatesEnum.MEM_RESERVE.value
)
# VirtualFreeEx dwFreeType. MEM_RELEASE frees the entire allocation and
# requires dwSize == 0. Not in MemoryAllocationStatesEnum (that enum models
# MBI.State / allocation-time flags), so it is defined locally.
_MEM_RELEASE = 0x8000
# Default protection for a fresh allocation: read/write/execute, so the region
# works for both data and injected code (matches the common tooling default).
_DEFAULT_ALLOC_PROTECT = MemoryProtectionsEnum.PAGE_EXECUTE_READWRITE.value

# psapi.dll — used for GetMappedFileNameW to resolve backing file paths for
# memory regions. The "K32" prefixed versions live in kernel32.dll on Win7+,
# but importing psapi directly works from XP through 11.
psapi = ctypes.WinDLL("psapi.dll", use_last_error=True)

# DWORD GetMappedFileNameW(HANDLE hProcess, LPVOID lpv,
#                          LPWSTR lpFilename, DWORD nSize);
psapi.GetMappedFileNameW.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.LPWSTR,
    ctypes.wintypes.DWORD,
)
psapi.GetMappedFileNameW.restype = ctypes.wintypes.DWORD

# Initial GetMappedFileNameW buffer, in WCHARs. A name that fills it may have
# been truncated, so the call is retried with a larger buffer up to the
# longest NT path (UNICODE_STRING.MaximumLength is a USHORT of bytes).
_MAPPED_FILENAME_BUF_SIZE = 512
_MAPPED_FILENAME_MAX_SIZE = 32768


# Native OS bitness, independent of how Python was built. GetNativeSystemInfo
# reports the true architecture even from a 32-bit (WOW64) interpreter.
_native_system_information = SYSTEM_INFO()
kernel32.GetNativeSystemInfo(ctypes.byref(_native_system_information))

# wProcessorArchitecture values that imply a 64-bit OS: AMD64 (9), ARM64 (12),
# IA64 (6). Anything else (notably INTEL = 0) means a 32-bit OS.
_PROCESSOR_ARCHITECTURE_64BIT = (6, 9, 12)
_OS_IS_64BIT = (
    _native_system_information.wProcessorArchitecture in _PROCESSOR_ARCHITECTURE_64BIT
)
# The running Python's bitness: the fallback guess when a target's can't be read.
_HOST_IS_64BIT = ctypes.sizeof(ctypes.c_void_p) == 8


def mbi_class_for_handle(process_handle: int):
    """
    Return the MEMORY_BASIC_INFORMATION layout ``VirtualQueryEx`` fills in.

    That is always the layout of the *calling* process (the running Python),
    whatever the target's bitness: ``VirtualQueryEx`` forwards to
    ``NtQueryVirtualMemory(MemoryBasicInformation)``, which rejects any buffer
    smaller than the caller's native ``MEMORY_BASIC_INFORMATION`` with
    ``STATUS_INFO_LENGTH_MISMATCH`` (``ERROR_BAD_LENGTH``) and otherwise writes
    that native layout. From a 64-bit Python that is the 48-byte
    ``MEMORY_BASIC_INFORMATION_64`` even for a 32-bit (WOW64) target — whose
    addresses simply fit in the wider fields; from a 32-bit Python it is the
    28-byte ``MEMORY_BASIC_INFORMATION_32``.

    The explicit ``MEMORY_BASIC_INFORMATION32`` / ``64`` forms in ``winnt.h``
    exist for debuggers decoding a foreign-architecture target's data (dumps,
    debug-engine queries), not for ``VirtualQueryEx``. Passing the 28-byte
    form from a 64-bit Python made every query of a WOW64 target fail, so the
    region walk — and every scan of a 32-bit process — raised.

    ``process_handle`` is accepted for backwards compatibility; the answer no
    longer depends on the target.
    """
    return MEMORY_BASIC_INFORMATION


def _detect_process_64bit(process_handle: int) -> Optional[bool]:
    """
    Return ``True``/``False`` when the target's bitness can be determined, or
    ``None`` when ``IsWow64Process`` fails so the answer is unknown. The raw
    *mechanism*: no guessing and no warning — the caller decides what an unknown
    result means (the public :func:`IsProcess64Bit` falls back to the host
    bitness; ``AbstractProcess.is_64bit`` honors ``strict_bitness``).

    On a 32-bit OS every process is 32-bit. On a 64-bit OS a process is 32-bit
    exactly when it runs under WOW64 (``IsWow64Process`` returns True); a
    native (non-WOW64) process is 64-bit. The OS bitness is taken from
    ``GetNativeSystemInfo`` so the answer is correct even from a 32-bit Python.
    """
    if not _OS_IS_64BIT:
        return False

    is_wow64 = ctypes.wintypes.BOOL(0)
    ok = kernel32.IsWow64Process(process_handle, ctypes.byref(is_wow64))
    if not ok:
        return None

    return not bool(is_wow64.value)


def IsProcess64Bit(process_handle: int) -> bool:
    """
    Return ``True`` if the target process is 64-bit, ``False`` if 32-bit.

    Thin *policy* wrapper over :func:`_detect_process_64bit`: when the bitness
    can't be queried it falls back to the host bitness (the most likely answer
    on a 64-bit host) rather than raise from a simple property access, and warns
    so a wrong pointer-width default (used by the pointer APIs) is at least
    traceable instead of silently mis-detected.
    """
    detected = _detect_process_64bit(process_handle)
    if detected is not None:
        return detected

    _logger.warning(
        "IsWow64Process failed (err=%d); assuming the target matches the "
        "host bitness (%d-bit). Pointer-width detection may be wrong if it "
        "does not.",
        ctypes.get_last_error(),
        64 if _HOST_IS_64BIT else 32,
    )
    return _HOST_IS_64BIT


T = TypeVar("T")


# Win32 error codes this module reasons about.
_ERROR_ACCESS_DENIED = 5
_ERROR_INVALID_HANDLE = 6
_ERROR_BAD_LENGTH = 24
_ERROR_INVALID_PARAMETER = 87
# GetExitCodeProcess reports this while the process is still running.
_STILL_ACTIVE = 259

# VirtualQueryEx / ReadProcessMemory failures that describe the *handle*, not
# the address: no amount of stepping to the next page or the next chunk will
# change the answer, so they end the operation instead of being skipped.
_HANDLE_LEVEL_ERRORS = frozenset((_ERROR_ACCESS_DENIED, _ERROR_INVALID_HANDLE))

# How many consecutive failed VirtualQueryEx calls a region walk tolerates
# before concluding the handle or the target is the problem. A transient skip
# is one page, maybe a handful; a dead target or an unusable handle fails on
# every address, and without this ceiling the walk would step one page at a
# time across the whole user address space (~2^47 / 4 KiB calls).
_REGION_MAX_CONSECUTIVE_FAILURES = 64

# How many times a module snapshot is retried while it fails with
# ERROR_BAD_LENGTH (the target's module list changed mid-snapshot). The
# documentation says to retry until it succeeds; a ceiling keeps a target that
# loads DLLs in a tight loop from hanging the caller.
_SNAPSHOT_BAD_LENGTH_RETRIES = 16

# Pause between those retries. Back-to-back attempts land inside the same
# loader transition and fail alike; a few milliseconds lets it finish, and the
# worst case stays well under a tenth of a second.
_SNAPSHOT_BAD_LENGTH_DELAY = 0.005


# Message for OpenProcess failing with ERROR_ACCESS_DENIED. The library never
# enables SeDebugPrivilege on its own (that is a security decision for the
# caller), so the hint lists what the caller can change.
_OPEN_PROCESS_ACCESS_DENIED_HINT = (
    "OpenProcess failed for pid %d: access denied. The target likely runs "
    "elevated, as another user or as a service, or is a protected process "
    "(anti-cheat, antivirus, system). Run Python as Administrator; SYSTEM "
    "services may still refuse unless your code enables SeDebugPrivilege "
    "(PyMemoryEditor never does), and protected processes cannot be opened "
    "for memory access from user mode. Requesting fewer rights (e.g. "
    "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) helps when only write "
    "access is refused."
)


def _raise_last_error(api_name: str) -> None:
    """Raise an OSError populated with the current GetLastError() value."""
    code = ctypes.get_last_error()
    if code == 0:
        # Fall back to a generic message; some APIs do not set the error code.
        raise OSError("%s failed." % api_name)
    raise ctypes.WinError(code, "%s failed." % api_name)


def CloseProcessHandle(process_handle: int) -> int:
    """
    Close the process handle.
    """
    return kernel32.CloseHandle(process_handle)


def _process_has_exited(process_handle: int) -> Optional[bool]:
    """
    Return ``True`` if the process behind ``process_handle`` has terminated,
    ``False`` if it is still running, or ``None`` when the handle lacks the
    query right needed to tell.
    """
    exit_code = ctypes.wintypes.DWORD(0)
    ctypes.set_last_error(0)
    if not kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)):
        return None
    return exit_code.value != _STILL_ACTIVE


def _raise_region_walk_failure(
    process_handle: int, pid: int, err: int, address: int
) -> None:
    """
    Turn a region walk that cannot make progress into the right exception.

    A target that exited mid-walk is reported as
    :class:`~PyMemoryEditor.ProcessIDNotExistsError` (the contract every
    backend's ``get_memory_regions`` documents). ``ERROR_ACCESS_DENIED`` on a
    live target is the handle missing ``PROCESS_QUERY_INFORMATION`` — the
    right ``VirtualQueryEx`` needs — and is raised as ``PermissionError`` with
    that hint. Anything else surfaces as an ``OSError`` carrying the Win32 code.
    """
    if pid and _process_has_exited(process_handle):
        raise ProcessIDNotExistsError(pid)
    if err == _ERROR_ACCESS_DENIED:
        raise PermissionError(
            "VirtualQueryEx failed at 0x%X with ERROR_ACCESS_DENIED. The handle "
            "cannot enumerate memory regions: open the process with "
            "PROCESS_QUERY_INFORMATION (or PROCESS_ALL_ACCESS), or the target "
            "has exited." % address
        )
    raise ctypes.WinError(
        err, "VirtualQueryEx failed at 0x%X; the region walk could not make progress." % address
    )


def _region_may_have_mapped_file(region) -> bool:
    """
    Whether ``GetMappedFileNameW`` can name the file behind ``region``.

    Only a view of a section — ``MEM_IMAGE`` or ``MEM_MAPPED`` — has a backing
    file. A ``MEM_FREE`` range belongs to no allocation (its ``Type`` is
    undefined), and ``MEM_PRIVATE`` memory (heaps, stacks, ``VirtualAlloc``
    reservations, committed or reserved) is never file-backed, so the call is
    guaranteed to fail there. Those are most of a process's regions; skipping
    them saves one cross-process system call per region on every walk.
    """
    if region.State == MemoryAllocationStatesEnum.MEM_FREE:
        return False
    return region.Type != MemoryTypesEnum.MEM_PRIVATE


def _get_mapped_filename(process_handle: int, address: int) -> str:
    """Return the NT device path backing *address*, or ``""`` on failure.

    Wraps ``GetMappedFileNameW`` (psapi.dll). The result is an NT path like
    ``\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll`` — the same
    format Cheat Engine and other tools display. Converting to a DOS path
    (``C:\\...``) would require ``QueryDosDevice`` for each volume, which is
    costly and unnecessary for display purposes.
    """
    size = _MAPPED_FILENAME_BUF_SIZE
    while True:
        buf = ctypes.create_unicode_buffer(size)
        length = psapi.GetMappedFileNameW(process_handle, address, buf, size)
        if length == 0:
            return ""
        # A name that fills the buffer was truncated (the call returns the
        # truncated length, and on older Windows without a terminating NUL):
        # retry with a larger buffer instead of reporting a clipped path.
        if length < size - 1 or size >= _MAPPED_FILENAME_MAX_SIZE:
            # Slicing a c_wchar array gives a str at run time.
            return cast(str, buf[:min(length, size)]).split("\x00", 1)[0]
        size *= 2


def GetMemoryRegions(process_handle: int, pid: int = 0) -> Generator[MemoryRegion, None, None]:
    """
    Yield a :class:`MemoryRegion` for every region in the target's address space.

    ``VirtualQueryEx`` always fills the running Python's native
    MEMORY_BASIC_INFORMATION layout (see :func:`mbi_class_for_handle`), so a
    64-bit Python walks a 32-bit (WOW64) target with the same 48-byte struct
    it uses for a 64-bit one.

    ``VirtualQueryEx`` returning 0 does not end enumeration unconditionally,
    since that would silently truncate the region list whenever the kernel
    hiccups on a single region (DLL unloaded mid-walk, transient permission
    edge). ``GetLastError`` decides: only the natural end-of-space case ends
    the walk; any other failure is logged and the cursor bumped by one page so
    the walk keeps making progress.

    That skip is bounded: a handle-level error (``ERROR_ACCESS_DENIED``,
    ``ERROR_INVALID_HANDLE``) or more than ``_REGION_MAX_CONSECUTIVE_FAILURES``
    failures in a row end the walk with
    :class:`~PyMemoryEditor.ProcessIDNotExistsError` when ``pid`` is given and
    the target has exited, ``PermissionError`` when the handle lacks
    ``PROCESS_QUERY_INFORMATION``, or ``OSError`` otherwise — never an endless
    crawl across the address space.

    The walk bounds come from ``GetNativeSystemInfo`` rather than
    ``GetSystemInfo`` so that, from a 64-bit Python attached to a 32-bit target,
    the ceiling reflects the host's full address space. A 64-bit caller sees a
    32-bit target's *whole* address space, so above the 4 GB line the walk
    reports a large free range plus the 64-bit WOW64 runtime the system maps
    there (the 64-bit ``ntdll.dll``, ``wow64*.dll``, 64-bit PEB/TEBs) — real
    regions of that process, just never touched by its 32-bit code. (From a
    64-bit Python the two infos are identical for the address-range fields
    anyway.)

    Note this does *not* extend the walk for a 32-bit (WOW64) Python attached to
    a 64-bit target. ``lpMaximumApplicationAddress`` is ``c_void_p`` (4 bytes in
    a 32-bit interpreter), so it cannot hold a >4 GB ceiling regardless of which
    *SystemInfo call fills it; and ``VirtualQueryEx`` takes a pointer-width
    ``lpAddress``, so a WOW64 process cannot query the target's high memory at
    all. Enumerating a 64-bit target's address space above 4 GB therefore
    requires a 64-bit Python — an API limitation, not something this call fixes.
    """
    mbi_class = mbi_class_for_handle(process_handle)
    mem_region_begin = _native_system_information.lpMinimumApplicationAddress
    mem_region_end = _native_system_information.lpMaximumApplicationAddress
    page_size = _native_system_information.dwPageSize or 0x1000

    current_address = mem_region_begin
    consecutive_failures = 0

    while current_address < mem_region_end:
        region = mbi_class()
        ctypes.set_last_error(0)
        result = kernel32.VirtualQueryEx(
            process_handle,
            current_address,
            ctypes.byref(region),
            ctypes.sizeof(region),
        )

        if result == 0:
            err = ctypes.get_last_error()
            # ERROR_INVALID_PARAMETER (87) is what VirtualQueryEx returns once
            # we walk past lpMaximumApplicationAddress on some Windows builds —
            # the natural end. Anything else is a transient skip, not a
            # terminator: log and step one page forward.
            if err in (0, _ERROR_INVALID_PARAMETER):
                return
            consecutive_failures += 1
            if (
                err in _HANDLE_LEVEL_ERRORS
                or consecutive_failures > _REGION_MAX_CONSECUTIVE_FAILURES
            ):
                _raise_region_walk_failure(process_handle, pid, err, current_address)
            _logger.debug(
                "GetMemoryRegions: VirtualQueryEx skipped 0x%X (err=%d); "
                "advancing one page",
                current_address, err,
            )
            current_address += page_size
            continue

        consecutive_failures = 0

        yield make_region(
            address=current_address, size=region.RegionSize, struct=region,
            path=(
                _get_mapped_filename(process_handle, current_address)
                if _region_may_have_mapped_file(region)
                else ""
            ),
        )

        if region.RegionSize == 0:
            # Defensive: would otherwise spin forever. Bump one page and keep
            # going so a single weird region can't cap the enumeration either.
            current_address += page_size
            continue
        current_address += region.RegionSize


def GetProcessHandle(access_right: int, inherit: bool, pid: int) -> int:
    """
    Get a process ID and return its process handle.

    :param access_right: The access to the process object. This access right is
    checked against the security descriptor for the process. This parameter can
    be one or more of the process access rights.

    :param inherit: if this value is TRUE, processes created by this process
    will inherit the handle. Otherwise, the processes do not inherit this handle.

    :param pid: The identifier of the local process to be opened.
    """
    ctypes.set_last_error(0)
    handle = kernel32.OpenProcess(access_right, inherit, pid)

    if not handle:
        code = ctypes.get_last_error()
        if code == _ERROR_ACCESS_DENIED:
            # ctypes.WinError(5, ...) is a PermissionError carrying
            # winerror=5, exactly as before — only the message gains the
            # likely causes, since a bare "Access is denied" gives no lead.
            raise ctypes.WinError(code, _OPEN_PROCESS_ACCESS_DENIED_HINT % pid)
        _raise_last_error("OpenProcess")

    return handle


def ReadProcessMemory(
    process_handle: int, address: int, pytype: Type[T], bufflength: int
) -> T:
    """
    Return a value from a memory address.

    Raises OSError if the read fails.
    """
    _validate_pytype(pytype)

    data = get_c_type_of(pytype, bufflength)
    bytes_read = ctypes.c_size_t(0)

    ctypes.set_last_error(0)
    success = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        ctypes.byref(data),
        bufflength,
        ctypes.byref(bytes_read),
    )

    if not success:
        _raise_last_error("ReadProcessMemory")

    # ReadProcessMemory can return TRUE with bytes_read < bufflength when the
    # target range crosses a freed/guarded page; the populated buffer then
    # contains a mix of real bytes and zeros. Surface that as OSError instead
    # of letting the caller decode garbage — mirrors the partial-write check
    # in WriteProcessMemory below.
    if bytes_read.value != bufflength:
        raise OSError(
            "ReadProcessMemory partial read at 0x%X: %d of %d bytes read."
            % (address, bytes_read.value, bufflength)
        )

    if pytype is str:
        # Match convert_from_byte_array: tolerate non-UTF-8 bytes in raw memory
        # (callers needing the raw bytes should pass pytype=bytes).
        return cast(T, bytes(data).decode("utf-8", errors="replace"))
    elif pytype is bytes:
        return cast(T, bytes(data))
    else:
        # Narrow widths pad with zeroes, which reads a signed value as
        # unsigned -- and a scan for the same bytes is signed.
        sign_extend_narrow_int(data, pytype, bufflength)
        return data.value


def ReadProcessMemoryInto(process_handle: int, address: int, buffer) -> int:
    """
    Read ``len(buffer)`` bytes from ``address`` directly into the writable
    ``buffer``, with no intermediate allocation. Returns the number of bytes
    read.

    Raises OSError if the read fails or returns fewer bytes than requested
    (same partial-read guard as :func:`ReadProcessMemory`).
    """
    c_buffer = as_writable_c_buffer(buffer)
    size = len(c_buffer)
    bytes_read = ctypes.c_size_t(0)

    ctypes.set_last_error(0)
    success = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        ctypes.byref(c_buffer),
        size,
        ctypes.byref(bytes_read),
    )

    if not success:
        _raise_last_error("ReadProcessMemory")

    if bytes_read.value != size:
        raise OSError(
            "ReadProcessMemory partial read at 0x%X: %d of %d bytes read."
            % (address, bytes_read.value, size)
        )

    return bytes_read.value


class _Win32FatalReadError(OSError):
    """
    ``ReadProcessMemory`` failed for a reason no scan may skip past: the
    handle lacks ``PROCESS_VM_READ`` / is invalid, or the target has exited.

    Distinct from :class:`_Win32ChunkReadError` (a page that vanished
    mid-scan, which the scan loops are allowed to walk past): the value and
    pattern scans re-raise it instead of skipping the chunk, and
    ``search_by_addresses`` treats it like every other non-transient error --
    raised with ``raise_error=True``, logged and reported as ``None`` values
    otherwise, exactly as on Linux and macOS.
    """

    def __init__(self, address: int, size: int, code: int, reason: str):
        super().__init__(
            "ReadProcessMemory failed at 0x%X (%d bytes): %s (error %d)."
            % (address, size, reason, code)
        )
        self.code = code


def _read_region(process_handle: int, address: int, size: int):
    """
    Read a memory region for the chunked scan loops.

    Returns the byte buffer, or ``None`` when the failure is one the scan may
    skip (``ERROR_PARTIAL_COPY`` / ``ERROR_NOACCESS`` for a page unmapped or
    re-protected mid-scan, a short read). Raises
    :class:`_Win32FatalReadError` when the failure describes the handle or the
    target instead of the page — ``ERROR_ACCESS_DENIED``,
    ``ERROR_INVALID_HANDLE``, or a target that has exited — because skipping
    every chunk there would turn a real error into a scan that silently finds
    nothing (the Linux and macOS backends propagate those too).
    """
    region_data = (ctypes.c_byte * size)()
    bytes_read = ctypes.c_size_t(0)

    ctypes.set_last_error(0)
    success = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        ctypes.byref(region_data),
        size,
        ctypes.byref(bytes_read),
    )
    if not success:
        err = ctypes.get_last_error()
        if err in _HANDLE_LEVEL_ERRORS:
            raise _Win32FatalReadError(
                address, size, err,
                "the handle cannot read the process memory (open it with "
                "PROCESS_VM_READ or PROCESS_ALL_ACCESS)"
                if err == _ERROR_ACCESS_DENIED
                else "the process handle is invalid",
            )
        if _process_has_exited(process_handle):
            raise _Win32FatalReadError(address, size, err, "the target process has exited")
        return None
    if bytes_read.value != size:
        # A short read leaves the tail of the buffer zero-filled, and the scan
        # kernels search the whole requested size: an exact scan for 0 would
        # "match" bytes that were never read. Skip the chunk, as the Linux and
        # macOS backends do with a partial read.
        _logger.debug(
            "_read_region: partial read at 0x%X: %d of %d bytes; chunk skipped",
            address, bytes_read.value, size,
        )
        return None
    return region_data


def SearchAddressesByValue(
    process_handle: int,
    pytype: Type[T],
    bufflength: int,
    value: Optional[Union[bool, int, float, str, bytes, tuple]],
    scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
    progress_information: bool = False,
    writeable_only: bool = False,
    *,
    memory_regions: Optional[Sequence[MemoryRegion]] = None,
    pid: int = 0,
    aligned: bool = True,
    target_value_bytes: Optional[Union[bytes, Tuple[bytes, ...]]] = None,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    Search the whole memory space, accessible to the process,
    for the provided value, returning the found addresses.

    Passing a `memory_regions` snapshot (see `snapshot_memory_regions()`) skips
    the per-call region enumeration — useful in refine-scan workflows. ``pid``
    only feeds the error reported when that enumeration finds the target gone.
    ``target_value_bytes`` is ``value`` already encoded (see
    :func:`~PyMemoryEditor.util.prepare_search_target`); when it is given,
    ``value`` is not used and may be ``None``.
    """
    _validate_pytype(pytype)

    if target_value_bytes is None:
        target_value_bytes = values_to_bytes(pytype, bufflength, value)

    source_regions = (
        memory_regions
        if memory_regions is not None
        else GetMemoryRegions(process_handle, pid)
    )
    filtered_regions = [
        region
        for region in source_regions
        if default_scan_filter(region, writeable_only=writeable_only)
    ]
    filtered_regions.sort(key=lambda region: region.address)

    def read_chunk(address: int, size: int):
        # `_read_region` returns None on transient failures (page unmapped /
        # made inaccessible mid-scan) and raises `_Win32FatalReadError` for
        # handle-level ones. The helper accepts None directly and skips the
        # chunk; with no transient classifier the exception propagates.
        return _read_region(process_handle, address, size)

    yield from iter_search_results(
        filtered_regions,
        pytype,
        bufflength,
        target_value_bytes,
        scan_type,
        read_chunk,
        progress_information=progress_information,
        aligned=aligned,
    )


def SearchAddressesByPattern(
    process_handle: int,
    pattern: PatternLike,
    *,
    byte_length: int = 0,
    progress_information: bool = False,
    memory_regions: Optional[Sequence[MemoryRegion]] = None,
    compiled_pattern: Optional[Tuple[Pattern[bytes], int]] = None,
    pid: int = 0,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    AOB scan against every readable, non-shared region of the target process.
    See :meth:`AbstractProcess.search_by_pattern`.
    """
    compiled, length = (
        compiled_pattern
        if compiled_pattern is not None
        else compile_pattern(pattern, byte_length=byte_length)
    )

    source_regions = (
        memory_regions
        if memory_regions is not None
        else GetMemoryRegions(process_handle, pid)
    )
    filtered_regions = [
        region for region in source_regions if default_scan_filter(region)
    ]
    filtered_regions.sort(key=lambda region: region.address)

    def read_chunk(address: int, size: int):
        # ``_read_region`` returns None on transient failures (page unmapped /
        # made inaccessible mid-scan) and raises ``_Win32FatalReadError`` for
        # handle-level ones; the helper accepts None directly and skips the
        # chunk, and with no transient classifier the exception propagates.
        return _read_region(process_handle, address, size)

    yield from iter_pattern_results(
        filtered_regions,
        compiled,
        length,
        read_chunk,
        progress_information=progress_information,
    )


class _Win32ChunkReadError(OSError):
    """Raised internally when ReadProcessMemory returns 0 during chunked reads."""


def SearchValuesByAddresses(
    process_handle: int,
    pytype: Type[T],
    bufflength: int,
    addresses: Sequence[int],
    *,
    memory_regions: Optional[Sequence[MemoryRegion]] = None,
    raise_error: bool = False,
    pid: int = 0,
) -> Generator[Tuple[int, Optional[T]], None, None]:
    """
    Search the whole memory space, accessible to the process,
    for the provided list of addresses, returning their values.

    Reads memory in chunks (see iter_region_chunks) to avoid allocating
    multi-GB regions at once. Chunks reading addresses near a boundary include
    `bufflength - 1` extra bytes so the value is fully covered. Addresses that
    fall in gaps between regions or extend past a region's end yield
    `(address, None)`.
    """
    _validate_pytype(pytype)

    # `None` means "no snapshot provided, enumerate now". An empty list passed
    # explicitly is honored verbatim — scanning nothing is a valid choice when
    # the caller pre-filtered to zero regions.
    if memory_regions is None:
        memory_regions = [
            region
            for region in GetMemoryRegions(process_handle, pid)
            # An address-list read has the caller already deciding *where* —
            # the library has no business filtering by region "interestingness"
            # (that would exclude MEM_MAPPED and diverge from Linux/macOS).
            # All three backends agree: just readable.
            if default_address_filter(region)
        ]
    elif not isinstance(memory_regions, MemoryRegionSnapshot):
        # Materialize one-shot iterables (the walk indexes and measures the
        # list). A MemoryRegionSnapshot is passed through untouched: copying it
        # into a plain list would drop the "already sorted" tag and make
        # ``iter_values_for_addresses`` re-sort it on every refine pass.
        memory_regions = list(memory_regions)

    def read_chunk(address: int, size: int):
        buffer = _read_region(process_handle, address, size)
        if buffer is None:
            raise _Win32ChunkReadError(
                "ReadProcessMemory failed at 0x%X (%d bytes)" % (address, size)
            )
        return buffer

    # ReadProcessMemory returning 0 during scanning typically means the page
    # was unmapped / made inaccessible mid-scan — transient. The user can still
    # force propagation via raise_error=True. `_Win32FatalReadError` (handle
    # lacks PROCESS_VM_READ, target exited) is deliberately *not* transient,
    # so `raise_error=True` surfaces it; with the default `raise_error=False`
    # it is logged and the chunk's addresses read as None, as on Linux/macOS.
    def is_transient(exc: BaseException) -> bool:
        return isinstance(exc, _Win32ChunkReadError)

    yield from iter_values_for_addresses(
        addresses,
        memory_regions,
        pytype,
        bufflength,
        read_chunk,
        raise_error=raise_error,
        transient_error_check=is_transient,
    )


def GetThreads(pid: int) -> Generator[ThreadInfo, None, None]:
    """
    Yield a :class:`ThreadInfo` for every thread of the target process.

    Uses ``CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`` followed by
    Thread32First/Next; this is the documented user-mode way to enumerate
    threads on Windows without an extra dependency. Caller does not need a
    process handle (and therefore no PROCESS_* permission) — the snapshot is
    system-wide and we filter by ``th32OwnerProcessID``.
    """
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    # Per the docs the function returns INVALID_HANDLE_VALUE (-1 cast to HANDLE)
    # on failure; in ctypes that comes back as a falsy value once we read it.
    if not snapshot or snapshot == ctypes.wintypes.HANDLE(-1).value:
        _raise_last_error("CreateToolhelp32Snapshot")

    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(entry)

    try:
        if not kernel32.Thread32First(snapshot, ctypes.byref(entry)):
            # Empty snapshot is legal (no threads visible). Log and bail.
            _logger.debug(
                "GetThreads: Thread32First returned 0 (snapshot empty for pid=%d)",
                pid,
            )
            return

        while True:
            if entry.th32OwnerProcessID == pid:
                yield ThreadInfo(
                    tid=entry.th32ThreadID,
                    start_address=None,
                    state=None,
                    priority=int(entry.tpBasePri),
                    raw=entry.th32ThreadID,
                )
            # THREADENTRY32 is reused across iterations — reset dwSize each
            # time per Microsoft's sample code.
            entry.dwSize = ctypes.sizeof(entry)
            if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)


def GetModules(
    pid: int, *, process_handle: Optional[int] = None
) -> Generator[ModuleInfo, None, None]:
    """
    Yield a :class:`ModuleInfo` for every module loaded in the target process.

    Uses ``CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)``
    followed by Module32FirstW/NextW — the documented user-mode way to enumerate
    modules without an extra dependency. Unlike the thread snapshot, the module
    snapshot is per-process, so the pid is passed through and honored.
    ``TH32CS_SNAPMODULE32`` is OR-ed in so a 64-bit Python can still see the
    32-bit modules of a WOW64 target.

    Module enumeration needs no ``PROCESS_*`` right on the handle — the caller
    only supplies the pid here. ``process_handle``, when given, is used only to
    tell a target that has exited (the snapshot fails or comes back empty)
    apart from a live one: that case raises
    :class:`~PyMemoryEditor.ProcessIDNotExistsError`, the contract
    ``AbstractProcess.get_modules`` documents. Without it, a pid probe answers
    the same question for a target that is gone entirely.

    The module snapshot fails with ``ERROR_BAD_LENGTH`` while the target's
    loader is changing its module list (a DLL loading or unloading); per the
    documentation the call is retried, a bounded number of times.
    """
    for _attempt in range(_SNAPSHOT_BAD_LENGTH_RETRIES):
        ctypes.set_last_error(0)
        snapshot = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
        )
        # CreateToolhelp32Snapshot returns INVALID_HANDLE_VALUE (-1 cast to
        # HANDLE) on failure — same check the thread snapshot uses.
        if snapshot and snapshot != ctypes.wintypes.HANDLE(-1).value:
            break
        if ctypes.get_last_error() != _ERROR_BAD_LENGTH:
            break
        if _attempt + 1 < _SNAPSHOT_BAD_LENGTH_RETRIES:
            time.sleep(_SNAPSHOT_BAD_LENGTH_DELAY)
    else:
        snapshot = None

    if not snapshot or snapshot == ctypes.wintypes.HANDLE(-1).value:
        code = ctypes.get_last_error()
        if _target_is_gone(pid, process_handle):
            raise ProcessIDNotExistsError(pid)
        ctypes.set_last_error(code)
        _raise_last_error("CreateToolhelp32Snapshot")

    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)

    try:
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
            # An empty snapshot of a live target is legal (not yet
            # initialized); of an exited one it is the documented error.
            if _target_is_gone(pid, process_handle):
                raise ProcessIDNotExistsError(pid)
            _logger.debug(
                "GetModules: Module32FirstW returned 0 (snapshot empty for pid=%d)",
                pid,
            )
            return

        while True:
            # szModule / szExePath are c_wchar arrays — accessing them returns
            # the NUL-terminated str directly. Toolhelp itself fills module
            # entries from the loader's ANSI module list, though, so characters
            # outside the system code page arrive here as "?" (process names,
            # from the kernel's Unicode list, are exact).
            name = entry.szModule
            path = entry.szExePath
            yield ModuleInfo(
                name=name,
                path=path or name,
                base_address=int(entry.modBaseAddr or 0),
                size=int(entry.modBaseSize),
                raw=int(entry.hModule or 0),
            )
            if not kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)


def _target_is_gone(pid: int, process_handle: Optional[int]) -> bool:
    """
    Whether the target has exited, for the Toolhelp walks. An open handle
    keeps the pid reserved after the process exits, so it is asked directly
    (``GetExitCodeProcess``); without one — or when it lacks the query right —
    the pid probe answers.
    """
    if process_handle:
        exited = _process_has_exited(process_handle)
        if exited is not None:
            return exited
    return not ProcessExists(pid)


def GetProcesses() -> Generator[Tuple[int, str], None, None]:
    """
    Yield ``(pid, name)`` for every process in the system.

    Uses ``CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`` followed by
    Process32FirstW/NextW — the documented user-mode way to enumerate processes
    without an extra dependency, mirroring how GetThreads/GetModules already
    work. ``szExeFile`` is the executable name only (no path).
    """
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == ctypes.wintypes.HANDLE(-1).value:
        _raise_last_error("CreateToolhelp32Snapshot")

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)

    try:
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            # Empty snapshot is theoretically possible; log and bail.
            _logger.debug("GetProcesses: Process32FirstW returned 0 (empty snapshot)")
            return

        while True:
            # c_wchar array: already a str, exactly as Windows stores it.
            yield int(entry.th32ProcessID), entry.szExeFile
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)


# Minimal right that lets OpenProcess succeed for a probe; available on every
# supported Windows version.
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def ProcessExists(pid: int) -> bool:
    """
    Return whether a process with ``pid`` currently exists.

    O(1) probe via ``OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)``: a handle
    means it exists; ``ERROR_ACCESS_DENIED`` means it exists but is protected
    (still True); any other failure (notably ``ERROR_INVALID_PARAMETER`` for an
    unknown pid) means it does not.
    """
    if pid < 0:
        return False

    ctypes.set_last_error(0)
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        kernel32.CloseHandle(handle)
        return True

    return ctypes.get_last_error() == _ERROR_ACCESS_DENIED


def AllocateMemory(process_handle: int, size: int, permission=None) -> int:
    """
    Commit ``size`` bytes in the target process via VirtualAllocEx and return
    the base address. Raises OSError if the allocation fails.

    :param permission: PAGE_* protection (``MemoryProtectionsEnum`` or int).
        Defaults to PAGE_EXECUTE_READWRITE.
    """
    if size <= 0:
        raise ValueError("size must be a positive number of bytes.")

    protect = _DEFAULT_ALLOC_PROTECT if permission is None else int(permission)

    ctypes.set_last_error(0)
    address = kernel32.VirtualAllocEx(
        process_handle, None, size, _MEM_COMMIT_RESERVE, protect
    )
    if not address:
        _raise_last_error("VirtualAllocEx")
    return int(address)


def FreeMemory(process_handle: int, address: int, size: int = 0) -> bool:
    """
    Release a region previously returned by :func:`AllocateMemory` via
    VirtualFreeEx with MEM_RELEASE. Raises OSError if the free fails.

    ``size`` is ignored — MEM_RELEASE requires it to be 0 and frees the whole
    allocation — but is accepted for a uniform cross-platform signature.
    """
    ctypes.set_last_error(0)
    ok = kernel32.VirtualFreeEx(
        process_handle, ctypes.c_void_p(address), 0, _MEM_RELEASE
    )
    if not ok:
        _raise_last_error("VirtualFreeEx")
    return True


def WriteProcessMemory(
    process_handle: int,
    address: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes],
) -> Union[bool, int, float, str, bytes]:
    """
    Write a value to a memory address.

    Raises OSError if the write fails.
    """
    _validate_pytype(pytype)

    data = get_c_type_of(pytype, bufflength)
    data.value = value.encode() if isinstance(value, str) else value

    bytes_written = ctypes.c_size_t(0)

    ctypes.set_last_error(0)
    success = kernel32.WriteProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        ctypes.byref(data),
        bufflength,
        ctypes.byref(bytes_written),
    )

    if not success:
        _raise_last_error("WriteProcessMemory")

    # WriteProcessMemory can return TRUE even when fewer than `bufflength` bytes
    # made it across (e.g. the target range straddles a freed/guarded page).
    # Surface that as OSError rather than silently lying about the write.
    if bytes_written.value != bufflength:
        raise OSError(
            "WriteProcessMemory partial write at 0x%X: %d of %d bytes written."
            % (address, bytes_written.value, bufflength)
        )

    return value
