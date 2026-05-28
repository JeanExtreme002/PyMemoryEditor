# -*- coding: utf-8 -*-

# Read more about operations with processes by win32 api here:
# https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
# https://learn.microsoft.com/en-us/windows/win32/api/psapi/
# ...

import ctypes
import ctypes.wintypes
import logging
from typing import Generator, Optional, Sequence, Tuple, Type, TypeVar, Union

from ..enums import ScanTypesEnum
from ..process.module_info import ModuleInfo
from ..process.region import (
    MemoryRegion,
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
    get_c_type_of,
    values_to_bytes,
)
from ..util.pattern import PatternLike, compile_pattern

from .enums import MemoryAllocationStatesEnum, MemoryProtectionsEnum
from .types import (
    MEMORY_BASIC_INFORMATION,
    MEMORY_BASIC_INFORMATION_32,
    MEMORY_BASIC_INFORMATION_64,
    MODULEENTRY32,
    SYSTEM_INFO,
    TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
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
    # The output struct varies between 32-bit and 64-bit layouts; declare the
    # buffer as a raw void pointer and rely on the caller passing a correctly
    # sized struct (see mbi_class_for_handle).
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCVOID,
    ctypes.c_void_p,
    ctypes.c_size_t,
)
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.GetSystemInfo.argtypes = (ctypes.POINTER(SYSTEM_INFO),)
kernel32.GetSystemInfo.restype = None

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

kernel32.Module32First.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(MODULEENTRY32),
)
kernel32.Module32First.restype = ctypes.wintypes.BOOL

kernel32.Module32Next.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(MODULEENTRY32),
)
kernel32.Module32Next.restype = ctypes.wintypes.BOOL

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


system_information = SYSTEM_INFO()
kernel32.GetSystemInfo(ctypes.byref(system_information))


# True when the running Python is a 64-bit build (and therefore the host OS is
# at least 64-bit too).
_HOST_IS_64BIT = ctypes.sizeof(ctypes.c_void_p) == 8


def mbi_class_for_handle(process_handle: int):
    """
    Return the appropriate MEMORY_BASIC_INFORMATION layout for the target process.

    On a 64-bit host attached to a 32-bit target (a "WOW64" process), the
    Windows kernel still returns a 32-bit layout via VirtualQueryEx — using the
    64-bit struct corrupts the fields. IsWow64Process tells us which one to use.
    """
    if not _HOST_IS_64BIT:
        return MEMORY_BASIC_INFORMATION_32

    is_wow64 = ctypes.wintypes.BOOL(0)
    ok = kernel32.IsWow64Process(process_handle, ctypes.byref(is_wow64))
    if not ok:
        # Conservatively fall back to the host-bitness default rather than fail
        # — the caller may not need region info at all.
        return MEMORY_BASIC_INFORMATION

    return (
        MEMORY_BASIC_INFORMATION_32 if is_wow64.value else MEMORY_BASIC_INFORMATION_64
    )


T = TypeVar("T")


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


def GetMemoryRegions(process_handle: int) -> Generator[MemoryRegion, None, None]:
    """
    Yield a :class:`MemoryRegion` for every region in the target's address space.

    Picks the right MEMORY_BASIC_INFORMATION layout (32-bit vs 64-bit) for the
    target process to handle the WOW64 case (64-bit Python attached to a 32-bit
    target). VirtualQueryEx is dispatched against `mbi_class` accordingly.

    ``VirtualQueryEx`` returning 0 used to terminate enumeration unconditionally,
    silently truncating the region list whenever the kernel hiccuped on a
    single region (DLL unloaded mid-walk, transient permission edge). Now we
    consult ``GetLastError``: only fall through for the natural end-of-space
    case; for any other failure log it and bump the cursor by one page so the
    walk keeps making progress.
    """
    mbi_class = mbi_class_for_handle(process_handle)
    mem_region_begin = system_information.lpMinimumApplicationAddress
    mem_region_end = system_information.lpMaximumApplicationAddress
    page_size = system_information.dwPageSize or 0x1000

    current_address = mem_region_begin

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
            if err in (0, 87):
                return
            _logger.debug(
                "GetMemoryRegions: VirtualQueryEx skipped 0x%X (err=%d); "
                "advancing one page",
                current_address, err,
            )
            current_address += page_size
            continue

        yield make_region(
            address=current_address, size=region.RegionSize, struct=region,
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
        return bytes(data).decode("utf-8", errors="replace")
    elif pytype is bytes:
        return bytes(data)
    else:
        return data.value


def _read_region(process_handle: int, address: int, size: int):
    """Read a memory region; returns the byte buffer or None on failure."""
    region_data = (ctypes.c_byte * size)()
    bytes_read = ctypes.c_size_t(0)

    success = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        ctypes.byref(region_data),
        size,
        ctypes.byref(bytes_read),
    )
    if not success or bytes_read.value == 0:
        return None
    return region_data


def SearchAddressesByValue(
    process_handle: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes, tuple],
    scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
    progress_information: bool = False,
    writeable_only: bool = False,
    *,
    memory_regions: Optional[Sequence[MemoryRegion]] = None,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    Search the whole memory space, accessible to the process,
    for the provided value, returning the found addresses.

    Passing a `memory_regions` snapshot (see `snapshot_memory_regions()`) skips
    the per-call region enumeration — useful in refine-scan workflows.
    """
    _validate_pytype(pytype)

    target_value_bytes = values_to_bytes(pytype, bufflength, value)

    source_regions = (
        memory_regions
        if memory_regions is not None
        else GetMemoryRegions(process_handle)
    )
    filtered_regions = [
        region
        for region in source_regions
        if default_scan_filter(region, writeable_only=writeable_only)
    ]
    filtered_regions.sort(key=lambda region: region.address)

    def read_chunk(address: int, size: int):
        # `_read_region` returns None on transient failures (page unmapped /
        # made inaccessible mid-scan). The helper accepts None directly and
        # skips the chunk — no exception classification needed here.
        return _read_region(process_handle, address, size)

    yield from iter_search_results(
        filtered_regions,
        pytype,
        bufflength,
        target_value_bytes,
        scan_type,
        read_chunk,
        progress_information=progress_information,
    )


def SearchAddressesByPattern(
    process_handle: int,
    pattern: PatternLike,
    *,
    byte_length: int = 0,
    progress_information: bool = False,
    memory_regions: Optional[Sequence[MemoryRegion]] = None,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    AOB scan against every scannable region of the target process. See
    :meth:`AbstractProcess.search_by_pattern`.
    """
    compiled, length = compile_pattern(pattern, byte_length=byte_length)

    source_regions = (
        memory_regions
        if memory_regions is not None
        else GetMemoryRegions(process_handle)
    )
    filtered_regions = [
        region for region in source_regions if default_scan_filter(region)
    ]
    filtered_regions.sort(key=lambda region: region.address)

    def read_chunk(address: int, size: int):
        # ``_read_region`` returns None on transient failures (page unmapped /
        # made inaccessible mid-scan); the helper accepts None directly and
        # skips the chunk — no exception classification needed here.
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
            for region in GetMemoryRegions(process_handle)
            # An address-list read has the caller already deciding *where* —
            # the library has no business filtering by region "interestingness"
            # (which used to exclude MEM_MAPPED here and diverge from
            # Linux/macOS). All three backends now agree: just readable.
            if default_address_filter(region)
        ]
    else:
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
    # force propagation via raise_error=True.
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


def GetModules(pid: int) -> Generator[ModuleInfo, None, None]:
    """
    Yield a :class:`ModuleInfo` for every module loaded in the target process.

    Uses ``CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)``
    followed by Module32First/Next — the documented user-mode way to enumerate
    modules without an extra dependency. Unlike the thread snapshot, the module
    snapshot is per-process, so the pid is passed through and honored.
    ``TH32CS_SNAPMODULE32`` is OR-ed in so a 64-bit Python can still see the
    32-bit modules of a WOW64 target.

    Module enumeration needs no ``PROCESS_*`` right on the handle — the caller
    only supplies the pid here.
    """
    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
    )
    # CreateToolhelp32Snapshot returns INVALID_HANDLE_VALUE (-1 cast to HANDLE)
    # on failure — same check the thread snapshot uses.
    if not snapshot or snapshot == ctypes.wintypes.HANDLE(-1).value:
        _raise_last_error("CreateToolhelp32Snapshot")

    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(entry)

    try:
        if not kernel32.Module32First(snapshot, ctypes.byref(entry)):
            # Empty snapshot is legal (target exited / not yet initialized).
            _logger.debug(
                "GetModules: Module32First returned 0 (snapshot empty for pid=%d)",
                pid,
            )
            return

        while True:
            # szModule / szExePath are c_char arrays — accessing them returns
            # the NUL-terminated bytes directly.
            name = entry.szModule.decode("utf-8", errors="replace")
            path = entry.szExePath.decode("utf-8", errors="replace")
            yield ModuleInfo(
                name=name,
                path=path or name,
                base_address=int(entry.modBaseAddr or 0),
                size=int(entry.modBaseSize),
                raw=int(entry.hModule or 0),
            )
            if not kernel32.Module32Next(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)


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
