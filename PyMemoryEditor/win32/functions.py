# -*- coding: utf-8 -*-

# Read more about operations with processes by win32 api here:
# https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
# https://learn.microsoft.com/en-us/windows/win32/api/psapi/
# ...

import ctypes
import ctypes.wintypes
from typing import Dict, Generator, Optional, Sequence, Tuple, Type, TypeVar, Union

from ..enums import ScanTypesEnum
from ..process.region import enrich_region
from ..process.scanning import iter_search_results, iter_values_for_addresses
from ..util import (
    _validate_pytype,
    get_c_type_of,
    values_to_bytes,
)

from .enums import MemoryAllocationStatesEnum, MemoryProtectionsEnum, MemoryTypesEnum
from .types import (
    MEMORY_BASIC_INFORMATION,
    MEMORY_BASIC_INFORMATION_32,
    MEMORY_BASIC_INFORMATION_64,
    SYSTEM_INFO,
)


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


def GetMemoryRegions(process_handle: int) -> Generator[dict, None, None]:
    """
    Generates dictionaries with the address and size of a region used by the process.

    Picks the right MEMORY_BASIC_INFORMATION layout (32-bit vs 64-bit) for the
    target process to handle the WOW64 case (64-bit Python attached to a 32-bit
    target). VirtualQueryEx is dispatched against `mbi_class` accordingly.
    """
    mbi_class = mbi_class_for_handle(process_handle)
    mem_region_begin = system_information.lpMinimumApplicationAddress
    mem_region_end = system_information.lpMaximumApplicationAddress

    current_address = mem_region_begin

    while current_address < mem_region_end:
        region = mbi_class()
        result = kernel32.VirtualQueryEx(
            process_handle,
            current_address,
            ctypes.byref(region),
            ctypes.sizeof(region),
        )

        if result == 0:
            break

        yield enrich_region(
            {"address": current_address, "size": region.RegionSize, "struct": region}
        )

        if region.RegionSize == 0:
            break
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


def _is_region_scannable(region, writeable_only: bool) -> bool:
    """Check whether a memory region should be scanned (private or image, committed, readable)."""
    info = region["struct"]
    if info.State != MemoryAllocationStatesEnum.MEM_COMMIT.value:
        return False
    if info.Type not in (
        MemoryTypesEnum.MEM_PRIVATE.value,
        MemoryTypesEnum.MEM_IMAGE.value,
    ):
        return False
    if info.Protect & MemoryProtectionsEnum.PAGE_READABLE.value == 0:
        return False
    if (
        writeable_only
        and info.Protect & MemoryProtectionsEnum.PAGE_READWRITEABLE.value == 0
    ):
        return False
    return True


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
    memory_regions: Optional[Sequence[Dict]] = None,
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
        if _is_region_scannable(region, writeable_only)
    ]
    filtered_regions.sort(key=lambda region: region["address"])

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


class _Win32ChunkReadError(OSError):
    """Raised internally when ReadProcessMemory returns 0 during chunked reads."""


def SearchValuesByAddresses(
    process_handle: int,
    pytype: Type[T],
    bufflength: int,
    addresses: Sequence[int],
    *,
    memory_regions: Optional[Sequence[Dict]] = None,
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
            # Accept both private and image (loaded DLLs) regions, matching
            # SearchAddressesByValue. Previously this filter was stricter and
            # caused addresses found via search_by_value to fail here.
            if _is_region_scannable(region, writeable_only=False)
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
