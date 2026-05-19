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
from ..util import (
    convert_from_byte_array,
    get_c_type_of,
    iter_region_chunks,
    scan_memory,
    scan_memory_for_exact_value,
    values_to_bytes,
)

from .enums import MemoryAllocationStatesEnum, MemoryProtectionsEnum, MemoryTypesEnum
from .types import (
    MEMORY_BASIC_INFORMATION,
    MEMORY_BASIC_INFORMATION_32,
    MEMORY_BASIC_INFORMATION_64,
    SYSTEM_INFO,
    WNDENUMPROC,
)


# Load the libraries.
kernel32 = ctypes.windll.LoadLibrary("kernel32.dll")
user32 = ctypes.windll.LoadLibrary("user32.dll")

# Configure argtypes/restype for each Windows API used.
# Skipping argtypes silently truncates 64-bit handles to 32-bit on x64 Python builds
# and lets Python misinterpret return values, hiding errors.

kernel32.OpenProcess.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE

kernel32.CloseHandle.argtypes = (ctypes.wintypes.HANDLE,)
kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = (
    ctypes.wintypes.HANDLE, ctypes.wintypes.LPCVOID, ctypes.wintypes.LPVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
)
kernel32.ReadProcessMemory.restype = ctypes.wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = (
    ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.wintypes.LPCVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
)
kernel32.WriteProcessMemory.restype = ctypes.wintypes.BOOL

kernel32.VirtualQueryEx.argtypes = (
    # The output struct varies between 32-bit and 64-bit layouts; declare the
    # buffer as a raw void pointer and rely on the caller passing a correctly
    # sized struct (see mbi_class_for_handle).
    ctypes.wintypes.HANDLE, ctypes.wintypes.LPCVOID,
    ctypes.c_void_p, ctypes.c_size_t,
)
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.GetSystemInfo.argtypes = (ctypes.POINTER(SYSTEM_INFO),)
kernel32.GetSystemInfo.restype = None

user32.EnumWindows.argtypes = (WNDENUMPROC, ctypes.wintypes.LPARAM)
user32.EnumWindows.restype = ctypes.wintypes.BOOL

user32.GetWindowTextW.argtypes = (ctypes.wintypes.HWND, ctypes.wintypes.LPWSTR, ctypes.c_int)
user32.GetWindowTextW.restype = ctypes.c_int

user32.GetWindowThreadProcessId.argtypes = (ctypes.wintypes.HWND, ctypes.POINTER(ctypes.wintypes.DWORD))
user32.GetWindowThreadProcessId.restype = ctypes.wintypes.DWORD

# BOOL IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);
# True when the target is a 32-bit process running on 64-bit Windows.
kernel32.IsWow64Process.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.BOOL))
kernel32.IsWow64Process.restype = ctypes.wintypes.BOOL


# Get the user's system information.
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

    return MEMORY_BASIC_INFORMATION_32 if is_wow64.value else MEMORY_BASIC_INFORMATION_64


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
            process_handle, current_address, ctypes.byref(region), ctypes.sizeof(region),
        )

        if result == 0:
            break

        yield {"address": current_address, "size": region.RegionSize, "struct": region}

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


def GetProcessIdByWindowTitle(window_title: str) -> int:
    """
    Return the process ID by querying a window title.
    """
    result = ctypes.wintypes.DWORD(0)

    string_buffer_size = len(window_title) + 2  # (+2) for the next possible character of a title and the NULL char.
    string_buffer = ctypes.create_unicode_buffer(string_buffer_size)

    def callback(hwnd, _lparam):
        user32.GetWindowTextW(hwnd, string_buffer, string_buffer_size)

        if window_title == string_buffer.value:
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(result))
            return False

        return True

    user32.EnumWindows(WNDENUMPROC(callback), 0)

    return result.value


def ReadProcessMemory(
    process_handle: int,
    address: int,
    pytype: Type[T],
    bufflength: int
) -> T:
    """
    Return a value from a memory address.

    Raises OSError if the read fails.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    data = get_c_type_of(pytype, bufflength)
    bytes_read = ctypes.c_size_t(0)

    ctypes.set_last_error(0)
    success = kernel32.ReadProcessMemory(
        process_handle, ctypes.c_void_p(address), ctypes.byref(data),
        bufflength, ctypes.byref(bytes_read),
    )

    if not success:
        _raise_last_error("ReadProcessMemory")

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
    if info.Type not in (MemoryTypesEnum.MEM_PRIVATE.value, MemoryTypesEnum.MEM_IMAGE.value):
        return False
    if info.Protect & MemoryProtectionsEnum.PAGE_READABLE.value == 0:
        return False
    if writeable_only and info.Protect & MemoryProtectionsEnum.PAGE_READWRITEABLE.value == 0:
        return False
    return True


def _read_region(process_handle: int, address: int, size: int):
    """Read a memory region; returns the byte buffer or None on failure."""
    region_data = (ctypes.c_byte * size)()
    bytes_read = ctypes.c_size_t(0)

    success = kernel32.ReadProcessMemory(
        process_handle, ctypes.c_void_p(address), ctypes.byref(region_data),
        size, ctypes.byref(bytes_read),
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
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    # Convert the target value (or tuple of values) to the corresponding bytes.
    target_value_bytes = values_to_bytes(pytype, bufflength, value)

    # Enumerate regions only when a snapshot wasn't provided.
    checked_memory_size = 0
    memory_total = 0
    filtered_regions = []

    source_regions = memory_regions if memory_regions is not None else GetMemoryRegions(process_handle)
    for region in source_regions:
        if not _is_region_scannable(region, writeable_only):
            continue
        memory_total += region["size"]
        filtered_regions.append(region)

    memory_regions = filtered_regions
    memory_regions.sort(key=lambda region: region["address"])

    # Avoid division by zero when no regions matched.
    if memory_total == 0:
        return

    searching_method = scan_memory
    if scan_type in [ScanTypesEnum.EXACT_VALUE, ScanTypesEnum.NOT_EXACT_VALUE]:
        searching_method = scan_memory_for_exact_value

    for region in memory_regions:
        address, size = region["address"], region["size"]

        for chunk_offset, chunk_size in iter_region_chunks(size, bufflength):
            chunk_address = address + chunk_offset
            chunk_data = _read_region(process_handle, chunk_address, chunk_size)
            if chunk_data is None:
                continue

            for offset in searching_method(chunk_data, chunk_size, target_value_bytes, bufflength, scan_type, pytype is str):
                found_address = chunk_address + offset

                if progress_information:
                    yield (found_address, {
                        "memory_total": memory_total,
                        "progress": (checked_memory_size + chunk_offset + offset) / memory_total,
                    })
                else:
                    yield found_address

        checked_memory_size += size


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
    `bufflength - 1` extra bytes so the value is fully covered.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    # `None` means "no snapshot provided, enumerate now". An empty list passed
    # explicitly is honored verbatim — scanning nothing is a valid choice when
    # the caller pre-filtered to zero regions.
    if memory_regions is None:
        memory_regions = []
        for region in GetMemoryRegions(process_handle):
            # Accept both private and image (loaded DLLs) regions, matching
            # SearchAddressesByValue. Previously this filter was stricter and
            # caused addresses found via search_by_value to fail here.
            if not _is_region_scannable(region, writeable_only=False):
                continue
            memory_regions.append(region)
    else:
        memory_regions = list(memory_regions)

    addresses = sorted(addresses)
    memory_regions.sort(key=lambda region: region["address"])
    address_index = 0

    for region in memory_regions:
        if address_index >= len(addresses):
            break

        base_address, size = region["address"], region["size"]
        if not (base_address <= addresses[address_index] < base_address + size):
            continue

        for chunk_offset, chunk_size in iter_region_chunks(size, bufflength):
            if address_index >= len(addresses):
                break

            chunk_address = base_address + chunk_offset
            chunk_end = chunk_address + chunk_size

            if addresses[address_index] >= chunk_end:
                continue

            # Read up to `bufflength - 1` bytes past the chunk so addresses
            # near the boundary can still be fully decoded.
            extra = bufflength - 1 if chunk_offset + chunk_size < size else 0
            read_size = chunk_size + extra
            chunk_data = _read_region(process_handle, chunk_address, read_size)

            if chunk_data is None:
                while address_index < len(addresses) and chunk_address <= addresses[address_index] < chunk_end:
                    yield addresses[address_index], None
                    address_index += 1
                continue

            while address_index < len(addresses) and chunk_address <= addresses[address_index] < chunk_end:
                target_address = addresses[address_index]
                offset_in_chunk = target_address - chunk_address

                try:
                    data = chunk_data[offset_in_chunk: offset_in_chunk + bufflength]
                    data = (ctypes.c_byte * bufflength)(*data)
                    yield target_address, convert_from_byte_array(data, pytype, bufflength)

                except (ValueError, UnicodeDecodeError, OSError) as error:
                    if raise_error:
                        raise error
                    yield target_address, None

                address_index += 1


def WriteProcessMemory(
    process_handle: int,
    address: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes]
) -> Union[bool, int, float, str, bytes]:
    """
    Write a value to a memory address.

    Raises OSError if the write fails.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    data = get_c_type_of(pytype, bufflength)
    data.value = value.encode() if isinstance(value, str) else value

    bytes_written = ctypes.c_size_t(0)

    ctypes.set_last_error(0)
    success = kernel32.WriteProcessMemory(
        process_handle, ctypes.c_void_p(address), ctypes.byref(data),
        bufflength, ctypes.byref(bytes_written),
    )

    if not success:
        _raise_last_error("WriteProcessMemory")

    return value
