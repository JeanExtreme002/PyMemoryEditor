# -*- coding: utf-8 -*-

# Read more about operations with processes by win32 api here:
# https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
# https://learn.microsoft.com/en-us/windows/win32/api/psapi/
# ...

from ..enums import ScanTypesEnum
from ..util import get_c_type_of, scan_memory, scan_memory_for_exact_value

from .enums import MemoryAllocationStatesEnum, MemoryProtectionsEnum, MemoryTypesEnum
from .types import MEMORY_BASIC_INFORMATION, SYSTEM_INFO, WNDENUMPROC

from typing import Generator, Tuple, Type, TypeVar, Union

import ctypes
import ctypes.wintypes

# Load the libraries.
kernel32 = ctypes.windll.LoadLibrary("kernel32.dll")
user32 = ctypes.windll.LoadLibrary("user32.dll")

# Set the argtypes to prevent ArgumentError.
kernel32.VirtualQueryEx.argtypes = (
    ctypes.wintypes.HANDLE, ctypes.wintypes.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_uint32
)


# Get the user's system information.
system_information = SYSTEM_INFO()
kernel32.GetSystemInfo(ctypes.byref(system_information))


T = TypeVar("T")


def CloseProcessHandle(process_handle: int) -> int:
    """
    Close the process handle.
    """
    return kernel32.CloseHandle(process_handle)


def GetMemoryRegions(process_handle: int) -> Generator[dict, None, None]:
    """
    Generates dictionaries with the address and size of a region used by the process.
    """
    mem_region_begin = system_information.lpMinimumApplicationAddress
    mem_region_end = system_information.lpMaximumApplicationAddress

    current_address = mem_region_begin

    while current_address < mem_region_end:
        region = MEMORY_BASIC_INFORMATION()
        kernel32.VirtualQueryEx(process_handle, current_address, ctypes.byref(region), ctypes.sizeof(region))

        yield {"address": current_address, "size": region.RegionSize, "struct": region}

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
    return kernel32.OpenProcess(access_right, inherit, pid)


def GetProcessIdByWindowTitle(window_title: str) -> int:
    """
    Return the process ID by querying a window title.
    """
    result = ctypes.c_uint32(0)

    string_buffer_size = len(window_title) + 2  # (+2) for the next possible character of a title and the NULL char.
    string_buffer = ctypes.create_unicode_buffer(string_buffer_size)

    def callback(hwnd, size):
        """
        This callback is used to get a window handle and compare
        its title with the target window title.

        To continue enumeration, the callback function must return TRUE;
        to stop enumeration, it must return FALSE.
        """
        nonlocal result, string_buffer

        user32.GetWindowTextW(hwnd, string_buffer, size)

        # Compare the window titles and get the process ID.
        if window_title == string_buffer.value:
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(result))
            return False

        # Indicate it must continue enumeration.
        return True

    # Enumerates all top-level windows on the screen by passing the handle to each window,
    # in turn, to an application-defined callback function.
    user32.EnumWindows(WNDENUMPROC(callback), string_buffer_size)

    return result.value


def ReadProcessMemory(
    process_handle: int,
    address: int,
    pytype: Type[T],
    bufflength: int
) -> T:
    """
    Return a value from a memory address.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    data = get_c_type_of(pytype, bufflength)
    kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(address), ctypes.byref(data), bufflength, None)

    return str(data.value) if pytype is str else data.value


def SearchAllMemory(
    process_handle: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes],
    scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
    progress_information: bool = False,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    Search the whole memory space, accessible to the process,
    for the provided value, returning the found addresses.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    # Get the target value as bytes.
    target_value = get_c_type_of(pytype, bufflength)
    target_value.value = value

    target_value_bytes = ctypes.cast(ctypes.byref(target_value), ctypes.POINTER(ctypes.c_byte * bufflength))
    target_value_bytes = bytes(target_value_bytes.contents)

    # Get the memory regions, computing the total amount of memory to be scanned.
    checked_memory_size = 0
    memory_total = 0
    regions = list()

    for region in GetMemoryRegions(process_handle):

        # Only committed, non-shared and readable memory pages.
        if region["struct"].State != MemoryAllocationStatesEnum.MEM_COMMIT.value: continue
        if region["struct"].Type != MemoryTypesEnum.MEM_PRIVATE.value: continue
        if region["struct"].Protect & MemoryProtectionsEnum.PAGE_READABLE.value == 0: continue

        memory_total += region["size"]
        regions.append(region)

    # Check each memory region used by the process.
    for region in regions:
        address, size = region["address"], region["size"]
        region_data = (ctypes.c_byte * size)()

        # Get data from the region.
        kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(address), ctypes.byref(region_data), size, None)

        # Choose the searching method.
        searching_method = scan_memory

        if scan_type in [ScanTypesEnum.EXACT_VALUE, ScanTypesEnum.NOT_EXACT_VALUE]:
            searching_method = scan_memory_for_exact_value

        # Search the value and return the found addresses.
        for offset in searching_method(region_data, size, target_value_bytes, bufflength, scan_type):
            found_address = address + offset

            extra_information = {
                "memory_total": memory_total,
                "progress": (checked_memory_size + offset) / memory_total,
            }
            yield (found_address, extra_information) if progress_information else found_address

        # Compute the region size to the checked memory size.
        checked_memory_size += size


def WriteProcessMemory(
    process_handle: int,
    address: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes]
) -> T:
    """
    Write a value to a memory address.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    data = get_c_type_of(pytype, bufflength)
    data.value = value.encode() if isinstance(value, str) else value

    kernel32.WriteProcessMemory(process_handle, ctypes.c_void_p(address), ctypes.byref(data), bufflength, None)

    return value
