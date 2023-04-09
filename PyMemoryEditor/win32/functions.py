# -*- coding: utf-8 -*-

# Read more about operations with processes by win32 api here:
# https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
# https://learn.microsoft.com/en-us/windows/win32/api/psapi/
# ...

from .types import MEMORY_BASIC_INFORMATION, SYSTEM_INFO, WNDENUMPROC
from .util import get_c_type_of
from ctypes import byref, c_uint32, c_void_p, create_unicode_buffer, sizeof, windll
from typing import Generator, Type, TypeVar, Union

kernel32 = windll.LoadLibrary("kernel32.dll")
user32 = windll.LoadLibrary("user32.dll")

# Get the user's system information.
system_information = SYSTEM_INFO()
kernel32.GetSystemInfo(byref(system_information))


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
        kernel32.VirtualQueryEx(process_handle, current_address, byref(region), sizeof(region))

        current_address += region.RegionSize
        yield {"address": current_address, "size": region.RegionSize, "info_struct": region}


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
    result = c_uint32(0)

    string_buffer_size = len(window_title) + 2  # (+2) for the next possible character of a title and the NULL char.
    string_buffer = create_unicode_buffer(string_buffer_size)

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
            user32.GetWindowThreadProcessId(hwnd, byref(result))
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

    data = get_c_type_of(pytype, int(bufflength))
    kernel32.ReadProcessMemory(process_handle, c_void_p(address), byref(data), bufflength, None)

    return str(data.value) if pytype is str else data.value


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

    data = get_c_type_of(pytype, int(bufflength))
    data.value = value.encode() if isinstance(value, str) else value

    kernel32.WriteProcessMemory(process_handle, c_void_p(address), byref(data), bufflength, None)

    return value
