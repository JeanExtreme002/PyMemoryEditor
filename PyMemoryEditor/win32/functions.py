# -*- coding: utf-8 -*-

# Read more about process operations by win32api here:
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/

from .util import get_c_type_of
from ctypes import byref, windll, c_void_p
from typing import Type, TypeVar, Union

kernel32 = windll.LoadLibrary("kernel32.dll")

T = TypeVar("T")

def CloseProcessHandle(process_handle: int) -> int:
    """
    Close the process handle.
    """
    return kernel32.CloseHandle(process_handle)


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


def ReadProcessMemory(
    process_handle: int,
    address: int,
    pytype: Type[T],
    bufflength: int
) -> T:
    """
    Return a value from a memory address.
    """
    if pytype not in [str, int, float]: raise ValueError("The type must be string, int or float.")

    data = get_c_type_of(pytype, int(bufflength))
    kernel32.ReadProcessMemory(process_handle, c_void_p(address), byref(data), bufflength, None)

    return data.value


def WriteProcessMemory(
    process_handle: int,
    address: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[int, float, str]
) -> T:
    """
    Write a value to a memory address.
    """
    if pytype not in [str, int, float]: raise ValueError("The type must be string, int or float.")

    data = get_c_type_of(pytype, int(bufflength))
    data.value = value.encode() if isinstance(value, str) else value

    kernel32.WriteProcessMemory(process_handle, c_void_p(address), byref(data), bufflength, None)

    return value
