# -*- coding: utf-8 -*-

from .util import get_c_type_of
from ctypes import byref, windll

kernel32 = windll.LoadLibrary("kernel32.dll")

def CloseHandle(handle) -> int:

    """
    Close the process handle.
    """

    return kernel32.CloseHandle(handle)

def GetProcessHandle(access_right, inherit, pid) -> int:

    """
    Get a process ID and return its process handle.
    """

    return kernel32.OpenProcess(access_right, inherit, pid)

def ReadProcessMemory(process_handle, address, pytype, bufflength):

    """
    Return a value from a memory address.
    """

    if not pytype in [str, int, float]: raise ValueError("The type must be string, int or float.")

    data = get_c_type_of(pytype, int(bufflength))
    kernel32.ReadProcessMemory(process_handle, address, byref(data), bufflength, None)

    return data.value

def WriteProcessMemory(process_handle, address, pytype, bufflength, value):

    """
    Write a value to a memory address.
    """

    if not pytype in [str, int, float]: raise ValueError("The type must be string, int or float.")

    data = get_c_type_of(pytype, int(bufflength))
    data.value = value.encode() if isinstance(value, str) else value

    kernel32.WriteProcessMemory(process_handle, address, byref(data), bufflength, None)

    return value
