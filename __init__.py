# -*- coding: utf-8 -*-

import win32api
import win32con
import win32gui
import win32process 
import ctypes

__all__ = ("get_process_id", "read_process_memory", "write_process_memory")
__author__ = "Jean Loui Bernard Silva de Jesus"

kernel32 = ctypes.windll.LoadLibrary("kernel32.dll")

def close_process_handle(process_handle):
    
    """
    Close the process handle.
    """
    
    win32api.CloseHandle(process_handle)

def get_c_type_of(type_, length):
    
    """
    Return a C type of a primitive type of the Python language.
    """
    
    if type_ is str:
        return ctypes.create_string_buffer(length)
    
    elif type_ is int:
        
        if length == 1:
            return ctypes.c_int8()
        
        if length == 2:
            return ctypes.c_int16()

        if length <= 4:
            return ctypes.c_int32()

        return ctypes.c_int64()
    
    elif type_ is float:
        return ctypes.c_float() if length <= 4 else ctypes.c_double()

    elif type_ is bool:
        return ctypes.c_bool()

def get_process_id(window_title):

    """
    Return the process ID.
    """
    
    hwnd = win32gui.FindWindow(None, window_title)
    tid, pid = win32process.GetWindowThreadProcessId(hwnd)

    return pid

def get_process_handle(pid, inherit = False):

    """
    Get a process ID and return its process handle.
    """
    
    return win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, inherit, pid)

def read_process_memory(pid, address, type_, bufflength):

    """
    Return a value from a memory address.

    @param pid: Process ID
    @param address: Target memory address in hexadecimal.
    @param type_: Type of the value to be received (str, int or float).
    @param bufflength: Value size in bytes (1, 2, 4, 8).
    """

    hProcess = get_process_handle(pid)
    data = get_c_type_of(type_, int(bufflength))
    
    kernel32.ReadProcessMemory(int(hProcess), address, ctypes.byref(data), bufflength, None)
    close_process_handle(hProcess)
    
    return data.value

def write_process_memory(pid, address, value, type_, bufflength):

    """
    Write a value to a memory address.

    @param pid: Process ID
    @param address: Target memory address in hexadecimal.
    @param type_: Type of value to be written into memory (str, int or float).
    @param bufflength: Value size in bytes (1, 2, 4, 8).
    """
    
    hProcess = get_process_handle(pid)
    
    data = get_c_type_of(type_, int(bufflength))
    data.value = value.encode() if isinstance(value, str) else value
    
    kernel32.WriteProcessMemory(int(hProcess), address, ctypes.byref(data), bufflength, None)
    close_process_handle(hProcess)
    
    return value
