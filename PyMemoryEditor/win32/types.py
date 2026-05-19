# -*- coding: utf-8 -*-

from ctypes import Structure, WINFUNCTYPE, c_bool, c_ulonglong, c_void_p, sizeof, wintypes


class MEMORY_BASIC_INFORMATION_32(Structure):
    _fields_ = [
        ("BaseAddress", wintypes.DWORD),
        ("AllocationBase", wintypes.DWORD),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", wintypes.DWORD),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class MEMORY_BASIC_INFORMATION_64(Structure):
    _fields_ = [
        ("BaseAddress", c_ulonglong),
        ("AllocationBase", c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]


class SYSTEM_INFO(Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", c_void_p),
        ("lpMaximumApplicationAddress", c_void_p),
        ("dwActiveProcessorMask", c_void_p),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]


# Default MEMORY_BASIC_INFORMATION layout based on the running Python's bitness.
# When the target process has a different bitness (Python x64 attached to a
# 32-bit target — common with legacy games), prefer
# `mbi_class_for_handle(handle)` from PyMemoryEditor.win32.functions, which
# dispatches based on IsWow64Process.
MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION_64 if sizeof(c_void_p) == 8 else MEMORY_BASIC_INFORMATION_32

# For EnumWindows and EnumDesktopWindows functions.
WNDENUMPROC = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)
