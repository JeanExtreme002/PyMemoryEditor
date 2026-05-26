# -*- coding: utf-8 -*-

from ctypes import (
    Structure,
    c_char,
    c_ulonglong,
    c_void_p,
    sizeof,
    wintypes,
)


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
MEMORY_BASIC_INFORMATION = (
    MEMORY_BASIC_INFORMATION_64
    if sizeof(c_void_p) == 8
    else MEMORY_BASIC_INFORMATION_32
)


# TH32CS_SNAPTHREAD flag for CreateToolhelp32Snapshot — used by get_threads().
TH32CS_SNAPTHREAD = 0x00000004


class THREADENTRY32(Structure):
    """Layout matching the Win32 ``THREADENTRY32`` returned by Thread32First/Next."""

    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


# CreateToolhelp32Snapshot flags for module enumeration — used by get_modules().
# TH32CS_SNAPMODULE32 is OR-ed in so a 64-bit caller can also see the 32-bit
# modules of a WOW64 target.
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

# Fixed buffer sizes from <tlhelp32.h> / <minwindef.h>.
MAX_MODULE_NAME32 = 255
MAX_PATH = 260


class MODULEENTRY32(Structure):
    """Layout matching the ANSI Win32 ``MODULEENTRY32`` (Module32First/Next).

    ``modBaseAddr`` is declared as a void pointer so it stays pointer-sized on
    both 32- and 64-bit builds; read it as an int via ``entry.modBaseAddr``.
    ``szModule`` / ``szExePath`` are ``c_char`` arrays — accessing them yields
    the NUL-terminated bytes directly.
    """

    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", c_char * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", c_char * MAX_PATH),
    ]
