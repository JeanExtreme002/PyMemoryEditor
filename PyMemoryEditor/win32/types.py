# -*- coding: utf-8 -*-

from ctypes import (
    Structure,
    c_ulonglong,
    c_void_p,
    c_wchar,
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


# MEMORY_BASIC_INFORMATION layout of the running Python. This is the layout
# VirtualQueryEx fills in for *every* target: NtQueryVirtualMemory always
# writes the caller's native struct (and rejects a smaller buffer with
# ERROR_BAD_LENGTH), so a 64-bit Python uses the 64-bit layout even for a
# 32-bit (WOW64) target. The explicit _32/_64 forms mirror winnt.h's
# MEMORY_BASIC_INFORMATION32/64, which exist for debuggers decoding a
# foreign-architecture target's data — not for VirtualQueryEx.
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


class MODULEENTRY32W(Structure):
    """Layout matching the Unicode Win32 ``MODULEENTRY32W`` (Module32FirstW/NextW).

    The wide variant is used so module names and paths come back as ``str``
    exactly as Windows stores them; the ANSI ``MODULEENTRY32`` converts them
    through the active code page, mangling any character outside it.
    ``modBaseAddr`` is declared as a void pointer so it stays pointer-sized on
    both 32- and 64-bit builds; read it as an int via ``entry.modBaseAddr``.
    ``szModule`` / ``szExePath`` are ``c_wchar`` arrays — accessing them yields
    the NUL-terminated ``str`` directly. Documented size: 1080 bytes on 64-bit,
    1064 on 32-bit.
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
        ("szModule", c_wchar * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", c_wchar * MAX_PATH),
    ]


# TH32CS_SNAPPROCESS flag for CreateToolhelp32Snapshot — used by get_processes()
# to enumerate every process in the system (pid + executable name).
TH32CS_SNAPPROCESS = 0x00000002


class PROCESSENTRY32W(Structure):
    """Layout matching the Unicode Win32 ``PROCESSENTRY32W`` (Process32FirstW/NextW).

    ``th32DefaultHeapID`` is a ``ULONG_PTR`` — declared as a void pointer so it
    stays pointer-sized on both 32- and 64-bit builds. ``szExeFile`` is a
    ``c_wchar`` array holding the NUL-terminated executable name (no path) as
    ``str``. Documented size: 568 bytes on 64-bit, 556 on 32-bit.
    """

    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", c_wchar * MAX_PATH),
    ]
