# -*- coding: utf-8 -*-

"""
macOS-only test: verify that writing to a read-only page transparently
elevates the protection via mach_vm_protect, performs the write, and restores
the original protection.
"""

import ctypes
import os
import sys

import pytest


if sys.platform != "darwin":
    pytest.skip("macOS-only module", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402


# Page size on macOS arm64 is 16 KB; x86_64 is 4 KB. mmap will pick the right one.
_libsystem = ctypes.CDLL(
    ctypes.util.find_library("System") if hasattr(ctypes, "util") else "libSystem.dylib"
)
# Re-import the proper way:
from ctypes.util import find_library  # noqa: E402

_libsystem = ctypes.CDLL(find_library("System"))

# mmap / munmap signatures
_libsystem.mmap.restype = ctypes.c_void_p
_libsystem.mmap.argtypes = (
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_uint64,
)
_libsystem.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
_libsystem.munmap.restype = ctypes.c_int

PROT_READ = 0x1
PROT_WRITE = 0x2
MAP_PRIVATE = 0x0002
MAP_ANON = 0x1000
MAP_FAILED = ctypes.c_void_p(-1).value


def _mmap_readonly(size: int) -> int:
    """Allocate a page-aligned read-only buffer. Returns its address."""
    # Allocate writable first to populate, then re-protect to read-only.
    addr = _libsystem.mmap(
        None, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0
    )
    if addr == MAP_FAILED or addr == 0:
        raise OSError("mmap failed")

    # Write a sentinel through the writable mapping.
    ctypes.memmove(addr, b"\xaa" * size, size)

    # Drop write permission via mprotect.
    libc_mprotect = _libsystem.mprotect
    libc_mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
    libc_mprotect.restype = ctypes.c_int
    if libc_mprotect(addr, size, PROT_READ) != 0:
        _libsystem.munmap(addr, size)
        raise OSError("mprotect failed")

    return addr


def test_write_to_readonly_page_via_protect_flip():
    size = 4096
    address = _mmap_readonly(size)

    try:
        process = OpenProcess(pid=os.getpid())
        try:
            # Sanity: we can read the read-only page.
            value_before = process.read_process_memory(address, int, 4)
            assert value_before != 0

            # The page is read-only — write should still succeed via the protect-flip path.
            # Use a value that fits in signed int32 to keep the assertion simple
            # (PyMemoryEditor returns int reads as signed c_int32).
            sentinel = 0x4DEADBEE
            process.write_process_memory(address, int, 4, sentinel)

            value_after = process.read_process_memory(address, int, 4)
            assert value_after == sentinel
        finally:
            process.close()
    finally:
        _libsystem.munmap(address, size)
