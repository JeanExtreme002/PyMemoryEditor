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


from ctypes.util import find_library  # noqa: E402

from PyMemoryEditor import OpenProcess  # noqa: E402
from PyMemoryEditor.process.region import default_scan_filter  # noqa: E402


# Page size on macOS arm64 is 16 KB; x86_64 is 4 KB. mmap will pick the right one.
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


def test_dyld_shared_cache_excluded_from_value_scans():
    """The dyld shared cache must be flagged shared so value scans skip it.

    macOS maps the read-only library blob (the dyld shared cache, ~6 GB) into
    every process. Its ``vm_region_basic_info`` ``shared`` flag is FALSE, so
    before the ``VM_MEMORY_SHARED_PMAP`` user_tag fix a default scan walked all
    ~6 GB of it — making macOS scans (and this suite) 4-6x slower than the
    other OSes, which exclude their equivalent file-backed library mappings.

    Regression guard: there is at least one large readable region flagged
    ``is_shared``, and ``default_scan_filter`` drops enough that the scanned set
    is a small fraction of all readable memory.
    """
    process = OpenProcess(pid=os.getpid())
    try:
        regions = list(process.get_memory_regions())
    finally:
        process.close()

    readable = [r for r in regions if r.is_readable]
    readable_bytes = sum(r.size for r in readable)
    scanned_bytes = sum(r.size for r in readable if default_scan_filter(r))

    # The dyld shared cache shows up as one or more large readable regions that
    # must now be classified as shared (256 MB is well below its real size).
    big_shared = [
        r for r in readable if r.is_shared and r.size >= 256 * 1024 * 1024
    ]
    assert big_shared, "dyld shared cache not recognized as a shared mapping"

    # With the cache excluded the scanned set is a small slice of all readable
    # memory — guards against a regression that scans the whole address space.
    assert scanned_bytes < readable_bytes * 0.5


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


def test_page_aligned_span_covers_a_straddling_write():
    """``_page_aligned_span`` must expand to whole pages around the byte range.

    A write that crosses a page boundary has to have *both* pages protected
    (and later restored) as one span — otherwise the restore can miss the
    second page and leave it permanently more permissive.
    """
    from PyMemoryEditor.macos.functions import _PAGE_SIZE, _page_aligned_span

    page = _PAGE_SIZE

    # Write of 8 bytes starting 4 bytes before a page boundary → touches two
    # pages; the aligned span must start at the first page and cover both.
    start, length = _page_aligned_span(page - 4, 8)
    assert start == 0
    assert length == 2 * page

    # A fully-contained write rounds out to exactly one page.
    start, length = _page_aligned_span(page + 16, 4)
    assert start == page
    assert length == page


def test_write_straddling_a_page_boundary_restores_both_pages():
    """A cross-page write must succeed and leave *both* pages read-only again.

    Regression guard for the protect-flip alignment fix: the elevate/restore
    span is page-aligned, so the second page isn't left writable after the
    write completes.
    """
    from PyMemoryEditor.macos.functions import _PAGE_SIZE

    page = _PAGE_SIZE
    size = 2 * page
    address = _mmap_readonly(size)

    try:
        process = OpenProcess(pid=os.getpid())
        try:
            boundary = address + page
            # 8 bytes centered on the page boundary (4 in each page).
            payload = b"\x01\x02\x03\x04\x05\x06\x07\x08"
            process.write_process_memory(boundary - 4, bytes, len(payload), payload)
            assert process.read_process_memory(boundary - 4, bytes, len(payload)) == payload

            # Both pages must be back to read-only — the restore covered the
            # whole aligned span, not just the literal byte range.
            for r in process.get_memory_regions():
                if r.address <= address < r.address + r.size:
                    assert not r.is_writable, "first page left writable after write"
                if r.address <= boundary < r.address + r.size:
                    assert not r.is_writable, "second page left writable after write"
        finally:
            process.close()
    finally:
        _libsystem.munmap(address, size)
