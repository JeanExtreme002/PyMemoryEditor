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


# --- protect-flip across regions with different protections -----------------
#
# The flip used to read the protection of the region holding `address` only,
# then restore that one value across the whole page-aligned span. A write that
# crosses into a neighbouring region with a different protection therefore
# left the neighbour with the *wrong* protection: an RW neighbour came back
# read-only, a read-only one came back writable. Each case below allocates two
# adjacent pages in the test's own task (mach_vm_allocate), re-protects them
# into two regions, writes across the boundary, and checks each page.


def _two_page_regions(first_protection, second_protection):
    """Allocate two adjacent pages and give each its own protection."""
    from PyMemoryEditor.macos import functions as mac
    from PyMemoryEditor.macos.libsystem import libsystem, mach_task_self_

    task = mach_task_self_.value
    page = mac._PAGE_SIZE
    address = mac.allocate_memory(task, 2 * page)
    for base, protection in ((address, first_protection), (address + page, second_protection)):
        kr = libsystem.mach_vm_protect(task, base, page, 0, protection)
        if kr != 0:
            mac.free_memory(task, address, 2 * page)
            pytest.skip("mach_vm_protect(0x%x) refused here (kr=%d)" % (protection, kr))
    return task, address, page


def _protection_at(task, address):
    from PyMemoryEditor.macos import functions as mac

    found = mac._basic_region_at(task, address)
    assert found is not None
    start, size, info = found
    assert start <= address < start + size
    return info.protection


_R = 0x1
_RW = 0x3
_RX = 0x5


@pytest.mark.parametrize(
    "first, second",
    (
        (_R, _RW),  # neighbour must stay writable
        (_RW, _R),  # neighbour must not be left writable
        (_R, _RX),  # neighbour must keep EXECUTE
    ),
)
def test_a_write_across_two_regions_restores_each_regions_protection(first, second):
    from PyMemoryEditor.macos import functions as mac

    task, address, page = _two_page_regions(first, second)
    try:
        assert _protection_at(task, address) == first
        assert _protection_at(task, address + page) == second

        payload = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        start = address + page - 4
        buffer = ctypes.create_string_buffer(payload, len(payload))
        mac._mach_write(task, start, ctypes.addressof(buffer), len(payload))

        assert mac.read_process_memory(task, start, bytes, len(payload)) == payload
        assert _protection_at(task, address) == first
        assert _protection_at(task, address + page) == second
    finally:
        mac.free_memory(task, address, 2 * page)


class _ProtectSpy:
    """Wrap ``mach_vm_protect`` to record calls and optionally refuse some."""

    def __init__(self, real, refuse=None):
        self.real = real
        self.refuse = refuse or (lambda address, protection: False)
        self.calls = []

    def __call__(self, task, address, size, set_maximum, protection):
        self.calls.append((address, size, protection))
        if self.refuse(address, protection):
            return 2  # KERN_PROTECTION_FAILURE
        return self.real(task, address, size, set_maximum, protection)


def test_the_flip_keeps_execute_when_the_kernel_allows_it(monkeypatch):
    """
    An RX page is first elevated *with* EXECUTE (so a thread running there
    doesn't fault mid-write); when W^X refuses RWX — the norm on Apple
    Silicon — it falls back to READ|WRITE|COPY and still restores RX.
    """
    from PyMemoryEditor.macos import functions as mac
    from PyMemoryEditor.macos.types import VM_PROT_COPY, VM_PROT_EXECUTE, VM_PROT_WRITE

    task, address, page = _two_page_regions(_RX, _RX)
    spy = _ProtectSpy(mac.libsystem.mach_vm_protect)
    monkeypatch.setattr(mac.libsystem, "mach_vm_protect", spy)
    try:
        buffer = ctypes.c_uint32(0x4DEADBEE)
        mac._mach_write(task, address + 16, ctypes.addressof(buffer), 4)

        elevations = [call for call in spy.calls if call[2] & VM_PROT_WRITE]
        assert elevations[0][2] == _RX | VM_PROT_WRITE | VM_PROT_COPY
        if len(elevations) > 1:  # RWX refused: fallback without EXECUTE
            assert elevations[1][2] == (_R | VM_PROT_WRITE | VM_PROT_COPY)
            assert not elevations[1][2] & VM_PROT_EXECUTE
        assert spy.calls[-1][2] == _RX  # restored

        monkeypatch.undo()
        assert mac.read_process_memory(task, address + 16, bytes, 4) == bytes(buffer)
        assert _protection_at(task, address) == _RX
    finally:
        monkeypatch.undo()
        mac.free_memory(task, address, 2 * page)


def test_a_non_executable_page_is_never_elevated_with_execute(monkeypatch):
    from PyMemoryEditor.macos import functions as mac
    from PyMemoryEditor.macos.types import VM_PROT_EXECUTE

    task, address, page = _two_page_regions(_R, _R)
    spy = _ProtectSpy(mac.libsystem.mach_vm_protect)
    monkeypatch.setattr(mac.libsystem, "mach_vm_protect", spy)
    try:
        buffer = ctypes.c_uint32(7)
        mac._mach_write(task, address, ctypes.addressof(buffer), 4)
        assert spy.calls
        assert not any(call[2] & VM_PROT_EXECUTE for call in spy.calls)
    finally:
        monkeypatch.undo()
        mac.free_memory(task, address, 2 * page)


def test_a_failed_elevate_rolls_back_the_regions_already_elevated(monkeypatch):
    """
    If the second region can't be made writable, the first — already elevated
    — must be put back before the error surfaces, not left writable.
    """
    from PyMemoryEditor.macos import functions as mac
    from PyMemoryEditor.macos.types import VM_PROT_WRITE

    task, address, page = _two_page_regions(_R, _RX)
    second = address + page
    spy = _ProtectSpy(
        mac.libsystem.mach_vm_protect,
        refuse=lambda addr, protection: addr == second and protection & VM_PROT_WRITE,
    )
    monkeypatch.setattr(mac.libsystem, "mach_vm_protect", spy)
    try:
        buffer = ctypes.create_string_buffer(b"\x01" * 8, 8)
        with pytest.raises(OSError, match="could not elevate"):
            mac._mach_write(task, second - 4, ctypes.addressof(buffer), 8)
        monkeypatch.undo()
        assert _protection_at(task, address) == _R
        assert _protection_at(task, second) == _RX
    finally:
        monkeypatch.undo()
        mac.free_memory(task, address, 2 * page)


# --- maximum protection ------------------------------------------------------
#
# VM_PROT_COPY adds WRITE to the region's *maximum* protection. The restore
# used to put back only the current protection, so a page whose maximum never
# allowed writing (a read-only shared file mapping, a code page) stayed
# writable-on-request for the rest of the target's life.

MAP_SHARED = 0x0001


def _max_protection_at(task, address):
    from PyMemoryEditor.macos import functions as mac

    found = mac._basic_region_at(task, address)
    assert found is not None
    return found[2].max_protection


def test_the_flip_restores_a_maximum_protection_without_write(tmp_path):
    from PyMemoryEditor.macos import functions as mac
    from PyMemoryEditor.macos.libsystem import mach_task_self_
    from PyMemoryEditor.macos.types import VM_PROT_WRITE

    page = mac._PAGE_SIZE
    backing = tmp_path / "readonly.bin"
    backing.write_bytes(b"\xaa" * page)
    fd = os.open(str(backing), os.O_RDONLY)
    try:
        # A shared mapping of a file opened read-only: the kernel caps its
        # maximum protection below WRITE.
        address = _libsystem.mmap(None, page, PROT_READ, MAP_SHARED, fd, 0)
    finally:
        os.close(fd)
    if address in (MAP_FAILED, 0, None):
        pytest.skip("mmap of the backing file failed")

    task = mach_task_self_.value
    try:
        original_max = _max_protection_at(task, address)
        if original_max & VM_PROT_WRITE:
            pytest.skip("this kernel already allows WRITE on the mapping")

        payload = ctypes.c_uint32(0x4DEADBEE)
        mac._mach_write(task, address, ctypes.addressof(payload), 4)

        assert mac.read_process_memory(task, address, bytes, 4) == bytes(payload)
        assert _protection_at(task, address) == PROT_READ
        assert _max_protection_at(task, address) == original_max
        # VM_PROT_COPY made the change private: the file is untouched.
        assert backing.read_bytes()[:4] == b"\xaa" * 4
    finally:
        _libsystem.munmap(address, page)


def test_the_maximum_is_left_alone_when_it_already_allowed_write(monkeypatch):
    from PyMemoryEditor.macos import functions as mac

    task, address, page = _two_page_regions(_R, _R)
    spy = _ProtectSpy(mac.libsystem.mach_vm_protect)
    max_calls = []

    def recording(task_, address_, size, set_maximum, protection):
        if set_maximum:
            max_calls.append(protection)
        return spy(task_, address_, size, set_maximum, protection)

    monkeypatch.setattr(mac.libsystem, "mach_vm_protect", recording)
    try:
        buffer = ctypes.c_uint32(7)
        mac._mach_write(task, address, ctypes.addressof(buffer), 4)
        # mach_vm_allocate'd memory has a maximum of rwx already.
        assert max_calls == []
    finally:
        monkeypatch.undo()
        mac.free_memory(task, address, 2 * page)
