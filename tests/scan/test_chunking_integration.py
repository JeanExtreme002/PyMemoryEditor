# -*- coding: utf-8 -*-

"""
Tests that exercise the chunking codepath in scan_addresses_by_value and
search_values_by_addresses without needing a real process with multi-GB
regions. We feed a synthetic "region list" plus a configurable max_chunk
to force the slow path.
"""

import struct
import sys
from typing import List

import pytest

from PyMemoryEditor.enums import ScanTypesEnum
from PyMemoryEditor.process.scanning import iter_search_results
from PyMemoryEditor.util import scan as scan_module
from PyMemoryEditor.util.scan import iter_region_chunks

from ._fakes import FakeMemory, small_chunks, pattern_hits


def test_iter_region_chunks_at_boundary():
    """Chunks must tile the region exactly without overlap."""
    region_size = 600 * 1024 * 1024  # 600 MB
    target_size = 4
    max_chunk = 256 * 1024 * 1024

    chunks: List = list(
        iter_region_chunks(region_size, target_size, max_chunk=max_chunk)
    )

    assert sum(size for _, size in chunks) == region_size

    expected_offset = 0
    for offset, size in chunks:
        assert offset == expected_offset
        expected_offset += size

    # All but the last chunk are aligned to target_size.
    for _, size in chunks[:-1]:
        assert size % target_size == 0


def test_iter_region_chunks_size_one_target():
    """target_value_size=1 (e.g. bool) must not divide by zero or align oddly."""
    region_size = 600 * 1024 * 1024
    chunks = list(
        iter_region_chunks(
            region_size, target_value_size=1, max_chunk=256 * 1024 * 1024
        )
    )
    assert sum(size for _, size in chunks) == region_size


def test_iter_region_chunks_fast_path_is_tuple():
    """Region <= max_chunk returns a tuple (not generator) — hot-path optimization."""
    result = iter_region_chunks(1024, 4)
    assert isinstance(result, tuple)
    assert result == ((0, 1024),)


def test_iter_region_chunks_slow_path_is_generator():
    """Region > max_chunk returns a lazy generator."""
    result = iter_region_chunks(10 * 1024 * 1024, 4, max_chunk=1024 * 1024)
    assert not isinstance(result, tuple)
    chunks = list(result)
    assert len(chunks) == 10


def test_scan_memory_across_chunked_region_finds_all_matches():
    """
    Simulate chunked reads of a large region by calling scan_memory on each
    chunk independently. Every aligned int32 value of 0xCAFE planted across
    the region must be found.
    """
    chunk_count = 5
    chunk_size = 64 * 1024  # 64 KB per chunk
    target = struct.pack("<I", 0xCAFE)

    chunks_data = []
    expected_global_offsets = []
    for chunk_index in range(chunk_count):
        buf = bytearray(chunk_size)
        # Plant target at offsets 100, 5000, and 60000 within the chunk.
        for local in (100, 5000, 60000):
            buf[local : local + 4] = target
            expected_global_offsets.append(chunk_index * chunk_size + local)
        chunks_data.append(bytes(buf))

    found = []
    for chunk_index, data in enumerate(chunks_data):
        for offset in scan_module.scan_memory_for_exact_value(
            data, len(data), target, 4, ScanTypesEnum.EXACT_VALUE
        ):
            found.append(chunk_index * chunk_size + offset)

    assert sorted(found) == sorted(expected_global_offsets)


@pytest.mark.skipif(sys.platform != "win32", reason="WOW64 handling is Win32-only")
def test_mbi_class_for_handle_is_the_host_layout_for_wow64_targets(monkeypatch):
    """
    VirtualQueryEx always fills the caller's native MEMORY_BASIC_INFORMATION
    (NtQueryVirtualMemory rejects a smaller buffer with ERROR_BAD_LENGTH), so
    a WOW64 target must *not* switch a 64-bit Python to the 28-byte layout.
    Regression: picking MEMORY_BASIC_INFORMATION_32 there made every region
    query of a 32-bit target fail and every scan of it raise.
    """
    import ctypes

    from PyMemoryEditor.win32 import functions as wf
    from PyMemoryEditor.win32.types import MEMORY_BASIC_INFORMATION

    def fake_is_wow64(handle, out_bool_ptr):
        out_bool_ptr._obj.value = 1  # type: ignore[attr-defined]
        return 1

    def fake_is_native(handle, out_bool_ptr):
        out_bool_ptr._obj.value = 0  # type: ignore[attr-defined]
        return 1

    for fake in (fake_is_wow64, fake_is_native):
        monkeypatch.setattr(wf.kernel32, "IsWow64Process", fake)
        mbi = wf.mbi_class_for_handle(0xDEAD)
        assert mbi is MEMORY_BASIC_INFORMATION
        # The native struct: 48 bytes on 64-bit Python, 28 on 32-bit.
        assert ctypes.sizeof(mbi) == (48 if ctypes.sizeof(ctypes.c_void_p) == 8 else 28)


# --------------------------------------------------------------------------- #
# Chunk-boundary overlap in the shared scan driver
# --------------------------------------------------------------------------- #

from PyMemoryEditor.process import scanning as scanning_module  # noqa: E402
from PyMemoryEditor.process.region import MemoryRegion  # noqa: E402


def _region(address: int, size: int) -> MemoryRegion:
    return MemoryRegion(
        address=address, size=size, is_readable=True, is_writable=True,
        is_executable=False, is_shared=False, path="",
    )


@pytest.mark.parametrize(
    "pytype, width",
    [(bytes, 4), (str, 4), (int, 3), (int, 5)],
)
def test_search_driver_finds_a_match_straddling_a_chunk_boundary(monkeypatch, pytype, width):
    """A ``bytes`` target (and an ``int`` at an unusual width) can start at any
    byte, so a match that begins in one chunk and ends in the next must still
    be found. Only ``str`` used to get the overlap read."""
    base = 0x10000
    chunk = 64  # force many small chunks instead of 256 MB ones
    monkeypatch.setattr(
        scanning_module,
        "iter_region_chunks",
        lambda size, value_size: iter_region_chunks(size, value_size, max_chunk=chunk),
    )

    target = (b"\x7f" * width) if pytype is not str else b"ABCD"
    buf = bytearray(4 * chunk)
    straddle = chunk - 2  # the first chunk holds 2 bytes of the match
    buf[straddle : straddle + width] = target
    aligned_slot = 2 * chunk + 8  # a second, fully-contained occurrence
    buf[aligned_slot : aligned_slot + width] = target

    def read_chunk(address, size):
        offset = address - base
        return bytes(buf[offset : offset + size])

    found = list(
        scanning_module.iter_search_results(
            [_region(base, len(buf))], pytype, width, target,
            ScanTypesEnum.EXACT_VALUE, read_chunk,
        )
    )
    assert found == [base + straddle, base + aligned_slot]
    # And nothing is reported twice (the overlap region is clamped).
    assert len(found) == len(set(found))


# --------------------------------------------------------------------------- #
# Chunk overlap stops at the end of the region
# --------------------------------------------------------------------------- #

def test_chunk_overlap_never_reads_past_the_region(monkeypatch):
    """With a width that does not divide the chunk size, the last chunk is
    shorter than the overlap; reading the full overlap ran past the region
    into unmapped memory and failed the read."""
    small_chunks(monkeypatch, 8)
    data = b"." * 5 + b"ab@c.de" + b"." * 30  # 42 bytes: last chunk is 2 bytes
    memory = FakeMemory({0x1000: data})  # nothing mapped after the region
    email = rb"[a-z]+@[a-z]+\.[a-z]+"
    assert pattern_hits(memory, email, byte_length=8) == [0x1005]
    assert all(addr + size <= 0x1000 + len(data) for addr, size in memory.reads)

    memory = FakeMemory({0x1000: data})
    found = list(iter_search_results(
        memory.regions, bytes, 7, b"ab@c.de", ScanTypesEnum.EXACT_VALUE,
        memory.read_chunk,
    ))
    assert found == [0x1005]
    assert all(addr + size <= 0x1000 + len(data) for addr, size in memory.reads)
