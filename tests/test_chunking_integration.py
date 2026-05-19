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
from PyMemoryEditor.util import scan as scan_module
from PyMemoryEditor.util.scan import iter_region_chunks


def test_iter_region_chunks_at_boundary():
    """Chunks must tile the region exactly without overlap."""
    region_size = 600 * 1024 * 1024  # 600 MB
    target_size = 4
    max_chunk = 256 * 1024 * 1024

    chunks: List = list(
        iter_region_chunks(region_size, target_size, max_chunk=max_chunk)
    )

    # Reconstructed region size matches the input.
    assert sum(size for _, size in chunks) == region_size

    # Chunks are contiguous.
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
    # Materialize and verify
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

    # Plant 0xCAFE at known offsets in each chunk.
    chunks_data = []
    expected_global_offsets = []
    for chunk_index in range(chunk_count):
        buf = bytearray(chunk_size)
        # Plant target at offsets 100, 5000, and 60000 within the chunk.
        for local in (100, 5000, 60000):
            buf[local : local + 4] = target
            expected_global_offsets.append(chunk_index * chunk_size + local)
        chunks_data.append(bytes(buf))

    # Run scan_memory on each chunk and collect global offsets.
    found = []
    for chunk_index, data in enumerate(chunks_data):
        for offset in scan_module.scan_memory_for_exact_value(
            data, len(data), target, 4, ScanTypesEnum.EXACT_VALUE
        ):
            found.append(chunk_index * chunk_size + offset)

    assert sorted(found) == sorted(expected_global_offsets)


@pytest.mark.skipif(sys.platform != "win32", reason="WOW64 dispatch is Win32-only")
def test_mbi_class_for_handle_wow64(monkeypatch):
    """When the target is WOW64, the 32-bit MBI layout is selected."""
    from PyMemoryEditor.win32 import functions as wf
    from PyMemoryEditor.win32.types import (
        MEMORY_BASIC_INFORMATION_32,
        MEMORY_BASIC_INFORMATION_64,
    )

    # Force "host is 64-bit" so the WOW64 branch is taken.
    monkeypatch.setattr(wf, "_HOST_IS_64BIT", True)

    # Fake IsWow64Process that flips the BOOL it gets via byref.
    def fake_is_wow64(handle, out_bool_ptr):
        out_bool_ptr._obj.value = 1  # type: ignore[attr-defined]
        return 1

    monkeypatch.setattr(wf.kernel32, "IsWow64Process", fake_is_wow64)
    assert wf.mbi_class_for_handle(0xDEAD) is MEMORY_BASIC_INFORMATION_32

    # Same handle but target is 64-bit.
    def fake_is_native(handle, out_bool_ptr):
        out_bool_ptr._obj.value = 0  # type: ignore[attr-defined]
        return 1

    monkeypatch.setattr(wf.kernel32, "IsWow64Process", fake_is_native)
    assert wf.mbi_class_for_handle(0xBEEF) is MEMORY_BASIC_INFORMATION_64
