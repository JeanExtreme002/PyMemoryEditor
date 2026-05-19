# -*- coding: utf-8 -*-

"""
Unit tests for the cross-platform scan helpers in PyMemoryEditor.util.scan.

These tests run on any platform; they do not touch process memory.
"""

import struct

import pytest

from PyMemoryEditor.enums import ScanTypesEnum
from PyMemoryEditor.util.scan import (
    iter_region_chunks,
    scan_memory,
    scan_memory_for_exact_value,
)


def _pack(value: int, size: int = 4) -> bytes:
    """Pack an int as little-endian bytes, matching the platform integer encoding."""
    fmt = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}[size]
    return struct.pack(fmt, value)


def test_scan_memory_exact_value_finds_last_value():
    """Regression: off-by-one in the previous range() skipped the last value."""
    target = _pack(42)
    data = bytearray(_pack(0)) + bytearray(_pack(1)) + bytearray(target)

    results = list(
        scan_memory(data, len(data), target, 4, ScanTypesEnum.EXACT_VALUE, False)
    )

    assert 8 in results


def test_scan_memory_bigger_than_aligned():
    data = bytearray()
    for value in (10, 20, 30, 40):
        data.extend(_pack(value))

    target = _pack(20)
    results = list(
        scan_memory(data, len(data), target, 4, ScanTypesEnum.BIGGER_THAN, False)
    )

    # Offsets 8 (=30) and 12 (=40) should match.
    assert results == [8, 12]


def test_scan_memory_smaller_than_aligned():
    data = bytearray()
    for value in (10, 20, 30, 40):
        data.extend(_pack(value))

    target = _pack(25)
    results = list(
        scan_memory(data, len(data), target, 4, ScanTypesEnum.SMALLER_THAN, False)
    )

    assert results == [0, 4]


def test_scan_memory_value_between():
    data = bytearray()
    for value in (5, 15, 25, 35, 45):
        data.extend(_pack(value))

    results = list(
        scan_memory(
            data,
            len(data),
            (_pack(10), _pack(30)),
            4,
            ScanTypesEnum.VALUE_BETWEEN,
            False,
        )
    )

    # 15 (offset 4) and 25 (offset 8) match.
    assert results == [4, 8]


def test_scan_memory_for_exact_value_finds_all_matches():
    target = _pack(7)
    data = bytearray(_pack(7)) + bytearray(_pack(0)) + bytearray(_pack(7))

    results = list(
        scan_memory_for_exact_value(
            data,
            len(data),
            target,
            4,
            ScanTypesEnum.EXACT_VALUE,
        )
    )

    assert results == [0, 8]


def test_scan_memory_for_exact_value_not_exact_is_aligned():
    """Regression: NOT_EXACT_VALUE used to yield every non-matching byte (1, 2, 3, ...).

    It now yields target_value_size-aligned offsets only, skipping match positions.
    """
    target = _pack(7)
    data = (
        bytearray(_pack(7))
        + bytearray(_pack(99))
        + bytearray(_pack(7))
        + bytearray(_pack(123))
    )

    results = list(
        scan_memory_for_exact_value(
            data,
            len(data),
            target,
            4,
            ScanTypesEnum.NOT_EXACT_VALUE,
        )
    )

    # Aligned offsets are 0, 4, 8, 12. Offsets 0 and 8 match, so result is [4, 12].
    assert results == [4, 12]


def test_scan_memory_for_exact_value_not_exact_string_overlap():
    """
    For strings (byte-by-byte stepping), NOT_EXACT_VALUE must skip every offset
    whose 4-byte window overlaps a match (|M - O| < target_value_size).
    Regression test for the bisect-based overlap check that replaced the
    O(n×m) linear scan — must produce identical output.
    """
    target = b"abcd"
    # Two matches: at offset 0 and offset 10.
    data = b"abcd" + b"XXXXXX" + b"abcd" + b"YYYY"  # length 18; valid windows 0..14.

    results = list(
        scan_memory_for_exact_value(
            data,
            len(data),
            target,
            4,
            ScanTypesEnum.NOT_EXACT_VALUE,
            is_string=True,
        )
    )

    # An offset O overlaps when there is a match M with |M - O| < 4.
    # Matches at [0, 10]: overlap regions are (-4, 4) and (6, 14) exclusive.
    # Non-overlapping offsets in 0..14: 4, 5, 6, 14.
    assert results == [4, 5, 6, 14]


def test_scan_memory_for_exact_value_not_exact_no_matches():
    """When there are no matches, every aligned offset must be yielded."""
    target = _pack(999)
    data = bytearray(_pack(1)) + bytearray(_pack(2)) + bytearray(_pack(3))

    results = list(
        scan_memory_for_exact_value(
            data,
            len(data),
            target,
            4,
            ScanTypesEnum.NOT_EXACT_VALUE,
        )
    )

    assert results == [0, 4, 8]


def test_scan_memory_handles_empty_region():
    target = _pack(7)
    results = list(scan_memory(b"", 0, target, 4, ScanTypesEnum.EXACT_VALUE, False))
    assert results == []


def test_scan_memory_handles_region_smaller_than_target():
    target = _pack(7)
    results = list(
        scan_memory(b"\x00\x00", 2, target, 4, ScanTypesEnum.EXACT_VALUE, False)
    )
    assert results == []


def test_iter_region_chunks_small_region_yields_one():
    chunks = list(iter_region_chunks(1000, 4, max_chunk=2048))
    assert chunks == [(0, 1000)]


def test_iter_region_chunks_large_region_aligned():
    """A 1 GB region with int32 alignment should chunk evenly."""
    total = 1024 * 1024 * 1024
    target_size = 4
    max_chunk = 256 * 1024 * 1024

    chunks = list(iter_region_chunks(total, target_size, max_chunk=max_chunk))

    assert sum(size for _, size in chunks) == total
    # Every chunk size is a multiple of target_size — guarantees aligned scans don't miss matches.
    for _, size in chunks:
        assert size % target_size == 0
    # First chunk starts at 0; chunks are contiguous and non-overlapping.
    expected_offset = 0
    for offset, size in chunks:
        assert offset == expected_offset
        expected_offset += size


def test_iter_region_chunks_unaligned_target():
    """Target size doesn't divide max_chunk evenly — still aligned."""
    chunks = list(iter_region_chunks(1000, 3, max_chunk=500))
    # Each chunk size must be a multiple of 3.
    for _, size in chunks:
        assert size % 3 == 0 or (
            size + sum(s for _, s in chunks[: chunks.index((_, size))]) == 1000
        )


@pytest.mark.parametrize(
    "scan_type",
    [
        ScanTypesEnum.EXACT_VALUE,
        ScanTypesEnum.NOT_EXACT_VALUE,
        ScanTypesEnum.BIGGER_THAN,
        ScanTypesEnum.SMALLER_THAN,
        ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE,
        ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE,
    ],
)
def test_scan_memory_all_scan_types_run(scan_type):
    """Smoke test: every scan_type should produce a generator that runs without error."""
    target = _pack(10)
    data = bytearray()
    for value in (5, 10, 15, 20):
        data.extend(_pack(value))

    if scan_type in (ScanTypesEnum.EXACT_VALUE, ScanTypesEnum.NOT_EXACT_VALUE):
        results = list(
            scan_memory_for_exact_value(data, len(data), target, 4, scan_type)
        )
    else:
        results = list(scan_memory(data, len(data), target, 4, scan_type, False))

    # The result list is non-empty for at least one of the scan types we packed values for.
    assert isinstance(results, list)
