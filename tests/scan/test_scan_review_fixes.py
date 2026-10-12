# -*- coding: utf-8 -*-

"""
Regression tests for the scan-layer review findings:

  - pattern scans report overlapping matches for fixed-width patterns, the way
    a value scan for the same bytes does;
  - ordered comparisons of ``bytes`` are lexicographic (big-endian), like
    ``str`` and like Python's own ``bytes`` comparison;
  - the NumPy fast path yields its offsets lazily, block by block;
  - ``iter_values_for_addresses`` reads only the bytes the requested values
    need, reads a value that runs into the next contiguous region, and lets a
    programming error escape ``raise_error=False``;
  - every scan driver accepts any iterable of regions, and a
    ``MemoryRegionSnapshot`` passes through untouched.

Everything runs against fake regions and a fake ``read_chunk`` — no process.
"""

import ctypes
import random
import re
import struct

import pytest

from PyMemoryEditor.enums import ScanTypesEnum
from PyMemoryEditor.process import scanning
from PyMemoryEditor.process.errors import ClosedProcess
from PyMemoryEditor.process.region import MemoryRegion, MemoryRegionSnapshot
from PyMemoryEditor.process.scanning import (
    _ensure_sorted_by_address,
    iter_pattern_results,
    iter_search_results,
    iter_values_for_addresses,
)
from PyMemoryEditor.util import scan_numpy
from PyMemoryEditor.util.pattern import compile_pattern, is_fixed_width
from PyMemoryEditor.util.scan import (
    _iter_large_region_chunks,
    scan_memory,
    scan_memory_for_exact_value,
)


class FakeMemory:
    """A sparse address space: ``{base: payload}``, with a recording reader."""

    def __init__(self, segments, *, readable=True):
        self.segments = dict(segments)
        self.regions = [
            MemoryRegion(address=base, size=len(data), is_readable=readable)
            for base, data in sorted(self.segments.items())
        ]
        self.reads = []

    def read_chunk(self, address, size):
        """Serve ``[address, address + size)`` if it is fully mapped by
        consecutive segments, else raise ``OSError`` (EFAULT)."""
        self.reads.append((address, size))
        out = b""
        cursor = address
        end = address + size
        for base, data in sorted(self.segments.items()):
            seg_end = base + len(data)
            if base <= cursor < seg_end:
                take = min(end, seg_end) - cursor
                out += data[cursor - base : cursor - base + take]
                cursor += take
                if cursor == end:
                    break
        if cursor != end:
            raise OSError(14, "Bad address")
        return (ctypes.c_byte * size).from_buffer_copy(out)


def _small_chunks(monkeypatch, max_chunk):
    """Force ``iter_region_chunks`` (as the scan drivers see it) to split every
    region into ``max_chunk``-byte chunks, so chunk-boundary rules are hit with
    tiny buffers."""
    monkeypatch.setattr(
        scanning,
        "iter_region_chunks",
        lambda size, width: tuple(_iter_large_region_chunks(size, width, max_chunk)),
    )


# --------------------------------------------------------------------------- #
# Pattern scans: overlapping matches
# --------------------------------------------------------------------------- #

def _pattern_hits(memory, pattern, byte_length=0):
    compiled, length = compile_pattern(pattern, byte_length=byte_length)
    return list(
        iter_pattern_results(memory.regions, compiled, length, memory.read_chunk)
    )


def test_ida_pattern_reports_overlapping_matches():
    memory = FakeMemory({0x1000: b"\x90\x90\x90"})
    assert _pattern_hits(memory, "90 90") == [0x1000, 0x1001]


def test_ida_pattern_agrees_with_exact_byte_scan():
    data = bytes(random.Random(7).choice((0x90, 0x90, 0xCC)) for _ in range(512))
    memory = FakeMemory({0x4000: data})
    exact = [
        0x4000 + offset
        for offset in scan_memory_for_exact_value(
            data, len(data), b"\x90\x90\x90", 3, ScanTypesEnum.EXACT_VALUE, bytes
        )
    ]
    assert _pattern_hits(memory, "90 90 90") == exact
    assert len(exact) > 10  # the data really has overlapping runs


def test_overlapping_matches_across_chunk_boundaries_are_reported_once(monkeypatch):
    _small_chunks(monkeypatch, 4)
    memory = FakeMemory({0x1000: b"\x90" * 10})
    assert _pattern_hits(memory, "90 90") == [0x1000 + i for i in range(9)]


def test_fixed_width_regex_reports_overlapping_matches():
    memory = FakeMemory({0x1000: b"ABABAB"})
    assert _pattern_hits(memory, rb"AB.B", byte_length=4) == [0x1000, 0x1002]


def test_variable_width_regex_keeps_non_overlapping_semantics():
    """A suffix of a variable-length match is not a new match."""
    memory = FakeMemory({0x1000: b"..john@example.com.."})
    email = rb"[a-z]+@[a-z]+\.[a-z]+"
    assert _pattern_hits(memory, email, byte_length=32) == [0x1002]


def test_lookahead_regex_reports_every_start():
    memory = FakeMemory({0x1000: b"AAAA"})
    assert _pattern_hits(memory, rb"(?=AA)", byte_length=2) == [0x1000, 0x1001, 0x1002]


def test_zero_width_pattern_terminates():
    memory = FakeMemory({0x1000: b"AB"})
    assert _pattern_hits(memory, rb"(?=)", byte_length=1) == [0x1000, 0x1001]


@pytest.mark.parametrize(
    "pattern, expected",
    [
        (rb"\x48\x8B..", True),
        (rb"ab|cd", True),
        (rb"ab|c", False),
        (rb"PLAYER_\d+", False),
        (rb"x{2,4}", False),
    ],
)
def test_is_fixed_width(pattern, expected):
    assert is_fixed_width(re.compile(pattern, re.DOTALL)) is expected


def test_ida_patterns_are_fixed_width():
    assert is_fixed_width(compile_pattern("48 8B ? ? 00")[0])


# --------------------------------------------------------------------------- #
# Ordered comparisons of bytes: lexicographic, like str
# --------------------------------------------------------------------------- #

def test_bytes_bigger_than_is_lexicographic():
    data = b"\x01\x00\x00\x01"
    by_bytes = list(scan_memory(data, 4, b"\x00\x01", 2, ScanTypesEnum.BIGGER_THAN, bytes))
    by_str = list(scan_memory(data, 4, b"\x00\x01", 2, ScanTypesEnum.BIGGER_THAN, str))
    assert by_bytes == by_str == [0]


@pytest.mark.parametrize(
    "scan_type, check",
    [
        (ScanTypesEnum.BIGGER_THAN, lambda w, t: w > t),
        (ScanTypesEnum.SMALLER_THAN, lambda w, t: w < t),
        (ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE, lambda w, t: w >= t),
        (ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE, lambda w, t: w <= t),
    ],
)
def test_bytes_ordered_scan_matches_python_bytes_comparison(scan_type, check):
    """What a refine that compares the bytes it reads back would keep (the GUI
    next scan does exactly that) must be what the first scan found."""
    rng = random.Random(scan_type.value)
    data = bytes(rng.randrange(256) for _ in range(400))
    target = bytes((0x80, 0x10, 0x00))
    found = list(scan_memory(data, len(data), target, 3, scan_type, bytes))
    expected = [
        offset
        for offset in range(len(data) - 2)
        if check(data[offset : offset + 3], target)
    ]
    assert found == expected


def test_bytes_value_between_is_lexicographic():
    data = b"\x00\x05\x01\x00\x02\x00"
    found = list(
        scan_memory(
            data, len(data), (b"\x00\x06", b"\x01\x80"), 2, ScanTypesEnum.VALUE_BETWEEN, bytes
        )
    )
    expected = [
        offset
        for offset in range(len(data) - 1)
        if b"\x00\x06" <= data[offset : offset + 2] <= b"\x01\x80"
    ]
    assert found == expected == [2]  # 01 00 (host little-endian order found nothing)


# --------------------------------------------------------------------------- #
# NumPy fast path: lazy, block by block
# --------------------------------------------------------------------------- #

numpy_only = pytest.mark.skipif(not scan_numpy.NUMPY_AVAILABLE, reason="NumPy not installed")


@numpy_only
def test_numpy_scan_offsets_is_lazy():
    buffer = struct.pack("<8i", *range(8))
    offsets = scan_numpy.scan_offsets(
        buffer, 4, ScanTypesEnum.NOT_EXACT_VALUE, int, "little", 0, 0, 0
    )
    assert offsets is not None
    assert not isinstance(offsets, list)
    assert next(iter(offsets)) == 4


@numpy_only
@pytest.mark.parametrize("scan_type", list(ScanTypesEnum))
def test_numpy_blocks_match_struct_loop(monkeypatch, scan_type):
    """Tiny blocks force many block boundaries; the offsets must still be the
    struct loop's, in the same order."""
    rng = random.Random(scan_type.value)
    values = [rng.randrange(-50, 50) for _ in range(103)]
    buffer = struct.pack("<%di" % len(values), *values)
    target = (struct.pack("<i", -10), struct.pack("<i", 20))
    if scan_type not in (ScanTypesEnum.VALUE_BETWEEN, ScanTypesEnum.NOT_VALUE_BETWEEN):
        target = target[0]

    monkeypatch.setattr(scan_numpy, "NUMPY_AVAILABLE", False)
    expected = list(scan_memory(buffer, len(buffer), target, 4, scan_type, int))
    monkeypatch.setattr(scan_numpy, "NUMPY_AVAILABLE", True)
    monkeypatch.setattr(scan_numpy, "_BLOCK_ELEMENTS", 7)
    found = list(scan_memory(buffer, len(buffer), target, 4, scan_type, int))

    assert found == expected


@numpy_only
def test_numpy_unaligned_merge_still_works_with_lazy_phases(monkeypatch):
    monkeypatch.setattr(scan_numpy, "_BLOCK_ELEMENTS", 3)
    buffer = b"\x00" + struct.pack("<i", 7) * 5 + b"\x00\x00\x00"
    found = list(
        scan_memory(buffer, len(buffer), struct.pack("<i", 7), 4,
                    ScanTypesEnum.EXACT_VALUE, int, aligned=False)
    )
    assert found == [1, 5, 9, 13, 17]


# --------------------------------------------------------------------------- #
# iter_values_for_addresses: narrow reads
# --------------------------------------------------------------------------- #

def _values(memory, addresses, **kwargs):
    return list(
        iter_values_for_addresses(addresses, memory.regions, int, 4, memory.read_chunk, **kwargs)
    )


def test_address_reads_cover_only_the_requested_values():
    payload = bytearray(1 << 20)
    struct.pack_into("<i", payload, 0x10, 11)
    struct.pack_into("<i", payload, 0x18, 22)
    struct.pack_into("<i", payload, 0x80000, 33)
    memory = FakeMemory({0x100000: bytes(payload)})

    results = _values(memory, [0x100000 + 0x80000, 0x100010, 0x100018])

    assert results == [(0x100010, 11), (0x100018, 22), (0x180000, 33)]
    # Two windows (the far address is > 64 KiB away), each just big enough.
    assert memory.reads == [(0x100010, 12), (0x180000, 4)]


def test_address_reads_respect_chunk_boundaries(monkeypatch):
    """A value right at the end of a chunk still decodes from bytes of the
    next chunk; every address is reported exactly once, in order."""
    _small_chunks(monkeypatch, 8)
    payload = struct.pack("<6i", 1, 2, 3, 4, 5, 6)
    memory = FakeMemory({0x1000: payload})
    addresses = [0x1000 + 4 * i for i in range(6)] + [0x1006]
    results = _values(memory, addresses)
    assert [addr for addr, _ in results] == sorted(addresses)
    assert [v for a, v in results if a % 4 == 0] == [1, 2, 3, 4, 5, 6]
    assert dict(results)[0x1006] == struct.unpack("<i", payload[6:10])[0]
    assert all(size <= 8 + 3 for _, size in memory.reads)


def test_failed_window_only_affects_its_own_addresses():
    payload = bytearray(1 << 20)
    struct.pack_into("<i", payload, 0x90000, 99)
    memory = FakeMemory({0x100000: bytes(payload)})
    real_read = memory.read_chunk

    def flaky(address, size):
        if address == 0x100000:
            raise OSError(14, "Bad address")
        return real_read(address, size)

    results = list(
        iter_values_for_addresses([0x100000, 0x190000], memory.regions, int, 4, flaky)
    )
    assert results == [(0x100000, None), (0x190000, 99)]


def test_duplicate_addresses_are_all_reported():
    memory = FakeMemory({0x1000: struct.pack("<i", 5)})
    assert _values(memory, [0x1000, 0x1000]) == [(0x1000, 5), (0x1000, 5)]


# --------------------------------------------------------------------------- #
# iter_values_for_addresses: values that run into the next region
# --------------------------------------------------------------------------- #

def test_value_straddling_into_adjacent_region_is_read():
    value = struct.pack("<i", 0x12345678)
    memory = FakeMemory({0x1000: b"\x00" * 6 + value[:2], 0x1008: value[2:] + b"\x00" * 6})
    assert _values(memory, [0x1006]) == [(0x1006, 0x12345678)]


def test_value_straddling_across_several_small_regions_is_read():
    value = struct.pack("<i", -2)
    memory = FakeMemory({0x1000: value[:1], 0x1001: value[1:2], 0x1002: value[2:]})
    assert _values(memory, [0x1000]) == [(0x1000, -2)]


def test_value_straddling_into_a_gap_is_none():
    memory = FakeMemory({0x1000: b"\x00" * 8, 0x1010: b"\x00" * 8})
    assert _values(memory, [0x1006]) == [(0x1006, None)]
    assert memory.reads == []  # nothing worth reading


def test_value_straddling_into_unreadable_region_is_none_even_with_raise_error():
    memory = FakeMemory({0x1000: b"\x00" * 8, 0x1008: b"\x00" * 8})
    regions = [memory.regions[0], MemoryRegion(0x1008, 8, is_readable=False)]
    results = list(
        iter_values_for_addresses(
            [0x1006], regions, int, 4, memory.read_chunk, raise_error=True
        )
    )
    assert results == [(0x1006, None)]


def test_straddling_value_read_failure_follows_error_semantics():
    memory = FakeMemory({0x1000: b"\x00" * 8, 0x1008: b"\x00" * 8})

    def failing(address, size):
        raise OSError(13, "Permission denied")

    assert list(
        iter_values_for_addresses([0x1006], memory.regions, int, 4, failing)
    ) == [(0x1006, None)]
    with pytest.raises(OSError):
        list(
            iter_values_for_addresses(
                [0x1006], memory.regions, int, 4, failing, raise_error=True
            )
        )


# --------------------------------------------------------------------------- #
# iter_values_for_addresses: which exceptions mean "unreadable"
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("error", [OSError(14, "Bad address"), ClosedProcess()])
def test_io_errors_become_none_without_raise_error(error):
    memory = FakeMemory({0x1000: b"\x00" * 4})

    def failing(address, size):
        raise error

    assert list(
        iter_values_for_addresses([0x1000], memory.regions, int, 4, failing)
    ) == [(0x1000, None)]


@pytest.mark.parametrize("error", [TypeError("bug"), AttributeError("bug"), MemoryError()])
def test_programming_errors_propagate_without_raise_error(error):
    memory = FakeMemory({0x1000: b"\x00" * 4})

    def failing(address, size):
        raise error

    with pytest.raises(type(error)):
        list(iter_values_for_addresses([0x1000], memory.regions, int, 4, failing))


# --------------------------------------------------------------------------- #
# Region inputs: any iterable; the snapshot tag survives
# --------------------------------------------------------------------------- #

def test_snapshot_passes_through_unsorted_check():
    snapshot = MemoryRegionSnapshot([MemoryRegion(0x1000, 4), MemoryRegion(0x2000, 4)])
    assert _ensure_sorted_by_address(snapshot) is snapshot


def test_any_iterable_is_sorted_into_a_list():
    regions = [MemoryRegion(0x2000, 4), MemoryRegion(0x1000, 4)]
    result = _ensure_sorted_by_address(region for region in regions)
    assert [r.address for r in result] == [0x1000, 0x2000]
    assert _ensure_sorted_by_address(iter(())) == []


def test_address_reads_accept_a_generator_of_regions():
    memory = FakeMemory({0x1000: struct.pack("<i", 3), 0x2000: struct.pack("<i", 4)})
    results = list(
        iter_values_for_addresses(
            [0x1000, 0x2000], (r for r in reversed(memory.regions)), int, 4, memory.read_chunk
        )
    )
    assert results == [(0x1000, 3), (0x2000, 4)]


def test_scan_drivers_accept_a_generator_of_regions():
    memory = FakeMemory({0x1000: struct.pack("<2i", 7, 7)})
    found = list(
        iter_search_results(
            (r for r in memory.regions), int, 4, struct.pack("<i", 7),
            ScanTypesEnum.EXACT_VALUE, memory.read_chunk,
        )
    )
    assert found == [0x1000, 0x1004]

    compiled, length = compile_pattern("07 00")
    found = list(
        iter_pattern_results(
            (r for r in memory.regions), compiled, length, memory.read_chunk,
            progress_information=True,
        )
    )
    assert [address for address, _info in found] == [0x1000, 0x1004]


# --------------------------------------------------------------------------- #
# Variable-width regex across a chunk boundary; overlap past the region end
# --------------------------------------------------------------------------- #

def test_variable_width_match_straddling_a_chunk_is_reported_once(monkeypatch):
    """The overlap bytes of chunk 1 are chunk 2's first bytes: chunk 2 used to
    report the suffix ``BB`` of the ``BBBB`` match chunk 1 already reported."""
    _small_chunks(monkeypatch, 8)
    memory = FakeMemory({0x1000: b"......BBBB" + b"." * 10})
    assert _pattern_hits(memory, rb"B+", byte_length=4) == [0x1006]


def test_variable_width_matches_agree_with_one_finditer(monkeypatch):
    """Chunked non-overlapping results equal a single ``finditer`` over the
    region whenever no match is longer than ``byte_length``."""
    rng = random.Random(11)
    data = bytes(rng.choice(b"AB..") for _ in range(400))
    pattern = rb"A[AB]{0,3}"
    expected = [0x1000 + m.start() for m in re.finditer(pattern, data, re.DOTALL)]
    for chunk in (4, 5, 8, 13):
        _small_chunks(monkeypatch, chunk)
        assert _pattern_hits(FakeMemory({0x1000: data}), pattern, byte_length=4) == expected


def test_chunk_overlap_never_reads_past_the_region(monkeypatch):
    """With a width that does not divide the chunk size, the last chunk is
    shorter than the overlap; reading the full overlap ran past the region
    into unmapped memory and failed the read."""
    _small_chunks(monkeypatch, 8)
    data = b"." * 5 + b"ab@c.de" + b"." * 30  # 42 bytes: last chunk is 2 bytes
    memory = FakeMemory({0x1000: data})  # nothing mapped after the region
    email = rb"[a-z]+@[a-z]+\.[a-z]+"
    assert _pattern_hits(memory, email, byte_length=8) == [0x1005]
    assert all(addr + size <= 0x1000 + len(data) for addr, size in memory.reads)

    memory = FakeMemory({0x1000: data})
    found = list(iter_search_results(
        memory.regions, bytes, 7, b"ab@c.de", ScanTypesEnum.EXACT_VALUE,
        memory.read_chunk,
    ))
    assert found == [0x1005]
    assert all(addr + size <= 0x1000 + len(data) for addr, size in memory.reads)


# --------------------------------------------------------------------------- #
# Eager validation helper for the generator-returning search methods
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "pytype, width, value",
    [
        (int, 4, 2 ** 40),        # does not fit
        (float, 5, 1.0),          # no 5-byte float
        (str, 0, ""),             # zero-width target
        (str, 2, "abc"),          # longer than the width
        (bool, 2, True),          # wider than c_bool
        (list, 4, 1),             # unsupported type
        (int, 4, (1, 2 ** 40)),   # one end of a range does not fit
    ],
)
def test_prepare_search_target_raises_what_the_scan_would(pytype, width, value):
    from PyMemoryEditor.util import prepare_search_target

    with pytest.raises(ValueError):
        prepare_search_target(pytype, width, value)


def test_prepare_search_target_returns_the_scan_encoding():
    from PyMemoryEditor.util import prepare_search_target, values_to_bytes

    assert prepare_search_target(int, 4, -1) == b"\xff" * 4
    assert prepare_search_target(int, 2, (1, 2)) == values_to_bytes(int, 2, (1, 2))
    assert prepare_search_target(str, 3, "hi") == b"hi\x00"
