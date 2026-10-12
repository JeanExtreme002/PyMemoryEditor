# -*- coding: utf-8 -*-

"""
Tests for the cross-backend `iter_values_for_addresses` helper.

These exercise the two correctness fixes the helper was extracted to enforce:
1. Addresses that fall in gaps between (or outside) memory regions must yield
   `(address, None)` — the previous per-backend code silently dropped them.
2. Addresses whose `[address, address+bufflength)` extends past the end of
   their containing region must yield `(address, None)` — the previous code
   read short and silently zero-padded.
"""

import ctypes
import struct

import pytest

from PyMemoryEditor.enums import ScanTypesEnum
from PyMemoryEditor.process import scanning
from PyMemoryEditor.process.errors import ClosedProcess
from PyMemoryEditor.process.region import MemoryRegion
from PyMemoryEditor.process.scanning import (
    iter_pattern_results,
    iter_search_results,
    iter_values_for_addresses,
)
from PyMemoryEditor.util.pattern import compile_pattern

from ._fakes import FakeMemory, small_chunks


# Tests build fake regions as ``MemoryRegion`` instances and keep the payload
# bytes in a side-channel dict keyed by base address (the dataclass is frozen,
# so attaching a payload to the region itself isn't an option). The
# ``_make_reader`` closure walks the regions and serves bytes from that dict.
_FAKE_PAYLOADS: "dict[int, bytes]" = {}


def _make_region(address: int, payload: bytes) -> MemoryRegion:
    """Build a fake region matching what get_memory_regions() yields."""
    _FAKE_PAYLOADS[address] = payload
    return MemoryRegion(address=address, size=len(payload), is_readable=True)


def _make_reader(regions):
    """
    Return a `read_chunk(addr, size)` that serves bytes out of the fake region
    list. Raises OSError(EFAULT) when the read straddles or sits outside any
    region (simulating process_vm_readv behavior).
    """

    def read_chunk(address: int, size: int):
        for region in regions:
            base = region.address
            end = base + region.size
            if base <= address and address + size <= end:
                offset = address - base
                slice_ = _FAKE_PAYLOADS[base][offset : offset + size]
                buf = (ctypes.c_byte * len(slice_))()
                ctypes.memmove(buf, slice_, len(slice_))
                return buf
        raise OSError(14, "EFAULT")  # 14 == EFAULT on Linux

    return read_chunk


def test_gap_between_regions_yields_none():
    # Region A covers [0x1000, 0x1010), gap, region B covers [0x2000, 0x2010).
    region_a = _make_region(0x1000, b"\x01\x00\x00\x00" * 4)  # four int32 = 1
    region_b = _make_region(0x2000, b"\x02\x00\x00\x00" * 4)
    regions = [region_a, region_b]

    # 0x1800 falls in the gap. It must come back as (addr, None) instead of
    # being silently dropped.
    addresses = [0x1000, 0x1800, 0x2000]

    results = list(
        iter_values_for_addresses(
            addresses, regions, int, 4, _make_reader(regions), raise_error=False
        )
    )

    assert results == [(0x1000, 1), (0x1800, None), (0x2000, 2)]


def test_address_before_first_region_yields_none():
    region = _make_region(0x2000, b"\x01\x00\x00\x00")
    results = list(
        iter_values_for_addresses(
            [0x1000, 0x2000], [region], int, 4, _make_reader([region])
        )
    )
    assert results == [(0x1000, None), (0x2000, 1)]


def test_address_after_last_region_yields_none():
    region = _make_region(0x1000, b"\x01\x00\x00\x00")
    results = list(
        iter_values_for_addresses(
            [0x1000, 0x5000], [region], int, 4, _make_reader([region])
        )
    )
    assert results == [(0x1000, 1), (0x5000, None)]


def test_value_straddling_region_end_yields_none():
    """
    The last 3 bytes of the region don't have enough room for a 4-byte int.
    The previous backends silently zero-padded; the helper must reject it.
    """
    # 8-byte region; only addresses [0x1000..0x1004] can hold an int32.
    region = _make_region(0x1000, b"\xAA" * 8)
    addresses = [0x1000, 0x1005, 0x1007]  # last two straddle the end

    results = list(
        iter_values_for_addresses(
            addresses, [region], int, 4, _make_reader([region])
        )
    )

    # 0x1000 has 4 valid bytes; 0x1005 leaves only 3 bytes; 0x1007 only 1.
    assert results[0][0] == 0x1000
    assert results[0][1] is not None
    assert results[1] == (0x1005, None)
    assert results[2] == (0x1007, None)


def test_transient_read_failure_yields_none_silently():
    """A read failure classified as transient must not propagate."""
    region = _make_region(0x1000, b"\x01\x00\x00\x00")

    def read_chunk(address: int, size: int):
        raise OSError(14, "EFAULT")  # always fail

    def is_transient(exc):
        return isinstance(exc, OSError) and exc.errno == 14

    results = list(
        iter_values_for_addresses(
            [0x1000],
            [region],
            int,
            4,
            read_chunk,
            raise_error=True,  # would propagate if not classified as transient
            transient_error_check=is_transient,
        )
    )

    assert results == [(0x1000, None)]


def test_non_transient_read_failure_propagates_when_requested():
    region = _make_region(0x1000, b"\x01\x00\x00\x00")

    def read_chunk(address: int, size: int):
        raise OSError(13, "EACCES")  # non-transient

    # raise_error=True must propagate non-transient failures.
    with pytest.raises(OSError):
        list(
            iter_values_for_addresses(
                [0x1000],
                [region],
                int,
                4,
                read_chunk,
                raise_error=True,
            )
        )


def test_non_transient_read_failure_swallowed_when_not_requested():
    region = _make_region(0x1000, b"\x01\x00\x00\x00")

    def read_chunk(address: int, size: int):
        raise OSError(13, "EACCES")

    results = list(
        iter_values_for_addresses(
            [0x1000], [region], int, 4, read_chunk, raise_error=False
        )
    )
    assert results == [(0x1000, None)]


def test_addresses_are_processed_in_sorted_order():
    """Helper must sort addresses before walking regions so a misordered input
    doesn't lose hits."""
    region_a = _make_region(0x1000, b"\xAA" * 4)
    region_b = _make_region(0x2000, b"\xBB" * 4)
    regions = [region_a, region_b]

    # Pass addresses out of order.
    results = list(
        iter_values_for_addresses(
            [0x2000, 0x1000], regions, int, 4, _make_reader(regions)
        )
    )
    addrs = [addr for addr, _ in results]
    assert sorted(addrs) == [0x1000, 0x2000]
    assert len(results) == 2


# --------------------------------------------------------------------------- #
# before_read: a check run before every read, never classified as a skip
# --------------------------------------------------------------------------- #


class _TargetGone(Exception):
    """Stands in for ProcessIDNotExistsError raised by a backend's check."""


def _countdown(reads_allowed):
    """A ``before_read`` that lets ``reads_allowed`` reads through, then raises."""
    calls = []

    def before_read():
        calls.append(1)
        if len(calls) > reads_allowed:
            raise _TargetGone()

    before_read.calls = calls
    return before_read


def test_before_read_runs_before_every_address_read_and_is_never_swallowed():
    # The Linux backend reads by pid and checks, before each read, that the pid
    # is still the process it opened. With raise_error=False a failed read
    # turns into (address, None) -- the check's error must not.
    region_a = _make_region(0x1000, b"\x01\x00\x00\x00" * 4)
    region_b = _make_region(0x9000, b"\x02\x00\x00\x00" * 4)
    regions = [region_a, region_b]
    before_read = _countdown(1)

    results = iter_values_for_addresses(
        [0x1000, 0x9000], regions, int, 4, _make_reader(regions),
        raise_error=False, transient_error_check=lambda exc: True,
        before_read=before_read,
    )
    assert next(results) == (0x1000, 1)
    with pytest.raises(_TargetGone):
        next(results)
    assert len(before_read.calls) == 2


def test_before_read_runs_before_every_scan_chunk(monkeypatch):
    monkeypatch.setattr(scanning, "iter_region_chunks", _chunks_of(16))
    region = _make_region(0x4000, b"\x07\x00\x00\x00" * 12)  # 48 bytes: 3 chunks
    reader = _make_reader([region])

    before_read = _countdown(3)
    found = list(iter_search_results(
        [region], int, 4, b"\x07\x00\x00\x00", ScanTypesEnum.EXACT_VALUE, reader,
        transient_error_check=lambda exc: True, before_read=before_read,
    ))
    assert len(found) == 12 and len(before_read.calls) == 3

    before_read = _countdown(1)
    compiled, length = compile_pattern("07 00 00 00")
    scan = iter_pattern_results(
        [region], compiled, length, reader,
        transient_error_check=lambda exc: True, before_read=before_read,
    )
    assert [next(scan) for _ in range(4)] == [0x4000, 0x4004, 0x4008, 0x400C]
    with pytest.raises(_TargetGone):
        next(scan)


def _chunks_of(chunk_size):
    """``iter_region_chunks`` capped at a small chunk size."""
    from PyMemoryEditor.util.scan import iter_region_chunks

    return lambda size, width: iter_region_chunks(size, width, max_chunk=chunk_size)


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
    small_chunks(monkeypatch, 8)
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
