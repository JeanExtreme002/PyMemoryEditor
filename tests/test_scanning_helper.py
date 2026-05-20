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

import pytest

from PyMemoryEditor.process.scanning import iter_values_for_addresses


def _make_region(address: int, payload: bytes) -> dict:
    """Build a fake region dict matching what get_memory_regions() yields."""
    return {"address": address, "size": len(payload), "_payload": payload}


def _make_reader(regions):
    """
    Return a `read_chunk(addr, size)` that serves bytes out of the fake region
    list. Raises OSError(EFAULT) when the read straddles or sits outside any
    region (simulating process_vm_readv behavior).
    """

    def read_chunk(address: int, size: int):
        for region in regions:
            base = region["address"]
            end = base + region["size"]
            if base <= address and address + size <= end:
                offset = address - base
                slice_ = region["_payload"][offset : offset + size]
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
