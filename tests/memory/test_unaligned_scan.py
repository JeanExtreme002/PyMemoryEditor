# -*- coding: utf-8 -*-

"""
``search_by_value(..., aligned=False)`` against this process: a 4-byte int
planted at an odd address is invisible to the default aligned scan and found
by the opt-in byte-granular one.
"""

import ctypes
import os
import struct

import pytest

from PyMemoryEditor import OpenProcess

SENTINEL = 0x5EC0DE42


@pytest.fixture(scope="module")
def process():
    with OpenProcess(pid=os.getpid()) as handle:
        yield handle


def _region_containing(process, address):
    for region in process.get_memory_regions():
        if region.address <= address < region.address + region.size:
            return region
    pytest.skip("could not map the buffer to a region")


def test_unaligned_int_is_found_only_with_aligned_false(process):
    buffer = ctypes.create_string_buffer(64)
    base = ctypes.addressof(buffer)
    # Pick an offset that puts the value at an address that is not a multiple
    # of 4, whatever the buffer's own alignment.
    offset = 3 if base % 4 == 0 else (4 - base % 4) + 3
    struct.pack_into("<I", buffer, offset, SENTINEL)
    planted = base + offset
    assert planted % 4 != 0

    regions = [_region_containing(process, planted)]

    found_aligned = list(
        process.search_by_value(int, 4, value=SENTINEL, memory_regions=regions)
    )
    found_loose = list(
        process.search_by_value(int, 4, value=SENTINEL, memory_regions=regions, aligned=False)
    )

    assert planted not in found_aligned
    assert planted in found_loose
    # Inside the buffer the byte-granular scan reports exactly the planted
    # address. (Outside it, our own heap holds transient copies of the target
    # whose presence depends on allocation order, so they are not compared.)
    inside = range(base, base + 64)
    assert [a for a in found_aligned if a in inside] == []
    assert [a for a in found_loose if a in inside] == [planted]


def test_aligned_flag_does_not_change_a_str_scan(process):
    buffer = ctypes.create_string_buffer(b"..pymemoryeditor-unaligned-probe..", 64)
    base = ctypes.addressof(buffer)
    regions = [_region_containing(process, base)]

    default = list(
        process.search_by_value(str, value="pymemoryeditor-unaligned-probe", memory_regions=regions)
    )
    loose = list(
        process.search_by_value(
            str, value="pymemoryeditor-unaligned-probe", memory_regions=regions, aligned=False
        )
    )

    # Compare inside the buffer only: scanning our own heap also turns up
    # transient copies of the target (the encoded search value, a freed
    # temporary) whose presence depends on allocation order, not on the flag.
    inside = range(base, base + 64)
    assert base + 2 in default
    assert [a for a in default if a in inside] == [a for a in loose if a in inside] == [base + 2]
