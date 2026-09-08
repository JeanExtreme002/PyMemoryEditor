# -*- coding: utf-8 -*-

"""A write of N bytes must touch exactly N bytes, on every platform.

All three backends size their buffer with ``get_c_type_of(pytype, bufflength)``,
which *rounds up* to the next C type — an ``int`` of 3 bytes gets a 4-byte
``c_int32``. Windows and macOS then hand ``bufflength`` to the syscall; the
Linux backend used to hand ``sizeof(data)``, so a 3-byte write destroyed a
fourth byte the caller never asked to touch, and a 5-byte write destroyed
three. Verified on Linux before the fix: ``w=3`` touched 4 bytes, ``w=5``
touched 8.

The read side disagreed too, less destructively but more confusingly: the same
``read_process_memory(addr, int, 3)`` returned ``0x11223344`` on Linux and
``0x223344`` on macOS.

These tests run on all three CI platforms, which is the only place the
divergence is visible — each backend looks self-consistent in isolation.
"""

import ctypes
import os

import pytest

from PyMemoryEditor import OpenProcess


FILLER = 0xAA


def _touched(raw: bytes) -> int:
    """How many leading bytes of ``raw`` are no longer the filler."""
    for index in range(len(raw)):
        if raw[index:] == bytes([FILLER]) * (len(raw) - index):
            return index
    return len(raw)


@pytest.fixture
def scratch():
    """A 16-byte buffer full of a recognisable filler byte."""
    buffer = (ctypes.c_char * 16)(*bytes([FILLER]) * 16)
    return buffer, ctypes.addressof(buffer)


@pytest.mark.parametrize(
    "bufflength, value",
    [
        (1, 0x01),
        (2, 0x0102),
        # The widths that round up to a wider C type — where the divergence was.
        (3, 0x010203),
        (4, 0x01020304),
        (5, 0x0102030405),
        (6, 0x010203040506),
        (7, 0x01020304050607),
        (8, 0x0102030405060708),
    ],
)
def test_an_int_write_touches_exactly_its_width(scratch, bufflength, value):
    buffer, address = scratch
    with OpenProcess(pid=os.getpid()) as process:
        process.write_process_memory(address, int, bufflength, value)

    assert _touched(bytes(buffer)) == bufflength


@pytest.mark.parametrize("bufflength", [4, 8])
def test_a_float_write_touches_exactly_its_width(scratch, bufflength):
    buffer, address = scratch
    with OpenProcess(pid=os.getpid()) as process:
        process.write_process_memory(address, float, bufflength, 2.5)

    assert _touched(bytes(buffer)) == bufflength


def test_a_bool_write_touches_one_byte(scratch):
    buffer, address = scratch
    with OpenProcess(pid=os.getpid()) as process:
        process.write_process_memory(address, bool, 1, True)

    assert _touched(bytes(buffer)) == 1


@pytest.mark.parametrize(
    "bufflength, expected",
    [(1, 0x44), (2, 0x3344), (3, 0x223344), (4, 0x11223344)],
)
def test_an_int_read_returns_exactly_its_width(bufflength, expected):
    """The read must not widen either: 3 bytes of 0x11223344 is 0x223344."""
    value = ctypes.c_int(0x11223344)
    with OpenProcess(pid=os.getpid()) as process:
        assert (
            process.read_process_memory(
                ctypes.addressof(value), int, bufflength
            )
            == expected
        )


def test_a_narrow_write_leaves_its_neighbour_alone(scratch):
    """The concrete damage, stated directly.

    A 3-byte write next to a marker byte must not disturb the marker — which
    is exactly what the Linux backend used to do.
    """
    buffer, address = scratch
    marker = 0x5A
    buffer[3] = bytes([marker])

    with OpenProcess(pid=os.getpid()) as process:
        process.write_process_memory(address, int, 3, 0x010203)

    assert bytes(buffer)[3] == marker
