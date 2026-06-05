# -*- coding: utf-8 -*-

"""
Write/encode-path safety tests.

Failure modes that must never pass silently for a memory-editing tool:

1. An ``int`` value too large for the requested byte width. ``ctypes`` would
   wrap it (``write_int(addr, 2**40)`` storing ``0`` into a 4-byte slot) and
   ``write_process_memory`` would report success — silent target corruption.
   The check lives in ``util.convert._check_int_fits`` and guards every numeric
   coercion point: the signed write path (``prepare_write``), the unsigned
   helpers (``AbstractProcess._write_unsigned``), the public ``RemotePointer``
   setter, and the *search-target* encoder (``value_to_bytes``) — where the same
   wrap would otherwise make ``search_by_value(int, value=2**40)`` quietly match
   every zeroed slot instead of erroring.

2. A write to an unmapped / read-only address. The OS rejects it and the backend
   must surface that as an ``OSError`` rather than swallowing it. Runs against
   the test process itself, so it exercises whichever backend the CI matrix is
   running on (Win32 / Linux / macOS all covered across the matrix).
"""

import ctypes
import os
import sys

import pytest

from PyMemoryEditor import OpenProcess
from PyMemoryEditor.util.convert import prepare_write


# --------------------------------------------------------------------------- #
# (1) int range validation — prepare_write is the single point all three
#     backends route writes through, so unit-testing it here covers them all.
# --------------------------------------------------------------------------- #

def test_prepare_write_rejects_int_too_large_for_width():
    # 2**40 needs 6 bytes; into a 4-byte field ctypes would silently store 0.
    with pytest.raises(ValueError):
        prepare_write(int, 4, 2**40)


def test_prepare_write_rejects_int_too_negative_for_width():
    # One below the signed 4-byte floor (-2**31) must be rejected.
    with pytest.raises(ValueError):
        prepare_write(int, 4, -(2**31) - 1)


def test_prepare_write_rejects_just_past_unsigned_ceiling():
    # 2**32 - 1 fits (see below); 2**32 does not.
    with pytest.raises(ValueError):
        prepare_write(int, 4, 2**32)


@pytest.mark.parametrize(
    "length, value",
    [
        (4, 0),
        (4, 2**31 - 1),       # signed max
        (4, -(2**31)),        # signed min
        (4, 0xFFFFFFFF),      # unsigned max — same bit pattern as -1, allowed
        (1, 255),             # unsigned byte max
        (1, -128),            # signed byte min
        (8, 2**63 - 1),
        (8, 2**64 - 1),
    ],
)
def test_prepare_write_accepts_values_that_fit(length, value):
    pytype, out_length, out_value = prepare_write(int, length, value)
    assert pytype is int
    assert out_length == length
    assert out_value == value


def test_write_int_overflow_raises_instead_of_truncating():
    """Regression: write_int(addr, 2**40) used to wrap to 0 and report success."""
    process = OpenProcess(pid=os.getpid())
    try:
        target = ctypes.c_int64(0)
        address = ctypes.addressof(target)

        with pytest.raises(ValueError):
            process.write_int(address, 2**40)

        # The bogus write must not have touched memory.
        assert process.read_longlong(address) == 0

        # A value that fits still round-trips unchanged.
        process.write_int(address, 1234)
        assert process.read_int(address) == 1234
    finally:
        process.close()


@pytest.mark.parametrize("method, value", [
    ("write_char", 2**20),
    ("write_short", 2**20),
    ("write_longlong", 2**80),
])
def test_signed_int_helpers_reject_out_of_range(method, value):
    """Every signed convenience writer routes through the same validation."""
    process = OpenProcess(pid=os.getpid())
    try:
        target = ctypes.c_int64(0)
        address = ctypes.addressof(target)
        with pytest.raises(ValueError):
            getattr(process, method)(address, value)
        # Nothing was written.
        assert process.read_longlong(address) == 0
    finally:
        process.close()


@pytest.mark.parametrize("method, value", [
    ("write_uchar", 2**20),   # over the 1-byte unsigned ceiling
    ("write_uint", 2**40),    # over the 4-byte unsigned ceiling
    ("write_uint", -1),       # negative is invalid for an unsigned write
    ("write_ulonglong", 2**80),
])
def test_unsigned_int_helpers_raise_value_error_not_overflow(method, value):
    """
    The unsigned helpers go through _write_unsigned (int.to_bytes), which used
    to leak a bare OverflowError. They must now raise the same clear ValueError
    as the signed path — and must not corrupt memory.
    """
    process = OpenProcess(pid=os.getpid())
    try:
        target = ctypes.c_int64(0)
        address = ctypes.addressof(target)
        with pytest.raises(ValueError):
            getattr(process, method)(address, value)
        assert process.read_longlong(address) == 0

        # Unsigned high values that DO fit still round-trip (bit pattern intact).
        process.write_uint(address, 0xFFFFFFFE)
        assert process.read_uint(address) == 0xFFFFFFFE
    finally:
        process.close()


# --------------------------------------------------------------------------- #
# (1b) the SAME silent-truncation class on the search-target encoder.
#      search_by_value(int, value=2**40) used to encode the target as 0 and
#      quietly match every zeroed slot — value_to_bytes now rejects it.
# --------------------------------------------------------------------------- #

def test_value_to_bytes_rejects_out_of_range_int():
    from PyMemoryEditor.util.convert import value_to_bytes

    with pytest.raises(ValueError):
        value_to_bytes(int, 4, 2**40)
    with pytest.raises(ValueError):
        value_to_bytes(int, 1, 999)
    # A value that fits is encoded normally.
    assert value_to_bytes(int, 4, 1) == (1).to_bytes(4, sys.byteorder)


def test_search_by_value_out_of_range_raises_instead_of_matching_zero():
    process = OpenProcess(pid=os.getpid())
    try:
        # The generator encodes the target eagerly enough that pulling the first
        # item surfaces the validation error rather than a bogus match on zeros.
        with pytest.raises(ValueError):
            next(process.search_by_value(int, value=2**40))
    finally:
        process.close()


def test_search_by_value_between_out_of_range_raises():
    """The range encoder routes each endpoint through value_to_bytes too."""
    process = OpenProcess(pid=os.getpid())
    try:
        with pytest.raises(ValueError):
            next(process.search_by_value_between(int, 4, 0, 2**40))
    finally:
        process.close()


def test_remote_pointer_value_setter_rejects_out_of_range():
    """The public RemotePointer write surface inherits the same validation."""
    process = OpenProcess(pid=os.getpid())
    try:
        target = ctypes.c_int32(0)
        ptr = process.get_pointer(ctypes.addressof(target), pytype=int, bufflength=4)
        with pytest.raises(ValueError):
            ptr.value = 2**40
        # Memory untouched, and an in-range write still works.
        assert target.value == 0
        ptr.value = 4242
        assert target.value == 4242
    finally:
        process.close()


# --------------------------------------------------------------------------- #
# (2) write to an invalid address must raise, not silently no-op.
# --------------------------------------------------------------------------- #

def test_write_to_unmapped_address_raises():
    """Page 0 is never mapped; a write there must surface an OSError."""
    process = OpenProcess(pid=os.getpid())
    try:
        # 7 fits in 4 bytes, so this gets past range validation and reaches the
        # OS write, which the kernel rejects for the unmapped low page.
        with pytest.raises(OSError):
            process.write_int(0x1, 7)
    finally:
        process.close()
