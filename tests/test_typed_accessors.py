# -*- coding: utf-8 -*-

"""
Tests for the typed convenience read/write helpers on ``AbstractProcess``
(``read_int``, ``write_float``, ``read_ulonglong``, ``read_string`` ...).

They are thin wrappers over ``read_process_memory`` / ``write_process_memory``,
so the goal here is to confirm each one targets the right byte width and
signedness. We plant ctypes values on the test's own heap and read them back
through the typed methods, and round-trip writes through the matching reads.
"""

import ctypes
import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402


@pytest.fixture
def process():
    handle = OpenProcess(pid=os.getpid())
    try:
        yield handle
    finally:
        handle.close()


# (method name, ctypes type, planted value) — signed integer family.
SIGNED_INT_CASES = [
    ("read_char", ctypes.c_int8, -7),
    ("read_short", ctypes.c_int16, -1234),
    ("read_int", ctypes.c_int32, -123456),
    ("read_long", ctypes.c_int32, -123456),
    ("read_longlong", ctypes.c_int64, -1234567890123),
]

# Unsigned integer family — values with the top bit set so a signed misread
# would surface as a negative number.
UNSIGNED_INT_CASES = [
    ("read_uchar", ctypes.c_uint8, 0xFF),
    ("read_ushort", ctypes.c_uint16, 0xFFFE),
    ("read_uint", ctypes.c_uint32, 0xFFFFFFFE),
    ("read_ulong", ctypes.c_uint32, 0xFFFFFFFE),
    ("read_ulonglong", ctypes.c_uint64, 0xFFFFFFFFFFFFFFFE),
]


@pytest.mark.parametrize("method, ctype, value", SIGNED_INT_CASES)
def test_signed_int_readers(process, method, ctype, value):
    holder = ctype(value)
    result = getattr(process, method)(ctypes.addressof(holder))
    assert result == value


@pytest.mark.parametrize("method, ctype, value", UNSIGNED_INT_CASES)
def test_unsigned_int_readers(process, method, ctype, value):
    holder = ctype(value)
    result = getattr(process, method)(ctypes.addressof(holder))
    assert result == value
    assert result > 0  # must never sign-extend into a negative


def test_unsigned_reader_width_isolation(process):
    """An unsigned read must not bleed bytes from neighbouring memory."""
    buffer = (ctypes.c_uint8 * 8)(0xFE, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD)
    # read_uchar at offset 0 must see only the 0xFE byte, not the trailing junk.
    assert process.read_uchar(ctypes.addressof(buffer)) == 0xFE


def test_float_and_double(process):
    f = ctypes.c_float(3.5)
    d = ctypes.c_double(2.718281828)
    assert process.read_float(ctypes.addressof(f)) == pytest.approx(3.5)
    assert process.read_double(ctypes.addressof(d)) == pytest.approx(2.718281828)


def test_bool(process):
    t = ctypes.c_bool(True)
    f = ctypes.c_bool(False)
    assert process.read_bool(ctypes.addressof(t)) is True
    assert process.read_bool(ctypes.addressof(f)) is False


def test_read_string_stops_at_nul(process):
    buffer = ctypes.create_string_buffer(b"hello\x00leftover", 32)
    assert process.read_string(ctypes.addressof(buffer), 32) == "hello"


def test_read_bytes_verbatim(process):
    buffer = (ctypes.c_uint8 * 4)(0xDE, 0xAD, 0xBE, 0xEF)
    assert process.read_bytes(ctypes.addressof(buffer), 4) == b"\xde\xad\xbe\xef"


# --- write round-trips -------------------------------------------------- #


def test_write_signed_round_trip(process):
    holder = ctypes.c_int32(0)
    assert process.write_int(ctypes.addressof(holder), -98765) == -98765
    assert process.read_int(ctypes.addressof(holder)) == -98765


def test_write_unsigned_round_trip(process):
    holder = ctypes.c_uint64(0)
    big = 0xFFFFFFFFFFFFFFFE
    assert process.write_ulonglong(ctypes.addressof(holder), big) == big
    assert process.read_ulonglong(ctypes.addressof(holder)) == big


def test_write_float_round_trip(process):
    holder = ctypes.c_float(0.0)
    process.write_float(ctypes.addressof(holder), 1.25)
    assert process.read_float(ctypes.addressof(holder)) == pytest.approx(1.25)


def test_write_bool_round_trip(process):
    holder = ctypes.c_bool(False)
    process.write_bool(ctypes.addressof(holder), True)
    assert process.read_bool(ctypes.addressof(holder)) is True


def test_write_string_round_trip(process):
    buffer = ctypes.create_string_buffer(32)
    assert process.write_string(ctypes.addressof(buffer), "héllo") == "héllo"
    assert process.read_string(ctypes.addressof(buffer), 32) == "héllo"


def test_write_string_default_no_terminator(process):
    """By default write_string writes just the characters — the tail survives."""
    buffer = ctypes.create_string_buffer(b"XXXXXXXX", 16)
    process.write_string(ctypes.addressof(buffer), "ab")
    # 'ab' overwrote the first two bytes; the rest of the field is untouched.
    assert process.read_bytes(ctypes.addressof(buffer), 4) == b"abXX"


def test_write_string_with_terminator(process):
    """null_terminator=True NUL-terminates so the old tail isn't read back."""
    buffer = ctypes.create_string_buffer(b"helloworld", 32)
    process.write_string(ctypes.addressof(buffer), "hi", null_terminator=True)
    assert process.read_string(ctypes.addressof(buffer), 32) == "hi"


def test_write_string_multibyte_does_not_raise(process):
    """Counting characters, not bytes, must succeed for write_string too."""
    buffer = ctypes.create_string_buffer(16)
    process.write_string(ctypes.addressof(buffer), "ção")
    assert process.read_string(ctypes.addressof(buffer), 16) == "ção"


def test_write_bytes_round_trip(process):
    buffer = (ctypes.c_uint8 * 4)()
    process.write_bytes(ctypes.addressof(buffer), b"\x01\x02\x03\x04")
    assert process.read_bytes(ctypes.addressof(buffer), 4) == b"\x01\x02\x03\x04"
