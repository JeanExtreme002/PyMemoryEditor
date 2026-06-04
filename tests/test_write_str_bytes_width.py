# -*- coding: utf-8 -*-

"""
Tests for the ``str`` / ``bytes`` write-width semantics of
``write_process_memory`` (see ``util.convert.prepare_write``).

``bufflength`` is a *maximum* width for these types that truncates the value
and never pads: for ``str`` the cap counts characters (applied before UTF-8
encoding, so multibyte characters are never split), for ``bytes`` it counts
bytes, shorter values are written as-is, and ``None`` writes the whole value.
"""

import ctypes
import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402
from PyMemoryEditor.util import UNSET, prepare_write  # noqa: E402


@pytest.fixture
def process():
    handle = OpenProcess(pid=os.getpid())
    try:
        yield handle
    finally:
        handle.close()


# --- prepare_write unit tests (platform-independent) -------------------- #


def test_prepare_write_caps_by_characters_not_bytes():
    """The cap counts characters: "óólá" capped at 2 keeps "óó" (4 UTF-8 bytes)."""
    pytype, length, raw = prepare_write(str, 2, "óólá")
    assert pytype is bytes
    assert raw == "óó".encode("utf-8")
    assert length == 4


def test_prepare_write_multibyte_within_cap_kept_whole():
    """"olá" is 3 characters (4 bytes); cap of 3 keeps it whole, never splits."""
    pytype, length, raw = prepare_write(str, 3, "olá")
    assert pytype is bytes
    assert raw == "olá".encode("utf-8")
    assert length == 4


def test_prepare_write_truncates_to_char_cap():
    assert prepare_write(str, 3, "ola") == (bytes, 3, b"ola")
    assert prepare_write(str, 2, "ola") == (bytes, 2, b"ol")


def test_prepare_write_shorter_than_cap_is_not_padded():
    pytype, length, raw = prepare_write(str, 16, "AB")
    assert pytype is bytes
    assert length == 2
    assert raw == b"AB"


def test_prepare_write_none_uses_encoded_length():
    pytype, length, raw = prepare_write(str, None, "héllo")
    assert pytype is bytes
    assert length == 6  # 'é' is two bytes
    assert raw == "héllo".encode("utf-8")


def test_prepare_write_bytes_caps_by_bytes():
    assert prepare_write(bytes, 2, b"\x01\x02\x03\x04") == (bytes, 2, b"\x01\x02")
    assert prepare_write(bytes, 4, b"\x01\x02") == (bytes, 2, b"\x01\x02")
    assert prepare_write(bytes, None, b"\x01\x02") == (bytes, 2, b"\x01\x02")


def test_prepare_write_numeric_unchanged():
    assert prepare_write(int, None, 5) == (int, 4, 5)
    assert prepare_write(int, 8, 5) == (int, 8, 5)
    assert prepare_write(float, None, 1.0) == (float, 8, 1.0)
    assert prepare_write(bool, None, True) == (bool, 1, True)


def test_prepare_write_rejects_non_str_bytes_value():
    with pytest.raises(TypeError):
        prepare_write(bytes, 4, 1234)


def test_prepare_write_rejects_missing_value():
    """The UNSET sentinel (caller never passed ``value``) raises a clear error."""
    with pytest.raises(TypeError, match="missing required argument: 'value'"):
        prepare_write(str, None, UNSET)


# --- end-to-end writes against our own memory --------------------------- #


def test_write_multibyte_string_does_not_raise(process):
    """The headline case: counting characters must not raise on multibyte."""
    buffer = ctypes.create_string_buffer(8)
    # 3 characters, 4 bytes — the cap counts characters, so it stays whole.
    assert process.write_process_memory(ctypes.addressof(buffer), str, 3, "olá") == "olá"
    assert process.read_string(ctypes.addressof(buffer), 8) == "olá"


def test_write_caps_string_to_char_count(process):
    """A string longer than the cap is truncated by character count."""
    buffer = ctypes.create_string_buffer(8)
    assert process.write_process_memory(ctypes.addressof(buffer), str, 2, "óólá") == "óólá"
    # Only the first 2 characters ("óó", 4 bytes) reach memory.
    assert process.read_string(ctypes.addressof(buffer), 4) == "óó"


def test_write_returns_original_value_not_bytes(process):
    """str writes must return the original str, not the routed-through bytes."""
    buffer = ctypes.create_string_buffer(16)
    result = process.write_process_memory(ctypes.addressof(buffer), str, 16, "name")
    assert result == "name"
    assert isinstance(result, str)


def test_write_shorter_than_cap_does_not_pad(process):
    """A string shorter than the cap writes only its own bytes — no padding."""
    buffer = (ctypes.c_uint8 * 8)(*([0xFF] * 8))
    process.write_process_memory(ctypes.addressof(buffer), str, 8, "AB")
    # Only the 2 written bytes change; the rest keep their previous value.
    assert process.read_bytes(ctypes.addressof(buffer), 8) == b"AB" + b"\xff" * 6


def test_write_bytes_capped_to_bufflength(process):
    buffer = (ctypes.c_uint8 * 4)()
    process.write_process_memory(ctypes.addressof(buffer), bytes, 2, b"\xde\xad\xbe\xef")
    # Only the first 2 bytes are written; the rest stay zero.
    assert process.read_bytes(ctypes.addressof(buffer), 4) == b"\xde\xad\x00\x00"


# --- bufflength is now optional: value may be passed by keyword ---------- #


def test_write_str_value_by_keyword_without_bufflength(process):
    """write_process_memory(addr, str, value="hi") — no bufflength needed."""
    buffer = ctypes.create_string_buffer(8)
    result = process.write_process_memory(ctypes.addressof(buffer), str, value="hi")
    assert result == "hi"
    assert process.read_string(ctypes.addressof(buffer), 8) == "hi"


def test_write_int_value_by_keyword_without_bufflength(process):
    """Numeric writes default to their natural width (int→4) when omitted."""
    buffer = (ctypes.c_uint8 * 4)()
    assert process.write_process_memory(ctypes.addressof(buffer), int, value=99) == 99
    assert process.read_process_memory(ctypes.addressof(buffer), int, 4) == 99


def test_write_bytes_value_by_keyword_without_bufflength(process):
    buffer = (ctypes.c_uint8 * 2)()
    process.write_process_memory(ctypes.addressof(buffer), bytes, value=b"\x01\x02")
    assert process.read_bytes(ctypes.addressof(buffer), 2) == b"\x01\x02"


def test_write_positional_call_still_works(process):
    """The original 4-positional-arg form is unchanged."""
    buffer = (ctypes.c_uint8 * 4)()
    assert process.write_process_memory(ctypes.addressof(buffer), int, 4, 1234) == 1234
    assert process.read_process_memory(ctypes.addressof(buffer), int, 4) == 1234


def test_write_missing_value_raises(process):
    """Omitting value entirely is still an error, with a clear message."""
    buffer = (ctypes.c_uint8 * 4)()
    with pytest.raises(TypeError, match="missing required argument: 'value'"):
        process.write_process_memory(ctypes.addressof(buffer), int)
