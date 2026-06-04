# -*- coding: utf-8 -*-

"""
Tests for the ``str`` / ``bytes`` write-width semantics of
``write_process_memory`` (see ``util.convert.prepare_write``).

``bufflength`` is a *minimum* field width for these types, not a hard cap:
the whole value is always written (counting characters, not bytes, must not
raise), shorter values NUL-pad up to ``bufflength``, and ``None`` writes
exactly the encoded length.
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


def test_prepare_write_multibyte_grows_to_fit():
    """"olá" is 3 characters but 4 UTF-8 bytes — width must grow, not raise."""
    pytype, length, raw = prepare_write(str, 3, "olá")
    assert pytype is bytes
    assert length == 4
    assert raw == "olá".encode("utf-8")


def test_prepare_write_pads_up_to_bufflength():
    pytype, length, raw = prepare_write(str, 16, "AB")
    assert pytype is bytes
    assert length == 16
    assert raw == b"AB" + b"\x00" * 14


def test_prepare_write_none_uses_encoded_length():
    pytype, length, raw = prepare_write(str, None, "héllo")
    assert pytype is bytes
    assert length == 6  # 'é' is two bytes
    assert raw == "héllo".encode("utf-8")


def test_prepare_write_bytes_grows_and_pads():
    assert prepare_write(bytes, 2, b"\x01\x02\x03\x04") == (bytes, 4, b"\x01\x02\x03\x04")
    assert prepare_write(bytes, 4, b"\x01\x02") == (bytes, 4, b"\x01\x02\x00\x00")
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
    # 3 characters, 4 bytes — would have raised ValueError before.
    assert process.write_process_memory(ctypes.addressof(buffer), str, 3, "olá") == "olá"
    assert process.read_string(ctypes.addressof(buffer), 8) == "olá"


def test_write_returns_original_value_not_bytes(process):
    """str writes must return the original str, not the routed-through bytes."""
    buffer = ctypes.create_string_buffer(16)
    result = process.write_process_memory(ctypes.addressof(buffer), str, 16, "name")
    assert result == "name"
    assert isinstance(result, str)


def test_write_pads_fixed_field(process):
    """Writing a short string into a wider field clears the trailing bytes."""
    buffer = (ctypes.c_uint8 * 8)(*([0xFF] * 8))
    process.write_process_memory(ctypes.addressof(buffer), str, 8, "AB")
    assert process.read_bytes(ctypes.addressof(buffer), 8) == b"AB" + b"\x00" * 6


def test_write_bytes_round_trip_grows(process):
    buffer = (ctypes.c_uint8 * 4)()
    process.write_process_memory(ctypes.addressof(buffer), bytes, 2, b"\xde\xad\xbe\xef")
    assert process.read_bytes(ctypes.addressof(buffer), 4) == b"\xde\xad\xbe\xef"


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
