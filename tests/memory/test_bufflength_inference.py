# -*- coding: utf-8 -*-

"""
Cross-platform tests for `bufflength` inference. The default widths match the
ctypes types used internally: int→4 (c_int32), float→8 (c_double), bool→1.
"""

import ctypes
import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402
from PyMemoryEditor.util import (  # noqa: E402
    UNSET,
    resolve_bufflength,
    resolve_bufflength_for_value,
)


def test_resolve_bufflength_defaults():
    assert resolve_bufflength(int, None) == 4
    assert resolve_bufflength(float, None) == 8
    assert resolve_bufflength(bool, None) == 1


def test_resolve_bufflength_honors_explicit():
    assert resolve_bufflength(int, 8) == 8
    assert resolve_bufflength(float, 4) == 4
    assert resolve_bufflength(bool, 1) == 1


def test_resolve_bufflength_str_requires_explicit():
    with pytest.raises(ValueError):
        resolve_bufflength(str, None)


def test_resolve_bufflength_bytes_requires_explicit():
    with pytest.raises(ValueError):
        resolve_bufflength(bytes, None)


def test_read_process_memory_infers_int_size():
    """Without passing bufflength, int reads default to 4 bytes."""
    target = ctypes.c_int(0x4DEADBEE)
    address = ctypes.addressof(target)

    process = OpenProcess(pid=os.getpid())
    try:
        # Use the default bufflength.
        value = process.read_process_memory(address, int)
        assert value == 0x4DEADBEE
    finally:
        process.close()


def test_read_process_memory_infers_float_size():
    target = ctypes.c_double(3.14159)
    address = ctypes.addressof(target)

    process = OpenProcess(pid=os.getpid())
    try:
        value = process.read_process_memory(address, float)
        assert abs(value - 3.14159) < 1e-9
    finally:
        process.close()


def test_read_process_memory_str_requires_bufflength():
    target = ctypes.create_string_buffer(b"hello", 20)
    address = ctypes.addressof(target)

    process = OpenProcess(pid=os.getpid())
    try:
        with pytest.raises(ValueError, match="bufflength is required"):
            # str/bytes can't infer — variable width.
            process.read_process_memory(address, str)
    finally:
        process.close()


# --- resolve_bufflength_for_value (the search helper) ------------------- #


def test_resolve_for_value_numeric_uses_defaults():
    assert resolve_bufflength_for_value(int, None, 100) == 4
    assert resolve_bufflength_for_value(float, None, 1.0) == 8
    assert resolve_bufflength_for_value(bool, None, True) == 1


def test_resolve_for_value_honors_explicit():
    assert resolve_bufflength_for_value(int, 2, 100) == 2
    assert resolve_bufflength_for_value(str, 16, "hi") == 16


def test_resolve_for_value_infers_str_bytes_from_value():
    """Unlike a read, a search carries the value, so str/bytes infer the width."""
    assert resolve_bufflength_for_value(str, None, "hello") == 5
    assert resolve_bufflength_for_value(str, None, "olá") == 4  # UTF-8
    assert resolve_bufflength_for_value(bytes, None, b"\x01\x02\x03") == 3


def test_resolve_for_value_between_uses_longest_endpoint():
    assert resolve_bufflength_for_value(str, None, "a", "abcd") == 4
    assert resolve_bufflength_for_value(bytes, None, b"\x01", b"\x01\x02") == 2


def test_resolve_for_value_missing_value_raises():
    with pytest.raises(TypeError, match="a search value is required"):
        resolve_bufflength_for_value(int, None, UNSET)
    with pytest.raises(TypeError, match="a search value is required"):
        resolve_bufflength_for_value(str, None, "ok", UNSET)


# --- search_by_value / _between: bufflength is optional ----------------- #


def test_search_by_value_numeric_without_bufflength():
    """search_by_value(int, value=...) — no bufflength needed."""
    target = ctypes.c_int32(0x51A2B3C4)
    address = ctypes.addressof(target)

    process = OpenProcess(pid=os.getpid())
    try:
        found = list(process.search_by_value(int, value=0x51A2B3C4))
        assert address in found
    finally:
        process.close()


def test_search_by_value_str_infers_width():
    target = ctypes.create_string_buffer(b"PYMEMSEARCHMARKER")
    address = ctypes.addressof(target)

    process = OpenProcess(pid=os.getpid())
    try:
        found = list(process.search_by_value(str, value="PYMEMSEARCHMARKER"))
        assert address in found
    finally:
        process.close()


def test_search_by_value_between_without_bufflength():
    target = ctypes.c_int32(0x4242)
    address = ctypes.addressof(target)

    process = OpenProcess(pid=os.getpid())
    try:
        found = list(process.search_by_value_between(int, start=0x4241, end=0x4243))
        assert address in found
    finally:
        process.close()


def test_search_positional_form_still_works():
    target = ctypes.c_int32(0x1357)
    address = ctypes.addressof(target)

    process = OpenProcess(pid=os.getpid())
    try:
        assert address in list(process.search_by_value(int, 4, 0x1357))
        assert address in list(process.search_by_value_between(int, 4, 0x1356, 0x1358))
    finally:
        process.close()


def test_search_missing_value_raises():
    process = OpenProcess(pid=os.getpid())
    try:
        with pytest.raises(TypeError, match="a search value is required"):
            next(process.search_by_value(int))
        with pytest.raises(TypeError, match="a search value is required"):
            next(process.search_by_value_between(int, start=1))
    finally:
        process.close()


# --- search_by_addresses: bufflength optional for numeric --------------- #


def test_search_by_addresses_numeric_without_bufflength():
    a = ctypes.c_int32(111)
    b = ctypes.c_int32(222)
    addr_a, addr_b = ctypes.addressof(a), ctypes.addressof(b)

    process = OpenProcess(pid=os.getpid())
    try:
        result = dict(process.search_by_addresses(int, addresses=[addr_a, addr_b]))
        assert result[addr_a] == 111
        assert result[addr_b] == 222
    finally:
        process.close()


def test_search_by_addresses_positional_form_still_works():
    target = ctypes.c_int32(0x2468)
    address = ctypes.addressof(target)

    process = OpenProcess(pid=os.getpid())
    try:
        result = dict(process.search_by_addresses(int, 4, [address]))
        assert result[address] == 0x2468
    finally:
        process.close()


def test_search_by_addresses_str_still_requires_bufflength():
    """No value to infer from here — only addresses — so str/bytes still need it."""
    target = ctypes.c_int32(0)
    address = ctypes.addressof(target)

    process = OpenProcess(pid=os.getpid())
    try:
        with pytest.raises(ValueError, match="bufflength is required"):
            list(process.search_by_addresses(str, addresses=[address]))
    finally:
        process.close()


def test_search_by_addresses_missing_addresses_raises():
    process = OpenProcess(pid=os.getpid())
    try:
        with pytest.raises(TypeError, match="addresses is required"):
            list(process.search_by_addresses(int))
    finally:
        process.close()
