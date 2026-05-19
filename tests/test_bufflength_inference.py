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
from PyMemoryEditor.util import resolve_bufflength  # noqa: E402


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
