# -*- coding: utf-8 -*-

"""
Tests for ``read_process_memory_into`` — the zero-copy read that fills a
caller-owned, reusable buffer instead of allocating a fresh object per call
(GitHub issue #71).

As with the typed-accessor tests, we plant ctypes values on the test's own
heap and read them back through the public API.
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


def test_reads_into_bytearray(process):
    source = (ctypes.c_uint8 * 4)(0xDE, 0xAD, 0xBE, 0xEF)
    buffer = bytearray(4)

    read = process.read_process_memory_into(ctypes.addressof(source), buffer)

    assert read == 4
    assert bytes(buffer) == b"\xde\xad\xbe\xef"


def test_returns_buffer_byte_length(process):
    source = (ctypes.c_uint8 * 16)(*range(16))
    buffer = bytearray(16)

    assert process.read_process_memory_into(ctypes.addressof(source), buffer) == 16
    assert bytes(buffer) == bytes(source)


def test_buffer_can_be_reused_across_reads(process):
    """The whole point of the API: one buffer, many reads, no new objects."""
    first = (ctypes.c_uint8 * 8)(1, 2, 3, 4, 5, 6, 7, 8)
    second = (ctypes.c_uint8 * 8)(8, 7, 6, 5, 4, 3, 2, 1)
    buffer = bytearray(8)

    process.read_process_memory_into(ctypes.addressof(first), buffer)
    assert bytes(buffer) == bytes(first)

    process.read_process_memory_into(ctypes.addressof(second), buffer)
    assert bytes(buffer) == bytes(second)


def test_buffer_length_decides_how_many_bytes_are_read(process):
    """A 4-byte buffer reads exactly 4 bytes from an 8-byte source."""
    source = (ctypes.c_uint8 * 8)(0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44)
    buffer = bytearray(4)

    process.read_process_memory_into(ctypes.addressof(source), buffer)

    assert bytes(buffer) == b"\xaa\xbb\xcc\xdd"


def test_reads_into_ctypes_array(process):
    source = (ctypes.c_uint8 * 4)(0x01, 0x02, 0x03, 0x04)
    destination = (ctypes.c_uint8 * 4)()

    process.read_process_memory_into(ctypes.addressof(source), destination)

    assert bytes(destination) == b"\x01\x02\x03\x04"


def test_reads_into_writable_memoryview(process):
    source = (ctypes.c_uint8 * 4)(0x10, 0x20, 0x30, 0x40)
    backing = bytearray(4)

    process.read_process_memory_into(ctypes.addressof(source), memoryview(backing))

    assert bytes(backing) == b"\x10\x20\x30\x40"


def test_element_typed_buffer_sized_in_bytes(process):
    """A 2-element int32 buffer is 8 bytes, not 2."""
    source = (ctypes.c_int32 * 2)(0x01020304, 0x05060708)
    destination = (ctypes.c_int32 * 2)()

    read = process.read_process_memory_into(ctypes.addressof(source), destination)

    assert read == 8
    assert destination[0] == 0x01020304
    assert destination[1] == 0x05060708


def test_matches_read_process_memory(process):
    """The bytes filled in must equal the plain read_process_memory result."""
    source = (ctypes.c_uint8 * 6)(0x09, 0x08, 0x07, 0x06, 0x05, 0x04)
    addr = ctypes.addressof(source)

    expected = process.read_process_memory(addr, bytes, 6)
    buffer = bytearray(6)
    process.read_process_memory_into(addr, buffer)

    assert bytes(buffer) == expected


def test_read_only_buffer_is_rejected(process):
    source = (ctypes.c_uint8 * 4)(0, 0, 0, 0)
    with pytest.raises(TypeError):
        process.read_process_memory_into(ctypes.addressof(source), b"immutable")


def test_empty_buffer_is_rejected(process):
    source = (ctypes.c_uint8 * 4)(0, 0, 0, 0)
    with pytest.raises(ValueError):
        process.read_process_memory_into(ctypes.addressof(source), bytearray(0))


def test_non_buffer_is_rejected(process):
    source = (ctypes.c_uint8 * 4)(0, 0, 0, 0)
    with pytest.raises(TypeError):
        process.read_process_memory_into(ctypes.addressof(source), 12345)
