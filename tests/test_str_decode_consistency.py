# -*- coding: utf-8 -*-

"""
Regression: `read_process_memory(addr, str, n)` used to call `bytes(data).decode()`
without `errors="replace"`, while `convert_from_byte_array` (used by
`search_by_addresses`) decoded with `errors="replace"`. The same raw memory
could therefore raise UnicodeDecodeError on one path and succeed on the other.

Both code paths now use `errors="replace"`.
"""

import ctypes
import os
import sys

import pytest


if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402


def test_read_str_with_non_utf8_bytes_does_not_raise():
    """Bytes 0x80..0xFF are invalid UTF-8 starts; the read must not raise."""
    # 0xFF is a continuation byte without lead — invalid UTF-8.
    buffer = ctypes.create_string_buffer(b"\xff\xfe\xfd\xfc", 4)
    address = ctypes.addressof(buffer)

    process = OpenProcess(pid=os.getpid())
    try:
        value = process.read_process_memory(address, str, 4)
        # Each invalid byte becomes U+FFFD (the replacement character).
        assert isinstance(value, str)
    finally:
        process.close()


def test_read_str_matches_search_by_addresses_decoding():
    """Both APIs should agree on the decoded form of the same bytes."""
    buffer = ctypes.create_string_buffer(b"\xc3\x28\xff hi", 6)
    address = ctypes.addressof(buffer)

    process = OpenProcess(pid=os.getpid())
    try:
        direct = process.read_process_memory(address, str, 6)
        via_search = dict(process.search_by_addresses(str, 6, [address]))[address]
        assert direct == via_search
    finally:
        process.close()
