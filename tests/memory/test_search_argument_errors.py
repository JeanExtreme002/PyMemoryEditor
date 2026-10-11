# -*- coding: utf-8 -*-

"""
The error a caller sees for the two most common search-argument mistakes:
passing the value where ``bufflength`` goes, and searching for an empty
``str`` / ``bytes``.
"""

import ctypes
import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)

from PyMemoryEditor import OpenProcess  # noqa: E402
from PyMemoryEditor.util import UNSET, resolve_bufflength_for_value, value_to_bytes  # noqa: E402


def test_a_value_passed_as_bufflength_is_pointed_out():
    """``search_by_value(int, 100)`` binds 100 to ``bufflength``; the message
    must say so instead of only "none was provided"."""
    with pytest.raises(TypeError, match=r"bufflength=100 was received") as info:
        resolve_bufflength_for_value(int, 100, UNSET)
    assert "value=100" in str(info.value)

    # Without a bufflength there is nothing to point at.
    with pytest.raises(TypeError) as info:
        resolve_bufflength_for_value(int, None, UNSET)
    assert "bufflength=" not in str(info.value)


def test_search_by_value_positional_trap_is_explained_end_to_end():
    process = OpenProcess(pid=os.getpid())
    try:
        with pytest.raises(TypeError, match="value=100"):
            next(process.search_by_value(int, 100))
    finally:
        process.close()


def test_value_too_long_for_bufflength_names_both_widths():
    """ctypes' own "byte string too long" said neither which width nor whose."""
    with pytest.raises(ValueError, match=r"too long for bufflength 2: str encodes to 5 bytes"):
        value_to_bytes(str, 2, "hello")
    with pytest.raises(ValueError, match=r"too long for bufflength 1: bytes encodes to 3 bytes"):
        value_to_bytes(bytes, 1, bytearray(b"abc"))
    # Exactly fitting and shorter values are still NUL-padded to the width.
    assert value_to_bytes(str, 5, "hello") == b"hello"
    assert value_to_bytes(bytes, 4, b"ab") == b"ab\x00\x00"


@pytest.mark.parametrize("pytype, value", [(str, ""), (bytes, b"")])
def test_an_empty_text_search_is_rejected(pytype, value):
    """A zero-width target matched at every address (one past the end of each
    region included)."""
    marker = ctypes.create_string_buffer(b"MARKER", 8)
    process = OpenProcess(pid=os.getpid())
    try:
        regions = [
            region for region in process.snapshot_memory_regions()
            if region.address <= ctypes.addressof(marker) < region.address + region.size
        ]
        with pytest.raises(ValueError, match="must not be empty"):
            next(process.search_by_value(pytype, value=value, memory_regions=regions))
    finally:
        process.close()
