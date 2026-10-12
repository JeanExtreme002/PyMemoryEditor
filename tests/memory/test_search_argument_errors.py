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


def test_a_search_encodes_its_value_and_compiles_its_pattern_once(monkeypatch):
    """The public method validates and encodes at the call, then hands the
    result to the backend: the backend must not redo either."""
    import importlib

    process = OpenProcess(pid=os.getpid())
    backend = importlib.import_module(
        type(process).__module__.rsplit(".", 1)[0] + ".functions"
    )

    def must_not_run(*args, **kwargs):
        raise AssertionError("the backend repeated work the call already did")

    monkeypatch.setattr(backend, "values_to_bytes", must_not_run)
    monkeypatch.setattr(backend, "compile_pattern", must_not_run)
    try:
        assert list(process.search_by_value(int, value=7, memory_regions=[])) == []
        assert list(process.search_by_value_between(
            int, start=1, end=9, memory_regions=[]
        )) == []
        assert list(process.search_by_pattern("90 ? 90", memory_regions=[])) == []
    finally:
        process.close()


# --------------------------------------------------------------------------- #
# Eager validation helper for the generator-returning search methods
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "pytype, width, value",
    [
        (int, 4, 2 ** 40),        # does not fit
        (float, 5, 1.0),          # no 5-byte float
        (str, 0, ""),             # zero-width target
        (str, 2, "abc"),          # longer than the width
        (bool, 2, True),          # wider than c_bool
        (list, 4, 1),             # unsupported type
        (int, 4, (1, 2 ** 40)),   # one end of a range does not fit
    ],
)
def test_prepare_search_target_raises_what_the_scan_would(pytype, width, value):
    from PyMemoryEditor.util import prepare_search_target

    with pytest.raises(ValueError):
        prepare_search_target(pytype, width, value)


def test_prepare_search_target_returns_the_scan_encoding():
    from PyMemoryEditor.util import prepare_search_target, values_to_bytes

    assert prepare_search_target(int, 4, -1) == b"\xff" * 4
    assert prepare_search_target(int, 2, (1, 2)) == values_to_bytes(int, 2, (1, 2))
    assert prepare_search_target(str, 3, "hi") == b"hi\x00"
