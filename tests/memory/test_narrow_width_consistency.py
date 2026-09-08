# -*- coding: utf-8 -*-

"""
Regression: an ``int`` width that is not 1, 2, 4 or 8 rounds up to the next C
type (``get_c_type_of(int, 3)`` is a ``c_int32``), and the two ways of reading
the same bytes disagreed about it.

``read_process_memory`` reads ``bufflength`` bytes into the front of that
wider, zero-initialised buffer and returns a value. ``convert_from_byte_array``
-- the path ``search_by_addresses`` goes through -- called
``from_buffer`` on an array of exactly ``bufflength`` bytes, which raised
``ValueError: Buffer size too small (3 instead of at least 4 bytes)``. That
error is caught by ``iter_values_for_addresses`` and turned into
``(address, None)``, so the address looked unreadable instead of erroring:
widths 3, 5, 6 and 7 silently returned nothing from a perfectly readable
address.

Both paths now zero-pad into the wider C type, so they agree by construction.
"""

import ctypes
import os
import sys

import pytest


if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402


# 8 distinct non-zero bytes, so a width that reads too few or too many bytes
# produces a different number rather than accidentally matching.
PAYLOAD = bytes(range(1, 9))


@pytest.mark.parametrize("width", [1, 2, 3, 4, 5, 6, 7, 8])
def test_search_by_addresses_agrees_with_a_direct_read_at_every_int_width(width):
    buffer = ctypes.create_string_buffer(PAYLOAD, len(PAYLOAD))
    address = ctypes.addressof(buffer)

    process = OpenProcess(pid=os.getpid())
    try:
        direct = process.read_process_memory(address, int, width)
        via_search = dict(process.search_by_addresses(int, width, [address]))[address]
    finally:
        process.close()

    # The None is the actual regression: the address is readable, and the
    # direct read proves it.
    assert via_search is not None
    assert via_search == direct


@pytest.mark.parametrize("width", [3, 5, 6, 7])
def test_a_narrow_int_read_uses_only_the_bytes_it_was_given(width):
    """The padding must be zeroes, not whatever follows the value in memory."""
    buffer = ctypes.create_string_buffer(PAYLOAD, len(PAYLOAD))
    address = ctypes.addressof(buffer)

    process = OpenProcess(pid=os.getpid())
    try:
        value = process.read_process_memory(address, int, width)
    finally:
        process.close()

    assert value == int.from_bytes(PAYLOAD[:width], "little")
