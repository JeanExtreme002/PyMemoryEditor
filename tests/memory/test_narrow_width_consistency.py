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

The padding is then sign-extended. Zero padding read every narrow value as
unsigned, while a scan is signed on both of its own sides
(``decode_scan_target`` and the unusual-width branch of ``scan_memory`` both
pass ``signed=True``), so ``search_by_value(int, 3, value=-1)`` matched an
address that every read then reported as 16777215. Signed wins: every C type
this library uses for ``int`` is signed, and there is no unsigned ``pytype``
to express the other intent.
"""

import ctypes
import os
import struct
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
    """The padding must not be whatever follows the value in memory."""
    buffer = ctypes.create_string_buffer(PAYLOAD, len(PAYLOAD))
    address = ctypes.addressof(buffer)

    process = OpenProcess(pid=os.getpid())
    try:
        value = process.read_process_memory(address, int, width)
    finally:
        process.close()

    assert value == int.from_bytes(PAYLOAD[:width], "little", signed=True)


# The bytes that make the signedness visible: a narrow value with its top bit
# set. PAYLOAD alone cannot catch a sign bug -- 0x01..0x08 are all below 0x80,
# so signed and unsigned agree on every prefix of it.
@pytest.mark.parametrize("raw, width, expected", [
    (b"\xff\xff\xff", 3, -1),
    (b"\x00\x00\x80", 3, -(1 << 23)),        # most negative 3-byte value
    (b"\xff\xff\x7f", 3, (1 << 23) - 1),     # most positive 3-byte value
    (b"\xff\xff\xff\xff\xff", 5, -1),
    (b"\xff\xff\xff\xff\xff\xff", 6, -1),
    (b"\xff\xff\xff\xff\xff\xff\xff", 7, -1),
])
def test_a_narrow_int_read_is_signed(raw, width, expected):
    buffer = ctypes.create_string_buffer(raw + b"\x00", len(raw) + 1)
    address = ctypes.addressof(buffer)

    process = OpenProcess(pid=os.getpid())
    try:
        direct = process.read_process_memory(address, int, width)
        via_search = dict(process.search_by_addresses(int, width, [address]))[address]
    finally:
        process.close()

    assert direct == expected
    assert via_search == expected


@pytest.mark.parametrize("width", [3, 5, 6, 7])
def test_a_scan_and_a_read_agree_on_a_negative_narrow_value(width):
    """The asymmetry itself: the scan matched -1 and the read denied it.

    Asserted end to end rather than on the helpers, because the two halves are
    reached through completely different code (`scan_memory`'s unusual-width
    fallback against the backend read path) and only agree if both are signed.
    """
    raw = b"\xff" * width
    buffer = ctypes.create_string_buffer(raw + b"\x00", len(raw) + 1)
    address = ctypes.addressof(buffer)

    process = OpenProcess(pid=os.getpid())
    try:
        regions = [
            region for region in process.snapshot_memory_regions()
            if region.address <= address < region.address + region.size
        ]
        matched = address in set(
            process.search_by_value(int, width, value=-1, memory_regions=regions)
        )
        read_back = process.read_process_memory(address, int, width)
    finally:
        process.close()

    assert matched, "the scan must still find the address it always found"
    assert read_back == -1, "and the read must not contradict it"


# --------------------------------------------------------------------------- #
# A narrow `float` is not a narrow value at all
# --------------------------------------------------------------------------- #
#
# The sign-extension fix above needed a "the C type is wider than the width"
# branch, and that branch was not restricted to `int`. `get_c_type_of(float, 3)`
# is a `c_double`, so three real bytes and five zeroes came back reinterpreted
# as a mantissa: 5.52603e-318. Before that branch existed, `from_buffer` raised
# and `iter_values_for_addresses` turned it into an honest `(address, None)`.
#
# So the fix traded "this width is not readable" for a number that looks like a
# measurement -- which is the failure the MCP layer's own VALID_NUMERIC_WIDTHS
# comment calls out, and worse than the bug it replaced.
#
# `int` at 3 bytes is a real 24-bit field. `float` has a 4-byte and an 8-byte
# IEEE-754 form and nothing between them, so the width is now refused outright
# and both read paths agree by refusing instead of by both guessing.

@pytest.mark.parametrize("width", [1, 2, 3, 5, 6, 7])
def test_a_float_width_between_the_two_ieee_forms_is_refused(width):
    buffer = ctypes.create_string_buffer(b"\x11" * 8, 8)
    address = ctypes.addressof(buffer)

    process = OpenProcess(pid=os.getpid())
    try:
        with pytest.raises(ValueError) as error:
            process.read_process_memory(address, float, width)

        # And the scan-shaped path reports "not readable" rather than a number.
        via_search = dict(
            process.search_by_addresses(float, width, [address])
        )[address]
    finally:
        process.close()

    assert "float" in str(error.value)
    assert via_search is None


@pytest.mark.parametrize("width", [4, 8])
def test_the_two_real_float_widths_still_work(width):
    """The guard must not cost the widths that mean something.

    4 bytes is Cheat Engine's default "Float" and 8 is its "Double".
    """
    planted = 12.5
    buffer = ctypes.create_string_buffer(8)
    ctypes.memmove(
        buffer,
        struct.pack("<f" if width == 4 else "<d", planted),
        width,
    )
    address = ctypes.addressof(buffer)

    process = OpenProcess(pid=os.getpid())
    try:
        direct = process.read_process_memory(address, float, width)
        via_search = dict(
            process.search_by_addresses(float, width, [address])
        )[address]
    finally:
        process.close()

    assert direct == planted
    assert via_search == planted
