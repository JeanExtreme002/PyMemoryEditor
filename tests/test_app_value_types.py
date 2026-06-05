# -*- coding: utf-8 -*-

"""
Functional tests for the scanner-panel input layer (PyMemoryEditor/app/value_types.py).

This is the first step of the scan flow: it turns what the user types in the
"Value Type" combo + value box into the ``(pytype, length, value)`` the library
scans for. It is pure logic with no Qt dependency, so it runs even without the
``[app]`` extra installed — and it was previously uncovered, despite a parsing
bug here silently changing what every scan searches for.
"""

import pytest

from PyMemoryEditor.app.value_types import (
    VALUE_TYPES,
    find_spec,
    parse_value,
)


def _spec(*, pytype=None, length=None, pattern=False):
    """Pick a value-type spec by shape rather than by its (typo-prone) label."""
    for spec in VALUE_TYPES:
        if spec.is_pattern != pattern:
            continue
        if pytype is not None and spec.pytype is not pytype:
            continue
        if length is not None and spec.length != length:
            continue
        return spec
    raise AssertionError(f"no spec for pytype={pytype} length={length} pattern={pattern}")


INT4 = _spec(pytype=int, length=4)
INT1 = _spec(pytype=int, length=1)
FLOAT = _spec(pytype=float, length=4)
BOOL = _spec(pytype=bool)
STR = _spec(pytype=str)
BYTES = _spec(pytype=bytes, pattern=False)
AOB = _spec(pattern=True)


# --- find_spec ------------------------------------------------------------- #

def test_find_spec_known_and_unknown():
    assert find_spec(INT4.label) is INT4
    assert find_spec("not a real label") is None


def test_default_spec_is_first_entry():
    # cheat_entry/scanner fall back to VALUE_TYPES[0]; pin that it's the 4-byte int.
    assert VALUE_TYPES[0] is INT4


# --- integer parsing ------------------------------------------------------- #

def test_parse_int_decimal_and_hex():
    assert INT4.parse("100") == 100
    assert INT4.parse("0x10") == 16
    assert INT4.parse("  42 ") == 42


def test_parse_int_rejects_out_of_range():
    # 1-byte signed int tops out at 127.
    with pytest.raises(ValueError):
        INT1.parse("200")
    with pytest.raises(ValueError):
        INT1.parse("-200")


def test_parse_int_empty_raises():
    with pytest.raises(ValueError):
        INT4.parse("")


# --- float / bool ---------------------------------------------------------- #

def test_parse_float_accepts_comma_decimal():
    assert FLOAT.parse("3.5") == pytest.approx(3.5)
    assert FLOAT.parse("3,5") == pytest.approx(3.5)


@pytest.mark.parametrize("text, expected", [
    ("true", True), ("1", True), ("yes", True), ("on", True),
    ("false", False), ("0", False), ("no", False), ("off", False),
])
def test_parse_bool_variants(text, expected):
    assert BOOL.parse(text) is expected


def test_parse_bool_invalid_raises():
    with pytest.raises(ValueError):
        BOOL.parse("maybe")


# --- byte array ------------------------------------------------------------ #

def test_parse_bytes_hex_with_spaces():
    assert BYTES.parse("DE AD BE EF") == b"\xDE\xAD\xBE\xEF"


def test_parse_bytes_rejects_odd_and_invalid():
    with pytest.raises(ValueError):
        BYTES.parse("ABC")            # odd number of hex digits
    with pytest.raises(ValueError):
        BYTES.parse("ZZ")             # not hex
    with pytest.raises(ValueError):
        BYTES.parse("")               # empty


# --- AOB pattern ----------------------------------------------------------- #

def test_parse_pattern_valid_returns_verbatim():
    assert AOB.parse("48 8B ? ? 00") == "48 8B ? ? 00"


def test_parse_pattern_empty_and_malformed_raise():
    with pytest.raises(ValueError):
        AOB.parse("   ")
    with pytest.raises(ValueError):
        AOB.parse("4G 8B")            # invalid hex token


# --- parse_value: length inference (the part that decides scan width) ------ #

def test_parse_value_int_passthrough_length():
    value, length = parse_value(INT4, "0x10")
    assert (value, length) == (16, 4)


def test_parse_value_bytes_defaults_to_natural_length():
    value, length = parse_value(BYTES, "DE AD BE")
    assert value == b"\xDE\xAD\xBE"
    assert length == 3


def test_parse_value_str_uses_utf8_byte_length_not_char_count():
    # "olá" is 3 characters but 4 UTF-8 bytes — under-allocating would truncate.
    value, length = parse_value(STR, "olá")
    assert value == "olá"
    assert length == 4


def test_parse_value_str_length_override_wins():
    value, length = parse_value(STR, "hi", length_override=10)
    assert value == "hi"
    assert length == 10


def test_parse_value_pattern_reports_zero_length():
    # AOB width comes from the pattern itself; parse_value must not count chars.
    value, length = parse_value(AOB, "48 8B ? ? 00")
    assert value == "48 8B ? ? 00"
    assert length == 0


# --- format round-trips ---------------------------------------------------- #

def test_format_round_trips():
    assert BYTES.format(b"\xDE\xAD") == "DE AD"
    assert INT4.format(123) == "123"
    assert BYTES.format(None) == ""
    assert INT4.format(None) == ""
