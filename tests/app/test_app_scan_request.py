# -*- coding: utf-8 -*-

"""
Unit tests for ``build_scan_request`` (PyMemoryEditor/app/scan_worker.py).

This is the pure core of ``ScannerPanel._build_request`` — the rules that turn
the scanner panel's fields into a ``ScanRequest``: the AOB-pattern short
circuit, the value-derived buffer width for String / Byte Array,
range parsing, and the no-value (Increased/Decreased/...) scan types. It used
to live inside a ``QWidget`` method and could only be exercised by driving the
live widget; lifting it out means these rules are now testable without a
``QApplication``.
"""

import pytest

pytest.importorskip("PySide6")

from PyMemoryEditor import ScanTypesEnum  # noqa: E402
from PyMemoryEditor.util.convert import value_to_bytes  # noqa: E402
from PyMemoryEditor.app.scan_types import NextScanType  # noqa: E402
from PyMemoryEditor.app.scan_worker import build_scan_request  # noqa: E402
from PyMemoryEditor.app.value_types import VALUE_TYPES  # noqa: E402


def _spec(*, pytype=None, length=None, pattern=False):
    for spec in VALUE_TYPES:
        if spec.is_pattern != pattern:
            continue
        if pytype is not None and spec.pytype is not pytype:
            continue
        if length is not None and spec.length != length:
            continue
        return spec
    raise AssertionError(f"no spec for pytype={pytype} length={length} pattern={pattern}")


def _regex_spec():
    for spec in VALUE_TYPES:
        if spec.is_regex:
            return spec
    raise AssertionError("no regex spec")


INT4 = _spec(pytype=int, length=4)
STR = _spec(pytype=str)
BYTES = _spec(pytype=bytes, pattern=False)
AOB = _spec(pattern=True)
REGEX = _regex_spec()


def test_exact_int_uses_fixed_width_and_passes_flags():
    req = build_scan_request(
        INT4,
        ScanTypesEnum.EXACT_VALUE,
        value_text="100",
        length_spin_value=99,  # ignored: int has a fixed width
        writeable_only=True,
    )
    assert req.scan_type is ScanTypesEnum.EXACT_VALUE
    assert req.value == 100
    assert req.length == 4
    assert req.writeable_only is True


def test_pattern_forces_exact_and_ignores_scan_type():
    # Even if a non-exact scan type leaks in, the pattern path forces EXACT.
    req = build_scan_request(
        AOB,
        ScanTypesEnum.BIGGER_THAN,
        value_text="90 90 ? 00",
    )
    assert req.scan_type is ScanTypesEnum.EXACT_VALUE
    assert req.value == "90 90 ? 00"


def test_pattern_with_value_false_drops_value():
    req = build_scan_request(
        AOB,
        ScanTypesEnum.EXACT_VALUE,
        value_text="90 90",
        with_value=False,
    )
    assert req.value is None


def test_regex_carries_byte_length_from_length_field_and_forces_exact():
    # Even a non-exact scan type is forced to EXACT; the Length field becomes
    # the regex's byte_length (max match width) and the value is the UTF-8
    # bytes pattern.
    req = build_scan_request(
        REGEX,
        ScanTypesEnum.BIGGER_THAN,
        value_text=r"Player[0-9]+",
        length_spin_value=32,
    )
    assert req.scan_type is ScanTypesEnum.EXACT_VALUE
    assert req.value == rb"Player[0-9]+"
    assert req.length == 32


def test_string_ignores_length_override_and_uses_utf8_byte_length():
    # A multibyte string must size by encoded bytes, not characters, and the
    # spin value must be ignored for str.
    req = build_scan_request(
        STR,
        ScanTypesEnum.EXACT_VALUE,
        value_text="óó",  # 2 chars, 4 UTF-8 bytes
        length_spin_value=99,
    )
    assert req.value == "óó"
    assert req.length == 4


def test_bytes_ignores_length_override_and_uses_the_parsed_byte_count():
    # The buffer must be exactly as wide as the value entered. A larger spin
    # value would NUL-pad the target, turning the scan into "these bytes
    # followed by zeros" without telling the user (issue #79).
    req = build_scan_request(
        BYTES,
        ScanTypesEnum.EXACT_VALUE,
        value_text="AA BB",  # 2 bytes
        length_spin_value=8,
    )
    assert req.value == b"\xaa\xbb"
    assert req.length == 2


def test_bytes_longer_than_the_length_field_is_not_truncated():
    # Regression for issue #79: a value wider than the (default 4) spin value
    # used to be squeezed into a 4-byte ctypes buffer, and the scan died with
    # "ValueError: byte string too long" instead of just working.
    req = build_scan_request(
        BYTES,
        ScanTypesEnum.EXACT_VALUE,
        value_text="00 11 22 AA BB CC",  # 6 bytes
        length_spin_value=4,
    )
    assert req.value == b"\x00\x11\x22\xaa\xbb\xcc"
    assert req.length == 6
    # The width is what the backend will encode the target with, so it must
    # survive the fixed-width conversion that used to raise.
    assert value_to_bytes(bytes, req.length, req.value) == req.value


def test_bytes_range_takes_the_wider_endpoint():
    req = build_scan_request(
        BYTES,
        ScanTypesEnum.VALUE_BETWEEN,
        value_text="AA",              # 1 byte
        second_value_text="AA BB CC",  # 3 bytes
        length_spin_value=4,
    )
    assert req.value == (b"\xaa", b"\xaa\xbb\xcc")
    assert req.length == 3


@pytest.mark.parametrize("spec", (BYTES, STR))
def test_no_value_scan_refines_at_the_previous_scan_width(spec):
    # Increased/Changed/... compare against the baseline the previous scan
    # recorded, so they must re-read at that scan's width for both
    # variable-width types. Falling back to the spec default would refine a
    # 4-byte scan by re-reading 16 bytes per address, so the value read back
    # ("olá\0\0…") never matches the one the first scan recorded and every
    # address reports as Changed.
    req = build_scan_request(
        spec,
        NextScanType.CHANGED_VALUE,
        value_text="",
        previous_scan_length=4,
    )
    assert req.value is None
    assert req.length == 4


@pytest.mark.parametrize("spec", (BYTES, STR))
def test_no_value_scan_ignores_the_length_field(spec):
    # The Length field tracks whatever value is typed right now, which the user
    # is free to edit between scans — only the previous scan's width describes
    # the baseline being compared against.
    req = build_scan_request(
        spec,
        NextScanType.CHANGED_VALUE,
        value_text="",
        length_spin_value=99,
        previous_scan_length=4,
    )
    assert req.length == 4


@pytest.mark.parametrize("spec", (BYTES, STR))
@pytest.mark.parametrize(
    "scan_type", (NextScanType.INCREASED_VALUE_BY, NextScanType.DECREASED_VALUE_BY)
)
def test_delta_scan_is_rejected_for_the_variable_width_types(spec, scan_type):
    # "Increased/Decreased value BY" adds the delta to the baseline, which only
    # means anything for a number: on str/bytes `prev + exp` concatenates (never
    # equal to the fixed-width current value) and `prev - exp` raises TypeError,
    # which the refine worker swallows into "doesn't match". Every address was
    # silently dropped; the user gets a message now.
    with pytest.raises(ValueError, match="doesn't apply"):
        build_scan_request(
            spec,
            scan_type,
            value_text="01",
            previous_scan_length=4,
        )


def test_delta_scan_on_a_fixed_width_type_ignores_the_previous_length():
    req = build_scan_request(
        INT4,
        NextScanType.INCREASED_VALUE_BY,
        value_text="1",
        previous_scan_length=99,
    )
    assert req.length == 4
    assert req.value == 1


def test_no_value_scan_falls_back_to_the_spec_width_without_a_previous_scan():
    req = build_scan_request(BYTES, NextScanType.CHANGED_VALUE, value_text="")
    assert req.length == BYTES.length


def test_no_value_scan_type_drops_value():
    req = build_scan_request(
        INT4,
        NextScanType.INCREASED_VALUE,
        value_text="this is ignored",
    )
    assert req.value is None
    assert req.scan_type is NextScanType.INCREASED_VALUE
    assert req.length == 4


def test_value_between_packs_a_tuple_and_takes_the_wider_length():
    req = build_scan_request(
        STR,
        ScanTypesEnum.VALUE_BETWEEN,
        value_text="a",       # 1 byte
        second_value_text="óó",  # 4 bytes
    )
    assert req.value == ("a", "óó")
    assert req.length == 4  # max(1, 4)


def test_invalid_value_raises_valueerror():
    with pytest.raises(ValueError):
        build_scan_request(INT4, ScanTypesEnum.EXACT_VALUE, value_text="not-an-int")


@pytest.mark.parametrize("spec", (BYTES, STR))
def test_empty_value_raises_valueerror(spec):
    # An empty string used to parse as a 1-byte NUL buffer, so the scan matched
    # every zeroed byte in the target. Byte Array already rejected its own empty
    # input; both variable-width types now do.
    with pytest.raises(ValueError):
        build_scan_request(spec, ScanTypesEnum.EXACT_VALUE, value_text="")


def test_invalid_pattern_raises_valueerror():
    with pytest.raises(ValueError):
        build_scan_request(AOB, ScanTypesEnum.EXACT_VALUE, value_text="")
