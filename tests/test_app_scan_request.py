# -*- coding: utf-8 -*-

"""
Unit tests for ``build_scan_request`` (PyMemoryEditor/app/scan_worker.py).

This is the pure core of ``ScannerPanel._build_request`` — the rules that turn
the scanner panel's fields into a ``ScanRequest``: the AOB-pattern short
circuit, the "String ignores the length field / Byte Array honours it" split,
range parsing, and the no-value (Increased/Decreased/...) scan types. It used
to live inside a ``QWidget`` method and could only be exercised by driving the
live widget; lifting it out means these rules are now testable without a
``QApplication``.
"""

import pytest

pytest.importorskip("PySide6")

from PyMemoryEditor import ScanTypesEnum  # noqa: E402
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


INT4 = _spec(pytype=int, length=4)
STR = _spec(pytype=str)
BYTES = _spec(pytype=bytes, pattern=False)
AOB = _spec(pattern=True)


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


def test_bytes_honours_length_override():
    req = build_scan_request(
        BYTES,
        ScanTypesEnum.EXACT_VALUE,
        value_text="AA BB",  # 2 bytes
        length_spin_value=8,
    )
    assert req.value == b"\xaa\xbb"
    assert req.length == 8


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


def test_invalid_pattern_raises_valueerror():
    with pytest.raises(ValueError):
        build_scan_request(AOB, ScanTypesEnum.EXACT_VALUE, value_text="")
