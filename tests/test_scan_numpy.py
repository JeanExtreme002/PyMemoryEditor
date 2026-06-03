# -*- coding: utf-8 -*-

"""
Equivalence tests for the optional NumPy-accelerated scan fast path
(:mod:`PyMemoryEditor.util.scan_numpy`, the ``[speed]`` extra).

The contract is simple and strict: with NumPy enabled, ``scan_memory`` must
return **exactly** the same offsets, in the same order, as the pure-Python
struct loop. These tests run the same inputs through both paths (toggling
``scan_numpy.NUMPY_AVAILABLE``) and assert the outputs are identical across
every scan type, byte width and signedness.

They run on any platform and never touch process memory.
"""

import random
import struct

import pytest

from PyMemoryEditor.enums import ScanTypesEnum
from PyMemoryEditor.util import scan as scan_module
from PyMemoryEditor.util import scan_numpy


numpy_required = pytest.mark.skipif(
    not scan_numpy.NUMPY_AVAILABLE,
    reason="NumPy is not installed (the [speed] extra is optional).",
)


# Every scan type that flows through scan_memory's numeric fast path.
_SINGLE_VALUE_SCANS = [
    ScanTypesEnum.EXACT_VALUE,
    ScanTypesEnum.NOT_EXACT_VALUE,
    ScanTypesEnum.BIGGER_THAN,
    ScanTypesEnum.SMALLER_THAN,
    ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE,
    ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE,
]
_RANGE_SCANS = [ScanTypesEnum.VALUE_BETWEEN, ScanTypesEnum.NOT_VALUE_BETWEEN]

_INT_FORMATS = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}
_FLOAT_FORMATS = {4: "<f", 8: "<d"}


def _scan(data, target, size, scan_type, pytype, *, numpy_enabled):
    """Run scan_memory with the NumPy fast path forced on or off."""
    original = scan_numpy.NUMPY_AVAILABLE
    scan_numpy.NUMPY_AVAILABLE = numpy_enabled
    try:
        return list(
            scan_module.scan_memory(data, len(data), target, size, scan_type, pytype)
        )
    finally:
        scan_numpy.NUMPY_AVAILABLE = original


def _assert_equivalent(data, target, size, scan_type, pytype):
    """The NumPy path and the pure-Python path must agree exactly."""
    with_numpy = _scan(data, target, size, scan_type, pytype, numpy_enabled=True)
    without_numpy = _scan(data, target, size, scan_type, pytype, numpy_enabled=False)
    assert with_numpy == without_numpy


# --- Integer equivalence ---------------------------------------------------


@numpy_required
@pytest.mark.parametrize("size", [1, 2, 4, 8])
@pytest.mark.parametrize("scan_type", _SINGLE_VALUE_SCANS)
def test_int_single_value_equivalence(size, scan_type):
    rng = random.Random(20240601 + size + scan_type.value)
    limit = 2 ** (8 * size - 1)
    values = [rng.randrange(-limit, limit) for _ in range(2000)]
    data = b"".join(struct.pack(_INT_FORMATS[size], v) for v in values)

    target = struct.pack(_INT_FORMATS[size], rng.randrange(-limit, limit))
    _assert_equivalent(data, target, size, scan_type, int)


@numpy_required
@pytest.mark.parametrize("size", [1, 2, 4, 8])
@pytest.mark.parametrize("scan_type", _RANGE_SCANS)
def test_int_range_equivalence(size, scan_type):
    rng = random.Random(777 + size + scan_type.value)
    limit = 2 ** (8 * size - 1)
    values = [rng.randrange(-limit, limit) for _ in range(2000)]
    data = b"".join(struct.pack(_INT_FORMATS[size], v) for v in values)

    low, high = sorted(
        (rng.randrange(-limit, limit), rng.randrange(-limit, limit))
    )
    target = (
        struct.pack(_INT_FORMATS[size], low),
        struct.pack(_INT_FORMATS[size], high),
    )
    not_between = scan_type is ScanTypesEnum.NOT_VALUE_BETWEEN
    _assert_equivalent(data, target, size, scan_type, int)
    assert not_between in (True, False)  # keeps both range types parametrized


@numpy_required
def test_int_negative_target_equivalence():
    """The classic signed-vs-unsigned regression, now checked across paths."""
    data = b"".join(struct.pack("<i", v) for v in (-10, -1, 0, 5, 100))
    target = struct.pack("<i", -5)
    _assert_equivalent(data, target, 4, ScanTypesEnum.BIGGER_THAN, int)


# --- Float equivalence -----------------------------------------------------


@numpy_required
@pytest.mark.parametrize("size", [4, 8])
@pytest.mark.parametrize("scan_type", _SINGLE_VALUE_SCANS)
def test_float_single_value_equivalence(size, scan_type):
    rng = random.Random(909 + size + scan_type.value)
    values = [rng.uniform(-1000.0, 1000.0) for _ in range(2000)]
    data = b"".join(struct.pack(_FLOAT_FORMATS[size], v) for v in values)

    target = struct.pack(_FLOAT_FORMATS[size], rng.uniform(-1000.0, 1000.0))
    _assert_equivalent(data, target, size, scan_type, float)


@numpy_required
@pytest.mark.parametrize("size", [4, 8])
@pytest.mark.parametrize("scan_type", _RANGE_SCANS)
def test_float_range_equivalence(size, scan_type):
    rng = random.Random(303 + size + scan_type.value)
    values = [rng.uniform(-1000.0, 1000.0) for _ in range(2000)]
    data = b"".join(struct.pack(_FLOAT_FORMATS[size], v) for v in values)

    low, high = sorted((rng.uniform(-1000.0, 1000.0), rng.uniform(-1000.0, 1000.0)))
    target = (
        struct.pack(_FLOAT_FORMATS[size], low),
        struct.pack(_FLOAT_FORMATS[size], high),
    )
    _assert_equivalent(data, target, size, scan_type, float)


@numpy_required
def test_float_raw_bytes_including_nan_equivalence():
    """Random raw bytes decode to floats that include NaN/inf; both paths must
    treat those identically (every comparison against NaN is False)."""
    rng = random.Random(4242)
    data = bytes(rng.randrange(256) for _ in range(4000))  # 1000 float32 values
    target = struct.pack("<f", 0.0)
    for scan_type in _SINGLE_VALUE_SCANS:
        _assert_equivalent(data, target, 4, scan_type, float)


# --- Bool equivalence ------------------------------------------------------


@numpy_required
@pytest.mark.parametrize(
    "scan_type", [ScanTypesEnum.EXACT_VALUE, ScanTypesEnum.NOT_EXACT_VALUE]
)
def test_bool_equivalence(scan_type):
    rng = random.Random(111 + scan_type.value)
    data = bytes(rng.randrange(2) for _ in range(2000))
    target = struct.pack("<B", 1)
    _assert_equivalent(data, target, 1, scan_type, bool)


# --- Fallback / dtype boundaries -------------------------------------------


def test_scan_offsets_returns_none_without_numpy(monkeypatch):
    """When NumPy is unavailable, scan_offsets must bow out so the struct loop runs."""
    monkeypatch.setattr(scan_numpy, "NUMPY_AVAILABLE", False)
    result = scan_numpy.scan_offsets(
        b"\x00\x00\x00\x00", 4, ScanTypesEnum.EXACT_VALUE, int, "little", 0, 0, 0
    )
    assert result is None


@numpy_required
@pytest.mark.parametrize(
    "size,pytype",
    [(3, int), (6, int), (7, int), (4, str), (4, bytes), (2, float)],
)
def test_numpy_dtype_has_no_fast_path_for_unusual_combos(size, pytype):
    """str/bytes and non-power-of-two integer widths have no NumPy fast path —
    numpy_dtype returns None and the caller falls back to the struct/byte loop."""
    assert scan_numpy.numpy_dtype("little", size, pytype) is None


@numpy_required
@pytest.mark.parametrize(
    "size,pytype,expected",
    [
        (1, int, "<i1"),
        (4, int, "<i4"),
        (8, int, "<i8"),
        (4, float, "<f4"),
        (8, float, "<f8"),
        (1, bool, "<u1"),
    ],
)
def test_numpy_dtype_mapping(size, pytype, expected):
    assert scan_numpy.numpy_dtype("little", size, pytype) == expected
    assert scan_numpy.numpy_dtype("big", size, pytype) == expected.replace("<", ">")
