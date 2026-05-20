# -*- coding: utf-8 -*-

"""
Property-based tests for the cross-platform scan helpers.

`scan_memory` has eight branch-inlined comparison loops (one per scan_type) for
performance. Inlining is the kind of optimization where a single typo in one
branch is invisible to the test suite — there is no shared comparator to
exercise. These tests check the **observable** property: for every input the
two interpretations (fast `struct.iter_unpack` path and the slow
`int.from_bytes` fallback) must yield identical offsets.

If the two diverge for any generated input, hypothesis shrinks to the minimal
failing buffer + comparison, which historically would have caught the signed-
vs-unsigned and IEEE-754-bit-pattern bugs the v2 release fixed.
"""

import struct

import pytest

hypothesis = pytest.importorskip("hypothesis")  # type: ignore[assignment]
from hypothesis import HealthCheck, given, settings, strategies as st  # noqa: E402

from PyMemoryEditor.enums import ScanTypesEnum  # noqa: E402
from PyMemoryEditor.util.scan import scan_memory  # noqa: E402


# Pre-compute valid value counts per (size, pytype) so hypothesis doesn't burn
# cycles on inputs the slow path silently rejects.
_INT_SIZES = (1, 2, 4, 8)
_FLOAT_SIZES = (4, 8)
_INT_FORMATS = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}
_FLOAT_FORMATS = {4: "<f", 8: "<d"}

# All ordered comparison types share the same per-element interpretation.
_ORDERED_SCAN_TYPES = (
    ScanTypesEnum.EXACT_VALUE,
    ScanTypesEnum.NOT_EXACT_VALUE,
    ScanTypesEnum.BIGGER_THAN,
    ScanTypesEnum.SMALLER_THAN,
    ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE,
    ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE,
)


@st.composite
def _int_payload(draw):
    size = draw(st.sampled_from(_INT_SIZES))
    count = draw(st.integers(min_value=1, max_value=64))
    bits = size * 8
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    values = draw(
        st.lists(
            st.integers(min_value=lo, max_value=hi),
            min_size=count,
            max_size=count,
        )
    )
    target = draw(st.integers(min_value=lo, max_value=hi))
    fmt = _INT_FORMATS[size]
    return size, b"".join(struct.pack(fmt, v) for v in values), struct.pack(fmt, target)


@st.composite
def _float_payload(draw):
    size = draw(st.sampled_from(_FLOAT_SIZES))
    count = draw(st.integers(min_value=1, max_value=32))
    # Allow_nan=False — NaN comparisons make < and > both False, which is
    # correct but only verifies an identity at most; not what we're testing.
    values = draw(
        st.lists(
            st.floats(
                width=32 if size == 4 else 64,
                allow_nan=False,
                allow_infinity=False,
            ),
            min_size=count,
            max_size=count,
        )
    )
    target = draw(
        st.floats(
            width=32 if size == 4 else 64,
            allow_nan=False,
            allow_infinity=False,
        )
    )
    fmt = _FLOAT_FORMATS[size]
    return size, b"".join(struct.pack(fmt, v) for v in values), struct.pack(fmt, target)


def _scan_via_slow_path(data, size, target, scan_type, pytype):
    """Reference implementation: pure-Python loop using struct.unpack."""
    fmt = _INT_FORMATS[size] if pytype is int else _FLOAT_FORMATS[size]
    target_value = struct.unpack(fmt, target)[0]
    end = len(data) - size + 1
    results = []
    for offset in range(0, end, size):
        value = struct.unpack(fmt, data[offset : offset + size])[0]
        if scan_type is ScanTypesEnum.EXACT_VALUE and value == target_value:
            results.append(offset)
        elif scan_type is ScanTypesEnum.NOT_EXACT_VALUE and value != target_value:
            results.append(offset)
        elif scan_type is ScanTypesEnum.BIGGER_THAN and value > target_value:
            results.append(offset)
        elif scan_type is ScanTypesEnum.SMALLER_THAN and value < target_value:
            results.append(offset)
        elif (
            scan_type is ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE
            and value >= target_value
        ):
            results.append(offset)
        elif (
            scan_type is ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE
            and value <= target_value
        ):
            results.append(offset)
    return results


@settings(
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
    max_examples=200,
)
@given(payload=_int_payload(), scan_type=st.sampled_from(_ORDERED_SCAN_TYPES))
def test_signed_int_scan_matches_reference(payload, scan_type):
    """Fast struct.iter_unpack path must agree with the slow reference impl."""
    size, data, target = payload

    # NOT_EXACT_VALUE goes through scan_memory_for_exact_value, which has a
    # different alignment policy than scan_memory's fast path. Restrict to
    # scan_memory's domain so the property is well-defined.
    if scan_type is ScanTypesEnum.NOT_EXACT_VALUE:
        return

    fast = list(scan_memory(data, len(data), target, size, scan_type, int))
    slow = _scan_via_slow_path(data, size, target, scan_type, int)
    assert fast == slow


@settings(
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
    max_examples=200,
)
@given(payload=_float_payload(), scan_type=st.sampled_from(_ORDERED_SCAN_TYPES))
def test_float_scan_matches_reference(payload, scan_type):
    """Same property for IEEE-754 floats (regression for the bit-pattern bug)."""
    if scan_type is ScanTypesEnum.NOT_EXACT_VALUE:
        return

    size, data, target = payload
    fast = list(scan_memory(data, len(data), target, size, scan_type, float))
    slow = _scan_via_slow_path(data, size, target, scan_type, float)
    assert fast == slow


@settings(
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
    max_examples=100,
)
@given(payload=_int_payload())
def test_value_between_signed_int_matches_reference(payload):
    """VALUE_BETWEEN inclusive range must match the obvious comparison."""
    size, data, _ = payload

    fmt = _INT_FORMATS[size]
    bits = size * 8
    lo_bound = -(1 << (bits - 1))
    hi_bound = (1 << (bits - 1)) - 1
    # Pick two arbitrary endpoints from the data so the range is non-trivial.
    sample = struct.unpack(fmt, data[:size])[0]
    start = max(lo_bound, sample - 100)
    end = min(hi_bound, sample + 100)
    if start > end:
        start, end = end, start
    target = (struct.pack(fmt, start), struct.pack(fmt, end))

    fast = list(
        scan_memory(data, len(data), target, size, ScanTypesEnum.VALUE_BETWEEN, int)
    )

    slow = []
    for offset in range(0, len(data) - size + 1, size):
        value = struct.unpack(fmt, data[offset : offset + size])[0]
        if start <= value <= end:
            slow.append(offset)

    assert fast == slow
