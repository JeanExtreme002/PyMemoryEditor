# -*- coding: utf-8 -*-

"""
Optional NumPy-accelerated inner loop for typed numeric scans (the ``[speed]``
extra).

``scan_memory`` in :mod:`PyMemoryEditor.util.scan` already does the heavy
lifting in C where it can — ``bytes.find`` for exact matches and
``struct.iter_unpack`` to decode a region. What stays in pure Python is the
*comparison loop*: for an ordered scan (``> n``, ``< n``, ``between``) it walks
every decoded value one at a time, paying the interpreter's per-element cost
(object boxing, tuple unpacking, a bytecode comparison) millions of times for a
multi-megabyte region.

This module replaces that loop with a vectorized NumPy comparison:

    arr  = np.frombuffer(buffer, dtype="<i4")   # bytes -> int array, zero-copy
    mask = arr > target                         # one C-level comparison, whole array
    offs = np.flatnonzero(mask) * item_size      # match positions -> byte offsets

The result is *identical* to the pure-Python loop — the same offsets in the
same ascending order — so it is a drop-in fast path, not a behavior change. The
tests in ``tests/test_scan_numpy.py`` assert equivalence against the Python
implementation across every scan type, width and signedness.

NumPy is an **optional** dependency. When it is not installed,
:data:`NUMPY_AVAILABLE` is ``False`` and :func:`scan_offsets` is never called —
:mod:`PyMemoryEditor.util.scan` keeps using its struct-based loop. Installing
``PyMemoryEditor[speed]`` pulls in NumPy and lights this path up automatically;
no code change is required on the caller's side.
"""

from typing import List, Literal, Optional, Type, Union

from ..enums import ScanTypesEnum

try:  # The whole module degrades to a no-op when NumPy is absent.
    import numpy as _np

    NUMPY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by the no-numpy fallback path
    _np = None  # type: ignore[assignment]
    NUMPY_AVAILABLE = False


_ByteOrder = Literal["little", "big"]


# NumPy dtype characters per (pytype, byte width). These mirror the struct
# formats used by ``scan.py`` exactly so the decoded values — and therefore the
# matches — are identical:
#   - int   -> signed   (i1/i2/i4/i8), matching struct b/h/i/q.
#   - bool  -> unsigned (u1/u2/u4/u8), matching struct B (only width 1 is used
#              in practice, but the full set keeps parity with _struct_format).
#   - float -> IEEE-754 (f4/f8),      matching struct f/d.
_NUMPY_DTYPE_CHARS = {
    int: {1: "i1", 2: "i2", 4: "i4", 8: "i8"},
    bool: {1: "u1", 2: "u2", 4: "u4", 8: "u8"},
    float: {4: "f4", 8: "f8"},
}


def numpy_dtype(
    byte_order: _ByteOrder, size: int, pytype: Optional[Type]
) -> Optional[str]:
    """
    Return a NumPy dtype string like ``"<i4"`` or ``">f8"`` for the
    ``(pytype, size)`` pair, or ``None`` when there is no vectorized fast path
    (str/bytes, or an unusual width like 3/6/7 bytes).

    Mirrors :func:`PyMemoryEditor.util.scan._struct_format` one-for-one so the
    NumPy and struct paths agree on signedness and endianness.
    """
    chars = _NUMPY_DTYPE_CHARS.get(pytype)  # type: ignore[arg-type]
    if chars is None:
        return None
    char = chars.get(size)
    if char is None:
        return None
    prefix = "<" if byte_order == "little" else ">"
    return prefix + char


def scan_offsets(
    buffer,
    target_value_size: int,
    scan_type: ScanTypesEnum,
    pytype: Optional[Type],
    byte_order: _ByteOrder,
    target_value: Union[int, float],
    start_value: Union[int, float],
    end_value: Union[int, float],
) -> Optional[List[int]]:
    """
    Vectorized equivalent of ``scan_memory``'s numeric fast path.

    :param buffer: a buffer-protocol object whose length is already a multiple
        of ``target_value_size`` (``scan.py`` slices it before calling).
    :param target_value: the decoded scalar compared against for the single-value
        scan types (EXACT / NOT_EXACT / the four ordered comparisons).
    :param start_value, end_value: the inclusive bounds for ``VALUE_BETWEEN`` /
        ``NOT_VALUE_BETWEEN`` (ignored for the other scan types).
    :return: byte offsets of every match in ascending order, or ``None`` when
        ``(pytype, target_value_size)`` has no NumPy fast path so the caller can
        fall back to the struct loop.
    """
    if not NUMPY_AVAILABLE:
        return None

    dtype = numpy_dtype(byte_order, target_value_size, pytype)
    if dtype is None:
        return None

    # Zero-copy reinterpretation of the raw bytes as a typed array. The caller
    # guarantees len(buffer) is a multiple of the item size, so frombuffer never
    # raises on a ragged tail.
    arr = _np.frombuffer(buffer, dtype=dtype)
    if arr.size == 0:
        return []

    if scan_type is ScanTypesEnum.EXACT_VALUE:
        mask = arr == target_value
    elif scan_type is ScanTypesEnum.NOT_EXACT_VALUE:
        mask = arr != target_value
    elif scan_type is ScanTypesEnum.BIGGER_THAN:
        mask = arr > target_value
    elif scan_type is ScanTypesEnum.SMALLER_THAN:
        mask = arr < target_value
    elif scan_type is ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE:
        mask = arr >= target_value
    elif scan_type is ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE:
        mask = arr <= target_value
    elif scan_type is ScanTypesEnum.VALUE_BETWEEN:
        mask = (arr >= start_value) & (arr <= end_value)
    elif scan_type is ScanTypesEnum.NOT_VALUE_BETWEEN:
        mask = ~((arr >= start_value) & (arr <= end_value))
    else:  # pragma: no cover - ScanTypesEnum is closed; defensive only.
        return None

    # flatnonzero returns ascending indices, so multiplying by the item size
    # yields ascending byte offsets — the same order the Python loop emits.
    return (_np.flatnonzero(mask) * target_value_size).tolist()


__all__ = ("NUMPY_AVAILABLE", "numpy_dtype", "scan_offsets")
