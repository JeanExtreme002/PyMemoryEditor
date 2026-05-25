# -*- coding: utf-8 -*-

import struct
import sys
from bisect import bisect_left
from typing import Generator, Iterable, Literal, Optional, Sequence, Tuple, Type, Union, cast

from ..enums import ScanTypesEnum


# Static alias mypy can narrow to int.from_bytes's expected byte-order parameter.
_ByteOrder = Literal["little", "big"]


def _as_bytes(memory_region_data: Sequence) -> bytes:
    """
    Return the memory region data as bytes for use with bytes.find / slicing.

    bytes.find requires a real bytes object (or bytearray); a ctypes array
    exposes the buffer protocol but bytes.find on it raises TypeError. We pay
    one materialization here to keep the find path correct.
    """
    if isinstance(memory_region_data, bytes):
        return memory_region_data
    return bytes(memory_region_data)


def _as_buffer(memory_region_data: Sequence):
    """
    Return a buffer-protocol view suitable for `struct.iter_unpack`.

    Avoids an extra copy when the input is a ctypes array (up to 256 MB per
    chunk in the hot path). `struct.iter_unpack` accepts any object exposing
    the buffer protocol.
    """
    if isinstance(memory_region_data, (bytes, bytearray, memoryview)):
        return memory_region_data
    # ctypes.Array exposes the buffer protocol but isn't typed as `Buffer`.
    return memoryview(memory_region_data).cast("B")  # type: ignore[arg-type]


# Cap of bytes we allocate at once for a memory region. Regions larger than
# this are read in chunks. 256 MB is large enough to keep the syscall cost low
# while preventing OOM in processes with multi-GB heaps (browsers, Java VMs).
DEFAULT_MAX_REGION_CHUNK = 256 * 1024 * 1024


def iter_region_chunks(
    region_size: int,
    target_value_size: int,
    max_chunk: int = DEFAULT_MAX_REGION_CHUNK,
) -> Iterable[Tuple[int, int]]:
    """
    Return an iterable of (chunk_offset, chunk_size) tuples to read a (possibly
    huge) region.

    For regions that fit in `max_chunk` (the common case for self-process scans
    and most game-sized targets), returns a single-element tuple — avoiding the
    overhead of a generator state machine in the hot path. Larger regions get a
    lazy generator that yields aligned chunks.

    Chunk sizes are aligned to target_value_size so typed numeric scans don't
    miss matches across boundaries. Strings (which can begin at any byte
    offset) may miss matches that span chunk boundaries when the region
    exceeds max_chunk — rare in practice and documented as a limitation.
    """
    if region_size <= max_chunk:
        return ((0, region_size),)
    return _iter_large_region_chunks(region_size, target_value_size, max_chunk)


def _iter_large_region_chunks(
    region_size: int,
    target_value_size: int,
    max_chunk: int,
) -> Generator[Tuple[int, int], None, None]:
    """Generator path used by `iter_region_chunks` when region exceeds max_chunk."""
    aligned_chunk = max(max_chunk // target_value_size, 1) * target_value_size

    offset = 0
    while offset < region_size:
        size = min(aligned_chunk, region_size - offset)
        yield offset, size
        offset += size


# struct format characters by byte width for each interpretation.
# Signed ints match the c_int8/16/32/64 encoding used by `value_to_bytes`.
# Floats use IEEE-754 f/d. Unsigned forms are kept for completeness but are
# only used for bytes/str/bool, where ordering against arbitrary signed ints
# doesn't apply.
_SIGNED_INT_FORMATS = {1: "b", 2: "h", 4: "i", 8: "q"}
_FLOAT_FORMATS = {4: "f", 8: "d"}
_UNSIGNED_INT_FORMATS = {1: "B", 2: "H", 4: "I", 8: "Q"}


def _struct_format(
    byte_order: _ByteOrder, size: int, pytype: Optional[Type]
) -> Optional[str]:
    """
    Return a struct format like '<i' or '<f' for fast iter_unpack, or None
    when the (size, pytype) combination has no struct shortcut.

    pytype dispatch:
      - int   → signed (b/h/i/q) so BIGGER_THAN/SMALLER_THAN of negative
                values orders correctly.
      - float → IEEE-754 (f/d) so 1.5 > -1.0 actually holds — comparing the
                bit-pattern as an integer gives the wrong ordering for negatives.
      - bool  → unsigned 1-byte (B). Only EXACT/NOT_EXACT is meaningful.
      - None  → caller is doing a bytewise scan (str/bytes/unusual size).
    """
    if pytype is float:
        char = _FLOAT_FORMATS.get(size)
    elif pytype is int:
        char = _SIGNED_INT_FORMATS.get(size)
    elif pytype is bool:
        char = _UNSIGNED_INT_FORMATS.get(size)
    else:
        return None
    if char is None:
        return None
    prefix = "<" if byte_order == "little" else ">"
    return prefix + char


def _decode_target(
    target_value: bytes, byte_order: _ByteOrder, pytype: Optional[Type]
) -> Union[int, float]:
    """
    Decode a bytes-encoded target value into the Python value scan_memory
    compares against, using the same interpretation as the per-value decoder.

    For ints we honor signed=True; for floats we struct-unpack; otherwise the
    bytewise (unsigned) view is fine since bytes/str scans only compare
    equality and the slow path uses int.from_bytes consistently on both sides.
    """
    if pytype is int:
        return int.from_bytes(target_value, byte_order, signed=True)
    if pytype is float:
        fmt = _FLOAT_FORMATS.get(len(target_value))
        if fmt is not None:
            prefix = "<" if byte_order == "little" else ">"
            return struct.unpack(prefix + fmt, target_value)[0]
    return int.from_bytes(target_value, byte_order)


def scan_memory_for_exact_value(
    memory_region_data: Sequence,
    memory_region_data_size: int,
    target_value: bytes,
    target_value_size: int,
    comparison: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
    is_string: Union[bool, Type, None] = False,
    *args,
    **kwargs,
) -> Generator[int, None, None]:
    """
    Search for an exact (or not-exact) match of the target value in the memory region.

    For EXACT_VALUE this is the fastest path (delegates to bytes.find).
    For NOT_EXACT_VALUE it returns each candidate offset whose value differs
    from target_value. Numeric scans step by `target_value_size` (natural
    alignment); string scans step byte-by-byte since strings can begin anywhere.

    The 6th argument accepts either a `pytype` (the value type — `str` means
    "treat as string") or a plain `is_string` boolean for backward
    compatibility with the previous API.
    """
    if is_string is str:
        is_string = True
    elif not isinstance(is_string, bool):
        # A non-str type (int/float/bool/bytes) collapses to non-string.
        is_string = False

    data = _as_bytes(memory_region_data)

    if comparison is ScanTypesEnum.EXACT_VALUE:
        found_index = data.find(target_value, 0)
        while found_index != -1:
            yield found_index
            found_index = data.find(target_value, found_index + 1)
        return

    if comparison is ScanTypesEnum.NOT_EXACT_VALUE:
        match_positions = []
        found_index = data.find(target_value, 0)
        while found_index != -1:
            match_positions.append(found_index)
            found_index = data.find(target_value, found_index + 1)

        end = memory_region_data_size - target_value_size + 1
        step = 1 if is_string else target_value_size

        # An offset O overlaps with a match M iff |M - O| < target_value_size,
        # i.e. M lies in (O - target_value_size, O + target_value_size). Since
        # match_positions is sorted (bytes.find yields ascending indices), a
        # bisect_left lookup turns the inner loop from O(m) into O(log m).
        for offset in range(0, end, step):
            idx = bisect_left(match_positions, offset - target_value_size + 1)
            if (
                idx < len(match_positions)
                and match_positions[idx] < offset + target_value_size
            ):
                continue
            yield offset


def scan_memory(
    memory_region_data: Sequence,
    memory_region_data_size: int,
    target_value: Union[bytes, Tuple[bytes, bytes]],
    target_value_size: int,
    scan_type: ScanTypesEnum,
    pytype: Optional[Type] = None,
) -> Generator[int, None, None]:
    """
    Search the memory region for values matching scan_type relative to target_value.

    `pytype` selects how the bytes are interpreted for ordering comparisons:
      - int   → signed integer (struct b/h/i/q)
      - float → IEEE-754 (struct f/d)
      - bool  → unsigned 1-byte
      - str   → bytewise comparison, step=1 (str matches can start at any byte)
      - bytes / None → bytewise comparison aligned to `target_value_size`

    Without this dispatch, BIGGER_THAN on signed ints (e.g. "> -1") would
    compare against the reinterpreted unsigned (e.g. 0xFFFFFFFF) and produce
    no matches; floats would order by their integer bit-pattern, which is
    wrong for negatives. Tight loops are inlined per scan_type to eliminate
    generator and tuple-unpacking overhead — for a multi-million-iteration
    scan this is the difference between minutes and seconds.
    """
    is_string = pytype is str
    # sys.byteorder is typed as Literal["little", "big"] — preserve that
    # narrowing for the downstream int.from_bytes / struct.unpack calls.
    byte_order: _ByteOrder = cast(_ByteOrder, "big" if is_string else sys.byteorder)

    if isinstance(target_value, tuple):
        start_target_value = _decode_target(target_value[0], byte_order, pytype)
        end_target_value = _decode_target(target_value[1], byte_order, pytype)
        target_value_decoded: Union[int, float] = 0
    else:
        target_value_decoded = _decode_target(target_value, byte_order, pytype)
        start_target_value = 0
        end_target_value = 0

    fmt = None if is_string else _struct_format(byte_order, target_value_size, pytype)

    # Fast path: numeric scan with a struct-supported size (1/2/4/8 bytes).
    # struct.iter_unpack runs in C; the inlined comparison loops avoid both
    # generator and tuple-unpacking overhead in the hottest path. Use a
    # memoryview to avoid materializing a copy of the (potentially multi-MB)
    # region for iter_unpack.
    if fmt is not None:
        buffer = _as_buffer(memory_region_data)
        total = (len(buffer) // target_value_size) * target_value_size
        if total == 0:
            return
        unpacker = struct.iter_unpack(fmt, buffer[:total])
        offset = 0
        step = target_value_size

        if scan_type is ScanTypesEnum.EXACT_VALUE:
            for (value,) in unpacker:
                if value == target_value_decoded:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.NOT_EXACT_VALUE:
            for (value,) in unpacker:
                if value != target_value_decoded:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.BIGGER_THAN:
            for (value,) in unpacker:
                if value > target_value_decoded:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.SMALLER_THAN:
            for (value,) in unpacker:
                if value < target_value_decoded:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE:
            for (value,) in unpacker:
                if value >= target_value_decoded:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE:
            for (value,) in unpacker:
                if value <= target_value_decoded:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.VALUE_BETWEEN:
            for (value,) in unpacker:
                if start_target_value <= value <= end_target_value:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.NOT_VALUE_BETWEEN:
            for (value,) in unpacker:
                if not (start_target_value <= value <= end_target_value):
                    yield offset
                offset += step
        return

    # Fallback: strings (byte-by-byte) or numeric with unusual sizes (3/6/7).
    # Numerics here decode through int.from_bytes; the target was already
    # decoded above with the matching signedness via _decode_target.
    data = _as_bytes(memory_region_data)
    step = 1 if is_string else target_value_size
    end = memory_region_data_size - target_value_size + 1
    int_from_bytes = int.from_bytes
    signed = pytype is int

    if scan_type is ScanTypesEnum.EXACT_VALUE:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order, signed=signed
            )
            if value == target_value_decoded:
                yield offset
    elif scan_type is ScanTypesEnum.NOT_EXACT_VALUE:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order, signed=signed
            )
            if value != target_value_decoded:
                yield offset
    elif scan_type is ScanTypesEnum.BIGGER_THAN:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order, signed=signed
            )
            if value > target_value_decoded:
                yield offset
    elif scan_type is ScanTypesEnum.SMALLER_THAN:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order, signed=signed
            )
            if value < target_value_decoded:
                yield offset
    elif scan_type is ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order, signed=signed
            )
            if value >= target_value_decoded:
                yield offset
    elif scan_type is ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order, signed=signed
            )
            if value <= target_value_decoded:
                yield offset
    elif scan_type is ScanTypesEnum.VALUE_BETWEEN:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order, signed=signed
            )
            if start_target_value <= value <= end_target_value:
                yield offset
    elif scan_type is ScanTypesEnum.NOT_VALUE_BETWEEN:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order, signed=signed
            )
            if not (start_target_value <= value <= end_target_value):
                yield offset
