# -*- coding: utf-8 -*-

import struct
import sys
from bisect import bisect_left
from typing import Generator, Iterable, Sequence, Tuple, Union

from ..enums import ScanTypesEnum


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


# struct format characters for unsigned integers by byte width — the natural
# representation we use when comparing typed numeric values via int.from_bytes
# (which returns unsigned values when signed=False).
_UNSIGNED_FORMATS = {1: "B", 2: "H", 4: "I", 8: "Q"}


def _struct_format(byte_order: str, size: int):
    """Return a struct format like '<I' for fast iter_unpack, or None when unsupported."""
    char = _UNSIGNED_FORMATS.get(size)
    if char is None:
        return None
    prefix = "<" if byte_order == "little" else ">"
    return prefix + char


def scan_memory_for_exact_value(
    memory_region_data: Sequence,
    memory_region_data_size: int,
    target_value: bytes,
    target_value_size: int,
    comparison: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
    is_string: bool = False,
    *args,
    **kwargs,
) -> Generator[int, None, None]:
    """
    Search for an exact (or not-exact) match of the target value in the memory region.

    For EXACT_VALUE this is the fastest path (delegates to bytes.find).
    For NOT_EXACT_VALUE it returns each candidate offset whose value differs
    from target_value. Numeric scans step by `target_value_size` (natural
    alignment); string scans step byte-by-byte since strings can begin anywhere.
    """
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
    is_string: bool,
) -> Generator[int, None, None]:
    """
    Search the memory region for values matching scan_type relative to target_value.

    Tight loops are inlined per scan_type to eliminate generator and tuple-
    unpacking overhead — for a multi-million-iteration scan this is the
    difference between minutes and seconds. Numeric scans are decoded in bulk
    via struct.iter_unpack when the size is 1/2/4/8 bytes; strings and unusual
    sizes fall back to int.from_bytes.
    """
    byte_order = sys.byteorder if not is_string else "big"

    if isinstance(target_value, tuple):
        start_target_value_int = int.from_bytes(target_value[0], byte_order)
        end_target_value_int = int.from_bytes(target_value[1], byte_order)
        target_value_int = 0
    else:
        target_value_int = int.from_bytes(target_value, byte_order)
        start_target_value_int = 0
        end_target_value_int = 0

    fmt = None if is_string else _struct_format(byte_order, target_value_size)

    # ──────────────────────────────────────────────────────────────────────
    # Fast path: numeric scan with a struct-supported size (1/2/4/8 bytes).
    # struct.iter_unpack runs in C; the inlined comparison loops avoid both
    # generator and tuple-unpacking overhead in the hottest path.
    #
    # Use a memoryview to avoid materializing a copy of the (potentially
    # multi-MB) region for iter_unpack.
    # ──────────────────────────────────────────────────────────────────────
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
                if value == target_value_int:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.NOT_EXACT_VALUE:
            for (value,) in unpacker:
                if value != target_value_int:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.BIGGER_THAN:
            for (value,) in unpacker:
                if value > target_value_int:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.SMALLER_THAN:
            for (value,) in unpacker:
                if value < target_value_int:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE:
            for (value,) in unpacker:
                if value >= target_value_int:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE:
            for (value,) in unpacker:
                if value <= target_value_int:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.VALUE_BETWEEN:
            for (value,) in unpacker:
                if start_target_value_int <= value <= end_target_value_int:
                    yield offset
                offset += step
        elif scan_type is ScanTypesEnum.NOT_VALUE_BETWEEN:
            for (value,) in unpacker:
                if not (start_target_value_int <= value <= end_target_value_int):
                    yield offset
                offset += step
        return

    # ──────────────────────────────────────────────────────────────────────
    # Fallback: strings (byte-by-byte) or numeric with unusual sizes (3/6/7).
    # ──────────────────────────────────────────────────────────────────────
    data = _as_bytes(memory_region_data)
    step = 1 if is_string else target_value_size
    end = memory_region_data_size - target_value_size + 1
    int_from_bytes = int.from_bytes

    if scan_type is ScanTypesEnum.EXACT_VALUE:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order
            )
            if value == target_value_int:
                yield offset
    elif scan_type is ScanTypesEnum.NOT_EXACT_VALUE:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order
            )
            if value != target_value_int:
                yield offset
    elif scan_type is ScanTypesEnum.BIGGER_THAN:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order
            )
            if value > target_value_int:
                yield offset
    elif scan_type is ScanTypesEnum.SMALLER_THAN:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order
            )
            if value < target_value_int:
                yield offset
    elif scan_type is ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order
            )
            if value >= target_value_int:
                yield offset
    elif scan_type is ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order
            )
            if value <= target_value_int:
                yield offset
    elif scan_type is ScanTypesEnum.VALUE_BETWEEN:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order
            )
            if start_target_value_int <= value <= end_target_value_int:
                yield offset
    elif scan_type is ScanTypesEnum.NOT_VALUE_BETWEEN:
        for offset in range(0, end, step):
            value = int_from_bytes(
                data[offset : offset + target_value_size], byte_order
            )
            if not (start_target_value_int <= value <= end_target_value_int):
                yield offset
