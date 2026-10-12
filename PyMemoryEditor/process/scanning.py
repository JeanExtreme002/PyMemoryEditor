# -*- coding: utf-8 -*-

"""
Shared scan/lookup helpers consumed by the three platform backends.

The chunking + boundary logic lives here once, so the three backends cannot
drift apart:

  - `iter_values_for_addresses` reads the value at each of a sorted list of
    addresses, grouping nearby addresses of the same region into one syscall,
    and yields `(address, value | None)` tuples. Addresses that fall in gaps
    between regions, or whose `[address, address+bufflength)` would extend
    past the containing region into unmapped memory, yield `(address, None)`
    — never dropped and never zero-padded.

  - `iter_search_results` walks every chunk of every region and yields
    `(found_address, chunk_offset, region_index)` triples driven by a
    backend-provided scanning function. Same chunking strategy as
    `iter_region_chunks` plus the same transient-error handling.
"""

import ctypes
import logging
from typing import (
    Any,
    Callable,
    Generator,
    Iterable,
    Optional,
    Pattern,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

from ..enums import ScanTypesEnum
from ..util import (
    convert_from_byte_array,
    get_c_type_of,
    iter_region_chunks,
    scan_memory,
    scan_memory_for_exact_value,
)
from ..util.pattern import is_fixed_width
from .errors import PyMemoryEditorError
from .region import MemoryRegion, MemoryRegionSnapshot


_logger = logging.getLogger("PyMemoryEditor")


# Shared type for the in-region search callable. ``scan_memory`` accepts a
# tuple target (for VALUE_BETWEEN) while ``scan_memory_for_exact_value`` does
# not — at runtime we only ever route VALUE_BETWEEN through ``scan_memory``,
# but mypy needs the widened signature on the local binding.
# (data, size, target, width, scan_type, pytype, *, aligned) -> offsets; both
# kernels share this shape, so the dispatch below is a plain assignment.
_SearchingMethod = Callable[..., Iterable[int]]


T = TypeVar("T")


def _ensure_sorted_by_address(
    memory_regions: Iterable[MemoryRegion],
) -> Sequence[MemoryRegion]:
    """
    Return ``memory_regions`` sorted by ``address``, reusing the input verbatim
    when it is a :class:`MemoryRegionSnapshot` (already address-sorted by
    contract).

    The optimization matters in tight refine-scan loops where snapshots are
    reused across many ``search_by_addresses`` / ``search_by_value*`` calls;
    re-sorting a 100k-region list per call would dominate the runtime. Any
    other iterable (a plain list, a tuple, a generator) is materialized into a
    new sorted list, so backends can pass the caller's ``memory_regions``
    through untouched and the snapshot tag survives.
    """
    if isinstance(memory_regions, MemoryRegionSnapshot):
        return memory_regions
    return sorted(memory_regions, key=lambda region: region.address)


def _as_region_sequence(
    memory_regions: Iterable[MemoryRegion],
) -> Sequence[MemoryRegion]:
    """Materialize a one-shot iterable: the scan drivers walk the regions twice
    (once to total the size for progress, once to scan). A list — snapshot or
    not — is returned as is."""
    if isinstance(memory_regions, Sequence):
        return memory_regions
    return list(memory_regions)


def _always_false(_exc: BaseException) -> bool:
    """Default ``transient_error_check`` — every exception is fatal."""
    return False


# What a ``read_chunk`` may raise for a read that failed: every backend reports
# I/O failures as an ``OSError`` subclass (``MachReadError``,
# ``_LinuxPartialIOError``, ``_Win32ChunkReadError`` / ``_Win32FatalReadError``)
# and a closed process as a library error. Anything else — a ``TypeError`` from
# a bad buffer, a ``MemoryError`` — is a bug or an exhausted host, not a dead
# page, and propagates even with ``raise_error=False``.
_READ_ERRORS = (OSError, PyMemoryEditorError)


# Two requested addresses closer than this share one read: copying the gap is
# cheaper than another syscall. Farther apart, each cluster gets its own read,
# so a handful of addresses in a 256 MiB region does not pull in the whole
# chunk.
_ADDRESS_WINDOW_GAP = 64 * 1024


def iter_values_for_addresses(
    addresses: Sequence[int],
    memory_regions: Iterable[MemoryRegion],
    pytype: Type[T],
    bufflength: int,
    read_chunk: Callable[[int, int], "ctypes.Array"],
    *,
    raise_error: bool = False,
    transient_error_check: Optional[Callable[[BaseException], bool]] = None,
) -> Generator[Tuple[int, Optional[T]], None, None]:
    """
    Yield `(address, value)` for each address in ascending address order.
    `read_chunk(address, size)` is expected to return a ctypes byte array (or
    any object supporting the buffer protocol) or raise.

    Reads are grouped: addresses of the same region chunk that lie within
    ``_ADDRESS_WINDOW_GAP`` bytes of each other share one read, which spans
    from the first of them to the end of the last value. Only the bytes the
    values need (plus small gaps) are read, never the whole chunk.

    Failures:
      - Address falls in a gap between regions → yield (address, None).
      - Address is in a region but the read fails with an I/O error (an
        ``OSError`` or a library error): if the error is classified transient
        (page gone) by `transient_error_check`, yield (address, None).
        Otherwise: if `raise_error` is True, propagate the exception; else
        yield (address, None) and continue. Any other exception is a bug and
        always propagates.
      - Address is near the very end of the region and `address + bufflength`
        extends past it: when the following regions continue the range
        without a gap (and are readable), the value is read directly, the way
        ``read_process_memory`` would; otherwise yield (address, None) —
        never a zero-padded value.
    """
    if transient_error_check is None:
        transient_error_check = _always_false
    is_transient = transient_error_check

    # Validate the width once, up front. A width the type cannot represent is
    # a caller error, not an I/O failure, so it propagates regardless of
    # `raise_error` (that flag is about reads that fail). Leaving it to the
    # per-address decode would turn it into `(address, None)` for every
    # address — indistinguishable from a dead target.
    get_c_type_of(pytype, bufflength)

    sorted_addresses = sorted(addresses)
    sorted_regions = _ensure_sorted_by_address(memory_regions)
    address_count = len(sorted_addresses)
    address_index = 0
    region_index = 0

    def read(address: int, size: int) -> Optional[memoryview]:
        """``read_chunk`` as one contiguous byte view, or ``None`` when the
        read failed in a way the caller allows us to skip."""
        try:
            data = read_chunk(address, size)
        except _READ_ERRORS as exc:
            if not is_transient(exc) and raise_error:
                raise
            _logger.debug(
                "iter_values_for_addresses: skipping read at 0x%X (%d bytes): %s",
                address,
                size,
                exc,
            )
            return None
        if data is None:  # a backend signalling a transient miss without raising
            return None
        # One contiguous byte view per read: slicing it below gives a buffer
        # `from_buffer_copy` accepts (a single memcpy) instead of a list of
        # ints that would have to be re-packed element by element. Works for
        # ctypes arrays, bytes and bytearray alike.
        return memoryview(data).cast("B")

    def decode(view: memoryview, offset: int) -> Optional[T]:
        raw = view[offset : offset + bufflength]
        if len(raw) < bufflength:
            # Defensive: the backend returned fewer bytes than requested.
            # Don't silently zero-pad.
            return None
        try:
            data = (ctypes.c_byte * bufflength).from_buffer_copy(raw)
            return convert_from_byte_array(data, pytype, bufflength)
        except (ValueError, UnicodeDecodeError, OSError):
            if raise_error:
                raise
            return None

    def read_straddling(target_address: int, current: int) -> Optional[T]:
        """A value running past the end of ``sorted_regions[current]``: read it
        directly when the next regions continue the range without a gap — the
        region list splits wherever the protection changes, so adjacent
        regions are one readable span to the OS — else report it unreadable."""
        needed_end = target_address + bufflength
        covered_end = sorted_regions[current].address + sorted_regions[current].size
        following = current + 1
        while covered_end < needed_end and following < len(sorted_regions):
            neighbour = sorted_regions[following]
            if neighbour.address > covered_end or not neighbour.is_readable:
                break
            covered_end = max(covered_end, neighbour.address + neighbour.size)
            following += 1
        if covered_end < needed_end:
            return None
        view = read(target_address, bufflength)
        return None if view is None else decode(view, 0)

    while address_index < address_count:
        current_address = sorted_addresses[address_index]

        # Advance past regions that end before the current address.
        while region_index < len(sorted_regions):
            region = sorted_regions[region_index]
            if current_address < region.address + region.size:
                break
            region_index += 1

        if region_index >= len(sorted_regions):
            # No region can contain this or any subsequent address.
            yield current_address, None
            address_index += 1
            continue

        region = sorted_regions[region_index]
        base_address = region.address
        size = region.size
        region_end = base_address + size

        # Address falls in the gap before this region (and no earlier region holds it).
        if current_address < base_address:
            yield current_address, None
            address_index += 1
            continue

        # We have a region containing `current_address`. Walk its chunks and
        # consume every address that lies inside the region. The chunks only
        # bound how far one read may reach (no read spans more than a chunk
        # plus `bufflength - 1` bytes); within a chunk the addresses are
        # clustered into windows and each window is read on its own.
        for chunk_offset, chunk_size in iter_region_chunks(size, bufflength):
            if address_index >= address_count:
                break

            chunk_end = base_address + chunk_offset + chunk_size
            if sorted_addresses[address_index] >= chunk_end:
                continue

            while (
                address_index < address_count
                and sorted_addresses[address_index] < chunk_end
            ):
                # Grow a window while the next address is close to the end of
                # the bytes already needed. A value that would straddle the
                # region's end is the last thing in the region (addresses are
                # sorted), needs no bytes from this window, and is handled
                # separately below.
                window_first = address_index
                window_start = sorted_addresses[window_first]
                window_end = window_start
                window_stop = window_first
                while (
                    window_stop < address_count
                    and sorted_addresses[window_stop] < chunk_end
                    and sorted_addresses[window_stop] <= window_end + _ADDRESS_WINDOW_GAP
                ):
                    target_address = sorted_addresses[window_stop]
                    if target_address + bufflength <= region_end:
                        window_end = target_address + bufflength
                    window_stop += 1

                view: Optional[memoryview] = None
                read_failed = False
                if window_end > window_start:
                    view = read(window_start, window_end - window_start)
                    read_failed = view is None

                for index in range(window_first, window_stop):
                    target_address = sorted_addresses[index]
                    if read_failed:
                        yield target_address, None
                    elif target_address + bufflength > region_end:
                        yield target_address, read_straddling(
                            target_address, region_index
                        )
                    else:
                        assert view is not None
                        yield target_address, decode(
                            view, target_address - window_start
                        )

                address_index = window_stop


def iter_search_results(
    memory_regions: Iterable[MemoryRegion],
    pytype: Type,
    bufflength: int,
    target_value_bytes: Union[bytes, Tuple[bytes, ...]],
    scan_type: ScanTypesEnum,
    read_chunk: Callable[[int, int], Any],
    *,
    progress_information: bool = False,
    transient_error_check: Optional[Callable[[BaseException], bool]] = None,
    aligned: bool = True,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    Walk every chunk of every region and yield the addresses where
    ``scan_memory`` (or ``scan_memory_for_exact_value`` for EXACT/NOT_EXACT)
    finds a match against ``target_value_bytes``. ``aligned=False`` lets a
    numeric value match at any byte offset (see the kernels).

    All three platform backends share this loop — chunking, progress-info
    computation and try/except classification — so chunk indexing, progress
    accounting and transient-error handling cannot drift between them.

    ``read_chunk(address, size)`` is expected to return a buffer object
    accepted by ``scan_memory``/``scan_memory_for_exact_value`` (typically a
    ``ctypes.Array``) or raise. Failures classified as transient by
    ``transient_error_check`` are swallowed (the chunk is skipped, scan
    continues); any other failure propagates so the caller sees real
    permission / configuration errors. ``read_chunk`` may also return ``None``
    to signal a transient miss without raising (kept for backends like Win32
    that already classified inside the helper).

    Regions are read in the order provided — callers should pre-sort by
    ``address`` if monotonic progress fractions matter.

    ``progress_information`` only reports progress *alongside a match* (the
    ``(address, info)`` shape has no room for anything else), so a scan with
    few or no hits shows little or no progress.
    """
    if transient_error_check is None:
        transient_error_check = _always_false

    memory_regions = _as_region_sequence(memory_regions)

    memory_total = 0
    for region in memory_regions:
        memory_total += region.size

    if memory_total == 0:
        return

    if scan_type in (ScanTypesEnum.EXACT_VALUE, ScanTypesEnum.NOT_EXACT_VALUE):
        searching_method: _SearchingMethod = cast(
            _SearchingMethod, scan_memory_for_exact_value
        )
    else:
        searching_method = cast(_SearchingMethod, scan_memory)

    checked_memory_size = 0

    # ``str`` and ``bytes`` matches can begin at any byte. For a region broken
    # across multiple chunks, a match that straddles a boundary would
    # otherwise be lost because the first chunk ends with only part of the
    # value and the next chunk starts past where the match begins. Read
    # ``bufflength - 1`` extra bytes from the next chunk so the scan can
    # complete a straddling decode without ever re-emitting an offset (the
    # scanner only yields offsets in ``range(0, read_size - bufflength + 1)``
    # over the *augmented* read_size, and the clamp below keeps every emitted
    # offset inside the original chunk). The same goes for an ``int`` at an
    # unusual width (3, 5, 6, 7 bytes), which has no natural alignment.
    # Numeric values at a natural width are stepped by that width and
    # ``iter_region_chunks`` aligns every chunk to it, so they can never
    # straddle a boundary and need no overlap -- unless ``aligned=False``
    # lets them start at any byte, in which case they need it like text.
    byte_granular = (
        pytype in (str, bytes) or bufflength not in (1, 2, 4, 8) or not aligned
    )
    byte_granular_overlap = bufflength - 1 if byte_granular else 0

    for region in memory_regions:
        address, size = region.address, region.size

        for chunk_offset, chunk_size in iter_region_chunks(size, bufflength):
            chunk_address = address + chunk_offset

            read_size = chunk_size + _overlap(
                byte_granular_overlap, size, chunk_offset, chunk_size
            )

            try:
                chunk_data = read_chunk(chunk_address, read_size)
            except Exception as exc:  # noqa: BLE001 — backend errors vary
                if transient_error_check(exc):
                    _logger.debug(
                        "iter_search_results: skipping chunk at 0x%X (%d bytes): %s",
                        chunk_address,
                        read_size,
                        exc,
                    )
                    chunk_data = None
                else:
                    raise

            if chunk_data is None:
                continue

            for offset in searching_method(
                chunk_data,
                read_size,
                target_value_bytes,
                bufflength,
                scan_type,
                pytype,
                aligned=aligned,
            ):
                # ``scan_memory_for_exact_value`` uses ``bytes.find`` over the
                # full augmented buffer and can therefore return offsets that
                # sit inside the overlap region — the *next* chunk's scan
                # would re-emit them. Clamp here so each match address is
                # attributed to exactly one chunk.
                if offset >= chunk_size:
                    continue
                found_address = chunk_address + offset

                if progress_information:
                    yield (
                        found_address,
                        {
                            "memory_total": memory_total,
                            "progress": (
                                checked_memory_size + chunk_offset + offset
                            )
                            / memory_total,
                        },
                    )
                else:
                    yield found_address

        checked_memory_size += size


def _overlap(wanted: int, region_size: int, chunk_offset: int, chunk_size: int) -> int:
    """How many bytes past a chunk to read so a match straddling its end is
    still seen: ``wanted``, but never past the end of the region. Chunks are
    aligned to the value width, so the last one can be shorter than
    ``wanted`` — reading the full overlap there ran past the region into
    memory that may not be mapped, failing the whole chunk."""
    return max(0, min(wanted, region_size - chunk_offset - chunk_size))


def _iter_matches(
    compiled_pattern: "Pattern[bytes]", data: bytes, overlapping: bool, position: int = 0
) -> Generator[Tuple[int, int], None, None]:
    """Ascending ``(start, end)`` offsets of the matches of
    ``compiled_pattern`` in ``data``, searching from ``position``.
    ``overlapping`` restarts the search one byte after each match's start
    instead of at its end, so a match beginning inside the previous one is
    reported too (a zero-width match advances one byte either way)."""
    if not overlapping:
        for found in compiled_pattern.finditer(data, position):
            yield found.start(), found.end()
        return
    search = compiled_pattern.search
    # ``search`` clamps a start past the end back to ``len(data)``, where a
    # zero-width pattern would match forever — stop once we are past it.
    while position <= len(data):
        match = search(data, position)
        if match is None:
            return
        start = match.start()
        yield start, match.end()
        position = start + 1


def iter_pattern_results(
    memory_regions: Iterable[MemoryRegion],
    compiled_pattern: "Pattern[bytes]",
    pattern_length: int,
    read_chunk: Callable[[int, int], Any],
    *,
    progress_information: bool = False,
    transient_error_check: Optional[Callable[[BaseException], bool]] = None,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    Walk every chunk of every region and yield the addresses where
    ``compiled_pattern`` matches. Implements AOB (Array Of Bytes) scanning,
    the technique used by Cheat Engine / IDA to locate code or data that
    moves between builds.

    Mirrors :func:`iter_search_results` for the regex case: same chunking
    strategy, same transient-error classification, same optional
    ``progress_information`` shape. ``pattern_length`` is the number of
    bytes each match consumes — needed because the regex source length is
    not a reliable proxy (an IDA-style ``"48 ? ? 00"`` matches 4 bytes but
    its escaped source is longer). The chunk overlap reads
    ``pattern_length - 1`` extra bytes from the next chunk so matches
    straddling a chunk boundary are still detected; matches that fall in
    the overlap region are clamped so each address is attributed to
    exactly one chunk.

    A fixed-width pattern (every IDA-style signature) reports overlapping
    matches — ``90 90`` over ``90 90 90`` yields offsets 0 and 1, the same
    as a value scan for those bytes. A variable-width regex follows
    ``re.finditer`` (leftmost, non-overlapping), so a long match is not
    re-reported once per suffix — including across a chunk boundary: the
    next chunk resumes searching where the last reported match ended, as one
    ``finditer`` over the whole region would. (A match longer than
    ``pattern_length`` is cut at the end of the chunk's read; its remainder
    can then surface as a separate match. Size ``byte_length`` for the
    longest match you expect.)
    """
    if transient_error_check is None:
        transient_error_check = _always_false

    pattern_length = max(1, pattern_length)
    memory_regions = _as_region_sequence(memory_regions)
    # A fixed-width pattern reports overlapping matches, like a value scan
    # (``90 90`` over ``90 90 90`` → offsets 0 and 1); a variable-width regex
    # keeps ``finditer``'s leftmost non-overlapping matches. See
    # ``util.pattern.is_fixed_width``.
    overlapping = is_fixed_width(compiled_pattern)

    memory_total = 0
    for region in memory_regions:
        memory_total += region.size

    if memory_total == 0:
        return

    checked_memory_size = 0

    for region in memory_regions:
        address, size = region.address, region.size
        # Non-overlapping mode: where the last reported match ended, so the
        # next chunk does not report a suffix of a match that straddled the
        # boundary (its overlap bytes are the next chunk's first bytes).
        resume_address = address

        for chunk_offset, chunk_size in iter_region_chunks(size, pattern_length):
            chunk_address = address + chunk_offset

            read_size = chunk_size + _overlap(
                pattern_length - 1, size, chunk_offset, chunk_size
            )

            try:
                chunk_data = read_chunk(chunk_address, read_size)
            except Exception as exc:  # noqa: BLE001 — backend errors vary
                if transient_error_check(exc):
                    _logger.debug(
                        "iter_pattern_results: skipping chunk at 0x%X (%d bytes): %s",
                        chunk_address,
                        read_size,
                        exc,
                    )
                    chunk_data = None
                else:
                    raise

            if chunk_data is None:
                continue

            # The regex engine needs a real bytes object. Convert once per
            # chunk; ctypes arrays expose the buffer protocol so this is a
            # single memcpy.
            data_bytes = bytes(chunk_data)

            position = 0 if overlapping else max(0, resume_address - chunk_address)
            for offset, end in _iter_matches(
                compiled_pattern, data_bytes, overlapping, position
            ):
                # Same clamping rule as iter_search_results: matches in the
                # overlap belong to the *next* chunk's emission slot. Starts
                # ascend, so nothing after this one belongs here either.
                if offset >= chunk_size:
                    break
                found_address = chunk_address + offset
                resume_address = chunk_address + end

                if progress_information:
                    yield (
                        found_address,
                        {
                            "memory_total": memory_total,
                            "progress": (
                                checked_memory_size + chunk_offset + offset
                            )
                            / memory_total,
                        },
                    )
                else:
                    yield found_address

        checked_memory_size += size


__all__ = (
    "iter_pattern_results",
    "iter_search_results",
    "iter_values_for_addresses",
)
