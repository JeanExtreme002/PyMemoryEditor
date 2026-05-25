# -*- coding: utf-8 -*-

"""
Shared scan/lookup helpers consumed by the three platform backends.

The chunking + boundary logic was copy-pasted between `linux/functions.py` and
`macos/functions.py` (and partially `win32/functions.py`) — same bug surface
in three places. This module owns it once:

  - `iter_values_for_addresses` reads the value at each of a sorted list of
    addresses, grouping syscalls by region and chunk, and yields
    `(address, value | None)` tuples. Addresses that fall in gaps between
    regions, or whose `[address, address+bufflength)` would extend past the
    last chunk of the containing region, yield `(address, None)` — the
    previous per-backend code silently dropped gap-addresses and zero-padded
    truncated reads.

  - `iter_search_results` walks every chunk of every region and yields
    `(found_address, chunk_offset, region_index)` triples driven by a
    backend-provided scanning function. Same chunking strategy as
    `iter_region_chunks` plus the same transient-error handling.
"""

import ctypes
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Iterable,
    Optional,
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
    iter_region_chunks,
    scan_memory,
    scan_memory_for_exact_value,
)


# Shared type for the in-region search callable. ``scan_memory`` accepts a
# tuple target (for VALUE_BETWEEN) while ``scan_memory_for_exact_value`` does
# not — at runtime we only ever route VALUE_BETWEEN through ``scan_memory``,
# but mypy needs the widened signature on the local binding.
_SearchingMethod = Callable[
    [Sequence, int, Any, int, ScanTypesEnum, Optional[Type]],
    Iterable[int],
]


T = TypeVar("T")


# Sentinel key on a region dict marking the dict as already address-sorted.
# `iter_values_for_addresses` and `iter_search_results` consult this to skip
# the per-call `sorted(...)` cost. ``snapshot_memory_regions()`` pre-sorts the
# list and tags every region; pre-filtered slices that preserve order can
# carry the tag through too.
_PRESORTED_KEY = "_pymemoryeditor_presorted"


def _ensure_sorted_by_address(memory_regions: Sequence[Dict]) -> Sequence[Dict]:
    """
    Return ``memory_regions`` sorted by ``address``, reusing the input verbatim
    when every region is already tagged with :data:`_PRESORTED_KEY`.

    Tagging is purely advisory — falsifying it on an unsorted snapshot would
    silently mis-walk regions, but no public API does that. The optimization
    matters in tight refine-scan loops where snapshots are reused across many
    ``search_by_addresses``/``search_by_value*`` calls.
    """
    if not memory_regions:
        return memory_regions
    # Cheap check: only inspect the first region; the tagging contract is
    # all-or-nothing.
    if memory_regions[0].get(_PRESORTED_KEY):
        return memory_regions
    return sorted(memory_regions, key=lambda region: region["address"])


def _always_false(_exc: BaseException) -> bool:
    """Default ``transient_error_check`` — every exception is fatal."""
    return False


def iter_values_for_addresses(
    addresses: Sequence[int],
    memory_regions: Sequence[Dict],
    pytype: Type[T],
    bufflength: int,
    read_chunk: Callable[[int, int], "ctypes.Array"],
    *,
    raise_error: bool = False,
    transient_error_check: Optional[Callable[[BaseException], bool]] = None,
) -> Generator[Tuple[int, Optional[T]], None, None]:
    """
    Yield `(address, value)` for each address, reading memory in region-level
    chunks. `read_chunk(address, size)` is expected to return a ctypes byte
    array (or any object supporting `[start:end]` byte slicing) or raise.

    Failures:
      - Address falls in a gap between regions → yield (address, None).
      - Address is in a region but the read fails: if the error is classified
        transient (page gone) by `transient_error_check`, yield (address, None).
        Otherwise: if `raise_error` is True, propagate the exception; else
        yield (address, None) and continue.
      - Address is near the very end of the region and `address + bufflength`
        extends past the region — yield (address, None). The previous code
        silently zero-padded.
    """
    if transient_error_check is None:
        transient_error_check = _always_false

    sorted_addresses = sorted(addresses)
    sorted_regions = _ensure_sorted_by_address(memory_regions)
    address_index = 0
    region_index = 0

    while address_index < len(sorted_addresses):
        current_address = sorted_addresses[address_index]

        # Advance past regions that end before the current address.
        while region_index < len(sorted_regions):
            region = sorted_regions[region_index]
            if current_address < region["address"] + region["size"]:
                break
            region_index += 1

        if region_index >= len(sorted_regions):
            # No region can contain this or any subsequent address.
            yield current_address, None
            address_index += 1
            continue

        region = sorted_regions[region_index]
        base_address = region["address"]
        size = region["size"]

        # Address falls in the gap before this region (and no earlier region holds it).
        if current_address < base_address:
            yield current_address, None
            address_index += 1
            continue

        # We have a region containing `current_address`. Walk its chunks and
        # consume every address that lies inside the region.
        for chunk_offset, chunk_size in iter_region_chunks(size, bufflength):
            if address_index >= len(sorted_addresses):
                break

            chunk_address = base_address + chunk_offset
            chunk_end = chunk_address + chunk_size

            if sorted_addresses[address_index] >= chunk_end:
                continue

            # Read up to `bufflength - 1` bytes past the chunk so addresses
            # near the chunk boundary (but still inside the same region)
            # can still be fully decoded. The last chunk of a region can't
            # extend past the region end — addresses near that boundary will
            # be detected and yielded as None below.
            extra = bufflength - 1 if chunk_offset + chunk_size < size else 0
            read_size = chunk_size + extra

            try:
                chunk_data = read_chunk(chunk_address, read_size)
            except Exception as exc:  # noqa: BLE001 — backend errors vary
                transient = transient_error_check(exc)
                if not transient and raise_error:
                    raise
                while (
                    address_index < len(sorted_addresses)
                    and sorted_addresses[address_index] < chunk_end
                    and sorted_addresses[address_index] >= base_address
                ):
                    yield sorted_addresses[address_index], None
                    address_index += 1
                continue

            while (
                address_index < len(sorted_addresses)
                and sorted_addresses[address_index] < chunk_end
                and sorted_addresses[address_index] >= base_address
            ):
                target_address = sorted_addresses[address_index]
                offset_in_chunk = target_address - chunk_address

                # Reject reads that would straddle the region's end (the only
                # remaining case where chunk_data could be too short).
                if target_address + bufflength > base_address + size:
                    yield target_address, None
                    address_index += 1
                    continue

                try:
                    raw = chunk_data[offset_in_chunk : offset_in_chunk + bufflength]
                    if len(raw) < bufflength:
                        # Defensive: the backend returned fewer bytes than
                        # requested. Don't silently zero-pad.
                        yield target_address, None
                        address_index += 1
                        continue
                    data = (ctypes.c_byte * bufflength)(*raw)
                    yield target_address, convert_from_byte_array(
                        data, pytype, bufflength
                    )
                except (ValueError, UnicodeDecodeError, OSError) as error:
                    if raise_error:
                        raise error
                    yield target_address, None

                address_index += 1


def iter_search_results(
    memory_regions: Sequence[Dict],
    pytype: Type,
    bufflength: int,
    target_value_bytes: Union[bytes, Tuple[bytes, ...]],
    scan_type: ScanTypesEnum,
    read_chunk: Callable[[int, int], Any],
    *,
    progress_information: bool = False,
    transient_error_check: Optional[Callable[[BaseException], bool]] = None,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    Walk every chunk of every region and yield the addresses where
    ``scan_memory`` (or ``scan_memory_for_exact_value`` for EXACT/NOT_EXACT)
    finds a match against ``target_value_bytes``.

    The three platform backends used to duplicate this loop verbatim — same
    chunking, same progress-info computation, same try/except classification.
    The duplication tracked bugs three-fold (off-by-one in chunk indexing,
    progress overflow, missing transient-error handling). Owning it once here
    keeps the next fix in one place.

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
    """
    if transient_error_check is None:
        transient_error_check = _always_false

    memory_total = 0
    for region in memory_regions:
        memory_total += region["size"]

    if memory_total == 0:
        return

    if scan_type in (ScanTypesEnum.EXACT_VALUE, ScanTypesEnum.NOT_EXACT_VALUE):
        searching_method: _SearchingMethod = cast(
            _SearchingMethod, scan_memory_for_exact_value
        )
    else:
        searching_method = cast(_SearchingMethod, scan_memory)

    checked_memory_size = 0

    # Strings can begin at any byte (step=1 in the scanner). For a region
    # broken across multiple chunks, a string match that straddles a
    # boundary would otherwise be lost because the first chunk ends with
    # only part of the string and the next chunk starts past where the
    # match begins. Read ``bufflength - 1`` extra bytes from the next
    # chunk so the scan can complete a straddling decode without ever
    # re-emitting an offset (the scanner only yields offsets in
    # ``range(0, chunk_size - bufflength + 1, step)`` from the *augmented*
    # size, which still maps to addresses inside the original chunk).
    str_overlap = bufflength - 1 if pytype is str else 0

    for region in memory_regions:
        address, size = region["address"], region["size"]

        for chunk_offset, chunk_size in iter_region_chunks(size, bufflength):
            chunk_address = address + chunk_offset

            is_last_chunk = chunk_offset + chunk_size >= size
            read_size = chunk_size + (0 if is_last_chunk else str_overlap)

            try:
                chunk_data = read_chunk(chunk_address, read_size)
            except Exception as exc:  # noqa: BLE001 — backend errors vary
                if transient_error_check(exc):
                    continue
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


__all__ = ("iter_search_results", "iter_values_for_addresses")
