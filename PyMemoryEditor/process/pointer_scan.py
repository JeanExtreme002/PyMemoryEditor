# -*- coding: utf-8 -*-

"""
Reverse pointer scanning — the Cheat Engine "Pointer scan" feature.

Given a *dynamic* address (one that changes every run, e.g. the address
``search_by_value`` found for the player's HP), this module finds **static
pointer paths** that resolve to it: chains of the form
``module + offset -> [+o1] -> [+o2] -> ... -> +on`` whose base is a fixed
location inside a loaded module, so the same recipe keeps working across
process restarts despite ASLR.

It is the inverse of :meth:`AbstractProcess.resolve_pointer_chain`: that walks a
chain you already know; this *discovers* the chains. The output
(:class:`PointerPath`) plugs straight back into ``resolve_pointer_chain`` /
:class:`RemotePointer`.

How it works
------------
1. **Pointer map.** Read the target's writable (by default) memory and record
   every aligned pointer-sized slot whose stored value points into mapped
   memory — i.e. every ``address -> pointer`` edge in the heap/data graph.
2. **Reverse walk.** Starting from the target address, repeatedly look for slots
   whose value lands within ``max_offset`` bytes *below* the current address
   (that slot could reach it with a positive offset), and recurse on the slot's
   own address. A branch succeeds when it reaches a slot inside a static module
   range — that slot becomes the chain's base.

Because every hop reads a pointer the program itself writes, scanning only
*writable* memory (the default) captures the usual "global pointer -> object ->
field" chains while keeping the map small enough for pure Python.

Everything here is built on plain data plus a ``read_chunk`` callable, so the
algorithm is unit-testable without a live process and identical on Windows,
Linux and macOS.
"""

import array
import sys
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from typing import (
    Callable,
    Generator,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    TYPE_CHECKING,
    Union,
)

from ..util import iter_region_chunks

if TYPE_CHECKING:
    from .abstract import AbstractProcess
    from .remote_pointer import RemotePointer


# array typecodes for the two supported pointer widths. Native byte order is
# fine: we read the memory of a process on the same machine, so its endianness
# matches the host's.
_ARRAY_TYPECODE = {4: "I", 8: "Q"}


@dataclass(frozen=True)
class PointerPath:
    """A discovered static pointer path to a target address.

    Resolving ``base_address`` then walking ``offsets`` with
    :meth:`AbstractProcess.resolve_pointer_chain` lands on the target. When the
    base sits inside a known module, ``module`` / ``module_offset`` express it
    ASLR-independently so the path survives a restart — feed it to
    :meth:`rebase` in the next run.

    :param base_address: absolute static base for *this* run (the slot whose
        pointer the chain dereferences first).
    :param offsets: forward-order offsets, ready to hand to
        ``resolve_pointer_chain(base_address, offsets)``.
    :param module: name of the module containing ``base_address`` (``None`` when
        the base fell in a caller-supplied static range with no known module).
    :param module_offset: ``base_address - module.base_address`` — the portable,
        ASLR-independent part of the base. ``None`` when ``module`` is.
    """

    base_address: int
    offsets: Tuple[int, ...]
    module: Optional[str] = None
    module_offset: Optional[int] = None
    ptr_size: int = field(default=8, compare=False)

    def resolve(self, process: "AbstractProcess") -> int:
        """Walk this path in ``process`` and return the final target address."""
        return process.resolve_pointer_chain(
            self.base_address, self.offsets, ptr_size=self.ptr_size
        )

    def to_pointer(
        self,
        process: "AbstractProcess",
        *,
        pytype: Type = int,
        bufflength: Optional[int] = None,
    ) -> "RemotePointer":
        """Build a live :class:`RemotePointer` for the value at the end of this path."""
        from .remote_pointer import RemotePointer

        return RemotePointer(
            process,
            self.base_address,
            list(self.offsets),
            pytype=pytype,
            bufflength=bufflength,
            ptr_size=self.ptr_size,
        )

    def rebase(self, process: "AbstractProcess") -> "PointerPath":
        """
        Return a copy with ``base_address`` recomputed from the live module base
        in ``process`` — the call that makes a path from a previous run valid
        again after a restart moved the module (ASLR).

        :raises ValueError: when this path has no associated module (its base
            came from a caller-supplied static range), so it cannot be rebased.
        :raises LookupError: when the module is not loaded in ``process``.
        """
        if self.module is None or self.module_offset is None:
            raise ValueError(
                "PointerPath has no module to rebase against (base came from a "
                "custom static range); its base_address is only valid for the "
                "run it was found in."
            )
        for module in process.get_modules():
            if module.name == self.module:
                return PointerPath(
                    base_address=module.base_address + self.module_offset,
                    offsets=self.offsets,
                    module=self.module,
                    module_offset=self.module_offset,
                    ptr_size=self.ptr_size,
                )
        raise LookupError("Module %r is not loaded in the target process." % self.module)

    def to_dict(self) -> dict:
        """
        Serialise to a JSON-friendly dict (hex strings) for export.

        The ASLR-independent part — ``module`` + ``module_offset`` + ``offsets``
        — is what makes a saved path replayable in a later run via
        :meth:`from_dict` + :meth:`rebase`; ``base_address`` is kept only as a
        reference for the run it was found in.
        """
        return {
            "base_address": "0x%X" % self.base_address,
            "offsets": ["0x%X" % offset for offset in self.offsets],
            "module": self.module,
            "module_offset": (
                None if self.module_offset is None else "0x%X" % self.module_offset
            ),
            "ptr_size": self.ptr_size,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PointerPath":
        """Rebuild a :class:`PointerPath` from :meth:`to_dict` output.

        Numeric fields accept either hex strings (``"0x158"``) or plain ints, so
        hand-edited export files keep working.
        """

        def as_int(value: Union[str, int]) -> int:
            if isinstance(value, str):
                return int(value, 16)
            return int(value)

        module_offset = data.get("module_offset")
        return cls(
            base_address=as_int(data["base_address"]),
            offsets=tuple(as_int(offset) for offset in data.get("offsets", ())),
            module=data.get("module"),
            module_offset=None if module_offset is None else as_int(module_offset),
            ptr_size=int(data.get("ptr_size", 8)),
        )

    def recipe(self) -> Tuple[Optional[str], Optional[int], Tuple[int, ...]]:
        """
        The ASLR-independent identity of this path: ``(module, module_offset,
        offsets)``. Two paths from different runs describe the *same* pointer
        when their recipes are equal — the absolute ``base_address`` differs
        every run and is deliberately left out.

        Used to intersect independent scans (see :func:`intersect_pointer_paths`).
        Paths with no ``module`` have no portable recipe (only an absolute base
        valid for one run) and compare equal only to themselves.
        """
        return (self.module, self.module_offset, self.offsets)

    def __str__(self) -> str:
        if self.module is not None and self.module_offset is not None:
            head = '"%s"+0x%X' % (self.module, self.module_offset)
        else:
            head = "0x%X" % self.base_address
        chain = "".join(" -> [+0x%X]" % o for o in self.offsets[:-1])
        if self.offsets:
            chain += " -> +0x%X" % self.offsets[-1]
        return head + chain


class AddressRanges:
    """Fast ``addr in ranges`` membership over a set of merged address ranges.

    Built from ``(start, size)`` pairs; overlapping/adjacent ranges are merged
    so a single :func:`bisect` answers membership. A cheap min/max bounds check
    rejects the common cases (NULL, small integers, kernel addresses) before the
    bisect, which matters when the test runs once per pointer-sized slot.
    """

    __slots__ = ("_starts", "_ends", "_min", "_max")

    def __init__(self, ranges: Sequence[Tuple[int, int]]):
        merged = _merge_ranges(ranges)
        self._starts = [start for start, _ in merged]
        self._ends = [end for _, end in merged]
        self._min = self._starts[0] if merged else 1
        self._max = self._ends[-1] if merged else 0

    def __bool__(self) -> bool:
        return bool(self._starts)

    def __contains__(self, address: int) -> bool:
        if address < self._min or address >= self._max:
            return False
        index = bisect_right(self._starts, address) - 1
        return index >= 0 and address < self._ends[index]


def _merge_ranges(ranges: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Sort ``(start, end)`` ranges and coalesce overlapping/adjacent ones."""
    cleaned = sorted((s, e) for s, e in ranges if e > s)
    if not cleaned:
        return []
    merged = [cleaned[0]]
    for start, end in cleaned[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def build_pointer_map(
    regions: Sequence[Tuple[int, int]],
    read_chunk: Callable[[int, int], Optional[bytes]],
    mapped_ranges: AddressRanges,
    *,
    ptr_size: int = 8,
    aligned: bool = True,
    progress_callback: Optional[Callable[[float], None]] = None,
) -> Tuple["array.array", "array.array"]:
    """
    Scan ``regions`` for pointer-sized slots whose value lies in
    ``mapped_ranges`` and return two parallel arrays ``(values, addresses)``
    sorted ascending by value — the index structure the reverse walk queries.

    :param regions: ``(start, size)`` pairs to scan (already filtered to the
        readable/writable set the caller wants in the map).
    :param read_chunk: ``read_chunk(address, size)`` returns the bytes at
        ``address`` or ``None`` to skip an unreadable chunk; it may also raise,
        in which case the chunk is skipped.
    :param mapped_ranges: a value is kept only if it points somewhere inside
        these ranges (a plausible, dereferenceable pointer).
    :param aligned: when ``True`` (default) only consider slots at pointer-size
        alignment — far faster and how real compilers lay pointers out. ``False``
        scans every byte offset (slow; catches packed/misaligned pointers).
    """
    typecode = _ARRAY_TYPECODE.get(ptr_size)
    if typecode is None:
        raise ValueError("ptr_size must be 4 (32-bit target) or 8 (64-bit target).")

    byteorder = sys.byteorder
    low, high = mapped_ranges._min, mapped_ranges._max

    pairs_value = array.array(typecode)
    pairs_addr = array.array("Q")

    total = sum(size for _, size in regions) or 1
    scanned = 0

    for region_start, region_size in regions:
        for chunk_offset, chunk_size in iter_region_chunks(region_size, ptr_size):
            chunk_address = region_start + chunk_offset

            try:
                data = read_chunk(chunk_address, chunk_size)
            except Exception:  # noqa: BLE001 — backend read errors vary; skip the chunk
                data = None
            if not data:
                continue

            if aligned:
                slots = array.array(typecode)
                usable = (len(data) // ptr_size) * ptr_size
                slots.frombytes(bytes(data[:usable]))
                for index, value in enumerate(slots):
                    # Cheap bounds reject before the (costlier) range membership.
                    if value < low or value >= high:
                        continue
                    if value in mapped_ranges:
                        pairs_value.append(value)
                        pairs_addr.append(chunk_address + index * ptr_size)
            else:
                view = bytes(data)
                for index in range(0, len(view) - ptr_size + 1):
                    value = int.from_bytes(
                        view[index : index + ptr_size], byteorder, signed=False
                    )
                    if value < low or value >= high:
                        continue
                    if value in mapped_ranges:
                        pairs_value.append(value)
                        pairs_addr.append(chunk_address + index)

        scanned += region_size
        if progress_callback is not None:
            progress_callback(min(scanned / total, 1.0))

    # Sort the two parallel arrays by value. zip+sort is the simplest stdlib
    # path; the intermediate list of tuples is freed once the arrays are rebuilt.
    if pairs_value:
        order = sorted(range(len(pairs_value)), key=pairs_value.__getitem__)
        values = array.array(typecode, (pairs_value[i] for i in order))
        addresses = array.array("Q", (pairs_addr[i] for i in order))
    else:
        values = pairs_value
        addresses = pairs_addr

    return values, addresses


def find_pointer_paths(
    target_address: int,
    values: "array.array",
    addresses: "array.array",
    is_static: Callable[[int], bool],
    module_resolver: Callable[[int], Optional[Tuple[str, int]]],
    *,
    max_depth: int = 5,
    max_offset: int = 0x400,
    ptr_size: int = 8,
    max_results: Optional[int] = None,
) -> Generator[PointerPath, None, None]:
    """
    Reverse-walk the pointer map (``values`` sorted ascending, ``addresses``
    parallel) to yield :class:`PointerPath` recipes that resolve to
    ``target_address``.

    :param is_static: ``is_static(addr)`` — True when ``addr`` is a valid chain
        base (inside a static module range).
    :param module_resolver: ``module_resolver(addr)`` → ``(name, module_base)``
        for a static base, or ``None`` when the base is in a custom range.
    :param max_depth: maximum number of offsets in a chain (pointer levels).
    :param max_offset: largest positive offset a single hop may add — the
        struct-size window the search considers (Cheat Engine's "max offset").
    :param max_results: stop after yielding this many paths (``None`` = no cap).
    """
    state = {"count": 0}

    def make_path(base_address: int, offsets: Tuple[int, ...]) -> PointerPath:
        resolved = module_resolver(base_address)
        if resolved is not None:
            name, module_base = resolved
            return PointerPath(
                base_address=base_address,
                offsets=offsets,
                module=name,
                module_offset=base_address - module_base,
                ptr_size=ptr_size,
            )
        return PointerPath(base_address=base_address, offsets=offsets, ptr_size=ptr_size)

    def recurse(
        current: int, offsets: Tuple[int, ...], depth: int, visited: frozenset
    ) -> Generator[PointerPath, None, None]:
        if max_results is not None and state["count"] >= max_results:
            return

        # A non-empty chain that reached a static slot is a complete result.
        if offsets and is_static(current):
            yield make_path(current, offsets)
            state["count"] += 1
            if max_results is not None and state["count"] >= max_results:
                return

        if depth >= max_depth:
            return

        # Slots whose stored pointer is within [current - max_offset, current]
        # can reach `current` with a positive offset.
        lo = bisect_left(values, current - max_offset)
        hi = bisect_right(values, current)
        for i in range(lo, hi):
            slot_address = addresses[i]
            if slot_address in visited:  # break pointer cycles within a path
                continue
            offset = current - values[i]
            yield from recurse(
                slot_address,
                (offset,) + offsets,
                depth + 1,
                visited | {slot_address},
            )
            if max_results is not None and state["count"] >= max_results:
                return

    yield from recurse(target_address, (), 0, frozenset())


def intersect_pointer_paths(
    path_lists: Sequence[Sequence[PointerPath]],
) -> List[PointerPath]:
    """
    Return the pointer paths common to *every* list — the set-intersection of
    several independent pointer scans.

    Two paths match when their :meth:`PointerPath.recipe` is equal (same module,
    module offset and offsets), so this is ASLR-independent: run a full pointer
    scan after each restart, export each, then intersect them here to keep only
    the paths that survived every run — the reliable static pointers. This is
    the file-based alternative to the live :meth:`AbstractProcess.scan_pointer_paths`
    → rescan loop, and needs no open process.

    Only module-backed paths participate (a path with ``module is None`` has no
    portable recipe across runs and is dropped). One representative per surviving
    recipe is returned, taken from the first list (so its ``module_offset`` /
    ``offsets`` are intact; the absolute ``base_address`` is only meaningful for
    that file's run — rebase it before resolving).
    """
    if not path_lists:
        return []

    def recipe_set(paths: Sequence[PointerPath]) -> set:
        return {p.recipe() for p in paths if p.module is not None}

    common = recipe_set(path_lists[0])
    for paths in path_lists[1:]:
        common &= recipe_set(paths)
        if not common:
            return []

    out: List[PointerPath] = []
    seen: set = set()
    for path in path_lists[0]:
        if path.module is None:
            continue
        key = path.recipe()
        if key in common and key not in seen:
            seen.add(key)
            out.append(path)
    return out


__all__ = (
    "AddressRanges",
    "PointerPath",
    "build_pointer_map",
    "find_pointer_paths",
    "intersect_pointer_paths",
)
