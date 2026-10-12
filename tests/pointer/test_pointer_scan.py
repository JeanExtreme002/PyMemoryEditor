# -*- coding: utf-8 -*-

"""
Tests for the reverse pointer scan (Cheat Engine's "Pointer scan").

Two layers:

  - Pure-algorithm tests drive ``build_pointer_map`` / ``find_pointer_paths``
    with a synthetic, in-memory pointer graph and a fake ``read_chunk`` — no
    process, deterministic on every platform.

  - Integration tests run ``AbstractProcess.scan_pointer_paths`` against the
    test's own process: a real pointer chain is built on the heap, the base
    slot's range is passed as a ``static_ranges`` override (the planted base
    isn't inside a module), and we assert the scan rediscovers a path that
    resolves back to the planted value.
"""

import array
import ctypes
import json
import logging
import os
import random
import struct
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)

from PyMemoryEditor import OpenProcess, PointerPath  # noqa: E402
from PyMemoryEditor.process import pointer_scan  # noqa: E402
from PyMemoryEditor.process.module_info import ModuleInfo  # noqa: E402
from PyMemoryEditor.process.pointer_scan import (  # noqa: E402
    AddressRanges,
    build_pointer_map,
    find_pointer_paths,
    intersect_pointer_paths,
)
from PyMemoryEditor.util import scan_numpy  # noqa: E402
from PyMemoryEditor.util.scan import _iter_large_region_chunks  # noqa: E402


# --------------------------------------------------------------------------- #
# AddressRanges
# --------------------------------------------------------------------------- #

def test_address_ranges_membership_and_merge():
    ranges = AddressRanges([(0x1000, 0x2000), (0x1800, 0x2400), (0x5000, 0x5100)])
    assert 0x1000 in ranges          # start inclusive
    assert 0x23FF in ranges          # inside the merged [0x1000, 0x2400)
    assert 0x2400 not in ranges      # end exclusive
    assert 0x4000 not in ranges      # gap
    assert 0x50FF in ranges
    assert 0x5100 not in ranges
    assert 0xFFF not in ranges       # below min bound


def test_address_ranges_empty_contains_nothing():
    ranges = AddressRanges([])
    assert 0 not in ranges
    assert 0x1000 not in ranges
    assert not ranges


# --------------------------------------------------------------------------- #
# Pure-algorithm pointer scan over a synthetic graph
# --------------------------------------------------------------------------- #

class FakeMemory:
    """A flat little address space backing a fake ``read_chunk``.

    Pointers are stored as ``ptr_size``-byte little-endian values so the scan's
    array-based decode sees real bytes. ``put_ptr`` plants a pointer; ``regions``
    yields the single contiguous span for ``build_pointer_map``.
    """

    def __init__(self, base=0x100000, size=0x1000, ptr_size=8):
        self.base = base
        self.size = size
        self.ptr_size = ptr_size
        self._buf = bytearray(size)

    def put_ptr(self, address, value):
        offset = address - self.base
        self._buf[offset : offset + self.ptr_size] = value.to_bytes(
            self.ptr_size, "little"
        )

    def read_chunk(self, address, size):
        offset = address - self.base
        if offset < 0 or offset + size > self.size:
            return None
        return bytes(self._buf[offset : offset + size])

    @property
    def regions(self):
        return [(self.base, self.size)]


def _scan(mem, target, static_ranges, **kwargs):
    mapped = AddressRanges(mem.regions and [(mem.base, mem.base + mem.size)])
    values, addresses = build_pointer_map(
        mem.regions, mem.read_chunk, mapped, ptr_size=mem.ptr_size
    )
    # Public convention for static_ranges is (start, size); AddressRanges wants
    # (start, end).
    static = AddressRanges([(start, start + size) for start, size in static_ranges])
    return list(
        find_pointer_paths(
            target,
            values,
            addresses,
            static.__contains__,
            lambda a: None,
            ptr_size=mem.ptr_size,
            **kwargs,
        )
    )


def test_single_level_path_found():
    """A static base holding a pointer ``base_ptr -> target_region`` with the
    value living at ``+offset`` from the pointed object is found as ``[+offset]``."""
    mem = FakeMemory()
    base_slot = mem.base + 0x10        # the static base (holds a pointer)
    obj = mem.base + 0x200             # object the base points to
    target = obj + 0x18                # value sits 0x18 into the object

    mem.put_ptr(base_slot, obj)

    paths = _scan(mem, target, [(base_slot, mem.ptr_size)], max_depth=3, max_offset=0x100)

    assert any(
        p.base_address == base_slot and p.offsets == (0x18,) for p in paths
    ), [str(p) for p in paths]

    # The discovered path must round-trip: resolving it reaches the target.
    for p in paths:
        if p.base_address == base_slot and p.offsets == (0x18,):
            # forward resolve emulation: [base] + 0x18
            assert obj + 0x18 == target


def test_two_level_path_found():
    """``base -> [+0] -> +off`` two-level chain is discovered with both offsets."""
    mem = FakeMemory()
    base_slot = mem.base + 0x10
    level1 = mem.base + 0x100          # base points here
    obj = mem.base + 0x300            # level1 points here
    target = obj + 0x8

    mem.put_ptr(base_slot, level1)     # [base] = level1
    mem.put_ptr(level1, obj)           # [level1 + 0] = obj

    paths = _scan(mem, target, [(base_slot, mem.ptr_size)], max_depth=4, max_offset=0x40)

    assert any(
        p.base_address == base_slot and p.offsets == (0x0, 0x8) for p in paths
    ), [str(p) for p in paths]


def test_offset_window_excludes_far_pointers():
    """A pointer farther than ``max_offset`` below the target is not a candidate."""
    mem = FakeMemory()
    base_slot = mem.base + 0x10
    obj = mem.base + 0x200
    target = obj + 0x500               # 0x500 past the object the base points to

    mem.put_ptr(base_slot, obj)

    # max_offset too small to bridge 0x500 → no path.
    assert _scan(mem, target, [(base_slot, mem.ptr_size)], max_offset=0x100) == []
    # Wide enough → found.
    assert _scan(mem, target, [(base_slot, mem.ptr_size)], max_offset=0x800)


def test_non_static_base_yields_nothing():
    """A chain whose only base is not in the static set produces no path."""
    mem = FakeMemory()
    base_slot = mem.base + 0x10
    obj = mem.base + 0x200
    target = obj + 0x8
    mem.put_ptr(base_slot, obj)

    # static set far away from base_slot.
    assert _scan(mem, target, [(mem.base + 0x900, mem.ptr_size)], max_offset=0x40) == []


def test_max_results_caps_output():
    mem = FakeMemory()
    obj = mem.base + 0x200
    target = obj + 0x8
    # Several static slots all pointing at the object → several 1-level paths.
    static = []
    for i in range(5):
        slot = mem.base + 0x10 + i * mem.ptr_size
        mem.put_ptr(slot, obj)
        static.append((slot, mem.ptr_size))

    capped = _scan(mem, target, static, max_offset=0x40, max_results=2)
    assert len(capped) == 2


# --------------------------------------------------------------------------- #
# Integration against the running process
# --------------------------------------------------------------------------- #
#
# These tests build a real pointer map over the whole test process — slow.
# Each one carries ``@pytest.mark.slow`` so ``pytest -m "not slow"`` skips the
# integration half while keeping the unit tests above in the fast subset.

@pytest.fixture
def process():
    handle = OpenProcess(pid=os.getpid())
    try:
        yield handle
    finally:
        handle.close()


@pytest.mark.slow
def test_scan_pointer_paths_rediscovers_planted_chain(process):
    """
    Plant ``base -> [+0] -> +offset`` on the heap, mark the base's address as a
    static range, and verify scan_pointer_paths finds a path that resolves back
    to the planted target address.
    """
    ptr_size = ctypes.sizeof(ctypes.c_void_p)

    # Innermost object holds the value at a known offset.
    value_offset = 0x10
    obj = (ctypes.c_uint8 * 0x40)()
    target_address = ctypes.addressof(obj) + value_offset

    # Intermediate level points at obj (offset 0 on this hop).
    level1 = ctypes.c_void_p(ctypes.addressof(obj))

    # Static base points at level1.
    base = ctypes.c_void_p(ctypes.addressof(level1))
    base_address = ctypes.addressof(base)

    paths = list(
        process.scan_pointer_paths(
            target_address,
            max_depth=4,
            max_offset=0x40,
            ptr_size=ptr_size,
            static_ranges=[(base_address, ptr_size)],
            max_results=200,
        )
    )

    # At least one discovered path must resolve exactly to the planted target.
    resolving = [p for p in paths if p.resolve(process) == target_address]
    assert resolving, (
        "no discovered path resolved to the planted target (found %d paths)"
        % len(paths)
    )

    # And the canonical [+0, +0x10] path from our base should be among them.
    assert any(
        p.base_address == base_address and p.offsets == (0x0, value_offset)
        for p in resolving
    ), [str(p) for p in resolving]


def test_scan_pointer_paths_rejects_bad_ptr_size(process):
    # Raised by the call itself, not deferred to the first next().
    with pytest.raises(ValueError, match="ptr_size"):
        process.scan_pointer_paths(0x1000, ptr_size=5)


@pytest.mark.slow
def test_save_load_pointer_paths_round_trip(process, tmp_path):
    paths = [
        PointerPath(0x1000, (0x0, 0x158), module="m.dylib", module_offset=0x10),
        PointerPath(0x2000, (0x8,), module="m.dylib", module_offset=0x20),
    ]
    file = tmp_path / "scan.json"
    process.save_pointer_paths(paths, str(file))
    loaded = process.load_pointer_paths(str(file))
    assert loaded == paths


@pytest.mark.slow
def test_rescan_pointer_paths_keeps_only_resolving(process, tmp_path):
    """
    Plant a chain, save a path to it plus a decoy, and confirm rescan keeps the
    real one and drops the decoy (which doesn't resolve to the target).
    """
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    obj = (ctypes.c_uint8 * 0x40)()
    target = ctypes.addressof(obj) + 0x10
    holder = ctypes.c_void_p(ctypes.addressof(obj))

    # A module-less direct path: base holds a pointer, offset 0x10 reaches target.
    good = PointerPath(ctypes.addressof(holder), (0x10,), ptr_size=ptr_size)
    decoy = PointerPath(ctypes.addressof(holder), (0x999,), ptr_size=ptr_size)

    file = tmp_path / "scan.json"
    process.save_pointer_paths([good, decoy], str(file))

    survivors = process.rescan_pointer_paths(str(file), target)
    assert good in survivors
    assert decoy not in survivors


@pytest.mark.slow
def test_rescan_pointer_paths_accepts_list(process):
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    obj = (ctypes.c_uint8 * 0x40)()
    target = ctypes.addressof(obj)
    holder = ctypes.c_void_p(ctypes.addressof(obj))
    good = PointerPath(ctypes.addressof(holder), (0x0,), ptr_size=ptr_size)

    survivors = process.rescan_pointer_paths([good], target)
    assert survivors == [good]


@pytest.mark.slow
def test_compare_pointer_scans_via_process(process, tmp_path):
    common = PointerPath(0x1, (0x8,), module="a.exe", module_offset=0x10)
    only1 = PointerPath(0x1, (0x4,), module="a.exe", module_offset=0x20)
    only2 = PointerPath(0x1, (0x4,), module="a.exe", module_offset=0x30)

    f1, f2 = tmp_path / "s1.json", tmp_path / "s2.json"
    process.save_pointer_paths([common, only1], str(f1))
    process.save_pointer_paths([common, only2], str(f2))

    result = process.compare_pointer_scans(str(f1), str(f2))
    assert [p.recipe() for p in result] == [common.recipe()]

    # Mixed file + in-memory list is also accepted.
    result2 = process.compare_pointer_scans(str(f1), [common, only2])
    assert [p.recipe() for p in result2] == [common.recipe()]


# --------------------------------------------------------------------------- #
# PointerPath helpers
# --------------------------------------------------------------------------- #

def test_pointer_path_str_with_module():
    path = PointerPath(
        base_address=0x14010F4F4,
        offsets=(0x0, 0x158),
        module="game.exe",
        module_offset=0x10F4F4,
    )
    assert str(path) == '"game.exe"+0x10F4F4 -> [+0x0] -> +0x158'


def test_pointer_path_str_without_module():
    path = PointerPath(base_address=0xDEAD0000, offsets=(0x20,))
    assert str(path) == "0xDEAD0000 -> +0x20"


def test_pointer_path_rebase_without_module_raises():
    path = PointerPath(base_address=0x1000, offsets=(0x4,))
    with pytest.raises(ValueError, match="no module"):
        path.rebase(None)


def test_pointer_path_dict_round_trip_with_module():
    path = PointerPath(
        base_address=0x14010F4F4,
        offsets=(0x0, 0x158),
        module="game.exe",
        module_offset=0x10F4F4,
        ptr_size=8,
    )
    restored = PointerPath.from_dict(path.to_dict())
    assert restored == path
    # Hex strings keep the export human-readable.
    assert path.to_dict()["offsets"] == ["0x0", "0x158"]


def test_pointer_path_dict_round_trip_without_module():
    path = PointerPath(base_address=0xDEAD0000, offsets=(0x20,), ptr_size=4)
    restored = PointerPath.from_dict(path.to_dict())
    assert restored == path
    assert restored.module is None and restored.module_offset is None


def _path(module, module_offset, offsets, base=0x1000):
    return PointerPath(
        base_address=base, offsets=tuple(offsets), module=module,
        module_offset=module_offset,
    )


def test_intersect_keeps_only_paths_in_every_scan():
    # Two "runs" with different absolute bases but overlapping recipes.
    run1 = [
        _path("game.exe", 0x1000, (0x8,), base=0x10000),
        _path("game.exe", 0x2000, (0x10, 0x20), base=0x10000),
        _path("game.exe", 0x3000, (0x0,), base=0x10000),
    ]
    run2 = [
        _path("game.exe", 0x1000, (0x8,), base=0x90000),   # same recipe as run1[0]
        _path("game.exe", 0x2000, (0x10, 0x20), base=0x90000),  # same as run1[1]
        _path("game.exe", 0x9999, (0x4,), base=0x90000),   # only in run2
    ]
    common = intersect_pointer_paths([run1, run2])
    recipes = {p.recipe() for p in common}
    assert recipes == {
        ("game.exe", 0x1000, (0x8,)),
        ("game.exe", 0x2000, (0x10, 0x20)),
    }
    # Representatives come from the first list (base preserved from run1).
    assert all(p.base_address == 0x10000 for p in common)


def test_intersect_empty_when_no_overlap():
    run1 = [_path("a.exe", 0x10, (0x0,))]
    run2 = [_path("a.exe", 0x20, (0x0,))]
    assert intersect_pointer_paths([run1, run2]) == []


def test_intersect_ignores_module_less_paths():
    # module=None paths have no portable recipe → never intersect.
    run1 = [PointerPath(base_address=0x500, offsets=(0x0,))]
    run2 = [PointerPath(base_address=0x500, offsets=(0x0,))]
    assert intersect_pointer_paths([run1, run2]) == []


def test_intersect_single_list_returns_its_module_paths():
    run1 = [_path("a.exe", 0x10, (0x0,)), PointerPath(0x1, (0x0,))]
    out = intersect_pointer_paths([run1])
    assert len(out) == 1 and out[0].module == "a.exe"


def test_pointer_path_from_dict_accepts_plain_ints():
    """Hand-edited files may use ints instead of hex strings."""
    restored = PointerPath.from_dict(
        {"base_address": 0x1000, "offsets": [0, 16], "module": "m", "module_offset": 32}
    )
    assert restored.base_address == 0x1000
    assert restored.offsets == (0, 16)
    assert restored.module_offset == 32


def test_build_pointer_map_keeps_only_in_range_pointers():
    """A slot whose value points outside mapped memory is dropped from the map."""
    ptr_size = 8
    base = 0x200000
    buf = bytearray(0x40)
    # slot 0: valid pointer into the region; slot 1: garbage far out of range.
    struct.pack_into("<Q", buf, 0x00, base + 0x20)
    struct.pack_into("<Q", buf, 0x08, 0xDEADBEEFCAFE)

    def read_chunk(address, size):
        off = address - base
        return bytes(buf[off : off + size])

    mapped = AddressRanges([(base, base + len(buf))])
    values, addresses = build_pointer_map(
        [(base, len(buf))], read_chunk, mapped, ptr_size=ptr_size
    )

    assert list(values) == [base + 0x20]
    assert list(addresses) == [base]
    assert isinstance(values, array.array)


# --------------------------------------------------------------------------- #
# Error propagation and export-file validation
# --------------------------------------------------------------------------- #

from PyMemoryEditor import ClosedProcess  # noqa: E402
from PyMemoryEditor.process.errors import ProcessIDNotExistsError  # noqa: E402


def test_build_pointer_map_propagates_a_dead_process():
    """A closed / vanished target is not a skippable page: an empty map would
    be indistinguishable from "no pointers found"."""
    base = 0x300000

    def read_chunk(address, size):
        raise ProcessIDNotExistsError(4242)

    mapped = AddressRanges([(base, base + 0x100)])
    with pytest.raises(ProcessIDNotExistsError):
        build_pointer_map([(base, 0x100)], read_chunk, mapped, ptr_size=8)


def test_build_pointer_map_still_skips_an_unreadable_chunk():
    base = 0x300000

    def read_chunk(address, size):
        raise OSError(14, "page gone")

    mapped = AddressRanges([(base, base + 0x100)])
    values, addresses = build_pointer_map([(base, 0x100)], read_chunk, mapped, ptr_size=8)
    assert list(values) == [] and list(addresses) == []


def test_rescan_pointer_paths_propagates_a_closed_process():
    """``rescan`` drops paths whose chain is broken, but a process that is
    closed would "break" every path — that is an error, not an empty result."""
    handle = OpenProcess(pid=os.getpid())
    handle.close()
    path = PointerPath(0x1000, (0x10,), ptr_size=ctypes.sizeof(ctypes.c_void_p))
    with pytest.raises(ClosedProcess):
        handle.rescan_pointer_paths([path], 0x2000)


def test_scan_pointer_paths_refuses_a_closed_process():
    """Like every search_* method, the call raises on a closed handle instead
    of handing back a generator that would use it."""
    handle = OpenProcess(pid=os.getpid())
    handle.close()
    with pytest.raises(ClosedProcess):
        handle.scan_pointer_paths(0x1000)


def test_scan_pointer_paths_stops_once_the_process_is_closed(monkeypatch):
    """A generator kept past close() must not go on using the handle."""
    path = PointerPath(0x1000, (0x0,), ptr_size=8)
    # Stub both phases: this is about the guard, not about reading memory.
    monkeypatch.setattr(pointer_scan, "build_pointer_map", lambda *a, **k: ((), ()))
    monkeypatch.setattr(pointer_scan, "find_pointer_paths", lambda *a, **k: iter([path, path]))

    handle = OpenProcess(pid=os.getpid())
    walk = handle.scan_pointer_paths(0x1000, max_depth=1, memory_regions=[])
    assert next(walk) == path
    handle.close()
    with pytest.raises(ClosedProcess):
        next(walk)


def _one_writable_region(process):
    for region in process.get_memory_regions():
        if region.is_writable and region.size >= 0x1000:
            return [region]
    pytest.skip("no writable region to scan")


def test_scan_pointer_paths_reports_a_target_that_exited(process, monkeypatch):
    """Backends report a read on a dead target as a plain ``OSError``, the
    same type a page that vanished mid-scan produces. The scan must ask
    whether the target is still there before writing the failure off as a
    skippable page -- otherwise a dead target yields an empty map that is
    indistinguishable from "no pointers found"."""
    regions = _one_writable_region(process)

    def dead_read(address, pytype, bufflength=None, *args, **kwargs):
        raise OSError(3, "No such process")

    monkeypatch.setattr(process, "read_process_memory", dead_read)
    monkeypatch.setattr(process, "_target_alive", lambda: False)

    with pytest.raises(ProcessIDNotExistsError):
        list(process.scan_pointer_paths(0x1000, max_depth=1, memory_regions=regions))


def test_scan_pointer_paths_still_skips_a_vanished_page(process, monkeypatch):
    """The other half of the contract: the same ``OSError`` on a target that
    is alive is a page that went away, and the scan walks past it."""
    regions = _one_writable_region(process)

    def gone_page(address, pytype, bufflength=None, *args, **kwargs):
        raise OSError(14, "Bad address")

    monkeypatch.setattr(process, "read_process_memory", gone_page)
    monkeypatch.setattr(process, "_target_alive", lambda: True)

    assert list(process.scan_pointer_paths(0x1000, max_depth=1, memory_regions=regions)) == []


def test_rescan_pointer_paths_reports_a_target_that_exited(process, monkeypatch):
    path = PointerPath(0x1000, (0x10,), ptr_size=ctypes.sizeof(ctypes.c_void_p))
    monkeypatch.setattr(
        process, "read_process_memory",
        lambda *a, **k: (_ for _ in ()).throw(OSError(3, "No such process")),
    )
    monkeypatch.setattr(process, "_target_alive", lambda: False)

    with pytest.raises(ProcessIDNotExistsError):
        process.rescan_pointer_paths([path], 0x2000)


def test_compare_pointer_scans_needs_a_source(process):
    with pytest.raises(ValueError, match="at least one source"):
        process.compare_pointer_scans()


def test_pointer_path_from_dict_parses_prefixed_hex_and_decimal():
    restored = PointerPath.from_dict(
        {"base_address": "0x1000", "offsets": ["0x10", "32", 48], "ptr_size": "8"}
    )
    assert restored.base_address == 0x1000
    assert restored.offsets == (0x10, 32, 48)
    assert restored.ptr_size == 8


@pytest.mark.parametrize(
    "data, field",
    [
        ({"base_address": "1F"}, "base_address"),          # hex without 0x: do not guess
        ({"base_address": "0x10", "offsets": ["zz"]}, "offsets"),
        ({"base_address": True}, "base_address"),
        ({"base_address": "0x10", "ptr_size": None}, "ptr_size"),
        ({"offsets": []}, "base_address"),
        ("not a mapping", "base_address"),
    ],
)
def test_pointer_path_from_dict_rejects_malformed_fields(data, field):
    with pytest.raises(ValueError, match=field):
        PointerPath.from_dict(data)


@pytest.mark.parametrize(
    "payload, message",
    [
        ({"paths": []}, "'format'"),
        ({"format": "pymemoryeditor-pointerscan", "version": 99, "paths": []}, "version 99"),
        ({"format": "pymemoryeditor-pointerscan", "version": 1}, "'paths'"),
        ({"format": "pymemoryeditor-pointerscan", "version": 1, "paths": {}}, "'paths'"),
        ([1, 2, 3], "JSON object"),
        (
            {"format": "pymemoryeditor-pointerscan", "version": 1, "paths": [{"base_address": "1F"}]},
            "base_address",
        ),
    ],
)
def test_load_pointer_paths_explains_a_file_that_is_not_an_export(process, tmp_path, payload, message):
    """A wrong file used to surface as a bare ``KeyError: 'paths'``."""
    file = tmp_path / "scan.json"
    file.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match=message) as info:
        process.load_pointer_paths(str(file))
    assert str(file) in str(info.value)


# --------------------------------------------------------------------------- #
# MemoryError is not a skippable page
# --------------------------------------------------------------------------- #

def test_build_pointer_map_propagates_memory_error():
    def read_chunk(address, size):
        raise MemoryError()

    with pytest.raises(MemoryError):
        build_pointer_map([(0x1000, 0x100)], read_chunk, AddressRanges([(0x1000, 0x1100)]))


def test_build_pointer_map_still_skips_backend_errors():
    calls = []

    def read_chunk(address, size):
        calls.append(address)
        raise OSError(14, "Bad address")

    values, addresses = build_pointer_map(
        [(0x1000, 0x100), (0x3000, 0x100)], read_chunk, AddressRanges([(0x1000, 0x1100)])
    )
    assert len(values) == len(addresses) == 0
    assert calls == [0x1000, 0x3000]  # the first failure did not stop the walk


def test_scan_pointer_paths_propagates_memory_error(process, monkeypatch):
    def out_of_memory(*_args, **_kwargs):
        raise MemoryError()

    monkeypatch.setattr(process, "read_process_memory", out_of_memory)
    from PyMemoryEditor.process.region import MemoryRegion

    regions = [MemoryRegion(0x1000, 0x100, is_readable=True, is_writable=True)]
    with pytest.raises(MemoryError):
        list(process.scan_pointer_paths(0x1000, max_depth=1, ptr_size=8, memory_regions=regions))


def test_rescan_pointer_paths_propagates_memory_error(process, monkeypatch):
    def out_of_memory(*_args, **_kwargs):
        raise MemoryError()

    monkeypatch.setattr(process, "resolve_pointer_chain", out_of_memory)
    with pytest.raises(MemoryError):
        process.rescan_pointer_paths([PointerPath(0x1000, (0x10,))], 0x1010)


# --------------------------------------------------------------------------- #
# Duplicate module names: first wins everywhere
# --------------------------------------------------------------------------- #

def test_rescan_and_rebase_agree_on_duplicate_module_names(process, monkeypatch):
    modules = [
        ModuleInfo(name="libdup.so", path="/a/libdup.so", base_address=0x10000, size=0x1000),
        ModuleInfo(name="libdup.so", path="/b/libdup.so", base_address=0x90000, size=0x1000),
    ]
    monkeypatch.setattr(process, "get_modules", lambda: iter(modules))
    # A walk that just adds the last offset to the base: enough to see which
    # module base the path was rebased onto.
    monkeypatch.setattr(
        process,
        "resolve_pointer_chain",
        lambda base, offsets, ptr_size=None: base + offsets[-1],
    )

    saved = PointerPath(0x0, (0x8,), module="libdup.so", module_offset=0x40)
    rebased = saved.rebase(process)
    assert rebased.base_address == 0x10040  # first module

    survivors = process.rescan_pointer_paths([saved], 0x10048)
    assert [path.base_address for path in survivors] == [rebased.base_address]
    assert process.rescan_pointer_paths([saved], 0x90048) == []


# --------------------------------------------------------------------------- #
# ptr_size validation on load
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ptr_size", [3, 0, 16, "0x2", -8])
def test_from_dict_rejects_invalid_ptr_size(ptr_size):
    with pytest.raises(ValueError, match="ptr_size"):
        PointerPath.from_dict({"base_address": "0x1000", "offsets": ["0x8"], "ptr_size": ptr_size})


@pytest.mark.parametrize("ptr_size", [4, 8, "4", "0x8"])
def test_from_dict_accepts_valid_ptr_size(ptr_size):
    path = PointerPath.from_dict({"base_address": "0x1000", "offsets": ["0x8"], "ptr_size": ptr_size})
    assert path.ptr_size == int(str(ptr_size), 0)


def test_from_dict_defaults_ptr_size_to_8():
    assert PointerPath.from_dict({"base_address": "0x1000"}).ptr_size == 8


def test_load_pointer_paths_names_the_file_for_a_bad_ptr_size(process, tmp_path):
    good = PointerPath(0x1000, (0x8,), module="m.so", module_offset=0x10)
    file = tmp_path / "scan.json"
    process.save_pointer_paths([good], str(file))

    payload = json.loads(file.read_text())
    payload["paths"][0]["ptr_size"] = 3
    file.write_text(json.dumps(payload))

    with pytest.raises(ValueError) as excinfo:
        process.load_pointer_paths(str(file))
    message = str(excinfo.value)
    assert str(file) in message
    assert "ptr_size" in message and "3" in message


# --------------------------------------------------------------------------- #
# The reverse walk can be stopped between yields
# --------------------------------------------------------------------------- #


def _barren_graph(fanout: int):
    """A pointer map in which every slot can reach the target and every other
    slot (all slots sit just above the one value they store, within
    ``max_offset``): without a static base the walk visits every ordering of
    the slots up to ``max_depth`` and finds nothing."""
    import array

    target = 0x10_0000
    values = array.array("Q", [target - 8] * fanout)
    addresses = array.array("Q", [target + 16 * i for i in range(fanout)])
    return target, values, addresses


def test_should_stop_ends_a_walk_that_never_yields():
    target, values, addresses = _barren_graph(fanout=64)
    polls = {"count": 0}

    def should_stop():
        polls["count"] += 1
        return polls["count"] >= 3

    paths = list(
        find_pointer_paths(
            target, values, addresses,
            is_static=lambda _addr: False,
            module_resolver=lambda _addr: None,
            max_depth=4, max_offset=0x400,
            should_stop=should_stop,
        )
    )

    assert paths == []
    # Stopped at the third poll; the full walk visits ~64**4 slots.
    assert polls["count"] == 3


def test_should_stop_never_true_leaves_the_results_unchanged():
    target, values, addresses = _barren_graph(fanout=4)
    statics = {int(addresses[0])}

    def walk(**extra):
        return [
            (p.base_address, p.offsets)
            for p in find_pointer_paths(
                target, values, addresses,
                is_static=statics.__contains__,
                module_resolver=lambda _addr: None,
                max_depth=3, max_offset=0x400,
                **extra,
            )
        ]

    assert walk() == walk(should_stop=lambda: False)
    assert walk()  # the graph does have paths


def test_first_module_bases_keeps_the_first_module_of_a_name():
    """The single rule behind rebase, rescan_pointer_paths and the app."""
    from PyMemoryEditor.process.pointer_scan import first_module_bases

    modules = [
        ModuleInfo(name="game.dll", path="/a/game.dll", base_address=0x1000, size=0x100),
        ModuleInfo(name="other.dll", path="/a/other.dll", base_address=0x2000, size=0x100),
        ModuleInfo(name="game.dll", path="/b/game.dll", base_address=0x9000, size=0x100),
    ]
    assert first_module_bases(modules) == {"game.dll": 0x1000, "other.dll": 0x2000}


# --------------------------------------------------------------------------- #
# build_pointer_map: chunk boundaries, NumPy parity, logging; intersect ptr_size
# --------------------------------------------------------------------------- #


def _small_pointer_chunks(monkeypatch, max_chunk):
    monkeypatch.setattr(
        pointer_scan,
        "iter_region_chunks",
        lambda size, width: tuple(_iter_large_region_chunks(size, width, max_chunk)),
    )


def _flat_reader(base, buf, reads=None):
    def read_chunk(address, size):
        if reads is not None:
            reads.append((address, size))
        offset = address - base
        if offset < 0 or offset + size > len(buf):
            raise OSError(14, "Bad address")
        return bytes(buf[offset : offset + size])

    return read_chunk


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_unaligned_map_finds_a_pointer_straddling_a_chunk(monkeypatch, ptr_size):
    """Each chunk was scanned on its own, so a misaligned pointer that began
    in the last ``ptr_size - 1`` bytes of a chunk was never decoded."""
    _small_pointer_chunks(monkeypatch, 32)
    base = 0x40000
    buf = bytearray(96)
    slot = 32 - 2  # two bytes in chunk 0, the rest in chunk 1
    target = base + 0x50
    buf[slot : slot + ptr_size] = target.to_bytes(ptr_size, sys.byteorder)
    reads = []
    values, addresses = build_pointer_map(
        [(base, len(buf))], _flat_reader(base, buf, reads),
        AddressRanges([(base, base + len(buf))]), ptr_size=ptr_size, aligned=False,
    )
    assert list(addresses) == [base + slot]
    assert list(values) == [target]
    # The overlap never reads past the region.
    assert all(address + size <= base + len(buf) for address, size in reads)


def _random_memory(ptr_size, seed):
    rng = random.Random(seed)
    base = 0x7F0000000000 if ptr_size == 8 else 0x10000000
    size = 4096
    mapped = [(base, base + size), (base + 0x10000, base + 0x12000)]
    buf = bytearray(size)
    for slot in range(0, size, ptr_size):
        pick = rng.random()
        if pick < 0.3:
            start, end = rng.choice(mapped)
            value = rng.randrange(start, end)
        elif pick < 0.4:
            value = rng.choice((base - 1, base + size, base + 0x12000, base + 0x10000))
        else:
            value = rng.randrange(0, 1 << (8 * ptr_size))
        buf[slot : slot + ptr_size] = value.to_bytes(ptr_size, sys.byteorder)
    return base, buf, AddressRanges(mapped)


@pytest.mark.skipif(not scan_numpy.NUMPY_AVAILABLE, reason="NumPy not installed")
@pytest.mark.parametrize("ptr_size", [4, 8])
def test_pointer_map_numpy_path_matches_the_python_loop(monkeypatch, ptr_size):
    _small_pointer_chunks(monkeypatch, 512)
    base, buf, mapped = _random_memory(ptr_size, 99 + ptr_size)
    reader = _flat_reader(base, buf)
    regions = [(base, len(buf))]

    with_numpy = build_pointer_map(regions, reader, mapped, ptr_size=ptr_size)
    monkeypatch.setattr(scan_numpy, "NUMPY_AVAILABLE", False)
    without = build_pointer_map(regions, reader, mapped, ptr_size=ptr_size)

    assert with_numpy[0].typecode == without[0].typecode
    assert list(with_numpy[0]) == list(without[0])
    assert list(with_numpy[1]) == list(without[1])
    assert len(without[0]) > 100


def test_pointer_map_logs_a_skipped_chunk(caplog):
    base = 0x40000
    buf = bytearray(64)
    with caplog.at_level(logging.DEBUG, logger="PyMemoryEditor"):
        build_pointer_map(
            [(base, 64), (0x900000, 64)], _flat_reader(base, buf),
            AddressRanges([(base, base + 64)]),
        )
    assert any(
        "build_pointer_map: skipping chunk at 0x900000" in record.getMessage()
        for record in caplog.records
    )


def test_pointer_map_progress_reaches_one_without_regions():
    seen = []
    build_pointer_map([], lambda a, s: None, AddressRanges([]), progress_callback=seen.append)
    assert seen == [1.0]


def test_intersect_does_not_merge_paths_of_different_pointer_widths():
    path32 = PointerPath(0x1000, (0x8, 0x10), module="game.exe", module_offset=0x20, ptr_size=4)
    path64 = PointerPath(0x9000, (0x8, 0x10), module="game.exe", module_offset=0x20, ptr_size=8)
    assert intersect_pointer_paths([[path32], [path64]]) == []
    assert intersect_pointer_paths([[path32], [path32]]) == [path32]
    # The public recipe shape is unchanged.
    assert path32.recipe() == ("game.exe", 0x20, (0x8, 0x10))
