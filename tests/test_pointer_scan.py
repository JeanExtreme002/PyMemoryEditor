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
import os
import struct
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)

from PyMemoryEditor import OpenProcess, PointerPath  # noqa: E402
from PyMemoryEditor.process.pointer_scan import (  # noqa: E402
    AddressRanges,
    build_pointer_map,
    find_pointer_paths,
    intersect_pointer_paths,
)


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

@pytest.fixture
def process():
    handle = OpenProcess(pid=os.getpid())
    try:
        yield handle
    finally:
        handle.close()


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
    with pytest.raises(ValueError, match="ptr_size"):
        list(process.scan_pointer_paths(0x1000, ptr_size=5))


def test_save_load_pointer_paths_round_trip(process, tmp_path):
    paths = [
        PointerPath(0x1000, (0x0, 0x158), module="m.dylib", module_offset=0x10),
        PointerPath(0x2000, (0x8,), module="m.dylib", module_offset=0x20),
    ]
    file = tmp_path / "scan.json"
    process.save_pointer_paths(paths, str(file))
    loaded = process.load_pointer_paths(str(file))
    assert loaded == paths


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


def test_rescan_pointer_paths_accepts_list(process):
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    obj = (ctypes.c_uint8 * 0x40)()
    target = ctypes.addressof(obj)
    holder = ctypes.c_void_p(ctypes.addressof(obj))
    good = PointerPath(ctypes.addressof(holder), (0x0,), ptr_size=ptr_size)

    survivors = process.rescan_pointer_paths([good], target)
    assert survivors == [good]


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
