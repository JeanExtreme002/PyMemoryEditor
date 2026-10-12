# -*- coding: utf-8 -*-

"""
Regression tests for the pointer-scan review findings:

  - ``build_pointer_map`` (and the ``read_chunk`` ``scan_pointer_paths`` feeds
    it) let ``MemoryError`` propagate instead of returning a silently
    incomplete map;
  - ``rescan_pointer_paths`` picks the *first* module of a given name, the same
    one ``PointerPath.rebase`` uses;
  - ``PointerPath.from_dict`` rejects a ``ptr_size`` other than 4 or 8, and the
    file loader names the file in that error;
  - the reverse walk honours a ``should_stop`` hook between yields, so a caller
    with a deadline or a cancel button can bound a walk that finds nothing.
"""

import json
import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)

from PyMemoryEditor import OpenProcess, PointerPath  # noqa: E402
from PyMemoryEditor.process.module_info import ModuleInfo  # noqa: E402
from PyMemoryEditor.process.pointer_scan import (  # noqa: E402
    AddressRanges,
    build_pointer_map,
    find_pointer_paths,
)


@pytest.fixture
def process():
    handle = OpenProcess(pid=os.getpid())
    try:
        yield handle
    finally:
        handle.close()


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

import logging  # noqa: E402
import random  # noqa: E402

from PyMemoryEditor.process import pointer_scan  # noqa: E402
from PyMemoryEditor.process.pointer_scan import intersect_pointer_paths  # noqa: E402
from PyMemoryEditor.util import scan_numpy  # noqa: E402
from PyMemoryEditor.util.scan import _iter_large_region_chunks  # noqa: E402


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
