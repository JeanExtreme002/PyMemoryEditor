# -*- coding: utf-8 -*-

"""
macOS-only test: ``search_values_by_addresses`` must hand a
:class:`MemoryRegionSnapshot` to the scanning kernel unchanged.

It used to copy every caller-supplied region list with ``list(...)``, which
drops the snapshot type — the tag ``process.scanning._ensure_sorted_by_address``
keys on to skip re-sorting — so every refine in a snapshot-reusing loop paid
for a full sort again.
"""

import os
import sys

import pytest


if sys.platform != "darwin":
    pytest.skip("macOS-only module", allow_module_level=True)


from PyMemoryEditor.macos import functions as mac  # noqa: E402
from PyMemoryEditor.process.region import MemoryRegionSnapshot  # noqa: E402


def _capture_regions(monkeypatch):
    captured = []

    def fake_iter_values(addresses, memory_regions, *args, **kwargs):
        captured.append(memory_regions)
        return iter(())

    monkeypatch.setattr(mac, "iter_values_for_addresses", fake_iter_values)
    return captured


def test_a_snapshot_is_passed_through_untouched(monkeypatch):
    captured = _capture_regions(monkeypatch)
    snapshot = MemoryRegionSnapshot([])
    list(mac.search_values_by_addresses(0, int, 4, [0x1000], memory_regions=snapshot))
    assert captured[0] is snapshot


def test_a_one_shot_iterable_is_still_materialized(monkeypatch):
    captured = _capture_regions(monkeypatch)
    regions = iter(())
    list(mac.search_values_by_addresses(0, int, 4, [0x1000], memory_regions=regions))
    assert isinstance(captured[0], list)


def test_a_snapshot_refine_reads_real_values():
    """End-to-end on the test's own process: a snapshot still decodes values."""
    import ctypes

    from PyMemoryEditor import OpenProcess

    value = ctypes.c_int32(0x1234567)
    address = ctypes.addressof(value)
    process = OpenProcess(pid=os.getpid())
    try:
        snapshot = process.snapshot_memory_regions()
        assert isinstance(snapshot, MemoryRegionSnapshot)
        results = dict(
            process.search_by_addresses(int, 4, [address], memory_regions=snapshot)
        )
    finally:
        process.close()
    assert results[address] == 0x1234567


# --- value / pattern scans take regions in address order ---------------------------


def _region(address):
    from PyMemoryEditor.process.region import MemoryRegion

    return MemoryRegion(address=address, size=0x1000, is_readable=True)


def _capture_scan_regions(monkeypatch, name):
    captured = []

    def fake(memory_regions, *args, **kwargs):
        captured.append([region.address for region in memory_regions])
        return iter(())

    monkeypatch.setattr(mac, name, fake)
    return captured


@pytest.mark.parametrize("snapshot_type, expected", (
    # A snapshot is a mutable list: one the caller reordered (append,
    # reverse, ...) must still be scanned in address order, so every input
    # is sorted -- a no-op pass over a list that already is.
    (MemoryRegionSnapshot, [0x1000, 0x3000]),
    (list, [0x1000, 0x3000]),
))
def test_a_value_scan_scans_regions_in_address_order(monkeypatch, snapshot_type, expected):
    captured = _capture_scan_regions(monkeypatch, "iter_search_results")
    regions = snapshot_type([_region(0x3000), _region(0x1000)])

    list(mac.search_addresses_by_value(0, int, 4, 7, memory_regions=regions))

    assert captured == [expected]


@pytest.mark.parametrize("snapshot_type, expected", (
    (MemoryRegionSnapshot, [0x1000, 0x3000]),
    (list, [0x1000, 0x3000]),
))
def test_a_pattern_scan_scans_regions_in_address_order(monkeypatch, snapshot_type, expected):
    captured = _capture_scan_regions(monkeypatch, "iter_pattern_results")
    regions = snapshot_type([_region(0x3000), _region(0x1000)])

    list(mac.search_addresses_by_pattern(0, "90", memory_regions=regions))

    assert captured == [expected]
