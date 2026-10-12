# -*- coding: utf-8 -*-

"""
Linux-only test: ``search_values_by_addresses`` hands a
:class:`MemoryRegionSnapshot` to the scan kernel as-is.

Copying it with ``list(...)`` dropped the type tag, so
``_ensure_sorted_by_address`` re-sorted the already-sorted region map on every
refine scan — the cost the snapshot exists to avoid.
"""

import os
import sys

import pytest


if not sys.platform.startswith("linux"):
    pytest.skip("Linux-only module", allow_module_level=True)


from PyMemoryEditor import MemoryRegionSnapshot  # noqa: E402
from PyMemoryEditor.linux import functions as lin  # noqa: E402


def _capture_regions(monkeypatch):
    seen = []

    def fake_iter(addresses, memory_regions, *args, **kwargs):
        seen.append(memory_regions)
        return iter(())

    monkeypatch.setattr(lin, "iter_values_for_addresses", fake_iter)
    return seen


def test_snapshot_is_passed_through_untouched(monkeypatch):
    seen = _capture_regions(monkeypatch)
    snapshot = MemoryRegionSnapshot(
        sorted(lin.get_memory_regions(os.getpid()), key=lambda r: r.address)
    )

    list(lin.search_values_by_addresses(
        os.getpid(), int, 4, [0], memory_regions=snapshot
    ))

    assert seen == [snapshot]
    assert seen[0] is snapshot


def test_other_iterables_are_still_materialized(monkeypatch):
    seen = _capture_regions(monkeypatch)
    regions = list(lin.get_memory_regions(os.getpid()))

    list(lin.search_values_by_addresses(
        os.getpid(), int, 4, [0], memory_regions=iter(regions)
    ))

    assert isinstance(seen[0], list)
    assert seen[0] == regions


# --- value / pattern scans keep a snapshot's order ---------------------------


def _region(address):
    from PyMemoryEditor import MemoryRegion

    return MemoryRegion(address=address, size=0x1000, is_readable=True)


def _capture_scan_regions(monkeypatch, name):
    captured = []

    def fake(memory_regions, *args, **kwargs):
        captured.append([region.address for region in memory_regions])
        return iter(())

    monkeypatch.setattr(lin, name, fake)
    return captured


@pytest.mark.parametrize("snapshot_type, expected", (
    # A snapshot is sorted by contract, so it is not sorted again. The order
    # here deliberately breaks that contract to make a re-sort observable.
    (MemoryRegionSnapshot, [0x3000, 0x1000]),
    (list, [0x1000, 0x3000]),
))
def test_a_value_scan_sorts_only_non_snapshot_inputs(monkeypatch, snapshot_type, expected):
    captured = _capture_scan_regions(monkeypatch, "iter_search_results")
    regions = snapshot_type([_region(0x3000), _region(0x1000)])

    list(lin.search_addresses_by_value(os.getpid(), int, 4, 7, memory_regions=regions))

    assert captured == [expected]


@pytest.mark.parametrize("snapshot_type, expected", (
    (MemoryRegionSnapshot, [0x3000, 0x1000]),
    (list, [0x1000, 0x3000]),
))
def test_a_pattern_scan_sorts_only_non_snapshot_inputs(monkeypatch, snapshot_type, expected):
    captured = _capture_scan_regions(monkeypatch, "iter_pattern_results")
    regions = snapshot_type([_region(0x3000), _region(0x1000)])

    list(lin.search_addresses_by_pattern(os.getpid(), "90", memory_regions=regions))

    assert captured == [expected]
