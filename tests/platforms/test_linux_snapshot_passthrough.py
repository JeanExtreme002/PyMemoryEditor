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
