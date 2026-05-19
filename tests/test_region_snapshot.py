# -*- coding: utf-8 -*-

"""
Tests for `snapshot_memory_regions()` and the `memory_regions=` keyword
parameter on `search_by_value*` / `search_by_addresses`. These let the caller
reuse a region snapshot across multiple scans (refine workflow) without paying
the enumeration cost each time.
"""

import ctypes
import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402


def test_snapshot_returns_materialized_list():
    process = OpenProcess(pid=os.getpid())
    try:
        snapshot = process.snapshot_memory_regions()
        assert isinstance(snapshot, list)
        assert len(snapshot) > 0
        # Each entry should expose the same shape as get_memory_regions().
        first = snapshot[0]
        assert "address" in first
        assert "size" in first
        assert "struct" in first
    finally:
        process.close()


def test_snapshot_can_be_iterated_multiple_times():
    """Generator from get_memory_regions() is single-pass; snapshot must be re-iterable."""
    process = OpenProcess(pid=os.getpid())
    try:
        snapshot = process.snapshot_memory_regions()
        # Two passes yield identical content.
        addresses_pass_1 = [r["address"] for r in snapshot]
        addresses_pass_2 = [r["address"] for r in snapshot]
        assert addresses_pass_1 == addresses_pass_2
    finally:
        process.close()


def test_search_by_addresses_accepts_snapshot():
    """The cached snapshot should produce the same result as re-enumeration."""
    targets = [ctypes.c_int(123 + i) for i in range(5)]
    addresses = [ctypes.addressof(t) for t in targets]

    process = OpenProcess(pid=os.getpid())
    try:
        snapshot = process.snapshot_memory_regions()

        results_with_snapshot = dict(
            process.search_by_addresses(int, 4, addresses, memory_regions=snapshot)
        )
        results_without = dict(process.search_by_addresses(int, 4, addresses))

        assert results_with_snapshot == results_without
        # And the values are right.
        for addr, target in zip(addresses, targets):
            assert results_with_snapshot[addr] == target.value
    finally:
        process.close()
