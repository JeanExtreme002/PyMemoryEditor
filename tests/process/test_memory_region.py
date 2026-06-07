# -*- coding: utf-8 -*-

"""
Tests for :meth:`AbstractProcess.get_memory_regions`.

Validates the basic contract of the generator across all platforms:
regions are non-empty, have sane sizes, carry consistent boolean flags,
and expose file-backed paths on supported OSes.
"""

import os
import sys

import pytest

from PyMemoryEditor import OpenProcess
from PyMemoryEditor.process.region import MemoryRegion, default_scan_filter


@pytest.fixture()
def self_process():
    """Open the current process and close it after the test."""
    process = OpenProcess(pid=os.getpid())
    yield process
    process.close()


class TestGetMemoryRegions:
    """Core tests for get_memory_regions()."""

    def test_returns_non_empty(self, self_process):
        """A live process must always have at least one memory region."""
        regions = list(self_process.get_memory_regions())
        assert regions

    def test_yields_memory_region_instances(self, self_process):
        """Every yielded item must be a MemoryRegion."""
        regions = list(self_process.get_memory_regions())
        for r in regions:
            assert isinstance(r, MemoryRegion)

    def test_address_and_size_are_positive(self, self_process):
        """Each region must have a non-negative address and a positive size."""
        regions = list(self_process.get_memory_regions())
        for r in regions:
            assert r.address >= 0
            assert r.size > 0

    def test_no_overlapping_regions(self, self_process):
        """Regions should not overlap (sorted by address, each ends before the next starts)."""
        regions = sorted(self_process.get_memory_regions(), key=lambda r: r.address)
        for i in range(len(regions) - 1):
            end = regions[i].address + regions[i].size
            assert end <= regions[i + 1].address, (
                f"Region at 0x{regions[i].address:X} (size {regions[i].size}) "
                f"overlaps with next at 0x{regions[i + 1].address:X}"
            )

    def test_at_least_one_readable_region(self, self_process):
        """The process must have at least one readable region (code/data are readable)."""
        regions = list(self_process.get_memory_regions())
        assert any(r.is_readable for r in regions)

    def test_at_least_one_writable_region(self, self_process):
        """The process must have at least one writable region (stack/heap are writable)."""
        regions = list(self_process.get_memory_regions())
        assert any(r.is_writable for r in regions)

    def test_at_least_one_executable_region(self, self_process):
        """The process must have at least one executable region (code segment)."""
        regions = list(self_process.get_memory_regions())
        assert any(r.is_executable for r in regions)

    def test_default_scan_filter_excludes_shared(self, self_process):
        """default_scan_filter must exclude shared/file-backed regions."""
        regions = list(self_process.get_memory_regions())
        shared = [r for r in regions if r.is_shared]
        if shared:
            assert all(not default_scan_filter(r) for r in shared)

    def test_struct_is_populated(self, self_process):
        """Every region must carry its platform-specific struct."""
        regions = list(self_process.get_memory_regions())
        for r in regions:
            assert r.struct is not None


class TestRegionPath:
    """Tests for the file-backed path field of memory regions."""

    def test_some_regions_have_path(self, self_process):
        """At least one region should have a non-empty path (mapped libraries)."""
        regions = list(self_process.get_memory_regions())
        paths = [r.path for r in regions if r.path]
        assert paths, (
            "No memory region reported a non-empty path — "
            "the path resolution syscall integration may be broken"
        )

    def test_path_contains_known_library(self, self_process):
        """At least one region path should reference a recognizable system library."""
        regions = list(self_process.get_memory_regions())
        paths = [r.path for r in regions if r.path]

        if sys.platform == "win32":
            assert any("ntdll" in p.lower() for p in paths), (
                f"Expected ntdll.dll in region paths; got: {paths[:10]}"
            )
        elif sys.platform == "darwin":
            assert any("libSystem" in p or "dyld" in p for p in paths), (
                f"Expected libSystem or dyld in region paths; got: {paths[:10]}"
            )
        else:
            # Linux: libc or ld-linux should be mapped.
            assert any("libc" in p or "ld-linux" in p or "ld-musl" in p for p in paths), (
                f"Expected libc or ld-linux in region paths; got: {paths[:10]}"
            )

    def test_path_is_always_str(self, self_process):
        """The path field must always be a str, even when empty."""
        regions = list(self_process.get_memory_regions())
        for r in regions:
            assert isinstance(r.path, str)
