# -*- coding: utf-8 -*-

"""
Integration tests for ``process.search_by_pattern`` against the current
process. Plants a known marker on the test's own stack, then verifies that
the scanner finds it via:

* a literal IDA-style pattern,
* an IDA-style pattern with wildcards,
* a raw bytes regex (``re.DOTALL``).

All tests use ``OpenProcess(pid=os.getpid())`` — no special privilege needed
on any of the three supported platforms.
"""

import ctypes
import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402


# A reasonably distinctive marker — eight bytes give us enough entropy that
# random other matches in the test process's address space are unlikely.
_MARKER = b"\x90\x90\xDE\xAD\xBE\xEF\xCA\xFE"


@pytest.fixture
def planted_marker():
    """Create a buffer holding the marker; yield (address, marker_bytes)."""
    buf = ctypes.create_string_buffer(_MARKER, len(_MARKER))
    yield ctypes.addressof(buf), _MARKER
    # `buf` stays alive for the entire test fixture scope — GC collects it
    # after the test returns, at which point the address may be reused.


def test_pattern_scan_finds_exact_marker(planted_marker):
    address, _ = planted_marker
    with OpenProcess(pid=os.getpid()) as process:
        hits = list(process.search_by_pattern("90 90 DE AD BE EF CA FE"))
    assert address in hits, (
        "expected scan to find the planted marker at 0x%X among %d hits"
        % (address, len(hits))
    )


def test_pattern_scan_with_wildcards(planted_marker):
    """Wildcards on the middle bytes still locate the marker."""
    address, _ = planted_marker
    with OpenProcess(pid=os.getpid()) as process:
        hits = list(process.search_by_pattern("90 90 ? ? BE EF CA FE"))
    assert address in hits


def test_pattern_scan_bytes_regex(planted_marker):
    """Bytes regex with explicit byte_length."""
    address, _ = planted_marker
    with OpenProcess(pid=os.getpid()) as process:
        hits = list(
            process.search_by_pattern(
                rb"\xDE\xAD\xBE\xEF\xCA\xFE", byte_length=6
            )
        )
    # The 6-byte slice starts 2 bytes into the marker.
    assert (address + 2) in hits


def test_pattern_scan_progress_information(planted_marker):
    """``progress_information=True`` yields (address, info) tuples."""
    address, _ = planted_marker
    with OpenProcess(pid=os.getpid()) as process:
        items = list(
            process.search_by_pattern(
                "90 90 DE AD BE EF CA FE", progress_information=True
            )
        )
    assert items, "expected at least one hit"

    # Validate shape of the first tuple.
    addr, info = items[0]
    assert isinstance(addr, int)
    assert "progress" in info
    assert "memory_total" in info
    assert 0.0 <= info["progress"] <= 1.0

    # The planted marker must be one of the addresses.
    assert any(item[0] == address for item in items)


def test_pattern_scan_no_match():
    """A pattern that cannot exist in our address space yields no hits."""
    # 16 random-looking bytes; the chance of a coincidence is effectively zero.
    with OpenProcess(pid=os.getpid()) as process:
        hits = list(
            process.search_by_pattern(
                "DE AD BE EF C0 DE F0 0D FE ED BA BE 13 37 C0 DE"
            )
        )
    assert hits == []


def test_pattern_scan_accepts_memory_regions_snapshot(planted_marker):
    """Passing a pre-built region snapshot must produce the same matches."""
    address, _ = planted_marker
    with OpenProcess(pid=os.getpid()) as process:
        snapshot = process.snapshot_memory_regions()
        hits_with_snapshot = list(
            process.search_by_pattern(
                "90 90 DE AD BE EF CA FE", memory_regions=snapshot
            )
        )
    assert address in hits_with_snapshot
