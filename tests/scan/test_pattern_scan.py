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
import random
import re
import sys

import pytest

from PyMemoryEditor.enums import ScanTypesEnum
from PyMemoryEditor.util.pattern import compile_pattern, is_fixed_width
from PyMemoryEditor.util.scan import scan_memory_for_exact_value

from ._fakes import FakeMemory, small_chunks, pattern_hits

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402


# Live pattern scans of the entire test-process address space — slow.
# Run with ``pytest -m "not slow"`` to skip them during fast feedback loops.
pytestmark = pytest.mark.slow


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


# --------------------------------------------------------------------------- #
# Pattern scans: overlapping matches
# --------------------------------------------------------------------------- #


def test_ida_pattern_reports_overlapping_matches():
    memory = FakeMemory({0x1000: b"\x90\x90\x90"})
    assert pattern_hits(memory, "90 90") == [0x1000, 0x1001]


def test_ida_pattern_agrees_with_exact_byte_scan():
    data = bytes(random.Random(7).choice((0x90, 0x90, 0xCC)) for _ in range(512))
    memory = FakeMemory({0x4000: data})
    exact = [
        0x4000 + offset
        for offset in scan_memory_for_exact_value(
            data, len(data), b"\x90\x90\x90", 3, ScanTypesEnum.EXACT_VALUE, bytes
        )
    ]
    assert pattern_hits(memory, "90 90 90") == exact
    assert len(exact) > 10  # the data really has overlapping runs


def test_overlapping_matches_across_chunk_boundaries_are_reported_once(monkeypatch):
    small_chunks(monkeypatch, 4)
    memory = FakeMemory({0x1000: b"\x90" * 10})
    assert pattern_hits(memory, "90 90") == [0x1000 + i for i in range(9)]


def test_fixed_width_regex_reports_overlapping_matches():
    memory = FakeMemory({0x1000: b"ABABAB"})
    assert pattern_hits(memory, rb"AB.B", byte_length=4) == [0x1000, 0x1002]


def test_variable_width_regex_keeps_non_overlapping_semantics():
    """A suffix of a variable-length match is not a new match."""
    memory = FakeMemory({0x1000: b"..john@example.com.."})
    email = rb"[a-z]+@[a-z]+\.[a-z]+"
    assert pattern_hits(memory, email, byte_length=32) == [0x1002]


def test_lookahead_regex_reports_every_start():
    memory = FakeMemory({0x1000: b"AAAA"})
    assert pattern_hits(memory, rb"(?=AA)", byte_length=2) == [0x1000, 0x1001, 0x1002]


def test_zero_width_pattern_terminates():
    memory = FakeMemory({0x1000: b"AB"})
    assert pattern_hits(memory, rb"(?=)", byte_length=1) == [0x1000, 0x1001]


@pytest.mark.parametrize(
    "pattern, expected",
    [
        (rb"\x48\x8B..", True),
        (rb"ab|cd", True),
        (rb"ab|c", False),
        (rb"PLAYER_\d+", False),
        (rb"x{2,4}", False),
    ],
)
def test_is_fixed_width(pattern, expected):
    assert is_fixed_width(re.compile(pattern, re.DOTALL)) is expected


def test_ida_patterns_are_fixed_width():
    assert is_fixed_width(compile_pattern("48 8B ? ? 00")[0])


# --------------------------------------------------------------------------- #
# Variable-width regex across a chunk boundary; overlap past the region end
# --------------------------------------------------------------------------- #

def test_variable_width_match_straddling_a_chunk_is_reported_once(monkeypatch):
    """The overlap bytes of chunk 1 are chunk 2's first bytes: chunk 2 used to
    report the suffix ``BB`` of the ``BBBB`` match chunk 1 already reported."""
    small_chunks(monkeypatch, 8)
    memory = FakeMemory({0x1000: b"......BBBB" + b"." * 10})
    assert pattern_hits(memory, rb"B+", byte_length=4) == [0x1006]


def test_variable_width_matches_agree_with_one_finditer(monkeypatch):
    """Chunked non-overlapping results equal a single ``finditer`` over the
    region whenever no match is longer than ``byte_length``."""
    rng = random.Random(11)
    data = bytes(rng.choice(b"AB..") for _ in range(400))
    pattern = rb"A[AB]{0,3}"
    expected = [0x1000 + m.start() for m in re.finditer(pattern, data, re.DOTALL)]
    for chunk in (4, 5, 8, 13):
        small_chunks(monkeypatch, chunk)
        assert pattern_hits(FakeMemory({0x1000: data}), pattern, byte_length=4) == expected
