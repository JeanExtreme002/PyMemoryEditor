# -*- coding: utf-8 -*-

"""
Regression test for string matches that straddle a chunk boundary.

`iter_region_chunks` cuts large regions into ``max_chunk`` (256 MB) pieces.
Strings (step=1) can begin at any byte, so a match whose first byte lands at
the end of chunk N and whose last byte falls in chunk N+1 used to be lost —
chunk N's scan didn't have enough bytes to decode it, and chunk N+1's scan
started one byte past where the match began.

`iter_search_results` now reads ``bufflength - 1`` overlap bytes from the
next chunk when the value type is ``str``, completing the straddling decode.
"""

import ctypes

from PyMemoryEditor.enums import ScanTypesEnum
from PyMemoryEditor.process.scanning import iter_search_results


def _make_region(address: int, payload: bytes) -> dict:
    return {"address": address, "size": len(payload), "_payload": payload}


def _make_reader(region):
    def read_chunk(addr: int, size: int):
        base = region["address"]
        offset = addr - base
        end = offset + size
        # Mimic how a backend reads: clamp at region end so over-reads still
        # return what's available rather than raising.
        payload = region["_payload"][offset:end]
        buf = (ctypes.c_byte * len(payload))()
        ctypes.memmove(buf, payload, len(payload))
        return buf

    return read_chunk


def test_string_match_straddling_chunk_boundary_is_found(monkeypatch):
    """
    Place a 4-byte string ``"NEED"`` so its first byte sits in chunk 0 and
    the remaining 3 bytes spill into chunk 1. Without overlap, scan misses it.
    """
    # Force a tiny chunk so we can demonstrate the boundary on a small region.
    from PyMemoryEditor.util import scan as scan_module

    monkeypatch.setattr(scan_module, "DEFAULT_MAX_REGION_CHUNK", 16)

    # 32-byte payload; "NEED" starts at offset 15 (last byte of chunk 0).
    payload = bytearray(32)
    needle = b"NEED"
    payload[15:19] = needle
    region = _make_region(0x1000, bytes(payload))

    matches = list(
        iter_search_results(
            [region],
            str,
            4,
            needle,
            ScanTypesEnum.EXACT_VALUE,
            _make_reader(region),
        )
    )

    assert 0x1000 + 15 in matches


def test_string_match_inside_single_chunk_not_duplicated(monkeypatch):
    """
    A match fully inside chunk 0 must not be re-emitted by chunk 1's scan,
    even though chunk 1's read overlaps the end of chunk 0.
    """
    from PyMemoryEditor.util import scan as scan_module

    monkeypatch.setattr(scan_module, "DEFAULT_MAX_REGION_CHUNK", 16)

    payload = bytearray(32)
    needle = b"YES"
    # Place fully inside chunk 0 (offsets 5..8).
    payload[5:8] = needle
    region = _make_region(0x2000, bytes(payload))

    matches = list(
        iter_search_results(
            [region],
            str,
            3,
            needle,
            ScanTypesEnum.EXACT_VALUE,
            _make_reader(region),
        )
    )

    # Exactly one hit — no duplicate from the overlap window.
    assert matches.count(0x2000 + 5) == 1
    assert len(matches) == 1


def test_numeric_scan_does_not_get_overlap(monkeypatch):
    """
    Sanity: int scans are aligned to ``target_value_size``, so they don't
    need the overlap and the helper must not introduce extra reads for them.
    The result must equal the obvious offset.
    """
    from PyMemoryEditor.util import scan as scan_module

    monkeypatch.setattr(scan_module, "DEFAULT_MAX_REGION_CHUNK", 16)

    import struct as struct_mod

    payload = bytearray(32)
    # Place an int32 = 42 at offset 12 (still inside chunk 0).
    payload[12:16] = struct_mod.pack("<i", 42)
    region = _make_region(0x3000, bytes(payload))

    target_bytes = struct_mod.pack("<i", 42)
    matches = list(
        iter_search_results(
            [region],
            int,
            4,
            target_bytes,
            ScanTypesEnum.EXACT_VALUE,
            _make_reader(region),
        )
    )

    assert matches == [0x3000 + 12]
