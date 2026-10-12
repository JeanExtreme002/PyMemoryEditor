# -*- coding: utf-8 -*-

"""
Fakes shared by the scan-driver tests: a sparse address space with a recording
``read_chunk``, and a way to force tiny chunks so chunk-boundary rules are hit
with small buffers. No process is involved.
"""

import ctypes

from PyMemoryEditor.process import scanning
from PyMemoryEditor.process.region import MemoryRegion
from PyMemoryEditor.process.scanning import iter_pattern_results
from PyMemoryEditor.util.pattern import compile_pattern
from PyMemoryEditor.util.scan import _iter_large_region_chunks


class FakeMemory:
    """A sparse address space: ``{base: payload}``, with a recording reader."""

    def __init__(self, segments, *, readable=True):
        self.segments = dict(segments)
        self.regions = [
            MemoryRegion(address=base, size=len(data), is_readable=readable)
            for base, data in sorted(self.segments.items())
        ]
        self.reads = []

    def read_chunk(self, address, size):
        """Serve ``[address, address + size)`` if it is fully mapped by
        consecutive segments, else raise ``OSError`` (EFAULT)."""
        self.reads.append((address, size))
        out = b""
        cursor = address
        end = address + size
        for base, data in sorted(self.segments.items()):
            seg_end = base + len(data)
            if base <= cursor < seg_end:
                take = min(end, seg_end) - cursor
                out += data[cursor - base : cursor - base + take]
                cursor += take
                if cursor == end:
                    break
        if cursor != end:
            raise OSError(14, "Bad address")
        return (ctypes.c_byte * size).from_buffer_copy(out)


def small_chunks(monkeypatch, max_chunk):
    """Force ``iter_region_chunks`` (as the scan drivers see it) to split every
    region into ``max_chunk``-byte chunks, so chunk-boundary rules are hit with
    tiny buffers."""
    monkeypatch.setattr(
        scanning,
        "iter_region_chunks",
        lambda size, width: tuple(_iter_large_region_chunks(size, width, max_chunk)),
    )


def pattern_hits(memory, pattern, byte_length=0):
    """Every match ``pattern`` reports over ``memory``'s regions."""
    compiled, length = compile_pattern(pattern, byte_length=byte_length)
    return list(
        iter_pattern_results(memory.regions, compiled, length, memory.read_chunk)
    )
