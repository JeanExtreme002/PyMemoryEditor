# -*- coding: utf-8 -*-

"""
Tests for ``AbstractProcess.resolve_pointer_chain``. Builds a chain of
ctypes pointers on the test's own heap and verifies that walking the chain
recovers the final address — the same operation Cheat Engine performs to
locate values that survive a process restart.
"""

import ctypes
import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402


@pytest.fixture
def process():
    """Open `OpenProcess` against the current process for the whole module."""
    handle = OpenProcess(pid=os.getpid())
    try:
        yield handle
    finally:
        handle.close()


def test_resolve_empty_offsets_dereferences_once(process):
    """
    With ``offsets=[]``, resolve_pointer_chain must dereference base once
    and return the resulting pointer — no further walking, no offset added.
    """
    target = ctypes.c_int(0xCAFEF00D)
    pointer_holder = ctypes.c_uint64(ctypes.addressof(target))

    resolved = process.resolve_pointer_chain(ctypes.addressof(pointer_holder), [])

    assert resolved == ctypes.addressof(target)


def test_resolve_two_level_chain(process):
    """``[base] → [ptr1+0] → ptr2+0`` resolves to the deepest address."""
    target = ctypes.c_int(0xDEADBEEF)
    level1 = ctypes.c_uint64(ctypes.addressof(target))
    level0 = ctypes.c_uint64(ctypes.addressof(level1))

    # Walk two levels, no extra offset on the last hop.
    resolved = process.resolve_pointer_chain(
        ctypes.addressof(level0), [0, 0]
    )

    assert resolved == ctypes.addressof(target)
    # And reading at the resolved address yields the value we planted.
    value = process.read_process_memory(resolved, int, 4)
    assert (value & 0xFFFFFFFF) == 0xDEADBEEF


def test_resolve_chain_with_offsets(process):
    """A chain whose last hop adds a non-zero offset returns base+offset."""
    # Layout: a struct-like buffer with two int fields, plus a pointer to it.
    pair = (ctypes.c_int * 2)(0x11111111, 0x22222222)
    pointer_holder = ctypes.c_uint64(ctypes.addressof(pair))

    # offsets[-1] = 4 — points to the second int, *without* extra dereference.
    resolved = process.resolve_pointer_chain(
        ctypes.addressof(pointer_holder), [4]
    )

    second_int_address = ctypes.addressof(pair) + 4
    assert resolved == second_int_address

    value = process.read_process_memory(resolved, int, 4)
    assert (value & 0xFFFFFFFF) == 0x22222222


def test_resolve_four_level_chain_with_large_offsets(process):
    """
    Walk a four-level pointer chain whose every offset is greater than 100 —
    same shape as the deep cheat-table dumps people share for modern games
    (e.g. ``"game.exe"+0x10F4F4 -> [+0x68] -> [+0x90] -> [+0xC8] -> [+0x158]``).

    Each level is a 256-byte buffer holding the pointer to the next level at
    a non-trivial offset, so the test exercises pointer arithmetic that has
    *nothing* in common with the "all-zeros" happy path.
    """
    level_size = 256
    offsets = [104, 128, 152, 200]  # all > 100, all distinct, none aligned with each other
    target_value = 0xABCD1234

    # Innermost level holds the value we want to recover, parked at the deep
    # offset rather than at the start of the buffer.
    level4 = (ctypes.c_uint8 * level_size)()
    ctypes.memmove(
        ctypes.addressof(level4) + offsets[3],
        ctypes.byref(ctypes.c_int32(target_value)),
        4,
    )

    # Each intermediate level stores the *address* of the next level at the
    # appropriate offset. memmove of a c_uint64 writes 8 raw bytes in native
    # byte order — exactly what the resolver will read back.
    level3 = (ctypes.c_uint8 * level_size)()
    ctypes.memmove(
        ctypes.addressof(level3) + offsets[2],
        ctypes.byref(ctypes.c_uint64(ctypes.addressof(level4))),
        8,
    )

    level2 = (ctypes.c_uint8 * level_size)()
    ctypes.memmove(
        ctypes.addressof(level2) + offsets[1],
        ctypes.byref(ctypes.c_uint64(ctypes.addressof(level3))),
        8,
    )

    level1 = (ctypes.c_uint8 * level_size)()
    ctypes.memmove(
        ctypes.addressof(level1) + offsets[0],
        ctypes.byref(ctypes.c_uint64(ctypes.addressof(level2))),
        8,
    )

    # Base just holds a raw pointer to level1 (no offset on the first hop).
    base = ctypes.c_uint64(ctypes.addressof(level1))

    resolved = process.resolve_pointer_chain(ctypes.addressof(base), offsets)

    expected = ctypes.addressof(level4) + offsets[3]
    assert resolved == expected, (
        "4-level chain resolved to 0x%X, expected 0x%X" % (resolved, expected)
    )

    # And the value at the final address must be the one we planted.
    value = process.read_process_memory(resolved, int, 4)
    assert (value & 0xFFFFFFFF) == target_value


def test_resolve_rejects_invalid_ptr_size(process):
    target = ctypes.c_int(1)
    pointer_holder = ctypes.c_uint64(ctypes.addressof(target))
    with pytest.raises(ValueError, match="ptr_size"):
        process.resolve_pointer_chain(
            ctypes.addressof(pointer_holder), [], ptr_size=5
        )


def test_resolve_unsigned_pointer_decoding(process):
    """
    A pointer whose top bit is set must be returned as a positive int, not
    sign-extended. We don't always have a pointer in the upper half of the
    address space available, but we can fabricate one by writing arbitrary
    bytes and checking the decoding directly via ptr_size=4 to keep the
    bit-pattern controllable on every platform.
    """
    raw = ctypes.c_uint32(0xFFFFFFFF)
    resolved = process.resolve_pointer_chain(
        ctypes.addressof(raw), [], ptr_size=4
    )
    # If sign-extension leaked through, ``resolved`` would be negative.
    assert resolved == 0xFFFFFFFF
    assert resolved > 0
