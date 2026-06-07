# -*- coding: utf-8 -*-

"""
Tests for :class:`PyMemoryEditor.RemotePointer` and the ``process.get_pointer()``
factory. Builds ctypes objects on the test's own heap and verifies that the
handle reads, writes and — crucially — re-resolves its address through a
pointer chain on every access, the way a Cheat Engine pointer entry does.
"""

import ctypes
import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess, RemotePointer  # noqa: E402


@pytest.fixture
def process():
    handle = OpenProcess(pid=os.getpid())
    try:
        yield handle
    finally:
        handle.close()


def test_direct_handle_reads_value(process):
    """offsets=None -> address is base_address, no dereference."""
    target = ctypes.c_int32(0x1234)
    ptr = RemotePointer(process, ctypes.addressof(target), pytype=int, bufflength=4)

    assert ptr.address == ctypes.addressof(target)
    assert ptr.value == 0x1234
    assert int(ptr) == ctypes.addressof(target)


def test_direct_handle_writes_value(process):
    """Writing .value updates the underlying memory."""
    target = ctypes.c_int32(0)
    ptr = process.get_pointer(ctypes.addressof(target), pytype=int, bufflength=4)

    ptr.value = 0x7FABCDEF
    assert target.value == 0x7FABCDEF


def test_value_setter_round_trips(process):
    target = ctypes.c_int32(5)
    ptr = process.get_pointer(ctypes.addressof(target), pytype=int, bufflength=4)

    ptr.value -= 10
    assert target.value == -5
    assert ptr.value == -5


def test_chain_resolves_through_pointer(process):
    """A non-empty offsets list walks the chain like resolve_pointer_chain."""
    target = ctypes.c_int32(0x22222222)
    holder = ctypes.c_uint64(ctypes.addressof(target))

    # [0x4] would point past; use [0x0] to land on target via one dereference.
    ptr = process.get_pointer(
        ctypes.addressof(holder), [0x0], pytype=int, bufflength=4
    )

    assert ptr.address == ctypes.addressof(target)
    assert ptr.value == 0x22222222


def test_chain_reresolves_on_each_access(process):
    """
    The whole point of the handle: when the intermediate pointer is changed to
    aim at a different object, the *same* RemotePointer follows it without being
    rebuilt.
    """
    first = ctypes.c_int32(111)
    second = ctypes.c_int32(222)
    holder = ctypes.c_uint64(ctypes.addressof(first))

    ptr = process.get_pointer(
        ctypes.addressof(holder), [0x0], pytype=int, bufflength=4
    )
    assert ptr.value == 111

    # Repoint the holder at the second object; the handle must follow.
    holder.value = ctypes.addressof(second)
    assert ptr.address == ctypes.addressof(second)
    assert ptr.value == 222


def test_empty_offsets_dereferences_once(process):
    """offsets=[] keeps resolve_pointer_chain semantics: one dereference."""
    target = ctypes.c_int32(0x5A5A5A5A)
    holder = ctypes.c_uint64(ctypes.addressof(target))

    ptr = process.get_pointer(ctypes.addressof(holder), [], pytype=int, bufflength=4)

    assert ptr.address == ctypes.addressof(target)
    assert ptr.value == 0x5A5A5A5A


def test_read_override_reinterprets_bytes(process):
    """read() can reinterpret the same address under a different type."""
    target = ctypes.c_int32(0x41424344)
    ptr = process.get_pointer(ctypes.addressof(target), pytype=int, bufflength=4)

    raw = ptr.read(bytes, 4)
    assert raw == bytes(ctypes.string_at(ctypes.addressof(target), 4))


def test_offsets_are_copied_not_aliased(process):
    """Mutating the caller's list after construction must not move the pointer."""
    target = ctypes.c_int32(7)
    holder = ctypes.c_uint64(ctypes.addressof(target))
    offsets = [0x0]

    ptr = process.get_pointer(
        ctypes.addressof(holder), offsets, pytype=int, bufflength=4
    )
    offsets.append(0x999)  # must not affect the already-built pointer

    assert ptr.value == 7


def test_factory_returns_remote_pointer(process):
    target = ctypes.c_int32(1)
    ptr = process.get_pointer(ctypes.addressof(target))
    assert isinstance(ptr, RemotePointer)
    assert ptr.process is process


def test_add_returns_shifted_pointer_without_touching_memory(process):
    """ptr + n is a new pointer n bytes ahead; the original is unchanged."""
    pair = (ctypes.c_int32 * 2)(0x11111111, 0x22222222)
    base = ctypes.addressof(pair)
    ptr = process.get_pointer(base, pytype=int, bufflength=4)

    shifted = ptr + 4
    assert isinstance(shifted, RemotePointer)
    assert shifted is not ptr
    assert shifted.address == base + 4
    assert shifted.value == 0x22222222

    # Original pointer untouched, and memory was never written.
    assert ptr.address == base
    assert ptr.value == 0x11111111


def test_radd_is_symmetric(process):
    target = ctypes.c_int32(0)
    base = ctypes.addressof(target)
    ptr = process.get_pointer(base)
    assert (8 + ptr).address == base + 8


def test_sub_int_shifts_backwards(process):
    pair = (ctypes.c_int32 * 2)(0xAAAAAAA, 0x22222222)
    base = ctypes.addressof(pair)
    second = process.get_pointer(base + 4, pytype=int, bufflength=4)

    first = second - 4
    assert first.address == base
    assert first.value == 0xAAAAAAA


def test_sub_pointer_returns_byte_distance(process):
    pair = (ctypes.c_int32 * 2)(0, 0)
    base = ctypes.addressof(pair)
    a = process.get_pointer(base)
    b = process.get_pointer(base + 12)
    assert b - a == 12
    assert a - b == -12


def test_arithmetic_preserves_type_metadata(process):
    target = ctypes.c_int32(0x41424344)
    ptr = process.get_pointer(ctypes.addressof(target), pytype=bytes, bufflength=4)
    shifted = ptr - 0  # no-op shift, but must keep pytype/bufflength
    assert shifted.read() == ptr.read()
    assert isinstance(shifted.value, bytes)


def test_add_shifts_chain_lazily(process):
    """
    Shifting a pointer chain must keep re-resolving: moving the intermediate
    pointer still moves where (ptr + 4) lands.
    """
    first = (ctypes.c_int32 * 2)(0x111, 0x222)
    second = (ctypes.c_int32 * 2)(0x333, 0x444)
    holder = ctypes.c_uint64(ctypes.addressof(first))

    base_ptr = process.get_pointer(
        ctypes.addressof(holder), [0x0], pytype=int, bufflength=4
    )
    shifted = base_ptr + 4  # second int of whatever the holder points at

    assert shifted.value == 0x222

    # Repoint the holder; the shifted pointer must follow to second[+4].
    holder.value = ctypes.addressof(second)
    assert shifted.value == 0x444


def test_add_rejects_non_int(process):
    ptr = process.get_pointer(0x1000)
    with pytest.raises(TypeError):
        ptr + 1.5
