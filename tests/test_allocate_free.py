# -*- coding: utf-8 -*-

"""
Cross-platform tests for ``AbstractProcess.allocate_memory`` / ``free_memory``.

The happy-path tests run against the test process itself (``os.getpid()``):
allocate a region, round-trip values through it, then free it. Allocation in a
remote process is a Windows/macOS capability; on Linux both methods raise
``NotImplementedError`` (no cross-process allocation syscall), so the Linux
build only asserts that contract.
"""

import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess  # noqa: E402


IS_LINUX = sys.platform.startswith("linux")
_unsupported = pytest.mark.skipif(
    IS_LINUX, reason="allocate_memory/free_memory are unsupported on Linux"
)


@pytest.fixture
def process():
    """Open the test process itself and close it afterwards."""
    with OpenProcess(pid=os.getpid()) as proc:
        yield proc


@_unsupported
def test_allocate_returns_writable_region(process):
    """A fresh allocation is non-zero and round-trips an int write/read."""
    address = process.allocate_memory(64)
    try:
        assert isinstance(address, int)
        assert address > 0

        process.write_process_memory(address, int, 4, 0x1234ABCD)
        value = process.read_process_memory(address, int, 4)
        assert (value & 0xFFFFFFFF) == 0x1234ABCD
    finally:
        assert process.free_memory(address) is True


@_unsupported
def test_allocate_string_roundtrip(process):
    """The allocated region holds arbitrary bytes (string round-trip)."""
    address = process.allocate_memory(32)
    try:
        process.write_process_memory(address, str, 5, "hello")
        assert process.read_process_memory(address, str, 5) == "hello"
    finally:
        process.free_memory(address)


@_unsupported
def test_free_without_size_uses_tracked_size(process):
    """``free_memory(address)`` works without a size — the size is remembered."""
    address = process.allocate_memory(128)
    assert process.free_memory(address) is True


@_unsupported
def test_multiple_allocations_are_distinct(process):
    """Separate allocations land at separate addresses and free independently."""
    a = process.allocate_memory(64)
    b = process.allocate_memory(64)
    try:
        assert a != b
    finally:
        assert process.free_memory(a) is True
        assert process.free_memory(b) is True


@_unsupported
def test_allocate_rejects_nonpositive_size(process):
    """A zero / negative size is rejected before any syscall."""
    with pytest.raises(ValueError):
        process.allocate_memory(0)
    with pytest.raises(ValueError):
        process.allocate_memory(-1)


@pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS needs the size to free; unknown address without size is a ValueError",
)
def test_macos_free_unknown_address_without_size_raises(process):
    """On macOS, freeing an address we didn't allocate (no size) is a ValueError."""
    with pytest.raises(ValueError):
        process.free_memory(0x1000)


@pytest.mark.skipif(
    not IS_LINUX, reason="Linux-specific: allocation is not supported"
)
def test_linux_allocate_free_not_implemented(process):
    """On Linux both methods must raise NotImplementedError, not silently no-op."""
    with pytest.raises(NotImplementedError):
        process.allocate_memory(64)
    with pytest.raises(NotImplementedError):
        process.free_memory(0x1000)
