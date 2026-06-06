# -*- coding: utf-8 -*-

"""
Tests for the bitness/architecture detection exposed by every backend:
``AbstractProcess.is_64bit`` / ``AbstractProcess.pointer_size`` and the
automatic ``ptr_size`` default it powers on the pointer APIs.

Opened against the test's own process, so ``is_64bit`` must agree with the
running interpreter's pointer width on all three platforms.
"""

import ctypes
import logging
import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import BitnessDetectionError, OpenProcess  # noqa: E402


HOST_IS_64BIT = ctypes.sizeof(ctypes.c_void_p) == 8


@pytest.fixture
def process():
    handle = OpenProcess(pid=os.getpid())
    try:
        yield handle
    finally:
        handle.close()


def test_is_64bit_matches_host(process):
    """Detection must agree with the interpreter we're running under."""
    assert process.is_64bit is HOST_IS_64BIT


def test_pointer_size_follows_is_64bit(process):
    """pointer_size is 8 for a 64-bit target, 4 for a 32-bit one."""
    assert process.pointer_size == (8 if process.is_64bit else 4)
    assert process.pointer_size == ctypes.sizeof(ctypes.c_void_p)


def test_is_64bit_is_cached(process):
    """The result is detected once and reused (no re-querying the OS)."""
    assert process._is_64bit_cache is None  # not yet detected
    first = process.is_64bit
    assert process._is_64bit_cache is first  # cached after first access
    assert process.is_64bit is first


def test_resolve_pointer_chain_uses_detected_ptr_size(process):
    """
    With ``ptr_size`` left as None, resolve_pointer_chain must read pointers at
    the target's native width — proven by recovering a planted address.
    """
    target = ctypes.c_int(0x1234ABCD)
    holder = ctypes.c_void_p(ctypes.addressof(target))

    resolved = process.resolve_pointer_chain(ctypes.addressof(holder), [])

    assert resolved == ctypes.addressof(target)


def test_remote_pointer_defaults_to_detected_ptr_size(process):
    """A RemotePointer built without ptr_size walks chains at pointer_size."""
    target = ctypes.c_int(0x0BADF00D)
    holder = ctypes.c_void_p(ctypes.addressof(target))

    pointer = process.get_pointer(ctypes.addressof(holder), [], pytype=int, bufflength=4)

    assert pointer.address == ctypes.addressof(target)
    assert (pointer.value & 0xFFFFFFFF) == 0x0BADF00D


# --- strict_bitness / is_bitness_certain -------------------------------- #
#
# The self-process always has a readable header, so detection is certain; the
# undeterminable path (a cross-bitness target whose header can't be read) is
# forced by stubbing the backend's raw detector to return None — the contract
# `_detect_is_64bit` uses to signal "unknown".


def test_is_bitness_certain_true_for_readable_target(process):
    """A target whose header is readable (here, ourselves) is certain."""
    assert process.is_bitness_certain is True
    assert process.is_64bit is HOST_IS_64BIT


def test_undeterminable_falls_back_to_host_and_warns(process, monkeypatch, caplog):
    """Non-strict (default): an unknown bitness guesses the host word size,
    flags the result as uncertain, and logs a WARNING."""
    monkeypatch.setattr(process, "_detect_is_64bit", lambda: None)
    process._is_64bit_cache = None  # clear any cached detection
    process._bitness_certain = None

    with caplog.at_level(logging.WARNING, logger="PyMemoryEditor"):
        assert process.is_64bit is HOST_IS_64BIT
    assert process.is_bitness_certain is False
    assert any(
        record.levelno == logging.WARNING and "bitness" in record.getMessage().lower()
        for record in caplog.records
    )


def test_strict_bitness_raises_when_undeterminable(monkeypatch):
    """strict_bitness=True turns the guess into a BitnessDetectionError."""
    handle = OpenProcess(pid=os.getpid(), strict_bitness=True)
    try:
        monkeypatch.setattr(handle, "_detect_is_64bit", lambda: None)
        with pytest.raises(BitnessDetectionError) as excinfo:
            _ = handle.is_64bit
        assert excinfo.value.pid == os.getpid()
    finally:
        handle.close()


def test_strict_bitness_succeeds_when_determinable():
    """strict_bitness must not interfere when the header is readable."""
    handle = OpenProcess(pid=os.getpid(), strict_bitness=True)
    try:
        assert handle.is_64bit is HOST_IS_64BIT
        assert handle.is_bitness_certain is True
    finally:
        handle.close()
