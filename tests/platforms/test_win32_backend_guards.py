# -*- coding: utf-8 -*-

"""
Windows-only regression tests for the Win32 backend:

- the region walk queries with the host's native MEMORY_BASIC_INFORMATION
  even for a WOW64 target (a smaller buffer fails with ERROR_BAD_LENGTH);
- ``GetMappedFileNameW`` is skipped for regions that cannot be file-backed;
- a ``MemoryRegionSnapshot`` reaches the address-list reader untouched;
- ``OpenProcess`` access-denied failures carry an actionable hint;
- ``free_memory`` refuses an address the object did not allocate unless the
  caller opts in with an explicit size.

The Win32 calls are patched at the ctypes seam like
tests/platforms/test_win32_region_walk.py does; the free_memory tests run
against the test process itself. No foreign process is involved.
"""

import ctypes
import os
import sys

import pytest


if sys.platform != "win32":
    pytest.skip("Windows-only module", allow_module_level=True)


from PyMemoryEditor import MemoryRegion, MemoryRegionSnapshot, OpenProcess  # noqa: E402
from PyMemoryEditor.win32 import functions as win  # noqa: E402
from PyMemoryEditor.win32.enums import (  # noqa: E402
    MemoryAllocationStatesEnum,
    MemoryProtectionsEnum,
    MemoryTypesEnum,
)


_ERROR_ACCESS_DENIED = 5
_ERROR_BAD_LENGTH = 24
_ERROR_INVALID_PARAMETER = 87
_FAKE_HANDLE = 0x1234


def _fake_kernel_query(regions):
    """
    ``VirtualQueryEx`` stand-in that behaves like NtQueryVirtualMemory: a
    buffer smaller than the native MEMORY_BASIC_INFORMATION fails with
    ERROR_BAD_LENGTH. ``regions`` is a list of (State, Type) pairs, each
    described as one 4 KiB region; after the last one the walk ends with
    ERROR_INVALID_PARAMETER.
    """
    calls = []

    def fake(handle, address, buffer, length):
        calls.append(address)
        if length < ctypes.sizeof(win.MEMORY_BASIC_INFORMATION):
            ctypes.set_last_error(_ERROR_BAD_LENGTH)
            return 0
        index = len(calls) - 1
        if index >= len(regions):
            ctypes.set_last_error(_ERROR_INVALID_PARAMETER)
            return 0
        state, mem_type = regions[index]
        region = ctypes.cast(buffer, ctypes.POINTER(win.MEMORY_BASIC_INFORMATION))
        region.contents.BaseAddress = address
        region.contents.RegionSize = 0x1000
        region.contents.State = state
        region.contents.Type = mem_type
        region.contents.Protect = MemoryProtectionsEnum.PAGE_READONLY.value
        return ctypes.sizeof(win.MEMORY_BASIC_INFORMATION)

    fake.calls = calls
    return fake


_COMMIT = MemoryAllocationStatesEnum.MEM_COMMIT.value
_FREE = MemoryAllocationStatesEnum.MEM_FREE.value
_RESERVE = MemoryAllocationStatesEnum.MEM_RESERVE.value
_IMAGE = MemoryTypesEnum.MEM_IMAGE.value
_MAPPED = MemoryTypesEnum.MEM_MAPPED.value
_PRIVATE = MemoryTypesEnum.MEM_PRIVATE.value


def _fake_is_wow64(handle, out_bool_ptr):
    out_bool_ptr._obj.value = 1  # type: ignore[attr-defined]
    return 1


# --------------------------------------------------------------------------- #
# WOW64 region query
# --------------------------------------------------------------------------- #

def test_region_walk_of_a_wow64_target_uses_the_native_struct(monkeypatch):
    monkeypatch.setattr(win.kernel32, "IsWow64Process", _fake_is_wow64)
    fake = _fake_kernel_query([(_COMMIT, _PRIVATE), (_COMMIT, _IMAGE)])
    monkeypatch.setattr(win.kernel32, "VirtualQueryEx", fake)
    monkeypatch.setattr(win, "_get_mapped_filename", lambda handle, address: "")

    regions = list(win.GetMemoryRegions(_FAKE_HANDLE, pid=os.getpid()))

    assert len(regions) == 2
    assert all(r.is_readable for r in regions)


def test_real_region_walk_of_self_succeeds():
    process_handle = win.GetProcessHandle(
        0x0400 | 0x0010, False, os.getpid()  # QUERY_INFORMATION | VM_READ
    )
    try:
        regions = list(win.GetMemoryRegions(process_handle, os.getpid()))
    finally:
        win.CloseProcessHandle(process_handle)

    assert any(r.is_readable for r in regions)
    assert any(r.path for r in regions), "no file-backed region named"


# --------------------------------------------------------------------------- #
# GetMappedFileNameW only where a file can back the region
# --------------------------------------------------------------------------- #

def test_mapped_file_name_is_only_queried_for_section_views(monkeypatch):
    layout = [
        (_FREE, 0),             # free: no allocation at all
        (_COMMIT, _PRIVATE),    # heap / stack
        (_RESERVE, _PRIVATE),   # VirtualAlloc reservation
        (_COMMIT, _IMAGE),      # a module image
        (_COMMIT, _MAPPED),     # a mapped file view
        (_RESERVE, _MAPPED),    # reserved part of a section view
    ]
    monkeypatch.setattr(win.kernel32, "VirtualQueryEx", _fake_kernel_query(layout))
    queried = []

    def fake_mapped(handle, address):
        queried.append(address)
        return "\\Device\\HarddiskVolume1\\file.bin"

    monkeypatch.setattr(win, "_get_mapped_filename", fake_mapped)

    regions = list(win.GetMemoryRegions(_FAKE_HANDLE))

    assert len(regions) == len(layout)
    assert [bool(r.path) for r in regions] == [False, False, False, True, True, True]
    assert queried == [r.address for r in regions[3:]]


# --------------------------------------------------------------------------- #
# MemoryRegionSnapshot passthrough
# --------------------------------------------------------------------------- #

def _region(address):
    return MemoryRegion(
        address=address, size=0x1000, is_readable=True, is_writable=True,
        is_executable=False, is_shared=False, path="",
    )


def _capture_regions(monkeypatch):
    captured = {}

    def fake_iter(addresses, memory_regions, *args, **kwargs):
        captured["regions"] = memory_regions
        return iter(())

    monkeypatch.setattr(win, "iter_values_for_addresses", fake_iter)
    return captured


def test_a_snapshot_reaches_the_address_reader_untouched(monkeypatch):
    captured = _capture_regions(monkeypatch)
    snapshot = MemoryRegionSnapshot([_region(0x1000), _region(0x2000)])

    list(win.SearchValuesByAddresses(
        _FAKE_HANDLE, int, 4, [0x1000], memory_regions=snapshot
    ))

    assert captured["regions"] is snapshot


def test_a_one_shot_iterable_is_still_materialized(monkeypatch):
    captured = _capture_regions(monkeypatch)

    list(win.SearchValuesByAddresses(
        _FAKE_HANDLE, int, 4, [0x1000],
        memory_regions=(r for r in [_region(0x2000), _region(0x1000)]),
    ))

    assert isinstance(captured["regions"], list)
    assert len(captured["regions"]) == 2


# --------------------------------------------------------------------------- #
# OpenProcess access denied
# --------------------------------------------------------------------------- #

def test_open_process_access_denied_explains_the_likely_causes(monkeypatch):
    def fake_open(access, inherit, pid):
        ctypes.set_last_error(_ERROR_ACCESS_DENIED)
        return None

    monkeypatch.setattr(win.kernel32, "OpenProcess", fake_open)

    with pytest.raises(PermissionError) as excinfo:
        win.GetProcessHandle(0x0010, False, 4242)

    assert excinfo.value.winerror == _ERROR_ACCESS_DENIED
    message = str(excinfo.value)
    assert "4242" in message
    assert "Administrator" in message
    assert "SeDebugPrivilege" in message


def test_open_process_other_errors_keep_the_plain_message(monkeypatch):
    def fake_open(access, inherit, pid):
        ctypes.set_last_error(_ERROR_INVALID_PARAMETER)
        return None

    monkeypatch.setattr(win.kernel32, "OpenProcess", fake_open)

    with pytest.raises(OSError) as excinfo:
        win.GetProcessHandle(0x0010, False, 4242)

    assert excinfo.value.winerror == _ERROR_INVALID_PARAMETER
    assert "Administrator" not in str(excinfo.value)


# --------------------------------------------------------------------------- #
# free_memory guard
# --------------------------------------------------------------------------- #

def test_free_memory_refuses_an_address_it_did_not_allocate():
    with OpenProcess(pid=os.getpid()) as owner, OpenProcess(pid=os.getpid()) as other:
        address = owner.allocate_memory(64)
        try:
            owner.write_process_memory(address, int, 4, 0x1234)

            with pytest.raises(ValueError, match="size="):
                other.free_memory(address)

            # Refused, not freed: the owner can still use the region.
            assert owner.read_process_memory(address, int, 4) == 0x1234
        finally:
            assert owner.free_memory(address) is True


def test_free_memory_frees_a_foreign_allocation_with_an_explicit_size():
    with OpenProcess(pid=os.getpid()) as owner, OpenProcess(pid=os.getpid()) as other:
        address = owner.allocate_memory(64)
        assert other.free_memory(address, size=64) is True

        with pytest.raises(OSError):
            owner.read_process_memory(address, int, 4)


def test_free_memory_refuses_an_unknown_address_before_any_syscall(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "PyMemoryEditor.win32.process.FreeMemory",
        lambda *args, **kwargs: calls.append(args) or True,
    )
    with OpenProcess(pid=os.getpid()) as process:
        with pytest.raises(ValueError):
            process.free_memory(0x1000)

    assert calls == []
