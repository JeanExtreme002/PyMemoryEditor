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


# --------------------------------------------------------------------------- #
# Module snapshot: ERROR_BAD_LENGTH retry, exited target
# --------------------------------------------------------------------------- #

_INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value
_FAKE_SNAPSHOT = 0x5678


def _fake_snapshot(script):
    """
    ``CreateToolhelp32Snapshot`` stand-in: each entry of ``script`` is a Win32
    error code (the call fails with it) or ``None`` (it returns a snapshot
    handle). The last entry repeats forever.
    """
    calls = []

    def fake(flags, pid):
        index = min(len(calls), len(script) - 1)
        err = script[index]
        calls.append(err)
        if err is None:
            return _FAKE_SNAPSHOT
        ctypes.set_last_error(err)
        return _INVALID_HANDLE_VALUE

    fake.calls = calls
    return fake


@pytest.fixture
def empty_module_walk(monkeypatch):
    """Module32FirstW finds nothing; CloseHandle is recorded, not called."""
    closed = []
    monkeypatch.setattr(win.kernel32, "Module32FirstW", lambda snapshot, entry: 0)
    monkeypatch.setattr(win.kernel32, "CloseHandle", lambda handle: closed.append(handle) or 1)
    # The target is alive unless a test says otherwise.
    monkeypatch.setattr(win, "ProcessExists", lambda pid: True)
    return closed


def test_module_snapshot_is_retried_on_bad_length(monkeypatch, empty_module_walk):
    # MSDN: "If the function fails with ERROR_BAD_LENGTH, retry the function
    # until it succeeds" — the loader was changing the module list.
    fake = _fake_snapshot([_ERROR_BAD_LENGTH, _ERROR_BAD_LENGTH, None])
    monkeypatch.setattr(win.kernel32, "CreateToolhelp32Snapshot", fake)

    assert list(win.GetModules(os.getpid())) == []
    assert fake.calls == [_ERROR_BAD_LENGTH, _ERROR_BAD_LENGTH, None]
    assert empty_module_walk == [_FAKE_SNAPSHOT]


def test_module_snapshot_retries_are_bounded(monkeypatch, empty_module_walk):
    fake = _fake_snapshot([_ERROR_BAD_LENGTH])
    monkeypatch.setattr(win.kernel32, "CreateToolhelp32Snapshot", fake)

    with pytest.raises(OSError) as excinfo:
        list(win.GetModules(os.getpid()))

    assert excinfo.value.winerror == _ERROR_BAD_LENGTH
    assert len(fake.calls) == win._SNAPSHOT_BAD_LENGTH_RETRIES


def test_module_snapshot_retries_wait_between_attempts(monkeypatch, empty_module_walk):
    # Back-to-back attempts fall inside the same loader transition; each
    # retry waits a little, and the last failure does not.
    fake = _fake_snapshot([_ERROR_BAD_LENGTH])
    monkeypatch.setattr(win.kernel32, "CreateToolhelp32Snapshot", fake)
    sleeps = []
    monkeypatch.setattr(win.time, "sleep", sleeps.append)

    with pytest.raises(OSError):
        list(win.GetModules(os.getpid()))

    assert sleeps == [win._SNAPSHOT_BAD_LENGTH_DELAY] * (win._SNAPSHOT_BAD_LENGTH_RETRIES - 1)


def test_other_snapshot_errors_are_not_retried(monkeypatch, empty_module_walk):
    fake = _fake_snapshot([_ERROR_ACCESS_DENIED])
    monkeypatch.setattr(win.kernel32, "CreateToolhelp32Snapshot", fake)

    with pytest.raises(PermissionError):
        list(win.GetModules(os.getpid()))

    assert fake.calls == [_ERROR_ACCESS_DENIED]


def test_a_failed_module_snapshot_of_an_exited_target_reports_the_pid(
    monkeypatch, empty_module_walk
):
    from PyMemoryEditor import ProcessIDNotExistsError

    monkeypatch.setattr(
        win.kernel32, "CreateToolhelp32Snapshot", _fake_snapshot([_ERROR_INVALID_PARAMETER])
    )
    monkeypatch.setattr(win, "_process_has_exited", lambda handle: True)

    with pytest.raises(ProcessIDNotExistsError) as excinfo:
        list(win.GetModules(4242, process_handle=_FAKE_HANDLE))

    assert excinfo.value.pid == 4242


def test_an_empty_module_snapshot_of_an_exited_target_reports_the_pid(
    monkeypatch, empty_module_walk
):
    from PyMemoryEditor import ProcessIDNotExistsError

    monkeypatch.setattr(win.kernel32, "CreateToolhelp32Snapshot", _fake_snapshot([None]))
    monkeypatch.setattr(win, "_process_has_exited", lambda handle: True)

    with pytest.raises(ProcessIDNotExistsError):
        list(win.GetModules(4242, process_handle=_FAKE_HANDLE))

    assert empty_module_walk == [_FAKE_SNAPSHOT]  # the snapshot is still closed


def test_an_empty_module_snapshot_of_a_live_target_is_just_empty(
    monkeypatch, empty_module_walk
):
    monkeypatch.setattr(win.kernel32, "CreateToolhelp32Snapshot", _fake_snapshot([None]))
    monkeypatch.setattr(win, "_process_has_exited", lambda handle: False)

    assert list(win.GetModules(4242, process_handle=_FAKE_HANDLE)) == []


# --------------------------------------------------------------------------- #
# Short ReadProcessMemory during a scan
# --------------------------------------------------------------------------- #

def _fake_short_read(fill, returned):
    """``ReadProcessMemory`` that succeeds but copies only ``returned`` bytes
    of ``fill`` (the rest of the caller's buffer stays zero)."""
    def fake(handle, address, buffer, size, bytes_read_ref):
        ctypes.memmove(buffer, fill, min(returned, size))
        bytes_read_ref._obj.value = returned  # type: ignore[attr-defined]
        return 1
    return fake


def test_a_short_read_is_a_skipped_chunk_not_a_zero_filled_one(monkeypatch):
    monkeypatch.setattr(
        win.kernel32, "ReadProcessMemory", _fake_short_read(b"\xff" * 8, 8)
    )

    assert win._read_region(_FAKE_HANDLE, 0x1000, 16) is None


def test_a_short_read_cannot_produce_false_zero_matches(monkeypatch):
    # The zero-filled tail of a short read used to be scanned like real
    # memory, so an exact scan for 0 "found" four addresses nobody read.
    monkeypatch.setattr(
        win.kernel32, "ReadProcessMemory", _fake_short_read(b"\xff" * 16, 16)
    )
    regions = [_region(0x10000)]  # 4 KiB region, only 16 bytes "readable"

    assert list(win.SearchAddressesByValue(
        _FAKE_HANDLE, int, 4, 0, memory_regions=regions
    )) == []


def test_a_full_read_is_returned(monkeypatch):
    monkeypatch.setattr(
        win.kernel32, "ReadProcessMemory", _fake_short_read(b"\x01" * 16, 16)
    )

    assert bytes(win._read_region(_FAKE_HANDLE, 0x1000, 16)) == b"\x01" * 16


# --------------------------------------------------------------------------- #
# GetMappedFileNameW buffer growth
# --------------------------------------------------------------------------- #

def test_a_long_mapped_file_name_is_not_truncated(monkeypatch):
    name = "\\Device\\HarddiskVolume1\\" + "d" * 900 + "\\file.bin"
    sizes = []

    def fake(handle, address, buffer, size):
        # Like the real call: copy what fits (NUL-terminated) and return the
        # number of characters copied.
        sizes.append(size)
        copied = min(len(name), size - 1)
        ctypes.memmove(
            buffer,
            ctypes.create_unicode_buffer(name[:copied]),
            (copied + 1) * ctypes.sizeof(ctypes.c_wchar),
        )
        return copied

    monkeypatch.setattr(win.psapi, "GetMappedFileNameW", fake)

    assert win._get_mapped_filename(_FAKE_HANDLE, 0x1000) == name
    assert sizes[0] == win._MAPPED_FILENAME_BUF_SIZE
    assert len(sizes) > 1


def test_a_short_mapped_file_name_takes_one_call(monkeypatch):
    sizes = []

    def fake(handle, address, buffer, size):
        sizes.append(size)
        source = ctypes.create_unicode_buffer("\\Device\\x.dll")
        ctypes.memmove(buffer, source, ctypes.sizeof(source))
        return len(source.value)

    monkeypatch.setattr(win.psapi, "GetMappedFileNameW", fake)

    assert win._get_mapped_filename(_FAKE_HANDLE, 0x1000) == "\\Device\\x.dll"
    assert len(sizes) == 1


# --------------------------------------------------------------------------- #
# Value / pattern scans keep a snapshot's order
# --------------------------------------------------------------------------- #

def _capture_scan_regions(monkeypatch, name):
    captured = []

    def fake(memory_regions, *args, **kwargs):
        captured.append([region.address for region in memory_regions])
        return iter(())

    monkeypatch.setattr(win, name, fake)
    return captured


@pytest.mark.parametrize("snapshot_type, expected", (
    # A snapshot is a mutable list: one the caller reordered (append,
    # reverse, ...) must still be scanned in address order, so every input
    # is sorted -- a no-op pass over a list that already is.
    (MemoryRegionSnapshot, [0x1000, 0x3000]),
    (list, [0x1000, 0x3000]),
))
def test_scans_take_regions_in_address_order(monkeypatch, snapshot_type, expected):
    values = _capture_scan_regions(monkeypatch, "iter_search_results")
    patterns = _capture_scan_regions(monkeypatch, "iter_pattern_results")

    list(win.SearchAddressesByValue(
        _FAKE_HANDLE, int, 4, 7,
        memory_regions=snapshot_type([_region(0x3000), _region(0x1000)]),
    ))
    list(win.SearchAddressesByPattern(
        _FAKE_HANDLE, "90",
        memory_regions=snapshot_type([_region(0x3000), _region(0x1000)]),
    ))

    assert values == [expected]
    assert patterns == [expected]
