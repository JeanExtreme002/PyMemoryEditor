# -*- coding: utf-8 -*-

"""
Windows-only tests: the region walk and the chunked scan reader distinguish
"this page is gone" (skip it) from "this handle / this target is gone" (stop).

Both ``VirtualQueryEx`` and ``ReadProcessMemory`` are patched at the ctypes
seam, the way tests/scan/test_chunking_integration.py patches
``IsWow64Process``; the fakes set the Win32 last-error the real calls would,
so the classification under test runs against exactly what it would see in
production. No foreign process is involved.
"""

import ctypes
import os
import sys

import pytest


if sys.platform != "win32":
    pytest.skip("Windows-only module", allow_module_level=True)


from PyMemoryEditor import ProcessIDNotExistsError  # noqa: E402
from PyMemoryEditor.win32 import functions as win  # noqa: E402


_ERROR_ACCESS_DENIED = 5
_ERROR_INVALID_HANDLE = 6
_ERROR_INVALID_PARAMETER = 87
_ERROR_PARTIAL_COPY = 299

_FAKE_HANDLE = 0x1234


def _fake_query(script):
    """
    ``VirtualQueryEx`` stand-in: each entry of ``script`` is either a Win32
    error code (the call fails with it) or ``None`` (the call succeeds and
    describes one 4 KiB region). The last entry repeats forever.
    """
    calls = []

    def fake(handle, address, buffer, length):
        index = min(len(calls), len(script) - 1)
        err = script[index]
        calls.append(err)
        if err is None:
            # `buffer` is the byref() the walker passed; argtypes are not
            # applied to a Python stand-in, so cast it back to the struct.
            region = ctypes.cast(buffer, ctypes.POINTER(win.MEMORY_BASIC_INFORMATION))
            region.contents.RegionSize = 0x1000
            return length
        ctypes.set_last_error(err)
        return 0

    fake.calls = calls
    return fake


@pytest.fixture
def host_mbi(monkeypatch):
    # The walk picks a 32- or 64-bit MBI layout from the handle; with a fake
    # handle, pin it to the host layout so the fake can fill it in.
    monkeypatch.setattr(win, "mbi_class_for_handle", lambda handle: win.MEMORY_BASIC_INFORMATION)
    monkeypatch.setattr(win, "_get_mapped_filename", lambda handle, address: "")


def test_a_transient_failure_is_skipped_and_the_walk_continues(monkeypatch, host_mbi):
    fake = _fake_query([_ERROR_PARTIAL_COPY, None, _ERROR_INVALID_PARAMETER])
    monkeypatch.setattr(win.kernel32, "VirtualQueryEx", fake)

    regions = list(win.GetMemoryRegions(_FAKE_HANDLE))

    assert len(regions) == 1
    assert fake.calls == [_ERROR_PARTIAL_COPY, None, _ERROR_INVALID_PARAMETER]


@pytest.mark.parametrize("err", (_ERROR_ACCESS_DENIED, _ERROR_INVALID_HANDLE))
def test_a_handle_level_error_ends_the_walk_at_once(monkeypatch, host_mbi, err):
    fake = _fake_query([err])
    monkeypatch.setattr(win.kernel32, "VirtualQueryEx", fake)
    monkeypatch.setattr(win, "_process_has_exited", lambda handle: False)

    with pytest.raises(OSError):
        list(win.GetMemoryRegions(_FAKE_HANDLE, pid=os.getpid()))

    assert len(fake.calls) == 1


def test_access_denied_on_a_live_target_names_the_missing_right(monkeypatch, host_mbi):
    monkeypatch.setattr(win.kernel32, "VirtualQueryEx", _fake_query([_ERROR_ACCESS_DENIED]))
    monkeypatch.setattr(win, "_process_has_exited", lambda handle: False)

    with pytest.raises(PermissionError, match="PROCESS_QUERY_INFORMATION"):
        list(win.GetMemoryRegions(_FAKE_HANDLE, pid=os.getpid()))


def test_an_exited_target_is_reported_as_process_id_not_exists(monkeypatch, host_mbi):
    monkeypatch.setattr(win.kernel32, "VirtualQueryEx", _fake_query([_ERROR_ACCESS_DENIED]))
    monkeypatch.setattr(win, "_process_has_exited", lambda handle: True)

    with pytest.raises(ProcessIDNotExistsError) as excinfo:
        list(win.GetMemoryRegions(_FAKE_HANDLE, pid=4242))

    assert excinfo.value.pid == 4242


def test_endless_failures_are_capped_instead_of_crawling_the_address_space(monkeypatch, host_mbi):
    fake = _fake_query([_ERROR_PARTIAL_COPY])
    monkeypatch.setattr(win.kernel32, "VirtualQueryEx", fake)
    monkeypatch.setattr(win, "_process_has_exited", lambda handle: False)

    with pytest.raises(OSError, match="could not make progress"):
        list(win.GetMemoryRegions(_FAKE_HANDLE, pid=os.getpid()))

    assert len(fake.calls) == win._REGION_MAX_CONSECUTIVE_FAILURES + 1


def _fake_read(err):
    def fake(handle, address, buffer, size, bytes_read_ref):
        ctypes.set_last_error(err)
        return 0
    return fake


def test_partial_copy_on_read_is_a_skippable_chunk(monkeypatch):
    monkeypatch.setattr(win.kernel32, "ReadProcessMemory", _fake_read(_ERROR_PARTIAL_COPY))
    monkeypatch.setattr(win, "_process_has_exited", lambda handle: False)

    assert win._read_region(_FAKE_HANDLE, 0x1000, 16) is None


@pytest.mark.parametrize("err", (_ERROR_ACCESS_DENIED, _ERROR_INVALID_HANDLE))
def test_handle_level_read_errors_are_fatal(monkeypatch, err):
    monkeypatch.setattr(win.kernel32, "ReadProcessMemory", _fake_read(err))

    with pytest.raises(win._Win32FatalReadError) as excinfo:
        win._read_region(_FAKE_HANDLE, 0x1000, 16)

    assert excinfo.value.code == err


def test_a_read_from_an_exited_target_is_fatal_even_with_a_page_level_error(monkeypatch):
    monkeypatch.setattr(win.kernel32, "ReadProcessMemory", _fake_read(_ERROR_PARTIAL_COPY))
    monkeypatch.setattr(win, "_process_has_exited", lambda handle: True)

    with pytest.raises(win._Win32FatalReadError, match="has exited"):
        win._read_region(_FAKE_HANDLE, 0x1000, 16)


def test_fatal_read_errors_are_not_classified_transient():
    # `search_by_addresses` swallows `_Win32ChunkReadError` unless
    # raise_error=True; the fatal class must never be mistaken for it.
    assert not isinstance(
        win._Win32FatalReadError(0x1000, 16, _ERROR_ACCESS_DENIED, "denied"),
        win._Win32ChunkReadError,
    )
