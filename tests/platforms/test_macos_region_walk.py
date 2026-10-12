# -*- coding: utf-8 -*-

"""
macOS-only tests: the region walk may skip a page the kernel declines to
describe, but it may not crawl the whole 64-bit address space when every call
fails.

``mach_vm_region`` is patched at the ctypes seam (the same way
tests/memory/test_partial_io.py patches ``mach_vm_read_overwrite``), so no
foreign process is involved: the fake decides what the kernel "says".
"""

import ctypes
import os
import sys

import pytest


if sys.platform != "darwin":
    pytest.skip("macOS-only module", allow_module_level=True)


from PyMemoryEditor import ProcessIDNotExistsError  # noqa: E402
from PyMemoryEditor.macos import functions as mac  # noqa: E402
from PyMemoryEditor.macos.types import (  # noqa: E402
    KERN_FAILURE,
    KERN_INVALID_ADDRESS,
    KERN_SUCCESS,
    MACH_SEND_INVALID_DEST,
)


# A pid that is not in use: 2**31-1 is pid_max's ceiling on every platform the
# suite runs on, and tests/core/test_errors.py relies on it the same way.
_DEAD_PID = 2**31 - 1

_FAKE_TASK = 0x1234


def _fake_region(script):
    """
    Build a ``mach_vm_region`` stand-in that answers with the codes in
    ``script`` in order, repeating the last one forever, and counts calls.
    """
    calls = []

    def fake(task, address_ref, size_ref, flavor, info, count_ref, name_ref):
        index = min(len(calls), len(script) - 1)
        kr = script[index]
        calls.append(kr)
        if kr == KERN_SUCCESS:
            # One 4 KiB region at the cursor; the walk then advances past it.
            size = ctypes.cast(size_ref, ctypes.POINTER(mac.mach_vm_size_t))
            size.contents.value = 0x1000
        return kr

    fake.calls = calls
    return fake


def test_a_transient_failure_is_skipped_and_the_walk_continues(monkeypatch):
    fake = _fake_region([KERN_FAILURE, KERN_SUCCESS, KERN_INVALID_ADDRESS])
    monkeypatch.setattr(mac.libsystem, "mach_vm_region", fake)
    monkeypatch.setattr(mac, "_region_is_shared", lambda *a: False)

    regions = list(mac.get_memory_regions(_FAKE_TASK))

    assert len(regions) == 1
    assert regions[0].address == mac._REGION_SKIP_BUMP
    assert fake.calls == [KERN_FAILURE, KERN_SUCCESS, KERN_INVALID_ADDRESS]


def test_a_dead_task_port_ends_the_walk_at_once(monkeypatch):
    fake = _fake_region([MACH_SEND_INVALID_DEST])
    monkeypatch.setattr(mac.libsystem, "mach_vm_region", fake)

    with pytest.raises(OSError, match="mach_vm_region failed"):
        list(mac.get_memory_regions(_FAKE_TASK))

    assert len(fake.calls) == 1


def test_a_dead_task_port_reports_the_pid_when_the_process_is_gone(monkeypatch):
    fake = _fake_region([MACH_SEND_INVALID_DEST])
    monkeypatch.setattr(mac.libsystem, "mach_vm_region", fake)

    with pytest.raises(ProcessIDNotExistsError) as excinfo:
        list(mac.get_memory_regions(_FAKE_TASK, pid=_DEAD_PID))

    assert excinfo.value.pid == _DEAD_PID


def test_endless_failures_are_capped_instead_of_crawling_the_address_space(monkeypatch):
    fake = _fake_region([KERN_FAILURE])
    monkeypatch.setattr(mac.libsystem, "mach_vm_region", fake)

    # The process is alive (it is us), so the cap must surface as OSError,
    # not as a ProcessIDNotExistsError that would be a lie.
    with pytest.raises(OSError, match="could not make progress"):
        list(mac.get_memory_regions(_FAKE_TASK, pid=os.getpid()))

    assert len(fake.calls) == mac._REGION_MAX_CONSECUTIVE_FAILURES + 1


def test_the_failure_counter_resets_on_success(monkeypatch):
    # Alternate failure/success for longer than the cap: never more than one
    # failure in a row, so the walk must run to its natural end.
    script = [KERN_FAILURE, KERN_SUCCESS] * (mac._REGION_MAX_CONSECUTIVE_FAILURES + 5)
    script.append(KERN_INVALID_ADDRESS)
    fake = _fake_region(script)
    monkeypatch.setattr(mac.libsystem, "mach_vm_region", fake)
    monkeypatch.setattr(mac, "_region_is_shared", lambda *a: False)

    regions = list(mac.get_memory_regions(_FAKE_TASK))

    assert len(regions) == mac._REGION_MAX_CONSECUTIVE_FAILURES + 5
    assert fake.calls[-1] == KERN_INVALID_ADDRESS


def _fake_layout(regions):
    """
    ``mach_vm_region`` stand-in that describes ``regions`` — ``(start, size)``
    pairs — like the kernel: the first region at or after the cursor, then
    KERN_INVALID_ADDRESS past the last one. Records each queried cursor.
    """
    cursors = []

    def fake(task, address_ref, size_ref, flavor, info, count_ref, name_ref):
        address = ctypes.cast(address_ref, ctypes.POINTER(mac.mach_vm_address_t))
        size = ctypes.cast(size_ref, ctypes.POINTER(mac.mach_vm_size_t))
        cursor = address.contents.value
        cursors.append(cursor)
        assert len(cursors) < 100, "the walk restarted or never ended"
        for start, length in regions:
            if start + max(length, 1) > cursor:
                address.contents.value = max(start, cursor)
                size.contents.value = length
                return KERN_SUCCESS
        return KERN_INVALID_ADDRESS

    fake.cursors = cursors
    return fake


def test_a_region_reaching_the_top_of_the_address_space_ends_the_walk(monkeypatch):
    # address + size == 2**64 wrapped the c_uint64 cursor back to 0, and the
    # walk restarted from the bottom, listing every region again forever.
    top = 2**64 - 0x4000
    fake = _fake_layout([(0x1000, 0x1000), (top, 0x4000)])
    monkeypatch.setattr(mac.libsystem, "mach_vm_region", fake)
    monkeypatch.setattr(mac, "_region_is_shared", lambda *a: False)

    regions = list(mac.get_memory_regions(_FAKE_TASK))

    assert [(r.address, r.size) for r in regions] == [(0x1000, 0x1000), (top, 0x4000)]
    assert fake.cursors == [0, 0x2000]


def test_an_empty_region_is_stepped_over_instead_of_ending_the_walk(monkeypatch):
    # A zero-size answer used to stop the walk, dropping every region above.
    fake = _fake_layout([(0x1000, 0), (0x10000, 0x1000)])
    monkeypatch.setattr(mac.libsystem, "mach_vm_region", fake)
    monkeypatch.setattr(mac, "_region_is_shared", lambda *a: False)

    regions = list(mac.get_memory_regions(_FAKE_TASK))

    assert (0x10000, 0x1000) in [(r.address, r.size) for r in regions]


def test_endless_empty_regions_are_capped(monkeypatch):
    calls = []

    def fake(task, address_ref, size_ref, flavor, info, count_ref, name_ref):
        calls.append(1)
        size = ctypes.cast(size_ref, ctypes.POINTER(mac.mach_vm_size_t))
        size.contents.value = 0
        return KERN_SUCCESS

    monkeypatch.setattr(mac.libsystem, "mach_vm_region", fake)
    monkeypatch.setattr(mac, "_region_is_shared", lambda *a: False)

    list(mac.get_memory_regions(_FAKE_TASK))

    assert len(calls) == mac._REGION_MAX_CONSECUTIVE_FAILURES + 1


def test_a_failed_user_tag_lookup_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(mac.libsystem, "mach_vm_region", _fake_region([KERN_FAILURE]))

    with caplog.at_level("DEBUG", logger="PyMemoryEditor"):
        assert mac._region_user_tag(_FAKE_TASK, 0x1000) == 0

    assert "assuming no user tag" in caplog.text
