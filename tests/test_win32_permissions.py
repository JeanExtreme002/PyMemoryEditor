# -*- coding: utf-8 -*-

"""
Windows-only tests for the permission gate logic in WindowsProcess.

Regression: PROCESS_ALL_ACCESS is a union of bits (0x1f0fff). The previous
check `perm & _READ_FLAGS != 0` accepted any single bit from that union as
sufficient — e.g. PROCESS_TERMINATE (0x0001) passed the read check despite
not conveying read permission.
"""

import sys

import pytest


if sys.platform != "win32":
    pytest.skip("Windows-only module", allow_module_level=True)


from PyMemoryEditor.win32.process import _can_read, _can_write  # noqa: E402
from PyMemoryEditor.win32.enums.process_operations import (
    ProcessOperationsEnum,
)  # noqa: E402


def test_explicit_vm_read_grants_read():
    assert _can_read(ProcessOperationsEnum.PROCESS_VM_READ.value)


def test_terminate_alone_does_not_grant_read():
    # Regression: any bit from PROCESS_ALL_ACCESS used to count as read.
    assert not _can_read(ProcessOperationsEnum.PROCESS_TERMINATE.value)


def test_suspend_resume_alone_does_not_grant_read():
    assert not _can_read(ProcessOperationsEnum.PROCESS_SUSPEND_RESUME.value)


def test_query_information_alone_does_not_grant_read():
    # PROCESS_QUERY_INFORMATION is required by VirtualQueryEx (region
    # enumeration) but must NOT by itself authorize ReadProcessMemory — the
    # gate has to keep them independent so the default read-only permission
    # bundle (VM_READ | QUERY_INFORMATION) remains the minimum.
    assert not _can_read(ProcessOperationsEnum.PROCESS_QUERY_INFORMATION.value)


def test_query_limited_information_alone_does_not_grant_read():
    assert not _can_read(
        ProcessOperationsEnum.PROCESS_QUERY_LIMITED_INFORMATION.value
    )


def test_terminate_and_suspend_resume_have_distinct_values():
    # Regression: PROCESS_TERMINATE used to be defined as 0x0800, which is the
    # same value as PROCESS_SUSPEND_RESUME — making it a silent alias under
    # Python's Enum semantics. Per MSDN, PROCESS_TERMINATE = 0x0001.
    assert ProcessOperationsEnum.PROCESS_TERMINATE.value == 0x0001
    assert ProcessOperationsEnum.PROCESS_SUSPEND_RESUME.value == 0x0800
    assert (
        ProcessOperationsEnum.PROCESS_TERMINATE
        is not ProcessOperationsEnum.PROCESS_SUSPEND_RESUME
    )


def test_all_access_grants_both_read_and_write():
    perm = ProcessOperationsEnum.PROCESS_ALL_ACCESS.value
    assert _can_read(perm)
    assert _can_write(perm)


def test_write_requires_both_write_and_operation():
    only_write = ProcessOperationsEnum.PROCESS_VM_WRITE.value
    assert not _can_write(only_write)

    only_op = ProcessOperationsEnum.PROCESS_VM_OPERATION.value
    assert not _can_write(only_op)

    combo = only_write | only_op
    assert _can_write(combo)


def test_partial_all_access_does_not_grant_write():
    # A bit included in PROCESS_ALL_ACCESS but not the write bits.
    perm = ProcessOperationsEnum.PROCESS_DUP_HANDLE.value
    assert not _can_write(perm)


def test_read_plus_write_combo():
    perm = (
        ProcessOperationsEnum.PROCESS_VM_READ.value
        | ProcessOperationsEnum.PROCESS_VM_WRITE.value
        | ProcessOperationsEnum.PROCESS_VM_OPERATION.value
    )
    assert _can_read(perm)
    assert _can_write(perm)


def test_process_all_access_uses_modern_value():
    """PROCESS_ALL_ACCESS bumped from the pre-Vista 0x1F0FFF to 0x1FFFFF.
    """
    assert ProcessOperationsEnum.PROCESS_ALL_ACCESS.value == 0x1FFFFF


def test_intflag_bitwise_composition_without_value_unwrap():
    """Regression: ProcessOperationsEnum is an IntFlag, so callers can compose
    members with ``|`` directly without reaching for ``.value`` everywhere."""
    perm = (
        ProcessOperationsEnum.PROCESS_VM_READ
        | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION
    )
    # The composed value should equal the int sum of the bits.
    assert int(perm) == 0x0010 | 0x0400
