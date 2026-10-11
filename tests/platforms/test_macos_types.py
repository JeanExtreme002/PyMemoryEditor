# -*- coding: utf-8 -*-

"""
macOS-only test: the ctypes mirrors of the Mach info structs must match the C
layout byte for byte.

<mach/vm_region.h> and <mach/task_info.h> wrap their structs in
``#pragma pack(push, 4)``. Without ``_pack_ = 4`` ctypes aligns the 8-byte
fields to 8, so ``vm_region_basic_info_64`` came out 40 bytes instead of 36
(``offset`` / ``behavior`` / ``user_wired_count`` at the wrong offsets) and the
derived ``*_COUNT`` constants over-stated the buffer by one natural_t. The
expected numbers below are what clang reports for the SDK headers.
"""

import ctypes
import sys

import pytest


if sys.platform != "darwin":
    pytest.skip("macOS-only module", allow_module_level=True)


from PyMemoryEditor.macos.types import (  # noqa: E402
    TASK_DYLD_INFO_COUNT,
    VM_REGION_BASIC_INFO_COUNT_64,
    VM_REGION_EXTENDED_INFO_COUNT,
    task_dyld_info_data_t,
    vm_region_basic_info_64,
    vm_region_extended_info,
)


def test_vm_region_basic_info_64_matches_the_packed_c_layout():
    assert ctypes.sizeof(vm_region_basic_info_64) == 36
    assert vm_region_basic_info_64.offset.offset == 20
    assert vm_region_basic_info_64.behavior.offset == 28
    assert vm_region_basic_info_64.user_wired_count.offset == 32
    # The kernel's VM_REGION_BASIC_INFO_COUNT_64.
    assert VM_REGION_BASIC_INFO_COUNT_64 == 9


def test_vm_region_extended_info_matches_the_c_layout():
    assert ctypes.sizeof(vm_region_extended_info) == 36
    assert vm_region_extended_info.user_tag.offset == 4
    assert vm_region_extended_info.pages_reusable.offset == 32
    assert VM_REGION_EXTENDED_INFO_COUNT == 9


def test_task_dyld_info_matches_the_packed_c_layout():
    assert ctypes.sizeof(task_dyld_info_data_t) == 20
    assert task_dyld_info_data_t.all_image_info_format.offset == 16
    assert TASK_DYLD_INFO_COUNT == 5


def test_the_kernel_fills_the_packed_basic_info_for_a_known_region():
    """
    End-to-end: query a region we allocated ourselves and check the fields
    that sit after the 8-byte ``offset`` decode sensibly (an anonymous,
    unwired allocation has ``user_wired_count == 0`` and a small ``behavior``).
    """
    from PyMemoryEditor.macos import functions as mac
    from PyMemoryEditor.macos.libsystem import libsystem, mach_task_self_
    from PyMemoryEditor.macos.types import (
        VM_REGION_BASIC_INFO_64,
        mach_msg_type_number_t,
        mach_port_t,
        mach_vm_address_t,
        mach_vm_size_t,
    )

    task = mach_task_self_.value
    address = mac.allocate_memory(task, mac._PAGE_SIZE)
    try:
        addr = mach_vm_address_t(address)
        size = mach_vm_size_t(0)
        info = vm_region_basic_info_64()
        count = mach_msg_type_number_t(VM_REGION_BASIC_INFO_COUNT_64)
        name = mach_port_t(0)
        kr = libsystem.mach_vm_region(
            task,
            ctypes.byref(addr),
            ctypes.byref(size),
            VM_REGION_BASIC_INFO_64,
            ctypes.cast(ctypes.byref(info), ctypes.c_void_p),
            ctypes.byref(count),
            ctypes.byref(name),
        )
        assert kr == 0
        assert count.value == VM_REGION_BASIC_INFO_COUNT_64
        assert addr.value == address
        assert info.protection == 3  # READ | WRITE
        assert info.user_wired_count == 0
        assert 0 <= info.behavior < 16
    finally:
        mac.free_memory(task, address, mac._PAGE_SIZE)
