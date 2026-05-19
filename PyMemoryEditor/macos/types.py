# -*- coding: utf-8 -*-

"""
Mach kernel types and structures used by the macOS backend.

References:
- mach/mach_types.h
- mach/vm_region.h
- mach/vm_prot.h
- mach/kern_return.h
"""

from ctypes import Structure, c_int, c_uint, c_uint64, c_ushort, sizeof

# Basic Mach types
mach_port_t = c_uint  # 32-bit port name
task_t = mach_port_t  # Same as mach_port_t for task ports
vm_map_t = mach_port_t
kern_return_t = c_int
vm_prot_t = c_int
vm_inherit_t = c_uint
boolean_t = c_int
vm_behavior_t = c_int
mach_vm_address_t = c_uint64
mach_vm_size_t = c_uint64
mach_msg_type_number_t = c_uint
memory_object_offset_t = c_uint64

# Region info flavors
VM_REGION_BASIC_INFO_64 = 9

# VM protection flags
VM_PROT_NONE = 0x00
VM_PROT_READ = 0x01
VM_PROT_WRITE = 0x02
VM_PROT_EXECUTE = 0x04
VM_PROT_COPY = 0x10  # Used with mach_vm_protect on read-only/mapped pages.

# Selected kern_return_t values
KERN_SUCCESS = 0
KERN_INVALID_ADDRESS = 1
KERN_PROTECTION_FAILURE = 2
KERN_INVALID_ARGUMENT = 4
KERN_FAILURE = 5
KERN_NO_ACCESS = 8


class vm_region_basic_info_64(Structure):
    """Layout of struct vm_region_basic_info_64 from <mach/vm_region.h>."""

    _fields_ = [
        ("protection", vm_prot_t),
        ("max_protection", vm_prot_t),
        ("inheritance", vm_inherit_t),
        ("shared", boolean_t),
        ("reserved", boolean_t),
        ("offset", memory_object_offset_t),
        ("behavior", vm_behavior_t),
        ("user_wired_count", c_ushort),
    ]


# Number of mach_msg_type_number_t (4-byte) units in vm_region_basic_info_64.
# Used as the in/out `info_count` parameter to mach_vm_region.
VM_REGION_BASIC_INFO_COUNT_64 = sizeof(vm_region_basic_info_64) // 4


class MEMORY_BASIC_INFORMATION(Structure):
    """
    Cross-platform-compatible view of a memory region exposed via
    `process.get_memory_regions()["struct"]`. Mirrors the Linux/Windows
    structures shipped by PyMemoryEditor.
    """

    _fields_ = [
        ("BaseAddress", c_uint64),
        ("RegionSize", c_uint64),
        ("Protection", vm_prot_t),
        ("MaxProtection", vm_prot_t),
        ("Shared", boolean_t),
        ("Reserved", boolean_t),
    ]
