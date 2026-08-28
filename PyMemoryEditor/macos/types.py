# -*- coding: utf-8 -*-

"""
Mach kernel types and structures used by the macOS backend.

References:
- mach/mach_types.h
- mach/vm_region.h
- mach/vm_prot.h
- mach/kern_return.h
"""

from ctypes import Structure, c_int, c_ubyte, c_uint, c_uint64, c_ushort, sizeof


# `info_count` in mach_vm_region is measured in mach_msg_type_number_t units
# (4 bytes each), so the conversion below divides struct size by this.
_NATURAL_T_SIZE = sizeof(c_uint)

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
VM_REGION_EXTENDED_INFO = 13

# user_tag (from vm_region_extended_info) of the dyld shared cache regions —
# the read-only library text/data blob the kernel maps into *every* process
# via a shared submap. On this machine it totals ~5.8 GB across three regions.
# Crucially, the basic-info `shared` flag reports FALSE for these regions, so
# without recognizing the tag a default value scan walks all ~6 GB of library
# memory — making macOS scans (and the test suite) 4-6x slower than Linux/Win32,
# which exclude the equivalent file-backed/shared mappings. See VM_MEMORY_*
# constants in <mach/vm_statistics.h>.
VM_MEMORY_SHARED_PMAP = 32

# task_info() flavor that returns dyld's image-list pointer (mach/task_info.h).
TASK_DYLD_INFO = 17

# VM protection flags
VM_PROT_NONE = 0x00
VM_PROT_READ = 0x01
VM_PROT_WRITE = 0x02
VM_PROT_EXECUTE = 0x04
VM_PROT_COPY = 0x10  # Used with mach_vm_protect on read-only/mapped pages.

# mach_vm_allocate flag: let the kernel pick the address (anywhere it fits).
VM_FLAGS_ANYWHERE = 0x0001

# Selected kern_return_t values
KERN_SUCCESS = 0
KERN_INVALID_ADDRESS = 1
KERN_PROTECTION_FAILURE = 2
KERN_INVALID_ARGUMENT = 4
KERN_FAILURE = 5
KERN_NO_ACCESS = 8
# "During a page fault, the memory object indicated that the data could not be
# returned. This failure may be temporary; future attempts to access this same
# data may succeed, as defined by the memory object." — mach/kern_return.h.
# Note the deliberate contrast with KERN_MEMORY_FAILURE (9) directly above it
# in that header, whose comment ends "This failure is permanent."
KERN_MEMORY_ERROR = 10


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


# Number of mach_msg_type_number_t units in vm_region_basic_info_64.
# Used as the in/out `info_count` parameter to mach_vm_region.
VM_REGION_BASIC_INFO_COUNT_64 = sizeof(vm_region_basic_info_64) // _NATURAL_T_SIZE


class vm_region_extended_info(Structure):
    """Layout of struct vm_region_extended_info_data_t from <mach/vm_region.h>.

    Only ``user_tag`` is consumed today (to recognize the dyld shared cache —
    see :data:`VM_MEMORY_SHARED_PMAP`); the remaining fields are declared so the
    struct size — and therefore :data:`VM_REGION_EXTENDED_INFO_COUNT` — matches
    what the kernel expects.
    """

    _fields_ = [
        ("protection", vm_prot_t),
        ("user_tag", c_uint),
        ("pages_resident", c_uint),
        ("pages_shared_now_private", c_uint),
        ("pages_swapped_out", c_uint),
        ("pages_dirtied", c_uint),
        ("ref_count", c_uint),
        ("shadow_depth", c_ushort),
        ("external_pager", c_ubyte),
        ("share_mode", c_ubyte),
        ("pages_reusable", c_uint),
    ]


# Number of mach_msg_type_number_t units in vm_region_extended_info.
VM_REGION_EXTENDED_INFO_COUNT = sizeof(vm_region_extended_info) // _NATURAL_T_SIZE


class task_dyld_info_data_t(Structure):
    """Layout of struct task_dyld_info from <mach/task_info.h>.

    ``all_image_info_addr`` is the address, *inside the target task*, of dyld's
    ``dyld_all_image_infos`` structure — the entry point for enumerating the
    Mach-O images loaded in the process.
    """

    _fields_ = [
        ("all_image_info_addr", mach_vm_address_t),
        ("all_image_info_size", mach_vm_size_t),
        ("all_image_info_format", c_int),
    ]


# task_info() reports the buffer length in natural_t (4-byte) units, like
# mach_vm_region's info_count.
TASK_DYLD_INFO_COUNT = sizeof(task_dyld_info_data_t) // _NATURAL_T_SIZE


class MEMORY_BASIC_INFORMATION(Structure):
    """
    Cross-platform-compatible view of a memory region exposed via
    ``MemoryRegion.struct`` (see ``PyMemoryEditor.MemoryRegion``). Mirrors the
    Linux/Windows structures shipped by PyMemoryEditor.
    """

    _fields_ = [
        ("BaseAddress", c_uint64),
        ("RegionSize", c_uint64),
        ("Protection", vm_prot_t),
        ("MaxProtection", vm_prot_t),
        ("Shared", boolean_t),
        ("Reserved", boolean_t),
    ]
