# -*- coding: utf-8 -*-

"""
libSystem bindings for the Mach VM APIs.

References:
- task_for_pid:           <mach/mach_init.h>
- mach_vm_read_overwrite: <mach/mach_vm.h>
- mach_vm_write:          <mach/mach_vm.h>
- mach_vm_region:         <mach/mach_vm.h>
- mach_port_deallocate:   <mach/mach_port.h>
- mach_error_string:      <mach/mach_error.h>
"""

import ctypes
from ctypes import POINTER
from ctypes.util import find_library

from .types import (
    kern_return_t,
    mach_msg_type_number_t,
    mach_port_t,
    mach_vm_address_t,
    mach_vm_size_t,
    task_t,
    vm_map_t,
    vm_region_basic_info_64,
)


libsystem = ctypes.CDLL(find_library("System"), use_errno=True)

# mach_task_self_ is a global variable (not a function). It holds the port
# representing the calling task. Reading it bypasses task_for_pid entirely for
# the self-process case — useful since task_for_pid on other processes requires
# the com.apple.security.cs.debugger entitlement on modern macOS.
mach_task_self_ = ctypes.c_uint.in_dll(libsystem, "mach_task_self_")


# kern_return_t task_for_pid(task_t target_tport, int pid, task_t *task);
libsystem.task_for_pid.argtypes = (mach_port_t, ctypes.c_int, POINTER(mach_port_t))
libsystem.task_for_pid.restype = kern_return_t

# kern_return_t mach_vm_read_overwrite(
#     vm_map_read_t       target_task,
#     mach_vm_address_t   address,
#     mach_vm_size_t      size,
#     mach_vm_address_t   data,        /* local buffer address */
#     mach_vm_size_t     *outsize);
libsystem.mach_vm_read_overwrite.argtypes = (
    task_t, mach_vm_address_t, mach_vm_size_t,
    mach_vm_address_t, POINTER(mach_vm_size_t),
)
libsystem.mach_vm_read_overwrite.restype = kern_return_t

# kern_return_t mach_vm_write(
#     vm_map_t                target_task,
#     mach_vm_address_t       address,
#     pointer_t               data,
#     mach_msg_type_number_t  data_count);
libsystem.mach_vm_write.argtypes = (
    vm_map_t, mach_vm_address_t,
    mach_vm_address_t, mach_msg_type_number_t,
)
libsystem.mach_vm_write.restype = kern_return_t

# kern_return_t mach_vm_region(
#     vm_map_t                target_task,
#     mach_vm_address_t      *address,
#     mach_vm_size_t         *size,
#     vm_region_flavor_t      flavor,
#     vm_region_info_t        info,
#     mach_msg_type_number_t *info_count,
#     mach_port_t            *object_name);
libsystem.mach_vm_region.argtypes = (
    vm_map_t, POINTER(mach_vm_address_t), POINTER(mach_vm_size_t),
    ctypes.c_int, POINTER(vm_region_basic_info_64),
    POINTER(mach_msg_type_number_t), POINTER(mach_port_t),
)
libsystem.mach_vm_region.restype = kern_return_t

# kern_return_t mach_vm_protect(
#     vm_map_t            target_task,
#     mach_vm_address_t   address,
#     mach_vm_size_t      size,
#     boolean_t           set_maximum,
#     vm_prot_t           new_protection);
libsystem.mach_vm_protect.argtypes = (
    vm_map_t, mach_vm_address_t, mach_vm_size_t,
    ctypes.c_int, ctypes.c_int,
)
libsystem.mach_vm_protect.restype = kern_return_t

# kern_return_t mach_port_deallocate(ipc_space_t task, mach_port_name_t name);
libsystem.mach_port_deallocate.argtypes = (mach_port_t, mach_port_t)
libsystem.mach_port_deallocate.restype = kern_return_t

# char *mach_error_string(mach_error_t error_value);
libsystem.mach_error_string.argtypes = (ctypes.c_int,)
libsystem.mach_error_string.restype = ctypes.c_char_p


def mach_error_message(kr: int) -> str:
    """Return a human-readable description of a kern_return_t."""
    msg = libsystem.mach_error_string(kr)
    return msg.decode("utf-8", errors="replace") if msg else "unknown Mach error"
