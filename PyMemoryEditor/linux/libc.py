# -*- coding: utf-8 -*-

"""
libc binding shared by Linux process operations.
"""

import ctypes
from ctypes.util import find_library

from .types import iovec


libc = ctypes.CDLL(find_library("c"), use_errno=True)

# process_vm_readv signature:
#   ssize_t process_vm_readv(pid_t pid,
#                            const struct iovec *local_iov, unsigned long liovcnt,
#                            const struct iovec *remote_iov, unsigned long riovcnt,
#                            unsigned long flags);
#
# Configuring `argtypes` is not cosmetic: without it, ctypes passes Python ints
# through the platform's default C-int width. On a 32-bit Linux build (or any
# host where the default int is narrower than the iovec pointer's representation)
# the address gets silently truncated before the kernel sees it — the same class
# of bug that motivated the v2 audit of the Win32 backend, where every API now
# declares argtypes/restype explicitly.
_PROCESS_VM_ARGTYPES = (
    ctypes.c_int,              # pid_t
    ctypes.POINTER(iovec),     # local_iov
    ctypes.c_ulong,            # liovcnt
    ctypes.POINTER(iovec),     # remote_iov
    ctypes.c_ulong,            # riovcnt
    ctypes.c_ulong,            # flags
)
libc.process_vm_readv.argtypes = _PROCESS_VM_ARGTYPES
libc.process_vm_readv.restype = ctypes.c_ssize_t
libc.process_vm_writev.argtypes = _PROCESS_VM_ARGTYPES
libc.process_vm_writev.restype = ctypes.c_ssize_t
