# -*- coding: utf-8 -*-

"""
libc binding shared by Linux process operations.
"""

import ctypes
from ctypes.util import find_library


libc = ctypes.CDLL(find_library("c"), use_errno=True)

# process_vm_readv signature:
#   ssize_t process_vm_readv(pid_t pid,
#                            const struct iovec *local_iov, unsigned long liovcnt,
#                            const struct iovec *remote_iov, unsigned long riovcnt,
#                            unsigned long flags);
libc.process_vm_readv.restype = ctypes.c_ssize_t
libc.process_vm_writev.restype = ctypes.c_ssize_t
