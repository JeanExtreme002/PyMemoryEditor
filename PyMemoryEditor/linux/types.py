# -*- coding: utf-8 -*-
from ctypes import Structure, c_size_t, c_void_p


class iovec(Structure):
    """
    Describes a region of memory, beginning at iov_base address and
    with the size of iov_len bytes.  System calls use arrays of this
    structure, where each element of the array represents a memory
    region, and the whole array represents a vector of memory
    regions. The maximum number of iovec structures in that array is
    limited by IOV_MAX (defined in <limits.h>, or accessible via the
    call sysconf(_SC_IOV_MAX)).

    Reference: https://man7.org/linux/man-pages/man3/iovec.3type.html
    """
    _fields_ = [
        ("iov_base", c_void_p),
        ("iov_len", c_size_t)
    ]
