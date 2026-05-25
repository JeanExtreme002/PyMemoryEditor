# -*- coding: utf-8 -*-

"""
Linux-only tests for MEMORY_BASIC_INFORMATION 64-bit field widths.

Regression: previously address/size/offset/inode were c_uint (32-bit), causing
silent truncation for mappings beyond 4 GB or with high inode numbers on
modern filesystems.
"""

import sys

import pytest


if not sys.platform.startswith("linux"):
    pytest.skip("Linux-only module", allow_module_level=True)


from PyMemoryEditor.linux.types import MEMORY_BASIC_INFORMATION  # noqa: E402


def test_struct_holds_64bit_address():
    high_address = 0x7FFF_FFFF_FFFF  # 48-bit, typical x86_64 user-space high
    region = MEMORY_BASIC_INFORMATION(high_address, 0x1000, b"r--p", 0, 0, 0, 0, b"")
    assert region.BaseAddress == high_address


def test_struct_holds_region_larger_than_4gb():
    huge_size = 5 * 1024**3  # 5 GB
    region = MEMORY_BASIC_INFORMATION(0, huge_size, b"r--p", 0, 0, 0, 0, b"")
    assert region.RegionSize == huge_size


def test_struct_holds_large_inode():
    big_inode = 2**40
    region = MEMORY_BASIC_INFORMATION(0, 0x1000, b"r--p", 0, 0, 0, big_inode, b"")
    assert region.InodeID == big_inode


def test_struct_holds_offset_above_4gb():
    big_offset = 8 * 1024**3  # 8 GB offset (large mmap'd file)
    region = MEMORY_BASIC_INFORMATION(0, 0x1000, b"r--p", big_offset, 0, 0, 0, b"")
    assert region.Offset == big_offset


def test_struct_owns_privileges_and_path_after_gc():
    """
    Regression: Privileges/Path used to be `c_char_p` pointers — once the
    originating Python bytes were freed the pointer dangled and accessing the
    fields was undefined behavior. With inline `c_char * N` arrays the struct
    owns the storage and survives GC of the constructor arguments.
    """
    import gc

    privileges_source = "rwxp".encode()
    path_source = ("/usr/lib/libfoo.so").encode()

    region = MEMORY_BASIC_INFORMATION(
        0x1000, 0x2000, privileges_source, 0, 0, 0, 0, path_source
    )

    # Drop the originating bytes objects and force collection — if the struct
    # held them by pointer, the next read would be UB.
    del privileges_source
    del path_source
    gc.collect()

    assert region.Privileges == b"rwxp"
    assert region.Path == b"/usr/lib/libfoo.so"
