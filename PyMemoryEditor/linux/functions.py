# -*- coding: utf-8 -*-

# Read more about process_vm_(read/write)v here:
# https://man7.org/linux/man-pages/man2/process_vm_readv.2.html

# Read more about proc and memory mapping here:
# https://man7.org/linux/man-pages/man5/proc.5.html

from ctypes import addressof, sizeof
from typing import Generator, Type, TypeVar, Union

from ..util import get_c_type_of
from .ptrace import libc
from .types import MEMORY_BASIC_INFORMATION, iovec


T = TypeVar("T")


def get_memory_regions(pid: int) -> Generator[dict, None, None]:
    """
    Generates dictionaries with the address and size of a region used by the process.
    """
    mapping_filename = "/proc/{}/maps".format(pid)

    with open(mapping_filename, "r") as mapping_file:
        for line in mapping_file:

            # Each line keeps information about a memory region of the process.
            addressing_range, privileges, offset, device, inode, path = line.split()[0: 6]

            # Convert hexadecimal values to decimal.
            start_address, end_address = [int(addr, 16) for addr in addressing_range.split("-")]
            major_id, minor_id = [int(_id, 16) for _id in device.split("-")]

            offset = int(offset, 16)
            inode = int(inode, 16)

            # Calculate the region size.
            size = end_address - start_address

            region = MEMORY_BASIC_INFORMATION(start_address, size, privileges, offset, major_id, minor_id, inode, path)
            yield {"address": start_address, "size": region.RegionSize, "struct": region}


def read_process_memory(
    pid: int,
    address: int,
    pytype: Type[T],
    bufflength: int
) -> T:
    """
    Return a value from a memory address.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    data = get_c_type_of(pytype, bufflength)

    libc.process_vm_readv(
        pid, (iovec * 1)(iovec(addressof(data), sizeof(data))),
        1, (iovec * 1)(iovec(address, sizeof(data))), 1, 0
    )
    return str(data.value) if pytype is str else data.value


def write_process_memory(
    pid: int,
    address: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes]
) -> T:
    """
    Write a value to a memory address.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    data = get_c_type_of(pytype, bufflength)
    data.value = value.encode() if isinstance(value, str) else value

    libc.process_vm_writev(
        pid, (iovec * 1)(iovec(addressof(data), sizeof(data))),
        1, (iovec * 1)(iovec(address, sizeof(data))), 1, 0
    )
    return value
