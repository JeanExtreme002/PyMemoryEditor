# -*- coding: utf-8 -*-

# Read more about process_vm_(read/write)v here:
# https://man7.org/linux/man-pages/man2/process_vm_readv.2.html

# Read more about proc and memory mapping here:
# https://man7.org/linux/man-pages/man5/proc.5.html

from ctypes import addressof, sizeof
from typing import Generator, Optional, Tuple, Type, TypeVar, Union

from ..enums import ScanTypesEnum
from ..util import get_c_type_of
from .ptrace import libc
from .types import MEMORY_BASIC_INFORMATION, iovec

import ctypes
import sys


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
            major_id, minor_id = [int(_id, 16) for _id in device.split(":")]

            offset = int(offset, 16)
            inode = int(inode, 16)

            # Calculate the region size.
            size = end_address - start_address

            region = MEMORY_BASIC_INFORMATION(start_address, size, privileges.encode(), offset, major_id, minor_id, inode, path.encode())
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


def search_all_memory(
    pid: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes],
    scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
    progress_information: Optional[bool] = False,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    Search the whole memory space, accessible to the process,
    for the provided value, returning the found addresses.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    # Get the target value as bytes.
    target_value = get_c_type_of(pytype, bufflength)
    target_value.value = value

    target_value_bytes = ctypes.cast(ctypes.byref(target_value), ctypes.POINTER(ctypes.c_byte * bufflength))
    target_value_bytes = int.from_bytes(bytes(target_value_bytes.contents), sys.byteorder)

    regions = list()
    memory_total = 0

    # Get the memory regions, computing the space size.
    for region in get_memory_regions(pid):

        # Only committed, non-shared and readable memory pages.
        if not b"r" in region["struct"].Privileges: continue

        memory_total += region["size"]
        regions.append(region)

    checked_memory_size = 0

    # Check each memory region used by the process.
    for region in regions:
        address, size = region["address"], region["size"]
        region_data = (ctypes.c_byte * size)()

        # Get data from the region.
        libc.process_vm_readv(
            pid, (iovec * 1)(iovec(addressof(region_data), sizeof(region_data))),
            1, (iovec * 1)(iovec(address, sizeof(region_data))), 1, 0
        )

        # Walk by the returned bytes, searching for the target value.
        for index in range(size - bufflength):
            data = region_data[index: index + bufflength]
            data = int.from_bytes(bytes((ctypes.c_byte * bufflength)(*data)), sys.byteorder)

            # Compare the values.
            if scan_type is ScanTypesEnum.EXACT_VALUE and data != target_value_bytes: continue
            elif scan_type is ScanTypesEnum.NOT_EXACT_VALUE and data == target_value_bytes: continue
            elif scan_type is ScanTypesEnum.BIGGER_THAN and data <= target_value_bytes: continue
            elif scan_type is ScanTypesEnum.SMALLER_THAN and data >= target_value_bytes: continue
            elif scan_type is ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE and data < target_value_bytes: continue
            elif scan_type is ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE and data > target_value_bytes: continue

            found_address = address + index

            extra_information = {
                "memory_total": memory_total,
                "progress": (checked_memory_size + index) / memory_total,
            }
            yield (found_address, extra_information) if progress_information else found_address

        # Compute the region size to the checked memory size.
        checked_memory_size += size


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
