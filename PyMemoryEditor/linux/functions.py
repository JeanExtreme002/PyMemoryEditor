# -*- coding: utf-8 -*-

# Read more about process_vm_(read/write)v here:
# https://man7.org/linux/man-pages/man2/process_vm_readv.2.html

# Read more about proc and memory mapping here:
# https://man7.org/linux/man-pages/man5/proc.5.html

import ctypes
import errno as errno_mod
import os
from ctypes import addressof, sizeof
from typing import Dict, Generator, Optional, Sequence, Tuple, Type, TypeVar, Union

from ..enums import ScanTypesEnum
from ..util import (
    convert_from_byte_array,
    get_c_type_of,
    iter_region_chunks,
    scan_memory,
    scan_memory_for_exact_value,
    values_to_bytes,
)
from .libc import libc
from .types import MEMORY_BASIC_INFORMATION, iovec


T = TypeVar("T")


# Errors that mean "the page is no longer mapped" — safe to skip during scans.
# Other errors (EACCES, EPERM, ESRCH, EINVAL) reveal a real problem and are
# propagated so callers can act on them.
_PAGE_GONE_ERRNOS = frozenset((errno_mod.EFAULT, errno_mod.ENOMEM))


def _process_vm_readv(
    pid: int, local_address: int, remote_address: int, length: int
) -> int:
    """
    Wrapper for process_vm_readv that raises OSError on failure.
    Returns the number of bytes read.
    """
    local = (iovec * 1)(iovec(local_address, length))
    remote = (iovec * 1)(iovec(remote_address, length))
    result = libc.process_vm_readv(pid, local, 1, remote, 1, 0)

    if result == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    return result


def _process_vm_writev(
    pid: int, local_address: int, remote_address: int, length: int
) -> int:
    """
    Wrapper for process_vm_writev that raises OSError on failure.
    Returns the number of bytes written.
    """
    local = (iovec * 1)(iovec(local_address, length))
    remote = (iovec * 1)(iovec(remote_address, length))
    result = libc.process_vm_writev(pid, local, 1, remote, 1, 0)

    if result == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    return result


def get_memory_regions(pid: int) -> Generator[dict, None, None]:
    """
    Generates dictionaries with the address and size of a region used by the process.
    """
    mapping_filename = "/proc/{}/maps".format(pid)

    with open(mapping_filename, "r") as mapping_file:
        for line in mapping_file:
            region_information = line.split()

            addressing_range, privileges, offset, device, inode = region_information[
                0:5
            ]
            path = region_information[5] if len(region_information) >= 6 else ""

            start_address, end_address = [
                int(addr, 16) for addr in addressing_range.split("-")
            ]
            major_id, minor_id = [int(_id, 16) for _id in device.split(":")]

            offset = int(offset, 16)
            inode = int(inode)  # /proc/<pid>/maps formats the inode as decimal.

            size = end_address - start_address

            region = MEMORY_BASIC_INFORMATION(
                start_address,
                size,
                privileges.encode(),
                offset,
                major_id,
                minor_id,
                inode,
                path.encode(),
            )
            yield {
                "address": start_address,
                "size": region.RegionSize,
                "struct": region,
            }


def read_process_memory(pid: int, address: int, pytype: Type[T], bufflength: int) -> T:
    """
    Return a value from a memory address.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    data = get_c_type_of(pytype, bufflength)
    _process_vm_readv(pid, addressof(data), address, sizeof(data))

    if pytype is str:
        return bytes(data).decode("utf-8", errors="replace")
    elif pytype is bytes:
        return bytes(data)
    else:
        return data.value


def search_addresses_by_value(
    pid: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes, tuple],
    scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
    progress_information: bool = False,
    writeable_only: bool = False,
    *,
    memory_regions: Optional[Sequence[Dict]] = None,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    Search the whole memory space, accessible to the process,
    for the provided value, returning the found addresses.

    Passing a `memory_regions` snapshot skips region enumeration.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    target_value_bytes = values_to_bytes(pytype, bufflength, value)

    checked_memory_size = 0
    memory_total = 0
    filtered_regions = []

    source_regions = (
        memory_regions if memory_regions is not None else get_memory_regions(pid)
    )
    for region in source_regions:
        privileges = region["struct"].Privileges
        if b"r" not in privileges:
            continue
        if writeable_only and b"w" not in privileges:
            continue
        # Skip shared mappings — they typically hold libc and other code that
        # the caller is not interested in, and scanning them adds noise and
        # CPU cost. Mirrors the Win32 backend filtering on MEM_PRIVATE.
        if b"s" in privileges:
            continue

        memory_total += region["size"]
        filtered_regions.append(region)

    memory_regions = filtered_regions
    memory_regions.sort(key=lambda region: region["address"])

    if memory_total == 0:
        return

    searching_method = scan_memory
    if scan_type in [ScanTypesEnum.EXACT_VALUE, ScanTypesEnum.NOT_EXACT_VALUE]:
        searching_method = scan_memory_for_exact_value

    for region in memory_regions:
        address, size = region["address"], region["size"]

        for chunk_offset, chunk_size in iter_region_chunks(size, bufflength):
            chunk_address = address + chunk_offset
            chunk_data = (ctypes.c_byte * chunk_size)()

            try:
                _process_vm_readv(
                    pid, addressof(chunk_data), chunk_address, sizeof(chunk_data)
                )
            except OSError as read_error:
                if read_error.errno in _PAGE_GONE_ERRNOS:
                    continue
                raise

            for offset in searching_method(
                chunk_data,
                chunk_size,
                target_value_bytes,
                bufflength,
                scan_type,
                pytype is str,
            ):
                found_address = chunk_address + offset

                if progress_information:
                    yield (
                        found_address,
                        {
                            "memory_total": memory_total,
                            "progress": (checked_memory_size + chunk_offset + offset)
                            / memory_total,
                        },
                    )
                else:
                    yield found_address

        checked_memory_size += size


def search_values_by_addresses(
    pid: int,
    pytype: Type[T],
    bufflength: int,
    addresses: Sequence[int],
    *,
    memory_regions: Optional[Sequence[Dict]] = None,
    raise_error: bool = False,
) -> Generator[Tuple[int, Optional[T]], None, None]:
    """
    Search the whole memory space, accessible to the process,
    for the provided list of addresses, returning their values.

    Memory is read in chunks (see iter_region_chunks) to bound the per-call
    allocation. Chunks near an address boundary read `bufflength - 1` extra
    bytes so values straddling the boundary are still decoded correctly.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    # `None` means "no snapshot provided, enumerate now". An empty list passed
    # explicitly is honored verbatim — scanning nothing is a valid choice when
    # the caller pre-filtered to zero regions.
    if memory_regions is None:
        memory_regions = []
        for region in get_memory_regions(pid):
            if b"r" not in region["struct"].Privileges:
                continue
            memory_regions.append(region)
    else:
        memory_regions = list(memory_regions)

    addresses = sorted(addresses)
    memory_regions.sort(key=lambda region: region["address"])
    address_index = 0

    for region in memory_regions:
        if address_index >= len(addresses):
            break

        base_address, size = region["address"], region["size"]
        if not (base_address <= addresses[address_index] < base_address + size):
            continue

        for chunk_offset, chunk_size in iter_region_chunks(size, bufflength):
            if address_index >= len(addresses):
                break

            chunk_address = base_address + chunk_offset
            chunk_end = chunk_address + chunk_size

            if addresses[address_index] >= chunk_end:
                continue

            extra = bufflength - 1 if chunk_offset + chunk_size < size else 0
            read_size = chunk_size + extra
            chunk_data = (ctypes.c_byte * read_size)()

            try:
                _process_vm_readv(
                    pid, addressof(chunk_data), chunk_address, sizeof(chunk_data)
                )
            except OSError as read_error:
                transient = read_error.errno in _PAGE_GONE_ERRNOS
                if not transient and raise_error:
                    raise
                while (
                    address_index < len(addresses)
                    and chunk_address <= addresses[address_index] < chunk_end
                ):
                    yield addresses[address_index], None
                    address_index += 1
                continue

            while (
                address_index < len(addresses)
                and chunk_address <= addresses[address_index] < chunk_end
            ):
                target_address = addresses[address_index]
                offset_in_chunk = target_address - chunk_address

                try:
                    data = chunk_data[offset_in_chunk : offset_in_chunk + bufflength]
                    data = (ctypes.c_byte * bufflength)(*data)
                    yield target_address, convert_from_byte_array(
                        data, pytype, bufflength
                    )

                except (ValueError, UnicodeDecodeError, OSError) as error:
                    if raise_error:
                        raise error
                    yield target_address, None

                address_index += 1


def write_process_memory(
    pid: int,
    address: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes],
) -> Union[bool, int, float, str, bytes]:
    """
    Write a value to a memory address.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    data = get_c_type_of(pytype, bufflength)
    data.value = value.encode() if isinstance(value, str) else value

    _process_vm_writev(pid, addressof(data), address, sizeof(data))
    return value
