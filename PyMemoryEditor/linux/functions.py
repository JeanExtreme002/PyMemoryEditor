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
from ..process.region import enrich_region
from ..process.scanning import iter_search_results, iter_values_for_addresses
from ..util import (
    _validate_pytype,
    get_c_type_of,
    values_to_bytes,
)
from .libc import libc
from .types import MEMORY_BASIC_INFORMATION, PATH_SIZE, PRIVILEGES_SIZE, iovec


T = TypeVar("T")


# Errors that mean "the page is no longer mapped" — safe to skip during scans.
# Other errors (EACCES, EPERM, ESRCH, EINVAL) reveal a real problem and are
# propagated so callers can act on them.
_PAGE_GONE_ERRNOS = frozenset((errno_mod.EFAULT, errno_mod.ENOMEM))


class _LinuxPartialIOError(OSError):
    """
    process_vm_readv / process_vm_writev returned fewer bytes than requested.

    In practice this happens when the target range straddles a freed or
    inaccessible page — the kernel transfers what it can and reports the
    short count. The previous behavior was to silently accept the short
    result, leaving the caller's buffer half-filled with real bytes and
    half with zeros (which downstream decoding would treat as valid).
    Mirrors the partial-read/write check the Win32 backend already does
    against ``ReadProcessMemory`` / ``WriteProcessMemory``.
    """

    def __init__(self, op: str, address: int, bytes_done: int, length: int):
        super().__init__(
            "%s partial transfer at 0x%X: %d of %d bytes."
            % (op, address, bytes_done, length)
        )
        self.address = address
        self.bytes_done = bytes_done
        self.length = length


def _process_vm_readv(
    pid: int, local_address: int, remote_address: int, length: int
) -> int:
    """
    Wrapper for process_vm_readv that raises OSError on failure.
    Returns the number of bytes read.

    Raises ``_LinuxPartialIOError`` when the kernel reports a short read
    (``result < length``) so callers don't decode a buffer that is part
    real-bytes, part zero-initialized. Scan loops classify this as a
    transient failure (same shape as a vanished page).
    """
    local = (iovec * 1)(iovec(local_address, length))
    remote = (iovec * 1)(iovec(remote_address, length))
    result = libc.process_vm_readv(pid, local, 1, remote, 1, 0)

    if result == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    if result != length:
        raise _LinuxPartialIOError(
            "process_vm_readv", remote_address, result, length
        )

    return result


def _process_vm_writev(
    pid: int, local_address: int, remote_address: int, length: int
) -> int:
    """
    Wrapper for process_vm_writev that raises OSError on failure.
    Returns the number of bytes written.

    Raises ``_LinuxPartialIOError`` on a short write so the caller learns
    that the value did not fully land. The Win32 backend already enforces
    this for ``WriteProcessMemory``.
    """
    local = (iovec * 1)(iovec(local_address, length))
    remote = (iovec * 1)(iovec(remote_address, length))
    result = libc.process_vm_writev(pid, local, 1, remote, 1, 0)

    if result == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    if result != length:
        raise _LinuxPartialIOError(
            "process_vm_writev", remote_address, result, length
        )

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

            # Truncate to fit the fixed-size inline byte arrays in the struct.
            # Leave room for a null so attribute reads always terminate cleanly.
            privileges_bytes = privileges.encode()[: PRIVILEGES_SIZE - 1]
            path_bytes = path.encode()[: PATH_SIZE - 1]

            region = MEMORY_BASIC_INFORMATION(
                start_address,
                size,
                privileges_bytes,
                offset,
                major_id,
                minor_id,
                inode,
                path_bytes,
            )
            yield enrich_region(
                {
                    "address": start_address,
                    "size": region.RegionSize,
                    "struct": region,
                }
            )


def read_process_memory(pid: int, address: int, pytype: Type[T], bufflength: int) -> T:
    """
    Return a value from a memory address.
    """
    _validate_pytype(pytype)

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
    _validate_pytype(pytype)

    target_value_bytes = values_to_bytes(pytype, bufflength, value)

    source_regions = (
        memory_regions if memory_regions is not None else get_memory_regions(pid)
    )

    def is_scannable(region) -> bool:
        privileges = region["struct"].Privileges
        if b"r" not in privileges:
            return False
        if writeable_only and b"w" not in privileges:
            return False
        # Skip shared mappings — they typically hold libc and other code that
        # the caller is not interested in, and scanning them adds noise and
        # CPU cost. Mirrors the Win32 backend filtering on MEM_PRIVATE.
        if b"s" in privileges:
            return False
        return True

    filtered_regions = [region for region in source_regions if is_scannable(region)]
    filtered_regions.sort(key=lambda region: region["address"])

    def read_chunk(address: int, size: int):
        buffer = (ctypes.c_byte * size)()
        _process_vm_readv(pid, addressof(buffer), address, sizeof(buffer))
        return buffer

    def is_transient(exc: BaseException) -> bool:
        # A short read mid-scan is equivalent to a page disappearing — the
        # scan should skip the chunk and keep going. Real permission /
        # configuration errors (EACCES, EPERM, ESRCH, EINVAL) propagate.
        if isinstance(exc, _LinuxPartialIOError):
            return True
        return isinstance(exc, OSError) and exc.errno in _PAGE_GONE_ERRNOS

    yield from iter_search_results(
        filtered_regions,
        pytype,
        bufflength,
        target_value_bytes,
        scan_type,
        read_chunk,
        progress_information=progress_information,
        transient_error_check=is_transient,
    )


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
    Addresses that fall in gaps between regions or extend past a region's end
    yield `(address, None)`.
    """
    _validate_pytype(pytype)

    # `None` means "no snapshot provided, enumerate now". An empty list passed
    # explicitly is honored verbatim — scanning nothing is a valid choice when
    # the caller pre-filtered to zero regions.
    if memory_regions is None:
        memory_regions = [
            region for region in get_memory_regions(pid) if region["is_readable"]
        ]
    else:
        memory_regions = list(memory_regions)

    def read_chunk(address: int, size: int):
        buffer = (ctypes.c_byte * size)()
        _process_vm_readv(pid, addressof(buffer), address, sizeof(buffer))
        return buffer

    def is_transient(exc: BaseException) -> bool:
        # A short read mid-scan is equivalent to a page disappearing — the
        # scan should skip the chunk and keep going. Real permission /
        # configuration errors (EACCES, EPERM, ESRCH, EINVAL) propagate.
        if isinstance(exc, _LinuxPartialIOError):
            return True
        return isinstance(exc, OSError) and exc.errno in _PAGE_GONE_ERRNOS

    yield from iter_values_for_addresses(
        addresses,
        memory_regions,
        pytype,
        bufflength,
        read_chunk,
        raise_error=raise_error,
        transient_error_check=is_transient,
    )


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
    _validate_pytype(pytype)

    data = get_c_type_of(pytype, bufflength)
    data.value = value.encode() if isinstance(value, str) else value

    _process_vm_writev(pid, addressof(data), address, sizeof(data))
    return value
