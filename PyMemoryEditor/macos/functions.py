# -*- coding: utf-8 -*-

"""
macOS (Mach) implementation of read/write/search primitives. Parallels
linux/functions.py and win32/functions.py.
"""

import ctypes
import logging
import os
import warnings
from typing import Dict, Generator, Optional, Sequence, Tuple, Type, TypeVar, Union

from ..enums import ScanTypesEnum
from ..process.region import enrich_region
from ..process.scanning import (
    iter_pattern_results,
    iter_search_results,
    iter_values_for_addresses,
)
from ..process.thread_info import ThreadInfo
from ..util import (
    _validate_pytype,
    get_c_type_of,
    values_to_bytes,
)
from ..util.pattern import PatternLike, compile_pattern

from .libsystem import libsystem, mach_error_message, mach_task_self_
from .types import (
    KERN_INVALID_ADDRESS,
    KERN_INVALID_ARGUMENT,
    KERN_NO_ACCESS,
    KERN_PROTECTION_FAILURE,
    KERN_SUCCESS,
    MEMORY_BASIC_INFORMATION,
    VM_PROT_COPY,
    VM_PROT_READ,
    VM_PROT_WRITE,
    VM_REGION_BASIC_INFO_64,
    VM_REGION_BASIC_INFO_COUNT_64,
    mach_msg_type_number_t,
    mach_port_t,
    mach_vm_address_t,
    mach_vm_size_t,
    vm_region_basic_info_64,
)


# kern_return_t codes that may signal a read-only / protection issue we can fix
# by elevating the protection. KERN_INVALID_ADDRESS is included because newer
# macOS returns it (instead of KERN_PROTECTION_FAILURE) when mach_vm_write
# refuses a write to a non-writable page even though the address is valid.
_WRITE_RETRY_CODES = (KERN_PROTECTION_FAILURE, KERN_INVALID_ADDRESS)


_logger = logging.getLogger("PyMemoryEditor")


T = TypeVar("T")


def get_task_for_pid(pid: int) -> int:
    """
    Return a Mach task port for the given pid.

    For the current process, returns mach_task_self_ directly (no entitlement
    needed). For other processes, calls task_for_pid(), which requires either:
      - root + the same uid as the target, on older macOS, or
      - the calling binary to be signed with the
        `com.apple.security.cs.debugger` entitlement on modern macOS.
    Without those, task_for_pid returns KERN_FAILURE (5).
    """
    if pid == os.getpid():
        return mach_task_self_.value

    task = mach_port_t(0)
    kr = libsystem.task_for_pid(mach_task_self_.value, pid, ctypes.byref(task))

    if kr != KERN_SUCCESS:
        raise PermissionError(
            "task_for_pid(%d) failed with kern_return_t=%d (%s). "
            "On macOS, opening other processes requires the Python binary "
            "to be signed with the com.apple.security.cs.debugger entitlement, "
            "or to run with SIP disabled and as root."
            % (pid, kr, mach_error_message(kr))
        )

    return task.value


def release_task(task: int) -> None:
    """Release a task port. No-op for mach_task_self_."""
    if task and task != mach_task_self_.value:
        libsystem.mach_port_deallocate(mach_task_self_.value, task)


def get_memory_regions(task: int) -> Generator[dict, None, None]:
    """
    Yield {address, size, struct} dicts describing each memory region of the task.
    Stops when mach_vm_region returns a non-success code (typical end of address space).
    """
    address = mach_vm_address_t(0)

    while True:
        size = mach_vm_size_t(0)
        info = vm_region_basic_info_64()
        info_count = mach_msg_type_number_t(VM_REGION_BASIC_INFO_COUNT_64)
        object_name = mach_port_t(0)

        kr = libsystem.mach_vm_region(
            task,
            ctypes.byref(address),
            ctypes.byref(size),
            VM_REGION_BASIC_INFO_64,
            ctypes.byref(info),
            ctypes.byref(info_count),
            ctypes.byref(object_name),
        )

        if kr != KERN_SUCCESS:
            break

        # mach_vm_region returns a port name for the backing object; release it.
        if object_name.value:
            libsystem.mach_port_deallocate(mach_task_self_.value, object_name.value)

        region_struct = MEMORY_BASIC_INFORMATION(
            address.value,
            size.value,
            info.protection,
            info.max_protection,
            info.shared,
            info.reserved,
        )

        yield enrich_region(
            {
                "address": address.value,
                "size": size.value,
                "struct": region_struct,
            }
        )

        if size.value == 0:
            break
        address.value += size.value


# kern_return_t codes that indicate a page is unmapped/unreadable but not a
# genuine permission/configuration error — safe to skip during region scans.
# KERN_NO_ACCESS / KERN_INVALID_ARGUMENT can also surface for guard pages and
# freshly-unmapped pages on modern macOS; treating them as fatal aborts a scan
# that should just skip the page.
_PAGE_GONE_KRS = (
    KERN_INVALID_ADDRESS,
    KERN_NO_ACCESS,
    KERN_INVALID_ARGUMENT,
)


class MachReadError(OSError):
    """OSError subclass that carries the underlying kern_return_t."""

    def __init__(self, kr: int, message: str):
        super().__init__(message)
        self.kr = kr


class MachPartialReadError(MachReadError):
    """
    ``mach_vm_read_overwrite`` returned KERN_SUCCESS but ``outsize`` was less
    than the requested ``size``. The kernel transferred what it could (often
    because the read straddled a freed or guarded page) and the caller's
    buffer is part real-bytes, part zero-initialized.

    The previous behavior silently accepted the short result, which let
    downstream code decode garbage as valid memory. Mirrors the Win32
    partial-read check on ``ReadProcessMemory``. Scan loops classify this
    as transient so the chunk is skipped instead of aborting.
    """

    def __init__(self, address: int, bytes_read: int, bytes_requested: int):
        super().__init__(
            KERN_INVALID_ADDRESS,
            "mach_vm_read_overwrite partial read at 0x%X: %d of %d bytes."
            % (address, bytes_read, bytes_requested),
        )
        self.address = address
        self.bytes_read = bytes_read
        self.bytes_requested = bytes_requested


def _mach_read(task: int, address: int, local_buffer_address: int, size: int) -> int:
    """Read `size` bytes from `address` into `local_buffer_address`. Raises on failure."""
    out_size = mach_vm_size_t(0)
    kr = libsystem.mach_vm_read_overwrite(
        task,
        address,
        size,
        local_buffer_address,
        ctypes.byref(out_size),
    )
    if kr != KERN_SUCCESS:
        raise MachReadError(
            kr,
            "mach_vm_read_overwrite failed: %s (kr=%d)" % (mach_error_message(kr), kr),
        )
    if out_size.value != size:
        raise MachPartialReadError(address, out_size.value, size)
    return out_size.value


def _mach_write(task: int, address: int, local_buffer_address: int, size: int) -> None:
    """
    Write `size` bytes from `local_buffer_address` to `address`.

    On read-only pages, mach_vm_write returns KERN_PROTECTION_FAILURE. This
    helper transparently elevates the page protection to RW (using VM_PROT_COPY
    so the change is private to the target task), performs the write, and
    restores the original protection. This mirrors the practical behavior of
    WriteProcessMemory on Windows.
    """
    kr = libsystem.mach_vm_write(task, address, local_buffer_address, size)
    if kr == KERN_SUCCESS:
        return

    if kr not in _WRITE_RETRY_CODES:
        raise OSError("mach_vm_write failed: %s (kr=%d)" % (mach_error_message(kr), kr))

    # Try to discover the page's original protection so we can restore it.
    region = _query_region(task, address)
    if region is None:
        # The address really is invalid — surface the original error.
        raise OSError("mach_vm_write failed: %s (kr=%d)" % (mach_error_message(kr), kr))

    original_protection = region["struct"].Protection

    new_protection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY
    protect_kr = libsystem.mach_vm_protect(task, address, size, 0, new_protection)
    if protect_kr != KERN_SUCCESS:
        raise OSError(
            "mach_vm_write failed (kr=%d) and mach_vm_protect could not elevate "
            "the protection (kr=%d, %s)."
            % (kr, protect_kr, mach_error_message(protect_kr))
        )

    try:
        kr = libsystem.mach_vm_write(task, address, local_buffer_address, size)
        if kr != KERN_SUCCESS:
            raise OSError(
                "mach_vm_write failed after protect: %s (kr=%d)"
                % (mach_error_message(kr), kr)
            )
    finally:
        # Best-effort restore. The write itself already succeeded, so raising
        # here would discard the user's intended outcome; but a silent failure
        # leaves the target page more permissive than it started, which is an
        # invisible side-effect the caller should know about.
        restore_kr = libsystem.mach_vm_protect(
            task, address, size, 0, original_protection
        )
        if restore_kr != KERN_SUCCESS:
            message = (
                "mach_vm_protect could not restore the original protection "
                "(0x%x) on the target page at 0x%x after a write-via-protect-flip; "
                "the page is left more permissive than before (kr=%d, %s)."
                % (
                    original_protection,
                    address,
                    restore_kr,
                    mach_error_message(restore_kr),
                )
            )
            _logger.warning(message)
            warnings.warn(message, ResourceWarning, stacklevel=2)


def _query_region(task: int, address: int):
    """Return the region containing `address`, or None when the query fails."""
    addr = mach_vm_address_t(address)
    size = mach_vm_size_t(0)
    info = vm_region_basic_info_64()
    info_count = mach_msg_type_number_t(VM_REGION_BASIC_INFO_COUNT_64)
    object_name = mach_port_t(0)

    kr = libsystem.mach_vm_region(
        task,
        ctypes.byref(addr),
        ctypes.byref(size),
        VM_REGION_BASIC_INFO_64,
        ctypes.byref(info),
        ctypes.byref(info_count),
        ctypes.byref(object_name),
    )

    if kr != KERN_SUCCESS:
        return None

    if object_name.value:
        libsystem.mach_port_deallocate(mach_task_self_.value, object_name.value)

    # mach_vm_region advances `addr` to the start of the containing region;
    # only return it when the caller's address actually lies inside.
    if not (addr.value <= address < addr.value + size.value):
        return None

    return {
        "address": addr.value,
        "size": size.value,
        "struct": MEMORY_BASIC_INFORMATION(
            addr.value,
            size.value,
            info.protection,
            info.max_protection,
            info.shared,
            info.reserved,
        ),
    }


def read_process_memory(
    task: int,
    address: int,
    pytype: Type[T],
    bufflength: int,
) -> T:
    """Return a value from a memory address."""
    _validate_pytype(pytype)

    data = get_c_type_of(pytype, bufflength)
    _mach_read(task, address, ctypes.addressof(data), bufflength)

    if pytype is str:
        return bytes(data).decode("utf-8", errors="replace")
    elif pytype is bytes:
        return bytes(data)
    else:
        return data.value


def write_process_memory(
    task: int,
    address: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes],
) -> Union[bool, int, float, str, bytes]:
    """Write a value to a memory address."""
    _validate_pytype(pytype)

    data = get_c_type_of(pytype, bufflength)
    data.value = value.encode() if isinstance(value, str) else value

    _mach_write(task, address, ctypes.addressof(data), bufflength)
    return value


def search_addresses_by_value(
    task: int,
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
    Walk every readable region of the task and yield addresses whose value
    matches the scan criteria.

    Passing a `memory_regions` snapshot skips region enumeration.
    """
    _validate_pytype(pytype)

    target_value_bytes = values_to_bytes(pytype, bufflength, value)

    source_regions = (
        memory_regions if memory_regions is not None else get_memory_regions(task)
    )

    def is_scannable(region) -> bool:
        protection = region["struct"].Protection
        if protection & VM_PROT_READ == 0:
            return False
        if writeable_only and protection & VM_PROT_WRITE == 0:
            return False
        return True

    filtered_regions = [region for region in source_regions if is_scannable(region)]
    filtered_regions.sort(key=lambda region: region["address"])

    def read_chunk(address: int, size: int):
        buffer = (ctypes.c_byte * size)()
        _mach_read(task, address, ctypes.addressof(buffer), size)
        return buffer

    def is_transient(exc: BaseException) -> bool:
        return isinstance(exc, MachReadError) and exc.kr in _PAGE_GONE_KRS

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


def get_threads(task: int) -> Generator[ThreadInfo, None, None]:
    """
    Yield a :class:`ThreadInfo` for every thread of the target task using
    Mach's ``task_threads``.

    .. note::
       ``tid`` here is the **Mach thread port name**, not the BSD/POSIX
       pthread id. Looking up the POSIX tid would require an extra
       ``thread_info(THREAD_IDENTIFIER_INFO)`` call per thread; the Mach port
       is sufficient for any further Mach-level operation and is what the
       kernel hands us cheaply.
    """
    thread_list = ctypes.POINTER(ctypes.c_uint)()
    count = ctypes.c_uint(0)

    kr = libsystem.task_threads(task, ctypes.byref(thread_list), ctypes.byref(count))
    if kr != KERN_SUCCESS:
        raise OSError(
            "task_threads failed: %s (kr=%d)" % (mach_error_message(kr), kr)
        )

    try:
        for index in range(count.value):
            yield ThreadInfo(
                tid=int(thread_list[index]),
                start_address=None,
                state=None,
                priority=None,
                raw=int(thread_list[index]),
            )
    finally:
        # The kernel out-allocates ``thread_list`` in the caller's address
        # space; freeing it back is the caller's responsibility, otherwise we
        # leak VM in *our own* task each enumeration. The deallocation size is
        # ``count * sizeof(mach_port_t)``.
        if count.value:
            libsystem.vm_deallocate(
                mach_task_self_.value,
                ctypes.cast(thread_list, ctypes.c_void_p),
                count.value * ctypes.sizeof(ctypes.c_uint),
            )


def search_addresses_by_pattern(
    task: int,
    pattern: PatternLike,
    *,
    byte_length: int = 0,
    progress_information: bool = False,
    memory_regions: Optional[Sequence[Dict]] = None,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    AOB scan against every readable region of the target task. See
    :meth:`AbstractProcess.search_by_pattern`.
    """
    compiled, length = compile_pattern(pattern, byte_length=byte_length)

    source_regions = (
        memory_regions if memory_regions is not None else get_memory_regions(task)
    )

    def is_scannable(region) -> bool:
        return (region["struct"].Protection & VM_PROT_READ) != 0

    filtered_regions = [region for region in source_regions if is_scannable(region)]
    filtered_regions.sort(key=lambda region: region["address"])

    def read_chunk(address: int, size: int):
        buffer = (ctypes.c_byte * size)()
        _mach_read(task, address, ctypes.addressof(buffer), size)
        return buffer

    def is_transient(exc: BaseException) -> bool:
        return isinstance(exc, MachReadError) and exc.kr in _PAGE_GONE_KRS

    yield from iter_pattern_results(
        filtered_regions,
        compiled,
        length,
        read_chunk,
        progress_information=progress_information,
        transient_error_check=is_transient,
    )


def search_values_by_addresses(
    task: int,
    pytype: Type[T],
    bufflength: int,
    addresses: Sequence[int],
    *,
    memory_regions: Optional[Sequence[Dict]] = None,
    raise_error: bool = False,
) -> Generator[Tuple[int, Optional[T]], None, None]:
    """
    Read values at the provided addresses, grouped by region for syscall efficiency.

    Memory is read in chunks (see iter_region_chunks) to bound allocation.
    Chunks reading addresses near a boundary include `bufflength - 1` extra
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
            region for region in get_memory_regions(task) if region["is_readable"]
        ]
    else:
        memory_regions = list(memory_regions)

    def read_chunk(address: int, size: int):
        buffer = (ctypes.c_byte * size)()
        _mach_read(task, address, ctypes.addressof(buffer), size)
        return buffer

    def is_transient(exc: BaseException) -> bool:
        return isinstance(exc, MachReadError) and exc.kr in _PAGE_GONE_KRS

    yield from iter_values_for_addresses(
        addresses,
        memory_regions,
        pytype,
        bufflength,
        read_chunk,
        raise_error=raise_error,
        transient_error_check=is_transient,
    )
