# -*- coding: utf-8 -*-

"""
macOS (Mach) implementation of read/write/search primitives. Parallels
linux/functions.py and win32/functions.py.
"""

import ctypes
import logging
import os
import warnings
from typing import Dict, Generator, List, Optional, Sequence, Tuple, Type, TypeVar, Union

from ..enums import ScanTypesEnum
from ..process.module_info import ModuleInfo
from ..process.region import (
    default_address_filter,
    default_scan_filter,
    enrich_region,
)
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
    TASK_DYLD_INFO,
    TASK_DYLD_INFO_COUNT,
    VM_FLAGS_ANYWHERE,
    VM_PROT_COPY,
    VM_PROT_READ,
    VM_PROT_WRITE,
    VM_REGION_BASIC_INFO_64,
    VM_REGION_BASIC_INFO_COUNT_64,
    mach_msg_type_number_t,
    mach_port_t,
    mach_vm_address_t,
    mach_vm_size_t,
    task_dyld_info_data_t,
    vm_region_basic_info_64,
)


# kern_return_t codes that may signal a read-only / protection issue we can fix
# by elevating the protection. KERN_INVALID_ADDRESS is included because newer
# macOS returns it (instead of KERN_PROTECTION_FAILURE) when mach_vm_write
# refuses a write to a non-writable page even though the address is valid.
_WRITE_RETRY_CODES = (KERN_PROTECTION_FAILURE, KERN_INVALID_ADDRESS)


_logger = logging.getLogger("PyMemoryEditor")


# When mach_vm_region returns a transient non-success code mid-enumeration we
# bump the cursor by one page and keep going instead of silently truncating
# the region list. 4 KiB is conservative: on Apple Silicon (16 KiB pages) we
# simply make 4 small hops past a problem page, which is cheap. Sized small
# enough that we do not accidentally skip a real adjacent region.
_REGION_SKIP_BUMP = 0x1000

# mach_vm_write's data_count parameter is `mach_msg_type_number_t` — a 32-bit
# unsigned int per the Mach interface. A write larger than UINT32_MAX would
# silently truncate at the kernel boundary. Guard it explicitly so the user
# sees a real error instead of a partial write.
_MACH_WRITE_MAX_SIZE = 0xFFFFFFFF


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

    ``mach_vm_region`` returning :data:`KERN_INVALID_ADDRESS` is the documented
    way the kernel says "no more regions past this address" — the natural end
    of the enumeration. Any *other* non-success code (``KERN_FAILURE``,
    ``KERN_NO_ACCESS`` on a guard page, etc.) used to terminate enumeration
    too, silently truncating the region list. Now those are logged and the
    cursor is bumped one page so the walk keeps going.
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
            if kr == KERN_INVALID_ADDRESS:
                return  # end of address space — the normal terminator
            _logger.debug(
                "get_memory_regions: mach_vm_region skipped 0x%X (kr=%d, %s); "
                "advancing one page",
                address.value, kr, mach_error_message(kr),
            )
            address.value += _REGION_SKIP_BUMP
            continue

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
            return
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

    ``mach_vm_write``'s ``data_count`` parameter is a 32-bit
    ``mach_msg_type_number_t`` per the Mach interface; reject ``size`` values
    that would silently truncate at the kernel boundary instead of letting
    them slip through.
    """
    if size > _MACH_WRITE_MAX_SIZE:
        raise OverflowError(
            "mach_vm_write size %d exceeds UINT32_MAX — the Mach interface "
            "would silently truncate. Split the write into smaller chunks."
            % size
        )

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


def _make_read_chunk(task: int):
    """
    Build a ``read_chunk(address, size)`` closure bound to ``task``.

    Hoisted here so every ``search_*`` entry point uses one canonical
    definition instead of re-declaring the closure inline three times.
    """
    def read_chunk(address: int, size: int):
        buffer = (ctypes.c_byte * size)()
        _mach_read(task, address, ctypes.addressof(buffer), size)
        return buffer

    return read_chunk


def _is_transient(exc: BaseException) -> bool:
    """Classify ``exc`` as a transient page-vanished failure for scan loops."""
    return isinstance(exc, MachReadError) and exc.kr in _PAGE_GONE_KRS


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


def allocate_memory(task: int, size: int, permission=None) -> int:
    """
    Allocate ``size`` bytes in the task via mach_vm_allocate and return the
    base address. The kernel chooses the address (VM_FLAGS_ANYWHERE) and the
    region starts as read+write.

    :param permission: optional VM_PROT_* bitmask. When given, the region's
        protection is set with mach_vm_protect after allocation; on failure the
        allocation is rolled back so it is not leaked. Requesting execute may be
        refused by the hardened runtime (e.g. RWX on Apple Silicon).
    """
    if size <= 0:
        raise ValueError("size must be a positive number of bytes.")

    address = mach_vm_address_t(0)
    kr = libsystem.mach_vm_allocate(
        task, ctypes.byref(address), size, VM_FLAGS_ANYWHERE
    )
    if kr != KERN_SUCCESS:
        raise OSError(
            "mach_vm_allocate failed: %s (kr=%d)" % (mach_error_message(kr), kr)
        )

    if permission is not None:
        kr = libsystem.mach_vm_protect(task, address.value, size, 0, int(permission))
        if kr != KERN_SUCCESS:
            # Don't leak the region we just created if we can't honor the
            # requested protection.
            libsystem.mach_vm_deallocate(task, address.value, size)
            raise OSError(
                "mach_vm_protect failed after allocate: %s (kr=%d)"
                % (mach_error_message(kr), kr)
            )

    return int(address.value)


def free_memory(task: int, address: int, size: int) -> bool:
    """
    Release a region previously returned by :func:`allocate_memory` via
    mach_vm_deallocate. Unlike Windows' MEM_RELEASE, Mach requires the exact
    size, so the caller must pass it (the process wrapper tracks it).
    """
    if size <= 0:
        raise ValueError(
            "macOS requires the allocation size to free a region (got %r)." % (size,)
        )

    kr = libsystem.mach_vm_deallocate(task, address, size)
    if kr != KERN_SUCCESS:
        raise OSError(
            "mach_vm_deallocate failed: %s (kr=%d)" % (mach_error_message(kr), kr)
        )
    return True


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

    filtered_regions = [
        region
        for region in source_regions
        if default_scan_filter(region, writeable_only=writeable_only)
    ]
    filtered_regions.sort(key=lambda region: region["address"])

    yield from iter_search_results(
        filtered_regions,
        pytype,
        bufflength,
        target_value_bytes,
        scan_type,
        _make_read_chunk(task),
        progress_information=progress_information,
        transient_error_check=_is_transient,
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


# Mach-O constants for sizing an image from its load commands.
_MH_MAGIC_64 = 0xFEEDFACF
_LC_SEGMENT_64 = 0x19
_MACH_HEADER_64_SIZE = 32  # sizeof(struct mach_header_64)


def _read_cstring(task: int, address: int, *, max_length: int = 4096) -> str:
    """
    Read a NUL-terminated UTF-8 string from the target task starting at
    ``address``. Reads in small chunks and shrinks the chunk near an unmapped
    boundary so a path that ends close to the edge of a mapping still comes
    back intact. Returns the decoded text (``errors="replace"``).
    """
    data = bytearray()
    chunk = 256

    while len(data) < max_length:
        try:
            piece = read_process_memory(task, address + len(data), bytes, chunk)
        except MachReadError:
            # The read crossed into an unmapped page; retry with a smaller
            # window. Give up only once even a single byte can't be read.
            if chunk == 1:
                break
            chunk = max(1, chunk // 4)
            continue

        nul = piece.find(b"\x00")
        if nul != -1:
            data.extend(piece[:nul])
            break
        data.extend(piece)

    return bytes(data[:max_length]).decode("utf-8", errors="replace")


def _macho_image_size(task: int, load_address: int) -> int:
    """
    Return the size of the ``__TEXT`` segment of the Mach-O image at
    ``load_address`` (its read-only code/constants), parsed from the load
    commands. Returns 0 when the header is unreadable or not a 64-bit Mach-O.

    macOS makes a single whole-module size hard to define: dylibs in the dyld
    *shared cache* have their segments scattered across the cache (so a span
    measurement is multi-gigabyte garbage), and several segments — ``__LINKEDIT``
    and the ``__OBJC_RO`` / ``__OBJC_RW`` runtime tables — are *merged blobs
    shared by every dylib*, so summing them double-counts hundreds of MB onto
    each module. ``__TEXT`` is the one segment that is always private to the
    image and accurately sized on and off the cache, and it is the region a
    code/AOB scan cares about — so it is the most useful, stable choice here.
    """
    try:
        header = read_process_memory(task, load_address, bytes, _MACH_HEADER_64_SIZE)
    except MachReadError:
        return 0

    if int.from_bytes(header[:4], "little") != _MH_MAGIC_64:
        return 0

    ncmds = int.from_bytes(header[16:20], "little")
    cmd_address = load_address + _MACH_HEADER_64_SIZE

    for _ in range(ncmds):
        try:
            cmd_header = read_process_memory(task, cmd_address, bytes, 8)
        except MachReadError:
            break

        cmd = int.from_bytes(cmd_header[:4], "little")
        cmd_size = int.from_bytes(cmd_header[4:8], "little")
        if cmd_size == 0:
            break  # malformed — avoid an infinite loop

        if cmd == _LC_SEGMENT_64:
            # struct segment_command_64: cmd, cmdsize, segname[16],
            # vmaddr (u64 @ offset 24), vmsize (u64 @ offset 32), ...
            try:
                seg = read_process_memory(task, cmd_address, bytes, 40)
            except MachReadError:
                break

            if seg[8:24].split(b"\x00", 1)[0] == b"__TEXT":
                return int.from_bytes(seg[32:40], "little")

        cmd_address += cmd_size

    return 0


# Segments that never hold a process's mutable global pointers and so are
# useless (or actively harmful) as pointer-scan static bases: __PAGEZERO is the
# multi-GB unmapped guard at the bottom of the image, and __LINKEDIT is a merged
# blob shared across dylibs (its address isn't private to one image).
_SKIP_SEGMENTS = (b"__PAGEZERO", b"__LINKEDIT")


def get_image_segments(task: int, load_address: int) -> List[Tuple[int, int]]:
    """
    Return the runtime ``(start, size)`` of every real segment of the Mach-O
    image at ``load_address`` — ``__TEXT``, ``__DATA``, ``__DATA_CONST``, etc.

    Unlike :func:`_macho_image_size` (which returns only ``__TEXT`` because it
    answers "how big is the code?"), this answers "which address ranges belong
    to this image?" — the question the pointer scanner needs, since a process's
    *global pointers* (the static bases of a pointer chain) live in the
    writable ``__DATA`` / ``__DATA_CONST`` segments, **not** in ``__TEXT``.

    Each segment is rebased by the image's ASLR slide (computed from where
    ``__TEXT`` actually landed), so the returned ranges are live addresses. This
    is exact for the main executable and ordinary dylibs; segments of
    dyld-shared-cache dylibs may be relocated independently of ``__TEXT`` and so
    come back approximate — harmless for static-base detection (a wrong range
    simply won't contain any real pointer slot). Returns ``[]`` when the header
    can't be parsed.
    """
    try:
        header = read_process_memory(task, load_address, bytes, _MACH_HEADER_64_SIZE)
    except MachReadError:
        return []

    if int.from_bytes(header[:4], "little") != _MH_MAGIC_64:
        return []

    ncmds = int.from_bytes(header[16:20], "little")
    cmd_address = load_address + _MACH_HEADER_64_SIZE

    segments: List[Tuple[bytes, int, int]] = []  # (segname, vmaddr, vmsize)
    text_vmaddr: Optional[int] = None

    for _ in range(ncmds):
        try:
            cmd_header = read_process_memory(task, cmd_address, bytes, 8)
        except MachReadError:
            break

        cmd = int.from_bytes(cmd_header[:4], "little")
        cmd_size = int.from_bytes(cmd_header[4:8], "little")
        if cmd_size == 0:
            break

        if cmd == _LC_SEGMENT_64:
            try:
                seg = read_process_memory(task, cmd_address, bytes, 40)
            except MachReadError:
                break
            segname = seg[8:24].split(b"\x00", 1)[0]
            vmaddr = int.from_bytes(seg[24:32], "little")
            vmsize = int.from_bytes(seg[32:40], "little")
            if segname == b"__TEXT":
                text_vmaddr = vmaddr
            segments.append((segname, vmaddr, vmsize))

        cmd_address += cmd_size

    if text_vmaddr is None:
        return []

    slide = load_address - text_vmaddr
    ranges: List[Tuple[int, int]] = []
    for segname, vmaddr, vmsize in segments:
        if vmsize == 0 or segname in _SKIP_SEGMENTS:
            continue
        ranges.append((vmaddr + slide, vmsize))
    return ranges


def get_modules(task: int) -> Generator[ModuleInfo, None, None]:
    """
    Yield a :class:`ModuleInfo` for every Mach-O image loaded in the task — the
    main executable plus every linked dylib.

    Walks dyld's image table: ``task_info(TASK_DYLD_INFO)`` returns the address
    of ``dyld_all_image_infos`` inside the target, then the image array is read
    out of the target's memory. Pointer-sized fields are read as 8 bytes (the
    macOS backend targets 64-bit tasks). ``size`` is derived from each image's
    Mach-O load commands (see :func:`_macho_image_size`); it falls back to 0 if
    the header can't be parsed.
    """
    info = task_dyld_info_data_t()
    count = mach_msg_type_number_t(TASK_DYLD_INFO_COUNT)

    kr = libsystem.task_info(
        task, TASK_DYLD_INFO, ctypes.byref(info), ctypes.byref(count)
    )
    if kr != KERN_SUCCESS:
        raise OSError(
            "task_info(TASK_DYLD_INFO) failed: %s (kr=%d)"
            % (mach_error_message(kr), kr)
        )

    all_infos_address = info.all_image_info_addr
    if not all_infos_address:
        return

    pointer_size = 8  # 64-bit task

    def read_pointer(address: int) -> int:
        return int.from_bytes(
            read_process_memory(task, address, bytes, pointer_size), "little"
        )

    def read_u32(address: int) -> int:
        return int.from_bytes(read_process_memory(task, address, bytes, 4), "little")

    # struct dyld_all_image_infos { uint32 version; uint32 infoArrayCount;
    #     const struct dyld_image_info* infoArray; ... }
    try:
        image_count = read_u32(all_infos_address + 4)
        info_array_address = read_pointer(all_infos_address + 8)
    except MachReadError as exc:
        raise OSError("could not read dyld_all_image_infos: %s" % exc)

    if not info_array_address or image_count == 0:
        return

    # struct dyld_image_info { const mach_header* imageLoadAddress;
    #     const char* imageFilePath; uintptr_t imageFileModDate; } — 3 pointers.
    entry_size = pointer_size * 3

    for index in range(image_count):
        entry_address = info_array_address + index * entry_size
        try:
            load_address = read_pointer(entry_address)
            path_address = read_pointer(entry_address + pointer_size)
        except MachReadError as exc:
            _logger.debug("get_modules: skipping image %d: %s", index, exc)
            continue

        path = _read_cstring(task, path_address) if path_address else ""
        name = os.path.basename(path) if path else ""

        yield ModuleInfo(
            name=name,
            path=path,
            base_address=load_address,
            size=_macho_image_size(task, load_address),
            raw=load_address,
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

    filtered_regions = [
        region for region in source_regions if default_scan_filter(region)
    ]
    filtered_regions.sort(key=lambda region: region["address"])

    yield from iter_pattern_results(
        filtered_regions,
        compiled,
        length,
        _make_read_chunk(task),
        progress_information=progress_information,
        transient_error_check=_is_transient,
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
            region for region in get_memory_regions(task) if default_address_filter(region)
        ]
    else:
        memory_regions = list(memory_regions)

    yield from iter_values_for_addresses(
        addresses,
        memory_regions,
        pytype,
        bufflength,
        _make_read_chunk(task),
        raise_error=raise_error,
        transient_error_check=_is_transient,
    )
