# -*- coding: utf-8 -*-

# Read more about process_vm_(read/write)v here:
# https://man7.org/linux/man-pages/man2/process_vm_readv.2.html

# Read more about proc and memory mapping here:
# https://man7.org/linux/man-pages/man5/proc.5.html

import ctypes
import errno as errno_mod
import logging
import os
import signal
from ctypes import addressof, sizeof
from typing import Dict, Generator, Optional, Pattern, Sequence, Tuple, Type, TypeVar, Union, cast

from ..enums import ScanTypesEnum
from ..process.errors import ProcessIDNotExistsError
from ..process.module_info import ModuleInfo
from ..process.region import (
    MemoryRegion,
    default_address_filter,
    default_scan_filter,
    MemoryRegionSnapshot,
    make_region,
)
from ..process.scanning import (
    iter_pattern_results,
    iter_search_results,
    iter_values_for_addresses,
)
from ..process.thread_info import ThreadInfo
from ..util import (
    _validate_pytype,
    as_writable_c_buffer,
    get_c_type_of,
    sign_extend_narrow_int,
    values_to_bytes,
)
from ..util.pattern import PatternLike, compile_pattern
from .libc import libc
from .types import MEMORY_BASIC_INFORMATION, PATH_SIZE, PRIVILEGES_SIZE, iovec


_logger = logging.getLogger("PyMemoryEditor")


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
    short count. Accepting the short result would leave the caller's buffer
    half-filled with real bytes and half with zeros (which downstream
    decoding would treat as valid), so it raises instead.
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


_PTRACE_SCOPE_HINT = (
    "The kernel refused ptrace-level access to the target: either Yama "
    "ptrace_scope restricts it (the usual cause for a process you own; relax "
    "it with `sudo sysctl kernel.yama.ptrace_scope=0` or make the target a "
    "child of this process), or the target belongs to another user / is not "
    "dumpable (setuid), which only root can read. Running as root covers both."
)


def _errno_or(exc: OSError, default: int) -> int:
    """``exc.errno``, or ``default`` when the exception was raised without one."""
    return exc.errno if exc.errno is not None else default


def _syscall_error(op: str, errno: int, remote_address: int, length: int) -> OSError:
    """
    Build the ``OSError`` for a failed ``process_vm_readv`` / ``process_vm_writev``.

    ``errno`` is preserved on every path (``_is_transient`` keys on it), but the
    two codes users actually hit get a message that points at the right knob:

    - ``EPERM`` is Yama ``ptrace_scope`` denying ``PTRACE_MODE_ATTACH`` — the
      policy that gates these two syscalls (not ``/proc/<pid>/maps``, which
      only needs ``PTRACE_MODE_READ`` and therefore opens fine).
    - ``EFAULT`` is an address the target does not map *or*, for a write, a
      page mapped without write permission. Unlike Windows and macOS, Linux
      has no protection flip here: ``process_vm_writev`` honours page
      protection and cannot write to a read-only page.
    """
    base = "%s failed at 0x%X (%d bytes): %s" % (
        op, remote_address, length, os.strerror(errno),
    )
    if errno == errno_mod.EPERM:
        return PermissionError(errno, "%s. %s" % (base, _PTRACE_SCOPE_HINT))
    if errno == errno_mod.EFAULT and op == "process_vm_writev":
        return OSError(
            errno,
            "%s. The address is not mapped in the target, or the page is not "
            "writable: Linux does not elevate page protection for writes (the "
            "Windows and macOS backends do), so read-only pages cannot be "
            "written through process_vm_writev." % base,
        )
    return OSError(errno, base)


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
        raise _syscall_error("process_vm_readv", errno, remote_address, length)

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
        raise _syscall_error("process_vm_writev", errno, remote_address, length)

    if result != length:
        raise _LinuxPartialIOError(
            "process_vm_writev", remote_address, result, length
        )

    return result


def _make_read_chunk(pid: int):
    """
    Build a `read_chunk(address, size)` closure bound to ``pid``.

    One closure per backend, shared by its three scan entry points
    (``search_addresses_by_value``, ``search_addresses_by_pattern``,
    ``search_values_by_addresses``) so they cannot drift.
    """
    def read_chunk(address: int, size: int):
        buffer = (ctypes.c_byte * size)()
        _process_vm_readv(pid, addressof(buffer), address, sizeof(buffer))
        return buffer

    return read_chunk


def _is_transient(exc: BaseException) -> bool:
    """
    Classify ``exc`` as a transient page-vanished failure that scan loops
    should swallow vs a real configuration / permission error that must
    propagate. Shared by every scanning entry point.
    """
    # A short read mid-scan is equivalent to a page disappearing — the scan
    # should skip the chunk and keep going. Real permission/configuration
    # errors (EACCES, EPERM, ESRCH, EINVAL) propagate.
    if isinstance(exc, _LinuxPartialIOError):
        return True
    return isinstance(exc, OSError) and exc.errno in _PAGE_GONE_ERRNOS


def get_memory_regions(pid: int) -> Generator["MemoryRegion", None, None]:
    """
    Yield a :class:`MemoryRegion` for each entry in ``/proc/<pid>/maps``.

    Translates the typical I/O failures of ``/proc/<pid>/maps`` into the
    library's own exception hierarchy so callers don't have to special-case
    raw ``FileNotFoundError`` / ``PermissionError`` from the kernel pseudo-fs.

    The file is parsed as bytes: a mapped path is whatever bytes the file
    system holds, not necessarily UTF-8, and decoding the file as text made
    one such path abort every listing and scan of that process with
    ``UnicodeDecodeError``. The raw path bytes go into the struct;
    ``MemoryRegion.path`` decodes them as UTF-8 with replacement characters.
    """
    mapping_filename = "/proc/{}/maps".format(pid)

    try:
        mapping_file = open(mapping_filename, "rb")
    except FileNotFoundError:
        # Target died between OpenProcess()'s pid_exists() check and now. The
        # caller already accepts ProcessIDNotExistsError from the open path,
        # so funnel into it instead of leaking a kernel pseudo-fs error.
        raise ProcessIDNotExistsError(pid)
    except PermissionError as exc:
        # /proc/<pid>/maps is gated by PTRACE_MODE_READ, which Yama's
        # ptrace_scope does *not* restrict — so failing here means the target
        # belongs to another uid (or is not dumpable: setuid, or
        # prctl(PR_SET_DUMPABLE, 0)). The ptrace_scope hint belongs to the
        # EPERM from process_vm_readv/writev, not to this path.
        raise PermissionError(
            _errno_or(exc, errno_mod.EACCES),
            "Cannot read %s: %s. The target process belongs to another user "
            "or is not dumpable; run as root or as the owner of the target."
            % (mapping_filename, exc),
        ) from exc

    with mapping_file:
        for line in mapping_file:
            region_information = line.split(maxsplit=5)

            try:
                addressing_range, privileges, raw_offset, device, raw_inode = (
                    region_information[0:5]
                )
                path = region_information[5].strip() if len(region_information) >= 6 else b""

                start_address, end_address = [
                    int(addr, 16) for addr in addressing_range.split(b"-")
                ]
                major_id, minor_id = [int(_id, 16) for _id in device.split(b":")]

                offset = int(raw_offset, 16)
                inode = int(raw_inode)  # /proc/<pid>/maps formats the inode as decimal.
            except (ValueError, IndexError) as exc:
                # A single malformed line (kernel quirk, racing teardown) must
                # not abort the whole region walk — skip it and keep going, the
                # same log-and-continue contract the Windows/macOS walkers use.
                _logger.debug(
                    "get_memory_regions: skipping unparseable maps line %r: %s",
                    line,
                    exc,
                )
                continue

            size = end_address - start_address

            # Truncate to fit the fixed-size inline byte arrays in the struct.
            # Leave room for a null so attribute reads always terminate cleanly.
            privileges_bytes = privileges[: PRIVILEGES_SIZE - 1]
            path_bytes = path[: PATH_SIZE - 1]

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
            yield make_region(
                address=start_address,
                size=region.RegionSize,
                struct=region,
            )


def get_modules(pid: int) -> Generator[ModuleInfo, None, None]:
    """
    Yield a :class:`ModuleInfo` for every file-backed module mapped by the
    process, derived from ``/proc/<pid>/maps``.

    A single library spans several consecutive mappings (its ``.text``,
    ``.rodata``, ``.data`` / ``.bss`` segments), all sharing the same backing
    path. Mappings are grouped by path: the module's ``base_address`` is the
    lowest mapping start and its ``size`` reaches the highest mapping end.

    Pseudo-mappings without a real backing file (``[heap]``, ``[stack]``,
    ``[vvar]``, anonymous memory) are not modules and are skipped — only paths
    beginning with ``/`` are considered. Modules are yielded in ascending
    ``base_address`` order, which is the order ``/proc/<pid>/maps`` lists them.
    """
    # path -> [min_start, max_end]; first_seen preserves the maps order, which
    # is already ascending by address, so we don't need to sort afterwards.
    bounds: Dict[str, list] = {}
    first_seen = []

    for region in get_memory_regions(pid):
        path = region.path
        if not path.startswith("/"):
            continue

        start = region.address
        end = start + region.size

        entry = bounds.get(path)
        if entry is None:
            bounds[path] = [start, end]
            first_seen.append(path)
        else:
            if start < entry[0]:
                entry[0] = start
            if end > entry[1]:
                entry[1] = end

    for path in first_seen:
        start, end = bounds[path]
        yield ModuleInfo(
            name=os.path.basename(path),
            path=path,
            base_address=start,
            size=end - start,
            raw=path,
        )


def _read_elf_class(path: str) -> Optional[int]:
    """
    Read the ``EI_CLASS`` byte from an ELF file's identification header.

    Returns 1 for ELFCLASS32, 2 for ELFCLASS64, or ``None`` if ``path`` can't
    be opened or isn't an ELF file (missing ``\\x7fELF`` magic).
    """
    try:
        with open(path, "rb") as elf:
            ident = elf.read(5)
    except OSError:
        return None

    if len(ident) < 5 or ident[:4] != b"\x7fELF":
        return None

    return ident[4]  # e_ident[EI_CLASS]: 1 = ELFCLASS32, 2 = ELFCLASS64


def _detect_process_64bit(pid: int) -> Optional[bool]:
    """
    Return ``True``/``False`` from the ELF ``EI_CLASS`` byte of the target's
    executable, or ``None`` when no header could be read. The raw *mechanism*:
    no guessing and no warning — the caller decides what an unknown result
    means (the public :func:`is_process_64bit` falls back to the host word size;
    ``AbstractProcess.is_64bit`` honors ``strict_bitness``).

    The primary source is ``/proc/<pid>/exe``; if that symlink can't be read (a
    different user without ``CAP_SYS_PTRACE``), it falls back to the first
    file-backed, executable mapping in ``/proc/<pid>/maps`` — the main image or
    a shared library, which share the process's bitness.
    """
    ei_class = _read_elf_class("/proc/{}/exe".format(pid))

    if ei_class is None:
        # Fallback: probe a file-backed executable mapping's on-disk ELF header.
        for region in get_memory_regions(pid):
            if not region.is_executable:
                continue
            path = region.path
            if not path or path.startswith("["):  # skip [heap], [stack], anon
                continue
            ei_class = _read_elf_class(path)
            if ei_class is not None:
                break

    if ei_class == 2:
        return True
    if ei_class == 1:
        return False
    return None


def is_process_64bit(pid: int) -> bool:
    """
    Return ``True`` if the target process is 64-bit, ``False`` if 32-bit.

    Thin *policy* wrapper over :func:`_detect_process_64bit`: when no ELF class
    can be read it assumes the host's word size (the usual case) and warns so a
    wrong pointer-width default (used by the pointer APIs) is traceable instead
    of a silent mis-detection on a cross-bitness target.
    """
    detected = _detect_process_64bit(pid)
    if detected is not None:
        return detected

    _logger.warning(
        "is_process_64bit: could not read the ELF class for pid %d; assuming "
        "the host word size. Pointer-width detection may be wrong for a "
        "cross-bitness target.",
        pid,
    )
    return ctypes.sizeof(ctypes.c_void_p) == 8


def read_process_memory(pid: int, address: int, pytype: Type[T], bufflength: int) -> T:
    """
    Return a value from a memory address.
    """
    _validate_pytype(pytype)

    data = get_c_type_of(pytype, bufflength)
    # `bufflength`, not `sizeof(data)`. The two differ whenever the width
    # rounds up to a wider C type — `int` at 3 bytes gets a `c_int32` — and
    # passing the buffer size made this backend read 4 bytes where Windows and
    # macOS read 3, so the same call returned a different value per platform
    # (0x11223344 here against 0x223344 there). `get_c_type_of` guarantees
    # `sizeof(data) >= bufflength`, so reading into the front of a larger,
    # zero-initialised buffer is safe and matches the other two backends.
    _process_vm_readv(pid, addressof(data), address, bufflength)

    if pytype is str:
        return cast(T, bytes(data).decode("utf-8", errors="replace"))
    elif pytype is bytes:
        return cast(T, bytes(data))
    else:
        # Narrow widths pad with zeroes, which reads a signed value as
        # unsigned -- and a scan for the same bytes is signed.
        sign_extend_narrow_int(data, pytype, bufflength)
        return data.value


def read_process_memory_into(pid: int, address: int, buffer) -> int:
    """
    Read ``len(buffer)`` bytes from ``address`` directly into the writable
    ``buffer``, with no intermediate allocation. Returns the number of bytes
    read (always the buffer's byte length on success; a short read raises
    ``_LinuxPartialIOError``).
    """
    c_buffer = as_writable_c_buffer(buffer)
    size = len(c_buffer)
    return _process_vm_readv(pid, addressof(c_buffer), address, size)


def search_addresses_by_value(
    pid: int,
    pytype: Type[T],
    bufflength: int,
    value: Optional[Union[bool, int, float, str, bytes, tuple]],
    scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
    progress_information: bool = False,
    writeable_only: bool = False,
    *,
    memory_regions: Optional[Sequence[MemoryRegion]] = None,
    aligned: bool = True,
    target_value_bytes: Optional[Union[bytes, Tuple[bytes, ...]]] = None,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    Search the whole memory space, accessible to the process,
    for the provided value, returning the found addresses.

    Passing a `memory_regions` snapshot skips region enumeration.
    ``target_value_bytes`` is ``value`` already encoded (see
    :func:`~PyMemoryEditor.util.prepare_search_target`); when it is given,
    ``value`` is not used and may be ``None``.
    """
    _validate_pytype(pytype)

    if target_value_bytes is None:
        target_value_bytes = values_to_bytes(pytype, bufflength, value)

    source_regions = (
        memory_regions if memory_regions is not None else get_memory_regions(pid)
    )

    filtered_regions = [
        region
        for region in source_regions
        if default_scan_filter(region, writeable_only=writeable_only)
    ]
    filtered_regions.sort(key=lambda region: region.address)

    yield from iter_search_results(
        filtered_regions,
        pytype,
        bufflength,
        target_value_bytes,
        scan_type,
        _make_read_chunk(pid),
        progress_information=progress_information,
        aligned=aligned,
        transient_error_check=_is_transient,
    )


def search_addresses_by_pattern(
    pid: int,
    pattern: PatternLike,
    *,
    byte_length: int = 0,
    progress_information: bool = False,
    memory_regions: Optional[Sequence[MemoryRegion]] = None,
    compiled_pattern: Optional[Tuple[Pattern[bytes], int]] = None,
) -> Generator[Union[int, Tuple[int, dict]], None, None]:
    """
    AOB scan against every readable, non-shared region of the target. See
    :meth:`AbstractProcess.search_by_pattern`. ``compiled_pattern`` is what
    :func:`~PyMemoryEditor.util.pattern.compile_pattern` returned for
    ``pattern``, when the caller already compiled it.
    """
    compiled, length = (
        compiled_pattern
        if compiled_pattern is not None
        else compile_pattern(pattern, byte_length=byte_length)
    )

    source_regions = (
        memory_regions if memory_regions is not None else get_memory_regions(pid)
    )

    filtered_regions = [
        region for region in source_regions if default_scan_filter(region)
    ]
    filtered_regions.sort(key=lambda region: region.address)

    yield from iter_pattern_results(
        filtered_regions,
        compiled,
        length,
        _make_read_chunk(pid),
        progress_information=progress_information,
        transient_error_check=_is_transient,
    )


def search_values_by_addresses(
    pid: int,
    pytype: Type[T],
    bufflength: int,
    addresses: Sequence[int],
    *,
    memory_regions: Optional[Sequence[MemoryRegion]] = None,
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
            region for region in get_memory_regions(pid) if default_address_filter(region)
        ]
    elif not isinstance(memory_regions, MemoryRegionSnapshot):
        # Materialize any other iterable (it is indexed and walked more than
        # once), but pass a snapshot through untouched: `list(...)` would drop
        # its type tag and make `_ensure_sorted_by_address` re-sort an
        # already-sorted region map on every refine scan.
        memory_regions = list(memory_regions)

    yield from iter_values_for_addresses(
        addresses,
        memory_regions,
        pytype,
        bufflength,
        _make_read_chunk(pid),
        raise_error=raise_error,
        transient_error_check=_is_transient,
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

    # `bufflength`, not `sizeof(data)` — this one corrupted memory rather than
    # merely disagreeing. A write of 3 bytes sized a 4-byte `c_int32` and then
    # wrote all four, destroying a byte the caller never asked to touch, while
    # Windows and macOS wrote exactly three. Verified on Linux: `w=3` touched 4
    # bytes and `w=5` touched 8.
    _process_vm_writev(pid, addressof(data), address, bufflength)
    return value


def get_threads(pid: int) -> Generator[ThreadInfo, None, None]:
    """
    Yield a :class:`ThreadInfo` for every thread of the target process by
    listing ``/proc/<pid>/task/`` — each subdirectory there is a TID.

    State and priority come from ``/proc/<pid>/task/<tid>/stat`` when readable;
    silent on per-thread race errors (a thread may exit between listing the
    directory and reading its stat file) but logged at DEBUG so observers can
    see it.

    A process that has exited yields nothing (its ``task`` directory is gone),
    matching the Windows backend. Being denied the directory listing itself,
    however, is a configuration problem and raises ``PermissionError`` — the
    same way macOS surfaces a ``task_threads`` failure — rather than
    masquerading as "no threads".
    """
    task_dir = "/proc/{}/task".format(pid)

    try:
        entries = os.listdir(task_dir)
    except FileNotFoundError as exc:
        _logger.debug("get_threads: %s is gone (target exited?): %s", task_dir, exc)
        return
    except PermissionError as exc:
        raise PermissionError(
            _errno_or(exc, errno_mod.EACCES),
            "Cannot list %s: %s. The target process belongs to another user "
            "or is not dumpable; run as root or as the owner of the target."
            % (task_dir, exc),
        ) from exc
    except OSError as exc:
        _logger.debug("get_threads: could not list %s: %s", task_dir, exc)
        return

    for entry in entries:
        try:
            tid = int(entry)
        except ValueError:
            continue

        state: Optional[str] = None
        priority: Optional[int] = None
        try:
            # `comm` inside the stat line is whatever bytes the thread named
            # itself (prctl PR_SET_NAME), not necessarily UTF-8; only the
            # ASCII fields after it are parsed, so decode leniently.
            with open(
                "{}/{}/stat".format(task_dir, entry),
                "r",
                encoding="utf-8",
                errors="replace",
            ) as fh:
                raw_stat = fh.read()
            # /proc/<pid>/task/<tid>/stat layout (man 5 proc):
            #   pid (comm) state ppid pgrp session tty_nr tpgid flags minflt
            #   cminflt majflt cmajflt utime stime cutime cstime priority ...
            # ``comm`` is wrapped in parens and *may itself contain whitespace
            # or parentheses*, so the only safe split point is the last ')'.
            close_paren = raw_stat.rfind(")")
            if close_paren != -1:
                rest = raw_stat[close_paren + 1 :].split()
                # rest[0] = state, rest[15] = priority (field 18 in the man
                # page, with the first two fields already consumed).
                if rest:
                    state = rest[0]
                if len(rest) > 15:
                    try:
                        priority = int(rest[15])
                    except ValueError:
                        priority = None
        except OSError as exc:
            _logger.debug(
                "get_threads: could not read stat for tid=%s: %s", entry, exc
            )

        yield ThreadInfo(
            tid=tid,
            start_address=None,
            state=state,
            priority=priority,
            raw=entry,
        )


def get_processes() -> Generator[Tuple[int, str], None, None]:
    """
    Yield ``(pid, name)`` for every process by listing ``/proc`` — each numeric
    subdirectory is a live pid.

    ``name`` comes from ``/proc/<pid>/comm`` (the kernel truncates it to 15
    characters via ``TASK_COMM_LEN``). Processes that vanish mid-scan are
    skipped silently (logged at DEBUG).

    ``comm`` is raw bytes a process can set to anything (``prctl(PR_SET_NAME)``),
    so it is decoded as UTF-8 with replacement characters, independent of the
    locale, so one process with a non-UTF-8 name cannot raise
    ``UnicodeDecodeError`` here and break ``OpenProcess(name=...)`` for every
    other process.
    """
    try:
        entries = os.listdir("/proc")
    except OSError as exc:
        _logger.debug("get_processes: could not list /proc: %s", exc)
        return

    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)

        try:
            with open(
                "/proc/{}/comm".format(entry), "r", encoding="utf-8", errors="replace"
            ) as fh:
                name = fh.readline().rstrip("\n")
        except OSError as exc:
            # Race (process exited) or permission issue — skip it.
            _logger.debug("get_processes: could not read comm for pid=%s: %s", entry, exc)
            continue

        yield pid, name


def process_exists(pid: int) -> bool:
    """Return whether a process with ``pid`` currently exists (``/proc/<pid>``)."""
    if pid < 0:
        return False
    return os.path.isdir("/proc/{}".format(pid))


# --- Target identity (PID-reuse guard) --------------------------------------
#
# Unlike a Windows process handle or a macOS task port, nothing on the Linux
# path pins the target: process_vm_readv / process_vm_writev and /proc take a
# bare pid. Once the target exits and is reaped, the kernel may hand that pid
# to an unrelated process, and every later call would silently act on it. The
# helpers below let LinuxProcess bind to the *original* process at open time
# and verify it before touching the target again.


def open_pidfd(pid: int) -> Optional[int]:
    """
    Return a pidfd for ``pid`` (``pidfd_open(2)``, Linux 5.3+), or ``None``
    when pidfds are unavailable: the kernel predates them (``ENOSYS``), a
    seccomp policy blocks the syscall (``EPERM``, e.g. older container
    runtimes), ``pid`` is a non-leader thread id (``EINVAL``), the fd table is
    full, or this Python was built without ``os.pidfd_open`` /
    ``signal.pidfd_send_signal``. Callers then fall back to
    :func:`read_start_time`.

    Raises :class:`~PyMemoryEditor.ProcessIDNotExistsError` when the process
    is already gone (``ESRCH``) — it exited after the open-time existence
    check.
    """
    pidfd_open = getattr(os, "pidfd_open", None)
    if pidfd_open is None or not hasattr(signal, "pidfd_send_signal"):
        return None
    try:
        return pidfd_open(pid, 0)
    except ProcessLookupError:
        raise ProcessIDNotExistsError(pid)
    except OSError as exc:
        _logger.debug(
            "open_pidfd: pidfd_open(%d) failed (%s); falling back to the "
            "/proc start-time check for PID-reuse detection.",
            pid,
            exc,
        )
        return None


def pidfd_alive(pidfd: int) -> Optional[bool]:
    """
    Whether the process ``pidfd`` refers to still exists, via a null signal
    (``pidfd_send_signal(pidfd, 0, NULL, 0)``): one syscall, no side effect.

    The answer is about the original process, not its pid number — after the
    target is reaped the call fails with ``ESRCH`` even if the pid has already
    been reused. A zombie still counts as alive (it keeps its pid until it is
    reaped), matching the ``kill(pid, 0)`` semantics of the base class.
    ``EPERM`` (target owned by another user) also means "exists". Returns
    ``None`` when the probe itself cannot answer (e.g. ``EINVAL`` for a
    target outside this pid namespace), so the caller can fall back.
    """
    try:
        signal.pidfd_send_signal(pidfd, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        _logger.debug("pidfd_alive: pidfd_send_signal failed: %s", exc)
        return None
    return True


def read_start_time(pid: int) -> Optional[int]:
    """
    Return the process start time (field 22 of ``/proc/<pid>/stat``, in clock
    ticks since boot), or ``None`` if the file can't be read or parsed (the
    process is gone, or ``/proc`` is mounted with ``hidepid``).

    ``(pid, start time)`` identifies a process uniquely — a recycled pid gets
    a later start time — which makes it the PID-reuse guard on kernels
    without pidfds.
    """
    try:
        with open("/proc/{}/stat".format(pid), "rb") as fh:
            raw_stat = fh.read()
    except OSError:
        return None

    # `comm` is parenthesised and may itself contain spaces or ')': split
    # after the *last* ')'. rest[0] is field 3 (state), so field 22 is rest[19].
    close_paren = raw_stat.rfind(b")")
    if close_paren == -1:
        return None
    rest = raw_stat[close_paren + 1 :].split()
    try:
        return int(rest[19])
    except (IndexError, ValueError):
        return None
