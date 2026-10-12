# -*- coding: utf-8 -*-

import logging
import os
import warnings
from typing import Generator, Optional, Pattern, Sequence, Tuple, Type, TypeVar, Union

from ..enums import ScanTypesEnum
from ..process import AbstractProcess
from ..process.errors import ClosedProcess, ProcessIDNotExistsError
from ..util import UNSET, prepare_write, resolve_bufflength
from ..process.module_info import ModuleInfo
from ..process.region import MemoryRegion
from ..process.thread_info import ThreadInfo
from .functions import (
    _detect_process_64bit,
    get_memory_regions,
    get_modules,
    get_threads,
    open_pidfd,
    pidfd_alive,
    process_exists,
    read_process_memory,
    read_process_memory_into,
    search_addresses_by_pattern,
    search_addresses_by_value,
    search_values_by_addresses,
    read_start_time,
    write_process_memory,
)


_logger = logging.getLogger("PyMemoryEditor")


T = TypeVar("T")


class LinuxProcess(AbstractProcess):
    """
    Class to open a Linux process for reading, writing and searching at its memory.
    """

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        pid: Optional[int] = None,
        permission=None,
        case_sensitive: bool = True,
        exact_match: bool = True,
        strict_bitness: bool = False,
    ):
        """
        :param name: name of the target process.
        :param pid: process ID.
        :param permission: accepted for cross-platform API parity; ignored on
            Linux (access is governed by ptrace_scope and process ownership).
            Passing a non-None value emits a ``UserWarning`` so a Windows-shaped
            mask doesn't disappear silently here — pass ``None`` (or omit) on
            non-Windows platforms.
        :param case_sensitive: when False, name matching ignores case.
        :param exact_match: when False, ``name`` is matched as a
            substring (e.g. ``"chrome"`` finds ``"chromium-browser"``).
        :param strict_bitness: raise ``BitnessDetectionError`` instead of
            guessing the host word size when the target's ELF class can't be
            read. See :class:`~PyMemoryEditor.AbstractProcess`.
        """
        super().__init__(
            name=name,
            pid=pid,
            case_sensitive=case_sensitive,
            exact_match=exact_match,
            strict_bitness=strict_bitness,
        )

        # Bind to *this* process, not to its pid number. Linux I/O takes a
        # bare pid (no handle / task port pins the target as on Windows and
        # macOS), so once the target exits and is reaped the pid can be
        # recycled and every later call would silently hit an unrelated
        # process. A pidfd refers to the original process for its whole
        # lifetime; where pidfds are unavailable, the /proc start time —
        # unique per (pid, boot) — stands in. Both are verified before each
        # operation (see `__require_target`).
        self.__pidfd: Optional[int] = open_pidfd(self.pid)
        self.__start_time: Optional[int] = read_start_time(self.pid)
        self.__closed = False

        # `permission` is accepted for cross-platform parity but has no effect
        # on Linux. Stay silent for the documented parity case (`permission=None`);
        # warn when the caller passes a real value that's about to be discarded.
        if permission is not None:
            warnings.warn(
                "`permission` has no effect on Linux — access is governed by "
                "ptrace_scope and process ownership. Pass `None` (or omit the "
                "argument) on non-Windows platforms.",
                UserWarning,
                stacklevel=2,
            )

    def _require_open(self) -> None:
        if self.__closed:
            raise ClosedProcess()

    def __require_target(self, *, hot_path: bool = False) -> None:
        """
        Raise ``ClosedProcess`` after ``close()``, and
        :class:`~PyMemoryEditor.ProcessIDNotExistsError` once the process this
        object was opened on has exited — even if its pid now belongs to
        another process. One ``pidfd_send_signal`` per call on kernels with
        pidfds (5.3+, ~0.3 us); a ``/proc/<pid>/stat`` read otherwise.

        ``hot_path`` marks single-value reads, which callers issue in tight
        loops: they are verified only when the cheap pidfd probe is
        available. Without a pidfd the start-time read would roughly
        quadruple the cost of every read, so there they are not verified.
        Writes are always verified, and so are scans and listings
        when they are called; their generators are not re-verified between
        items, so one held while the target exits and its pid is reused would
        read the newcomer -- create the scan again after a long pause.
        """
        self._require_open()
        if hot_path and self.__pidfd is None:
            return
        if not self._target_alive():
            raise ProcessIDNotExistsError(self.pid)

    def _target_alive(self) -> bool:
        pidfd = self.__pidfd
        if pidfd is not None:
            alive = pidfd_alive(pidfd)
            if alive is not None:
                return alive
        if self.__start_time is not None:
            current = read_start_time(self.pid)
            if current is not None:
                return current == self.__start_time
            # Unreadable now: gone (no /proc entry) or hidden — ask by pid.
            return process_exists(self.pid)
        return super()._target_alive()

    def close(self) -> bool:
        if self.__closed:
            return True

        self.__closed = True
        pidfd, self.__pidfd = self.__pidfd, None
        if pidfd is not None:
            try:
                os.close(pidfd)
            except OSError as exc:
                # Never raise from close() (`__exit__` / `__del__` call it);
                # report through the return value like the Windows backend.
                _logger.warning(
                    "Closing the pidfd of process %d failed: %s", self.pid, exc
                )
                return False
        return True

    def __del__(self) -> None:
        """
        Best-effort safety net for callers who forget to ``close()`` / use
        the context manager: releases the pidfd, mirroring how the Windows and
        macOS backends release their handle / task port. ``__del__`` is not
        guaranteed to run, so this is only a fallback.
        """
        # Construction failed before the pidfd was set: nothing to release.
        if getattr(self, "_LinuxProcess__closed", True):
            return
        try:
            self.close()
        except Exception:
            # __del__ must not raise; the interpreter may be shutting down.
            pass

    def _detect_is_64bit(self) -> Optional[bool]:
        self.__require_target()
        return _detect_process_64bit(self.pid)

    def _require_listing(self) -> None:
        self.__require_target()

    def _iter_memory_regions(self) -> Generator[MemoryRegion, None, None]:
        return get_memory_regions(self.pid)

    def _iter_threads(self) -> Generator[ThreadInfo, None, None]:
        return get_threads(self.pid)

    def _iter_modules(self) -> Generator[ModuleInfo, None, None]:
        return get_modules(self.pid)

    def read_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int] = None,
    ) -> T:
        self.__require_target(hot_path=True)
        self._require_address(address)
        return read_process_memory(
            self.pid, address, pytype, resolve_bufflength(pytype, bufflength)
        )

    def read_process_memory_into(self, address: int, buffer: object) -> int:
        self.__require_target(hot_path=True)
        self._require_address(address)
        return read_process_memory_into(self.pid, address, buffer)

    def _scan_addresses(
        self,
        pytype: Type[T],
        bufflength: int,
        addresses: Sequence[int],
        *,
        raise_error: bool,
        memory_regions: Optional[Sequence[MemoryRegion]],
    ) -> Generator[Tuple[int, Optional[T]], None, None]:
        return search_values_by_addresses(
            self.pid,
            pytype,
            bufflength,
            addresses,
            memory_regions=memory_regions,
            raise_error=raise_error,
        )

    def _scan_values(
        self,
        pytype: Type,
        bufflength: int,
        target_value_bytes: Union[bytes, Tuple[bytes, ...]],
        scan_type: ScanTypesEnum,
        *,
        progress_information: bool,
        writeable_only: bool,
        memory_regions: Optional[Sequence[MemoryRegion]],
        aligned: bool,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        return search_addresses_by_value(
            self.pid,
            pytype,
            bufflength,
            value=None,  # given already encoded, as target_value_bytes
            scan_type=scan_type,
            progress_information=progress_information,
            writeable_only=writeable_only,
            memory_regions=memory_regions,
            aligned=aligned,
            target_value_bytes=target_value_bytes,
        )

    def _scan_pattern(
        self,
        compiled_pattern: Tuple[Pattern[bytes], int],
        *,
        progress_information: bool,
        memory_regions: Optional[Sequence[MemoryRegion]],
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        return search_addresses_by_pattern(
            self.pid,
            compiled_pattern[0],
            progress_information=progress_information,
            memory_regions=memory_regions,
            compiled_pattern=compiled_pattern,
        )

    def write_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int] = None,
        value: Union[bool, int, float, str, bytes] = UNSET,
    ) -> Union[bool, int, float, str, bytes]:
        self.__require_target()
        self._require_address(address)
        w_pytype, w_length, w_value = prepare_write(pytype, bufflength, value)
        write_process_memory(self.pid, address, w_pytype, w_length, w_value)
        return value

    def allocate_memory(self, size: int, *, permission=None) -> int:
        self._require_open()
        raise NotImplementedError(
            "allocate_memory is not supported on Linux: there is no syscall to "
            "allocate memory in another process's address space (mmap only "
            "affects the calling process). Doing so would require a ptrace-based "
            "engine to make the target call mmap itself. Use the Windows or "
            "macOS backend for cross-process allocation."
        )

    def free_memory(self, address: int, size: int = 0) -> bool:
        self._require_open()
        raise NotImplementedError(
            "free_memory is not supported on Linux (see allocate_memory): "
            "releasing memory in another process would require a ptrace-based "
            "engine to make the target call munmap itself."
        )
