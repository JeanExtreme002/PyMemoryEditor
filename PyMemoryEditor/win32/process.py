# -*- coding: utf-8 -*-

import ctypes
import logging
from typing import Dict, Generator, Optional, Pattern, Sequence, Tuple, Type, TypeVar, Union

from ..util import UNSET, prepare_write, resolve_bufflength

from ..enums import ScanTypesEnum
from ..process import AbstractProcess
from ..process.errors import ClosedProcess
from ..process.module_info import ModuleInfo
from ..process.region import MemoryRegion
from ..process.thread_info import ThreadInfo
from .enums import ProcessOperationsEnum

from .functions import (
    AllocateMemory,
    CloseProcessHandle,
    FreeMemory,
    GetMemoryRegions,
    GetModules,
    GetProcessHandle,
    GetThreads,
    ReadProcessMemory,
    ReadProcessMemoryInto,
    SearchAddressesByPattern,
    SearchAddressesByValue,
    SearchValuesByAddresses,
    WriteProcessMemory,
    _detect_process_64bit,
    _process_has_exited,
)


T = TypeVar("T")

_logger = logging.getLogger("PyMemoryEditor")

_PROCESS_ALL_ACCESS = ProcessOperationsEnum.PROCESS_ALL_ACCESS.value
_PROCESS_VM_READ = ProcessOperationsEnum.PROCESS_VM_READ.value
_PROCESS_VM_WRITE = ProcessOperationsEnum.PROCESS_VM_WRITE.value
_PROCESS_VM_OPERATION = ProcessOperationsEnum.PROCESS_VM_OPERATION.value
_PROCESS_QUERY_INFORMATION = ProcessOperationsEnum.PROCESS_QUERY_INFORMATION.value

# Default permission for the typical read-and-write workflow. VirtualQueryEx
# (used by get_memory_regions, snapshot_memory_regions, search_by_value*, and
# search_by_addresses) requires PROCESS_QUERY_INFORMATION in addition to
# PROCESS_VM_READ — without it the kernel returns 0 from VirtualQueryEx and
# every region scan comes back empty. PROCESS_VM_WRITE | PROCESS_VM_OPERATION
# are bundled in so write_process_memory works without opt-in.
DEFAULT_PERMISSION = (
    _PROCESS_VM_READ
    | _PROCESS_VM_WRITE
    | _PROCESS_VM_OPERATION
    | _PROCESS_QUERY_INFORMATION
)


def _permission_value(permission) -> int:
    """Accept either a ProcessOperationsEnum or a raw int bitmask."""
    if isinstance(permission, ProcessOperationsEnum):
        return permission.value
    if isinstance(permission, int):
        return permission
    raise TypeError("permission must be a ProcessOperationsEnum or an int bitmask.")


def _has_all_access(perm: int) -> bool:
    """True when perm contains every bit of PROCESS_ALL_ACCESS."""
    return (perm & _PROCESS_ALL_ACCESS) == _PROCESS_ALL_ACCESS


def _can_read(perm: int) -> bool:
    return bool(perm & _PROCESS_VM_READ) or _has_all_access(perm)


def _can_write(perm: int) -> bool:
    needed = _PROCESS_VM_WRITE | _PROCESS_VM_OPERATION
    return ((perm & needed) == needed) or _has_all_access(perm)


class WindowsProcess(AbstractProcess):
    """
    Class to open a Windows process for reading, writing and searching at its memory.
    """

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        pid: Optional[int] = None,
        permission: Union[ProcessOperationsEnum, int] = DEFAULT_PERMISSION,
        case_sensitive: bool = False,
        exact_match: bool = True,
        strict_bitness: bool = False,
    ):
        """
        :param name: name of the target process.
        :param pid: process ID.
        :param permission: access mode to the process. Defaults to the
            read-and-write set: PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
            (PROCESS_QUERY_INFORMATION is required by VirtualQueryEx, used
            internally for region enumeration). Narrow the mask if you want
            a read-only handle, or pass PROCESS_ALL_ACCESS for full control.
        :param case_sensitive: when False (default on Windows), name
            matching ignores case to align with the OS convention.
        :param exact_match: when False, ``name`` is matched as a
            substring (e.g. ``"chrome"`` finds ``"chrome.exe"``).
        """
        super().__init__(
            name=name,
            pid=pid,
            case_sensitive=case_sensitive,
            exact_match=exact_match,
            strict_bitness=strict_bitness,
        )
        self.__closed = False

        # Base address -> allocated size, so free_memory(address) can be called
        # without the caller tracking sizes.
        self.__allocations: Dict[int, int] = {}

        self.__permission_value = _permission_value(permission)

        self.__process_handle = GetProcessHandle(
            self.__permission_value, False, self.pid
        )

    def _require_open(self) -> None:
        if self.__closed:
            raise ClosedProcess()

    def __require_operation(self) -> None:
        # VirtualAllocEx / VirtualFreeEx need PROCESS_VM_OPERATION.
        has_op = bool(self.__permission_value & _PROCESS_VM_OPERATION)
        if not (has_op or _has_all_access(self.__permission_value)):
            raise PermissionError(
                "The handle does not have permission to allocate or free memory. "
                "Open the process with PROCESS_VM_OPERATION (or PROCESS_ALL_ACCESS)."
            )

    def __require_read(self) -> None:
        if not _can_read(self.__permission_value):
            raise PermissionError(
                "The handle does not have permission to read the process memory. "
                "Open the process with PROCESS_VM_READ (or PROCESS_ALL_ACCESS)."
            )

    def __require_write(self) -> None:
        if not _can_write(self.__permission_value):
            raise PermissionError(
                "The handle does not have permission to write to the process memory. "
                "Open the process with PROCESS_VM_WRITE | PROCESS_VM_OPERATION "
                "(or PROCESS_ALL_ACCESS)."
            )

    def close(self) -> bool:
        if self.__closed:
            return True

        ctypes.set_last_error(0)
        result = CloseProcessHandle(self.__process_handle)
        # Mark closed regardless of CloseHandle's return value — leaving
        # `__closed=False` after a failed close means the *next* `close()`
        # would retry against a handle the kernel has already considered
        # released, which historically masked real bugs (double-close) and
        # made the object's state ambiguous.
        self.__closed = True
        if result == 0:
            # A failed CloseHandle leaks the handle until the interpreter
            # exits; it cannot be retried and nothing the caller does fixes
            # it. Log it (the Linux and macOS backends never raise from
            # `close()` either, and `__exit__` / `__del__` must not raise) and
            # report it through the return value.
            _logger.warning(
                "CloseHandle failed for process %d (err=%d); the handle is leaked.",
                self.pid,
                ctypes.get_last_error(),
            )
            return False
        return True

    def __del__(self) -> None:
        """
        Best-effort safety net for callers who forget to ``close()`` / use
        the context manager, mirroring the macOS backend: the process handle
        stays open — and keeps the target's pid and kernel object alive after
        it exits — until ``CloseHandle`` runs.

        ``__del__`` is not guaranteed to run (cyclic GC, interpreter
        teardown), so this is only a fallback.
        """
        # Avoid touching anything if construction failed before the handle
        # was set.
        if getattr(self, "_WindowsProcess__closed", True):
            return
        try:
            self.close()
        except Exception:
            # __del__ must not raise; the interpreter may be shutting down.
            pass

    def _target_alive(self) -> bool:
        # An open handle keeps the pid reserved after the process exits, so a
        # pid probe would say "alive" forever; GetExitCodeProcess asks the
        # handle itself. None means the handle lacks the query right (only a
        # custom narrowed `permission=` mask drops it). The pid probe is the
        # only answer left then, and for an exited target it is the wrong one:
        # the scan treats that target's reads as vanished pages.
        exited = _process_has_exited(self.__process_handle)
        if exited is None:
            return super()._target_alive()
        return not exited

    def _detect_is_64bit(self) -> Optional[bool]:
        self._require_open()
        return _detect_process_64bit(self.__process_handle)

    def _require_scanning(self) -> None:
        self._require_listing()
        self.__require_read()

    def _iter_memory_regions(self) -> Generator[MemoryRegion, None, None]:
        return GetMemoryRegions(self.__process_handle, self.pid)

    def _iter_threads(self) -> Generator[ThreadInfo, None, None]:
        # Toolhelp32 takes a PID, not a handle — no PROCESS_* right needed.
        return GetThreads(self.pid)

    def _iter_modules(self) -> Generator[ModuleInfo, None, None]:
        # The Toolhelp32 module snapshot takes a PID, not a handle; the handle
        # only tells a failed snapshot of an exited target apart.
        return GetModules(self.pid, process_handle=self.__process_handle)

    def _scan_addresses(
        self,
        pytype: Type[T],
        bufflength: int,
        addresses: Sequence[int],
        *,
        raise_error: bool,
        memory_regions: Optional[Sequence[MemoryRegion]],
    ) -> Generator[Tuple[int, Optional[T]], None, None]:
        return SearchValuesByAddresses(
            self.__process_handle,
            pytype,
            bufflength,
            addresses,
            memory_regions=memory_regions,
            raise_error=raise_error,
            pid=self.pid,
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
        return SearchAddressesByValue(
            self.__process_handle,
            pytype,
            bufflength,
            value=None,  # given already encoded, as target_value_bytes
            scan_type=scan_type,
            progress_information=progress_information,
            writeable_only=writeable_only,
            memory_regions=memory_regions,
            aligned=aligned,
            pid=self.pid,
            target_value_bytes=target_value_bytes,
        )

    def _scan_pattern(
        self,
        compiled_pattern: Tuple[Pattern[bytes], int],
        *,
        progress_information: bool,
        memory_regions: Optional[Sequence[MemoryRegion]],
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        return SearchAddressesByPattern(
            self.__process_handle,
            compiled_pattern[0],
            progress_information=progress_information,
            memory_regions=memory_regions,
            pid=self.pid,
            compiled_pattern=compiled_pattern,
        )

    def read_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int] = None,
    ) -> T:
        self._require_open()
        self.__require_read()
        self._require_address(address)
        return ReadProcessMemory(
            self.__process_handle,
            address,
            pytype,
            resolve_bufflength(pytype, bufflength),
        )

    def read_process_memory_into(self, address: int, buffer: object) -> int:
        self._require_open()
        self.__require_read()
        self._require_address(address)
        return ReadProcessMemoryInto(self.__process_handle, address, buffer)

    def write_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int] = None,
        value: Union[bool, int, float, str, bytes] = UNSET,
    ) -> Union[bool, int, float, str, bytes]:
        self._require_open()
        self.__require_write()
        self._require_address(address)
        w_pytype, w_length, w_value = prepare_write(pytype, bufflength, value)
        WriteProcessMemory(
            self.__process_handle,
            address,
            w_pytype,
            w_length,
            w_value,
        )
        return value

    def allocate_memory(self, size: int, *, permission=None) -> int:
        self._require_open()
        self.__require_operation()
        address = AllocateMemory(self.__process_handle, size, permission)
        self.__allocations[address] = size
        return address

    def free_memory(self, address: int, size: int = 0) -> bool:
        self._require_open()
        self.__require_operation()
        self._require_address(address)
        # MEM_RELEASE tears down whatever VirtualAlloc'd block starts at
        # `address` -- a heap segment or a thread stack just as readily as one
        # of ours -- so an address this object did not allocate is refused
        # unless the caller opts in with an explicit size, the same contract
        # as macOS (where the size is needed anyway). The size itself is not
        # passed on: MEM_RELEASE requires 0 and frees the whole allocation.
        if address not in self.__allocations and size <= 0:
            raise ValueError(
                "Unknown allocation at 0x%X: it was not returned by this "
                "object's allocate_memory. Pass an explicit size= to free a "
                "region this object did not allocate." % address
            )
        FreeMemory(self.__process_handle, address)
        self.__allocations.pop(address, None)
        return True
