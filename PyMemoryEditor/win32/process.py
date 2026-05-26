# -*- coding: utf-8 -*-

import ctypes
from typing import Dict, Generator, Optional, Sequence, Tuple, Type, TypeVar, Union

from ..util import resolve_bufflength

from ..enums import ScanTypesEnum
from ..process import AbstractProcess
from ..process.errors import ClosedProcess
from ..process.module_info import ModuleInfo
from ..process.thread_info import ThreadInfo
from .enums import ProcessOperationsEnum

from .functions import (
    CloseProcessHandle,
    GetMemoryRegions,
    GetModules,
    GetProcessHandle,
    GetThreads,
    ReadProcessMemory,
    SearchAddressesByPattern,
    SearchAddressesByValue,
    SearchValuesByAddresses,
    WriteProcessMemory,
)


T = TypeVar("T")

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
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        permission: Union[ProcessOperationsEnum, int] = DEFAULT_PERMISSION,
        case_sensitive: bool = False,
        exact_match: bool = True,
    ):
        """
        :param process_name: name of the target process.
        :param pid: process ID.
        :param permission: access mode to the process. Defaults to the
            read-and-write set: PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
            (PROCESS_QUERY_INFORMATION is required by VirtualQueryEx, used
            internally for region enumeration). Narrow the mask if you want
            a read-only handle, or pass PROCESS_ALL_ACCESS for full control.
        :param case_sensitive: when False (default on Windows), process_name
            matching ignores case to align with the OS convention.
        :param exact_match: when False, ``process_name`` is matched as a
            substring (e.g. ``"chrome"`` finds ``"chrome.exe"``).
        """
        super().__init__(
            process_name=process_name,
            pid=pid,
            case_sensitive=case_sensitive,
            exact_match=exact_match,
        )
        self.__closed = False

        self.__permission_value = _permission_value(permission)

        self.__process_handle = GetProcessHandle(
            self.__permission_value, False, self.pid
        )

    def __require_open(self) -> None:
        if self.__closed:
            raise ClosedProcess()

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

        result = CloseProcessHandle(self.__process_handle)
        # Mark closed regardless of CloseHandle's return value — leaving
        # `__closed=False` after a failed close means the *next* `close()`
        # would retry against a handle the kernel has already considered
        # released, which historically masked real bugs (double-close) and
        # made the object's state ambiguous.
        self.__closed = True
        if result == 0:
            # Surface the underlying Win32 error code via OSError so the
            # caller knows something went wrong, instead of the previous
            # silent `return False`. Callers using the `with` context manager
            # will see the exception; callers checking the return value of
            # close() now get a strict pass/fail (True only on success).
            last_error = ctypes.get_last_error()
            if last_error:
                raise ctypes.WinError(last_error, "CloseHandle failed.")
            raise OSError("CloseHandle failed.")
        return True

    def get_memory_regions(self) -> Generator[dict, None, None]:
        self.__require_open()
        return GetMemoryRegions(self.__process_handle)

    def get_threads(self) -> Generator[ThreadInfo, None, None]:
        self.__require_open()
        # Toolhelp32 takes a PID, not a handle — no PROCESS_* right needed.
        return GetThreads(self.pid)

    def get_modules(self) -> Generator[ModuleInfo, None, None]:
        self.__require_open()
        # The Toolhelp32 module snapshot takes a PID, not a handle.
        return GetModules(self.pid)

    def search_by_addresses(
        self,
        pytype: Type[T],
        bufflength: Optional[int],
        addresses: Sequence[int],
        *,
        raise_error: bool = False,
        memory_regions: Optional[Sequence[Dict]] = None,
    ) -> Generator[Tuple[int, Optional[T]], None, None]:
        self.__require_open()
        self.__require_read()
        return SearchValuesByAddresses(
            self.__process_handle,
            pytype,
            resolve_bufflength(pytype, bufflength),
            addresses,
            memory_regions=memory_regions,
            raise_error=raise_error,
        )

    def search_by_value(
        self,
        pytype: Type[T],
        bufflength: Optional[int],
        value: Union[bool, int, float, str, bytes],
        scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
        *,
        progress_information: bool = False,
        writeable_only: bool = False,
        memory_regions: Optional[Sequence[Dict]] = None,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        self.__require_open()
        self.__require_read()

        if scan_type in [ScanTypesEnum.VALUE_BETWEEN, ScanTypesEnum.NOT_VALUE_BETWEEN]:
            raise ValueError(
                "Use the method search_by_value_between(...) to search within a range of values."
            )

        return SearchAddressesByValue(
            self.__process_handle,
            pytype,
            resolve_bufflength(pytype, bufflength),
            value,
            scan_type,
            progress_information,
            writeable_only,
            memory_regions=memory_regions,
        )

    def search_by_pattern(
        self,
        pattern,
        *,
        byte_length: int = 0,
        progress_information: bool = False,
        memory_regions: Optional[Sequence[Dict]] = None,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        self.__require_open()
        self.__require_read()
        return SearchAddressesByPattern(
            self.__process_handle,
            pattern,
            byte_length=byte_length,
            progress_information=progress_information,
            memory_regions=memory_regions,
        )

    def search_by_value_between(
        self,
        pytype: Type[T],
        bufflength: Optional[int],
        start: Union[bool, int, float, str, bytes],
        end: Union[bool, int, float, str, bytes],
        *,
        not_between: bool = False,
        progress_information: bool = False,
        writeable_only: bool = False,
        memory_regions: Optional[Sequence[Dict]] = None,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        self.__require_open()
        self.__require_read()

        scan_type = (
            ScanTypesEnum.NOT_VALUE_BETWEEN
            if not_between
            else ScanTypesEnum.VALUE_BETWEEN
        )
        return SearchAddressesByValue(
            self.__process_handle,
            pytype,
            resolve_bufflength(pytype, bufflength),
            (start, end),
            scan_type,
            progress_information,
            writeable_only,
            memory_regions=memory_regions,
        )

    def read_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int] = None,
    ) -> T:
        self.__require_open()
        self.__require_read()
        return ReadProcessMemory(
            self.__process_handle,
            address,
            pytype,
            resolve_bufflength(pytype, bufflength),
        )

    def write_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int],
        value: Union[bool, int, float, str, bytes],
    ) -> Union[bool, int, float, str, bytes]:
        self.__require_open()
        self.__require_write()
        return WriteProcessMemory(
            self.__process_handle,
            address,
            pytype,
            resolve_bufflength(pytype, bufflength),
            value,
        )
