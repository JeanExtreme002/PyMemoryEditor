# -*- coding: utf-8 -*-

from typing import Dict, Generator, Optional, Sequence, Tuple, Type, TypeVar, Union

from ..util import resolve_bufflength

from ..enums import ScanTypesEnum
from ..process import AbstractProcess
from ..process.errors import ClosedProcess
from .enums import ProcessOperationsEnum

from .functions import (
    CloseProcessHandle,
    GetMemoryRegions,
    GetProcessHandle,
    ReadProcessMemory,
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

# Default permission for a read-only workflow. VirtualQueryEx (used by
# get_memory_regions, snapshot_memory_regions, search_by_value*, and
# search_by_addresses) requires PROCESS_QUERY_INFORMATION in addition to
# PROCESS_VM_READ — without it the kernel returns 0 from VirtualQueryEx and
# every region scan comes back empty.
DEFAULT_PERMISSION = _PROCESS_VM_READ | _PROCESS_QUERY_INFORMATION


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
        window_title: Optional[str] = None,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        permission: Union[ProcessOperationsEnum, int] = DEFAULT_PERMISSION,
        case_sensitive: bool = False,
    ):
        """
        :param window_title: window title of the target program.
        :param process_name: name of the target process.
        :param pid: process ID.
        :param permission: access mode to the process. Defaults to the minimal
            read-only set: PROCESS_VM_READ | PROCESS_QUERY_INFORMATION (the
            latter is required by VirtualQueryEx, used internally for region
            enumeration). Combine flags with bitwise OR for write access, e.g.
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
            PROCESS_QUERY_INFORMATION.
        :param case_sensitive: when False (default on Windows), process_name
            matching ignores case to align with the OS convention.
        """
        super().__init__(
            window_title=window_title,
            process_name=process_name,
            pid=pid,
            case_sensitive=case_sensitive,
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

        self.__closed = CloseProcessHandle(self.__process_handle) != 0
        return self.__closed

    def get_memory_regions(self) -> Generator[dict, None, None]:
        self.__require_open()
        return GetMemoryRegions(self.__process_handle)

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
