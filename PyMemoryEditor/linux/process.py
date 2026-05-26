# -*- coding: utf-8 -*-

import warnings
from typing import Dict, Generator, Optional, Sequence, Tuple, Type, TypeVar, Union

from ..enums import ScanTypesEnum
from ..process import AbstractProcess
from ..process.errors import ClosedProcess
from ..util import resolve_bufflength
from ..process.module_info import ModuleInfo
from ..process.thread_info import ThreadInfo
from .functions import (
    get_memory_regions,
    get_modules,
    get_threads,
    read_process_memory,
    search_addresses_by_pattern,
    search_addresses_by_value,
    search_values_by_addresses,
    write_process_memory,
)


T = TypeVar("T")


class LinuxProcess(AbstractProcess):
    """
    Class to open a Linux process for reading, writing and searching at its memory.
    """

    def __init__(
        self,
        *,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        permission=None,
        case_sensitive: bool = True,
        exact_match: bool = True,
    ):
        """
        :param process_name: name of the target process.
        :param pid: process ID.
        :param permission: accepted for cross-platform API parity; ignored on
            Linux (access is governed by ptrace_scope and process ownership).
            Passing a non-None value emits a ``UserWarning`` so a Windows-shaped
            mask doesn't disappear silently here — pass ``None`` (or omit) on
            non-Windows platforms.
        :param case_sensitive: when False, process_name matching ignores case.
        :param exact_match: when False, ``process_name`` is matched as a
            substring (e.g. ``"chrome"`` finds ``"chromium-browser"``).
        """
        super().__init__(
            process_name=process_name,
            pid=pid,
            case_sensitive=case_sensitive,
            exact_match=exact_match,
        )
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

    def __require_open(self) -> None:
        if self.__closed:
            raise ClosedProcess()

    def close(self) -> bool:
        self.__closed = True
        return True

    def get_memory_regions(self) -> Generator[dict, None, None]:
        self.__require_open()
        return get_memory_regions(self.pid)

    def get_threads(self) -> Generator[ThreadInfo, None, None]:
        self.__require_open()
        return get_threads(self.pid)

    def get_modules(self) -> Generator[ModuleInfo, None, None]:
        self.__require_open()
        return get_modules(self.pid)

    def read_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int] = None,
    ) -> T:
        self.__require_open()
        return read_process_memory(
            self.pid, address, pytype, resolve_bufflength(pytype, bufflength)
        )

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
        return search_values_by_addresses(
            self.pid,
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

        if scan_type in [ScanTypesEnum.VALUE_BETWEEN, ScanTypesEnum.NOT_VALUE_BETWEEN]:
            raise ValueError(
                "Use the method search_by_value_between(...) to search within a range of values."
            )

        return search_addresses_by_value(
            self.pid,
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
        return search_addresses_by_pattern(
            self.pid,
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

        scan_type = (
            ScanTypesEnum.NOT_VALUE_BETWEEN
            if not_between
            else ScanTypesEnum.VALUE_BETWEEN
        )
        return search_addresses_by_value(
            self.pid,
            pytype,
            resolve_bufflength(pytype, bufflength),
            (start, end),
            scan_type,
            progress_information,
            writeable_only,
            memory_regions=memory_regions,
        )

    def write_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int],
        value: Union[bool, int, float, str, bytes],
    ) -> Union[bool, int, float, str, bytes]:
        self.__require_open()
        return write_process_memory(
            self.pid, address, pytype, resolve_bufflength(pytype, bufflength), value
        )
