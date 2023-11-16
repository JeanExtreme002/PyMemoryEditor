# -*- coding: utf-8 -*-

from ..enums import ScanTypesEnum
from ..errors import ClosedProcess
from ..process import AbstractProcess
from .functions import read_process_memory, search_all_memory, write_process_memory
from typing import Generator, Optional, Tuple, Type, TypeVar, Union


T = TypeVar("T")


class LinuxProcess(AbstractProcess):
    """
    Class to open a Linux process for reading and writing memory.
    """

    def __init__(
        self,
        *,
        window_title: Optional[str] = None,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        **kwargs
    ):
        """
        :param window_title: window title of the target program.
        :param process_name: name of the target process.
        :param pid: process ID.
        """
        super().__init__(
            window_title = window_title,
            process_name = process_name,
            pid = pid
        )
        self.__closed = False

    def close(self) -> bool:
        """
        Close the process handle.
        """
        self.__closed = True
        return True

    def read_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: int
    ) -> T:
        """
        Return a value from a memory address.

        :param address: target memory address (ex: 0x006A9EC0).
        :param pytype: type of the value to be received (bool, int, float, str or bytes).
        :param bufflength: value size in bytes (1, 2, 4, 8).
        """
        if self.__closed: raise ClosedProcess()
        return read_process_memory(self.pid, address, pytype, bufflength)

    def search_by_value(
        self,
        pytype: Type[T],
        bufflength: int,
        value: Union[bool, int, float, str, bytes],
        scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
        *,
        progress_information: bool = False,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        """
        Search the whole memory space, accessible to the process,
        for the provided value, returning the found addresses.

        :param pytype: type of value to be queried (bool, int, float, str or bytes).
        :param bufflength: value size in bytes (1, 2, 4, 8).
        :param value: value to be queried (bool, int, float, str or bytes).
        :param scan_type: the way to compare the values.
        :param progress_information: if True, a dictionary with the progress information will be return.
        """
        if self.__closed: raise ClosedProcess()

        if scan_type in [ScanTypesEnum.VALUE_BETWEEN, ScanTypesEnum.NOT_VALUE_BETWEEN]:
            raise ValueError("Use the method search_by_value_between(...) to search within a range of values.")

        return search_all_memory(self.pid, pytype, bufflength, value, scan_type, progress_information)

    def search_by_value_between(
        self,
        pytype: Type[T],
        bufflength: int,
        start: Union[bool, int, float, str, bytes],
        end: Union[bool, int, float, str, bytes],
        *,
        not_between: bool = False,
        progress_information: bool = False,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        """
        Search the whole memory space, accessible to the process,
        for a value within the provided range, returning the found addresses.

        :param pytype: type of value to be queried (bool, int, float, str or bytes).
        :param bufflength: value size in bytes (1, 2, 4, 8).
        :param start: minimum inclusive value to be queried (bool, int, float, str or bytes).
        :param end: maximum inclusive value to be queried (bool, int, float, str or bytes).
        :param not_between: if True, return only addresses of values that are NOT within the range.
        :param progress_information: if True, a dictionary with the progress information will be return.
        """
        if self.__closed: raise ClosedProcess()

        scan_type = ScanTypesEnum.NOT_VALUE_BETWEEN if not_between else ScanTypesEnum.VALUE_BETWEEN
        return search_all_memory(self.pid, pytype, bufflength, (start, end), scan_type, progress_information)

    def write_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: int,
        value: Union[bool, int, float, str, bytes]
    ) -> T:
        """
        Write a value to a memory address.

        :param address: target memory address (ex: 0x006A9EC0).
        :param pytype: type of value to be written into memory (bool, int, float, str or bytes).
        :param bufflength: value size in bytes (1, 2, 4, 8).
        :param value: value to be written (bool, int, float, str or bytes).
        """
        if self.__closed: raise ClosedProcess()

        return write_process_memory(self.pid, address, pytype, bufflength, value)
