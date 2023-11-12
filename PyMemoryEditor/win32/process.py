# -*- coding: utf-8 -*-

from ..process import AbstractProcess
from .enums import ProcessOperationsEnum, ScanTypesEnum

from .functions import (
    CloseProcessHandle,
    GetProcessHandle,
    ReadProcessMemory,
    SearchAllMemory,
    WriteProcessMemory
)

from typing import Generator, Optional, Tuple, Type, TypeVar, Union


T = TypeVar("T")


class WindowsProcess(AbstractProcess):
    """
    Class to open a Windows process for reading and writing memory.
    """

    def __init__(
        self,
        *,
        window_title: Optional[str] = None,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        permission: ProcessOperationsEnum = ProcessOperationsEnum.PROCESS_ALL_ACCESS
    ):
        """
        :param window_title: window title of the target program.
        :param process_name: name of the target process.
        :param pid: process ID.
        :param permission: access mode to the process.
        """
        super().__init__(
            window_title = window_title,
            process_name = process_name,
            pid = pid
        )

        # Instantiate the permission argument.
        self.__permission = permission

        # Get the process handle.
        self.__process_handle = GetProcessHandle(self.__permission.value, False, self.pid)

    def close(self):
        """
        Close the process handle.
        """
        return CloseProcessHandle(self.__process_handle)

    def search_by_value(
        self,
        pytype: Type[T],
        bufflength: int,
        value: Union[bool, int, float, str, bytes],
        scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
        *,
        progress_information: Optional[bool] = False,
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
        valid_permissions = [
            ProcessOperationsEnum.PROCESS_ALL_ACCESS.value,
            ProcessOperationsEnum.PROCESS_VM_READ.value
        ]
        if self.__permission.value not in valid_permissions:
            raise PermissionError("The handle does not have permission to read the process memory.")

        return SearchAllMemory(self.__process_handle, pytype, bufflength, value, scan_type, progress_information)

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
        valid_permissions = [
            ProcessOperationsEnum.PROCESS_ALL_ACCESS.value,
            ProcessOperationsEnum.PROCESS_VM_READ.value
        ]
        if self.__permission.value not in valid_permissions:
            raise PermissionError("The handle does not have permission to read the process memory.")

        return ReadProcessMemory(self.__process_handle, address, pytype, bufflength)

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
        valid_permissions = [
            ProcessOperationsEnum.PROCESS_ALL_ACCESS.value,
            ProcessOperationsEnum.PROCESS_VM_OPERATION.value | ProcessOperationsEnum.PROCESS_VM_WRITE.value
        ]
        if self.__permission.value not in valid_permissions:
            raise PermissionError("The handle does not have permission to write to the process memory.")

        return WriteProcessMemory(self.__process_handle, address, pytype, bufflength, value)
