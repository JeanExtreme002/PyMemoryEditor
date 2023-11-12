# -*- coding: utf-8 -*-

from ..process import AbstractProcess

from functions import (
    read_process_memory, write_process_memory
)

from typing import Optional, Type, TypeVar, Union


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

    def close(self):
        """
        Close the process handle.
        """
        pass

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
        return read_process_memory(self.pid, address, pytype, bufflength)

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
        return write_process_memory(self.pid, address, pytype, bufflength, value)
