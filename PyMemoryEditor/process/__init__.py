# -*- coding: utf-8 -*-
from abc import ABC, abstractmethod
from typing import Any, Optional, Type, TypeVar, Union

from ..process.info import ProcessInfo


T = TypeVar("T")


class AbstractProcess(ABC):
    """
    Abstract class to represent a process.
    """

    @abstractmethod
    def __init__(self, *, window_title: Optional[str] = None, process_name: Optional[str] = None, pid: Optional[int] = None):
        """
        :param window_title: window title of the target program.
        :param process_name: name of the target process.
        :param pid: process ID.
        """
        self._process_info = ProcessInfo()

        # Set the attributes to the process.
        if pid:
            self._process_info.pid = pid

        elif window_title:
            self._process_info.window_title = window_title

        elif process_name:
            self._process_info.process_name = process_name

        else:
            raise TypeError("You must pass an argument to one of these parameters (window_title, process_name, pid).")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    @property
    def pid(self) -> int:
        return self._process_info.pid

    @abstractmethod
    def close(self) -> Any:
        """
        Close the process handle.
        """
        raise NotImplementedError()

    @abstractmethod
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
        raise NotImplementedError()

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
        raise NotImplementedError()
