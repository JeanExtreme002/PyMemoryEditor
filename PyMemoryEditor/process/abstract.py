# -*- coding: utf-8 -*-
from abc import ABC, abstractmethod
from typing import (
    Dict,
    Generator,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from ..enums import ScanTypesEnum
from .info import ProcessInfo
from .scanning import _PRESORTED_KEY


T = TypeVar("T")


class AbstractProcess(ABC):
    """
    Abstract class to represent a process.
    """

    @abstractmethod
    def __init__(
        self,
        *,
        window_title: Optional[str] = None,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        case_sensitive: bool = True,
    ):
        """
        :param window_title: window title of the target program (Windows only).
        :param process_name: name of the target process.
        :param pid: process ID.
        :param case_sensitive: when False, process_name matching ignores case
            (recommended on Windows where process names are case-insensitive).
        """
        self._process_info = ProcessInfo()

        # Set the attributes to the process.
        if pid is not None:
            self._process_info.pid = pid

        elif window_title:
            self._process_info.window_title = window_title

        elif process_name:
            self._process_info.set_process_name(
                process_name, case_sensitive=case_sensitive
            )

        else:
            raise TypeError(
                "You must pass an argument to one of these parameters (window_title, process_name, pid)."
            )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    @property
    def pid(self) -> int:
        return self._process_info.pid

    @abstractmethod
    def close(self) -> bool:
        """
        Close the process handle.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_memory_regions(self) -> Generator[dict, None, None]:
        """
        Generates dictionaries with the address, size and other
        information of each memory region used by the process.
        """
        raise NotImplementedError()

    def snapshot_memory_regions(self) -> List[Dict]:
        """
        Return a materialized snapshot of the process memory regions.

        Pass the result as the `memory_regions` keyword to subsequent calls of
        `search_by_value`, `search_by_value_between` or `search_by_addresses`
        to skip the region enumeration. Useful for "scan → refine → refine"
        workflows where the region map doesn't change between calls.

        Regions are pre-sorted by base address and tagged so that the helper
        functions in ``process.scanning`` skip their per-call ``sorted(...)``
        step on reuse. Don't reorder the returned list manually; if you must
        slice or filter, pass the result of ``sorted(my_slice, key=...)`` (or
        an unsorted slice) — the helpers re-sort defensively when the tag is
        missing.
        """
        regions = list(self.get_memory_regions())
        regions.sort(key=lambda region: region["address"])
        for region in regions:
            region[_PRESORTED_KEY] = True
        return regions

    @abstractmethod
    def search_by_addresses(
        self,
        pytype: Type[T],
        bufflength: Optional[int],
        addresses: Sequence[int],
        *,
        raise_error: bool = False,
        memory_regions: Optional[Sequence[Dict]] = None,
    ) -> Generator[Tuple[int, Optional[T]], None, None]:
        """
        Search the whole memory space, accessible to the process,
        for the provided list of addresses, returning their values.

        :param memory_regions: optional snapshot returned by `snapshot_memory_regions()`.
            Pass it to skip the region enumeration on hot iterative workflows.
        """
        raise NotImplementedError()

    @abstractmethod
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
        """
        Search the whole memory space, accessible to the process,
        for the provided value, returning the found addresses.

        :param pytype: type of value to be queried (bool, int, float, str or bytes).
        :param bufflength: value size in bytes (1, 2, 4, 8). For numeric types
            (int, float, bool) you may pass None to use the default
            (int→4, float→8, bool→1). str and bytes require an explicit value.
        :param value: value to be queried (bool, int, float, str or bytes).
        :param scan_type: the way to compare the values.
        :param progress_information: if True, a dictionary with the progress information will be returned.
        :param writeable_only: if True, search only at writeable memory regions.
        :param memory_regions: optional snapshot returned by `snapshot_memory_regions()`.
            Pass it to skip the region enumeration on hot iterative workflows.
        """
        raise NotImplementedError()

    @abstractmethod
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
        """
        Search the whole memory space, accessible to the process,
        for a value within the provided range, returning the found addresses.

        See `search_by_value` for parameter semantics.
        """
        raise NotImplementedError()

    @abstractmethod
    def read_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int] = None,
    ) -> T:
        """
        Return a value from a memory address.

        :param address: target memory address (ex: 0x006A9EC0).
        :param pytype: type of the value to be received (bool, int, float, str or bytes).
        :param bufflength: value size in bytes (1, 2, 4, 8). For numeric types
            (int, float, bool) you may omit this; defaults are int→4, float→8,
            bool→1. str and bytes require an explicit size.

        .. note::
           When ``pytype=str`` the raw bytes are decoded with
           ``errors="replace"``: any byte sequence that is not valid UTF-8
           becomes the Unicode replacement character (``U+FFFD``) instead of
           raising ``UnicodeDecodeError``. This matches ``search_by_addresses``
           and ``convert_from_byte_array``. Callers that need the original
           bytes verbatim (no decoding) should pass ``pytype=bytes``.
        """
        raise NotImplementedError()

    @abstractmethod
    def write_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int],
        value: Union[bool, int, float, str, bytes],
    ) -> Union[bool, int, float, str, bytes]:
        """
        Write a value to a memory address.

        :param address: target memory address (ex: 0x006A9EC0).
        :param pytype: type of value to be written into memory (bool, int, float, str or bytes).
        :param bufflength: value size in bytes. For numeric types (int, float,
            bool) you may pass None to use the default — int→4, float→8, bool→1.
            str and bytes require an explicit size.
        :param value: value to be written.
        """
        raise NotImplementedError()
