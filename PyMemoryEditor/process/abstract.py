# -*- coding: utf-8 -*-
import sys
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
from .module_info import ModuleInfo
from .scanning import _PRESORTED_KEY
from .thread_info import ThreadInfo


T = TypeVar("T")


class AbstractProcess(ABC):
    """
    Abstract class to represent a process.
    """

    @abstractmethod
    def __init__(
        self,
        *,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        case_sensitive: bool = True,
        exact_match: bool = True,
    ):
        """
        :param process_name: name of the target process.
        :param pid: process ID.
        :param case_sensitive: when False, process_name matching ignores case
            (recommended on Windows where process names are case-insensitive).
        :param exact_match: when False, ``process_name`` is matched as a
            substring — ``"chrome"`` matches ``"chrome.exe"`` / ``"Google Chrome"``.
            If more than one process matches, ``AmbiguousProcessNameError`` is
            raised so you can pick a PID from the list.
        """
        self._process_info = ProcessInfo()

        if pid is not None:
            self._process_info.pid = pid

        elif process_name:
            self._process_info.set_process_name(
                process_name,
                case_sensitive=case_sensitive,
                exact_match=exact_match,
            )

        else:
            raise TypeError(
                "You must pass an argument to one of these parameters (process_name, pid)."
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

    @abstractmethod
    def get_threads(self) -> Generator[ThreadInfo, None, None]:
        """
        Yield a :class:`~PyMemoryEditor.ThreadInfo` for every thread running
        inside the target process.

        The fields that each backend can fill in cheaply vary — see
        ``ThreadInfo`` for which attributes may be ``None`` per platform.
        The ``tid`` field's *meaning* is platform-specific (POSIX TID on
        Linux, DWORD TID on Windows, Mach port name on macOS).

        Use :attr:`main_thread` for the conventional "main thread" shortcut.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_modules(self) -> Generator[ModuleInfo, None, None]:
        """
        Yield a :class:`~PyMemoryEditor.ModuleInfo` for every module loaded in
        the target process — the main executable plus each shared library
        (``.dll`` / ``.so`` / ``.dylib``).

        A module's ``base_address`` is the load address the OS chose for this
        run; combine it with a static offset (``base_address + offset``) to
        reach a known location despite ASLR. That sum is the typical
        ``base_address`` argument to :meth:`resolve_pointer_chain`.

        Each backend fills the ``ModuleInfo`` fields with what its OS surfaces
        cheaply — see :class:`~PyMemoryEditor.ModuleInfo` for the per-platform
        meaning of ``raw`` and for when ``size`` may be ``0``.
        """
        raise NotImplementedError()

    @property
    def main_thread(self) -> Optional[ThreadInfo]:
        """
        The conventional "main thread" of the target — by convention, the
        thread with the smallest ``tid``. Returns ``None`` if the target has
        no listable threads (rare; typically means the process just exited).

        Useful as a quick hand-off into thread-specific operations, and as a
        sanity check ("is anything still running in there?").
        """
        threads = list(self.get_threads())
        if not threads:
            return None
        return min(threads, key=lambda t: t.tid)

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
    def search_by_pattern(
        self,
        pattern: Union[str, bytes, "object"],
        *,
        byte_length: int = 0,
        progress_information: bool = False,
        memory_regions: Optional[Sequence[Dict]] = None,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        """
        Scan the target's memory for a byte pattern (AOB) — the Cheat Engine /
        IDA technique for locating code or data that moves between builds.

        :param pattern: one of the forms accepted by
            :func:`PyMemoryEditor.util.pattern.compile_pattern` — an IDA-style
            hex string with ``?`` wildcards (``"48 8B ? ? 00"``), a raw bytes
            regex, or a pre-compiled ``re.Pattern[bytes]``.
        :param byte_length: required when ``pattern`` is a regex / pre-compiled
            Pattern — the number of bytes one match consumes. Ignored for
            IDA-style strings (inferred from the token count).
        :param progress_information: if True, yields ``(address, info)``
            tuples (same shape as ``search_by_value``).
        :param memory_regions: optional snapshot from
            ``snapshot_memory_regions()`` to skip region enumeration on
            iterative workflows.
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

    def resolve_pointer_chain(
        self,
        base_address: int,
        offsets: Sequence[int],
        *,
        ptr_size: int = 8,
    ) -> int:
        """
        Walk a multi-level pointer chain — the kind of recipe Cheat Engine
        exports for addresses that survive a process restart.

        Reads ``ptr_size`` bytes at ``base_address`` to obtain the first
        pointer, then for each offset in ``offsets[:-1]`` adds the offset and
        dereferences again. The **last** offset is added *without*
        dereferencing — the returned integer is the final address where the
        value of interest lives. Read or write it with the regular
        ``read_process_memory`` / ``write_process_memory`` calls.

        :param base_address: starting address — typically
            ``module_base + static_offset``.
        :param offsets: sequence of offsets to walk. Pass ``[]`` to dereference
            ``base_address`` once and return that pointer.
        :param ptr_size: pointer width — 8 for 64-bit targets (default), 4 for
            32-bit targets.

        Example
        -------
        Cheat-Engine cheat table entry::

            "game.exe" + 0x10F4F4 -> [+0x0] -> [+0x158]   ; HP

        Translates to::

            hp_addr = process.resolve_pointer_chain(0x14010F4F4, [0x0, 0x158])
            hp = process.read_process_memory(hp_addr, int, 4)
        """
        if ptr_size not in (4, 8):
            raise ValueError(
                "ptr_size must be 4 (32-bit target) or 8 (64-bit target)."
            )

        # ``read_process_memory(.., int, ..)`` decodes as a *signed* integer
        # (see util.convert.get_c_type_of). Pointers in the upper half of the
        # address space would come back negative and the next dereference would
        # land at an invalid kernel-side address. Read as raw bytes and
        # reinterpret as unsigned so every pointer fits the OS's natural range.
        byte_order = sys.byteorder

        def _read_ptr(addr: int) -> int:
            raw = self.read_process_memory(addr, bytes, ptr_size)
            return int.from_bytes(raw, byte_order, signed=False)

        if not offsets:
            return _read_ptr(base_address)

        current = _read_ptr(base_address)

        for offset in offsets[:-1]:
            current = _read_ptr(current + offset)

        return current + offsets[-1]
