# -*- coding: utf-8 -*-

import warnings
from typing import Dict, Generator, Optional, Sequence, Tuple, Type, TypeVar, Union

from ..enums import ScanTypesEnum
from ..process import AbstractProcess
from ..process.errors import ClosedProcess
from ..util import resolve_bufflength

from .functions import (
    get_memory_regions,
    get_task_for_pid,
    read_process_memory,
    release_task,
    search_addresses_by_value,
    search_values_by_addresses,
    write_process_memory,
)


T = TypeVar("T")


class MacProcess(AbstractProcess):
    """
    Class to open a macOS process for reading, writing and searching at its memory.

    Note on entitlements: opening a process other than the current one requires
    the Python binary to be signed with the `com.apple.security.cs.debugger`
    entitlement (or SIP disabled and root). The current process always works
    because we use `mach_task_self_` directly. See README for details.
    """

    def __init__(
        self,
        *,
        window_title: Optional[str] = None,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        permission=None,
        case_sensitive: bool = True,
    ):
        """
        :param window_title: not supported on macOS (raises OSError).
        :param process_name: name of the target process.
        :param pid: process ID.
        :param permission: accepted for cross-platform API parity; ignored on
            macOS (access is governed by entitlements / mach_task_self_).
            Passing a non-None value emits a ``UserWarning`` so a Windows-shaped
            mask doesn't disappear silently here — pass ``None`` (or omit) on
            non-Windows platforms.
        :param case_sensitive: when False, process_name matching ignores case.
        """
        if window_title is not None:
            raise OSError(
                "Opening a process by window title is not supported on macOS."
            )

        super().__init__(
            window_title=None,
            process_name=process_name,
            pid=pid,
            case_sensitive=case_sensitive,
        )

        # `permission` is accepted for cross-platform parity but has no effect
        # on macOS. Stay silent for the documented parity case (`permission=None`);
        # warn when the caller passes a real value that's about to be discarded.
        if permission is not None:
            warnings.warn(
                "`permission` has no effect on macOS — access is governed by "
                "the com.apple.security.cs.debugger entitlement (or SIP off + "
                "root) and by mach_task_self_ for the current process. Pass "
                "`None` (or omit the argument) on non-Windows platforms.",
                UserWarning,
                stacklevel=2,
            )

        self.__closed = False
        self.__task = get_task_for_pid(self.pid)

    def __require_open(self) -> None:
        if self.__closed:
            raise ClosedProcess()

    def close(self) -> bool:
        if self.__closed:
            return True

        release_task(self.__task)
        self.__task = 0
        self.__closed = True
        return True

    def __del__(self) -> None:
        """
        Best-effort safety net for callers who forget to ``close()`` /
        use the context manager. The Mach task port lives until ``close()``
        deallocates it (no-op for the self-task) — leaving it leaked
        accumulates port-name slots in the host across multiple
        ``OpenProcess`` calls.

        ``__del__`` is not guaranteed to run (cyclic GC, interpreter
        teardown), so this is only a fallback. ``release_task`` itself
        catches errors via ``mach_port_deallocate`` returning a
        kern_return_t we never read here.
        """
        # Avoid touching anything if construction failed before __task was set.
        if getattr(self, "_MacProcess__closed", True):
            return
        try:
            self.close()
        except Exception:
            # __del__ must not raise; the port may already be gone if the
            # interpreter is shutting down.
            pass

    def get_memory_regions(self) -> Generator[dict, None, None]:
        self.__require_open()
        return get_memory_regions(self.__task)

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
            self.__task,
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
            self.__task,
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

        scan_type = (
            ScanTypesEnum.NOT_VALUE_BETWEEN
            if not_between
            else ScanTypesEnum.VALUE_BETWEEN
        )
        return search_addresses_by_value(
            self.__task,
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
        return read_process_memory(
            self.__task, address, pytype, resolve_bufflength(pytype, bufflength)
        )

    def write_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int],
        value: Union[bool, int, float, str, bytes],
    ) -> Union[bool, int, float, str, bytes]:
        """
        Write a value to a memory address.

        .. warning::
           **macOS-specific side effect.** When the target page is read-only,
           this method transparently elevates its protection via
           ``mach_vm_protect`` (with ``VM_PROT_COPY``), performs the write,
           and tries to restore the original protection. If the restore step
           fails (e.g. the target task disappears mid-call), a
           ``ResourceWarning`` is emitted and the page is left more
           permissive than it started — a *persistent* side effect outside
           the library's process. Defensive tooling should treat that
           warning as an event to log/alert on, not ignore.

        :param address: target memory address.
        :param pytype: type of value to be written (bool, int, float, str, bytes).
        :param bufflength: value size in bytes. ``None`` uses the default for
            numeric types (int→4, float→8, bool→1); ``str``/``bytes`` require
            an explicit size.
        :param value: value to be written.
        """
        self.__require_open()
        return write_process_memory(
            self.__task, address, pytype, resolve_bufflength(pytype, bufflength), value
        )
