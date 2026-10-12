# -*- coding: utf-8 -*-

import warnings
from typing import Dict, Generator, Optional, Pattern, Sequence, Tuple, Type, TypeVar, Union

from ..enums import ScanTypesEnum
from ..process import AbstractProcess
from ..process.errors import ClosedProcess
from ..process.module_info import ModuleInfo
from ..process.region import MemoryRegion
from ..process.thread_info import ThreadInfo
from ..util import UNSET, prepare_write, resolve_bufflength

from .functions import (
    allocate_memory,
    free_memory,
    get_image_segments,
    get_memory_regions,
    get_modules,
    get_task_for_pid,
    get_threads,
    read_process_memory,
    read_process_memory_into,
    release_task,
    search_addresses_by_pattern,
    search_addresses_by_value,
    search_values_by_addresses,
    write_process_memory,
    _detect_task_64bit,
    _macho_image_size,
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
        name: Optional[str] = None,
        pid: Optional[int] = None,
        permission=None,
        case_sensitive: bool = True,
        exact_match: bool = True,
        strict_bitness: bool = False,
    ):
        """
        :param name: name of the target process.
        :param pid: process ID.
        :param permission: accepted for cross-platform API parity; ignored on
            macOS (access is governed by entitlements / mach_task_self_).
            Passing a non-None value emits a ``UserWarning`` so a Windows-shaped
            mask doesn't disappear silently here — pass ``None`` (or omit) on
            non-Windows platforms.
        :param case_sensitive: when False, name matching ignores case.
        :param exact_match: when False, ``name`` is matched as a
            substring (e.g. ``"chrome"`` finds ``"Google Chrome"``).
        :param strict_bitness: raise ``BitnessDetectionError`` instead of
            defaulting to 64-bit when no Mach-O header can be read. See
            :class:`~PyMemoryEditor.AbstractProcess`.
        """
        super().__init__(
            name=name,
            pid=pid,
            case_sensitive=case_sensitive,
            exact_match=exact_match,
            strict_bitness=strict_bitness,
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

        # Base address -> allocated size; lets free_memory(address) work without
        # the caller tracking sizes (Mach's mach_vm_deallocate needs the size).
        self.__allocations: Dict[int, int] = {}

    def _require_open(self) -> None:
        if self.__closed:
            raise ClosedProcess()

    def close(self) -> bool:
        if self.__closed:
            return True

        # Mark closed even when the deallocate fails: the port name cannot be
        # retried meaningfully, and a later call must not reuse it. Report the
        # failure through the return value, like the Windows and Linux
        # backends (``release_task`` has already logged it).
        released = release_task(self.__task)
        self.__task = 0
        self.__closed = True
        return released

    def __del__(self) -> None:
        """
        Best-effort safety net for callers who forget to ``close()`` /
        use the context manager. The Mach task port lives until ``close()``
        deallocates it (no-op for the self-task) — leaving it leaked
        accumulates port-name slots in the host across multiple
        ``OpenProcess`` calls.

        ``__del__`` is not guaranteed to run (cyclic GC, interpreter
        teardown), so this is only a fallback. ``release_task`` never
        raises: a failed ``mach_port_deallocate`` is logged and reported
        through ``close()``'s return value.
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

    def _detect_is_64bit(self) -> Optional[bool]:
        self._require_open()
        return _detect_task_64bit(self.__task)

    def _iter_memory_regions(self) -> Generator[MemoryRegion, None, None]:
        return get_memory_regions(self.__task, self.pid)

    def _iter_threads(self) -> Generator[ThreadInfo, None, None]:
        return get_threads(self.__task)

    def _iter_modules(self) -> Generator[ModuleInfo, None, None]:
        return get_modules(self.__task, self.pid)

    def _static_image_ranges(self):
        """
        macOS-specific static ranges for the pointer scanner.

        ``ModuleInfo.size`` on macOS is only the ``__TEXT`` segment, so the base
        implementation would miss the writable ``__DATA`` segments where a
        process keeps its global pointers — making pointer scans on macOS find
        no static base at all. Here we expand each module into the runtime
        ranges of *all* its Mach-O segments (see ``get_image_segments``), tagged
        with the module name and ``__TEXT`` base so discovered paths still
        rebase across runs.
        """
        self._require_open()
        ranges = []
        # Modules are listed without their sizes: each size parses the image's
        # load commands, which get_image_segments parses anyway. The __TEXT
        # size is only needed as the fallback when no segment came back.
        for module in get_modules(self.__task, self.pid, image_sizes=False):
            segments = get_image_segments(self.__task, module.base_address)
            if segments:
                for start, size in segments:
                    ranges.append(
                        (start, start + size, module.name, module.base_address)
                    )
                continue
            text_size = _macho_image_size(self.__task, module.base_address)
            if text_size > 0:
                ranges.append(
                    (
                        module.base_address,
                        module.base_address + text_size,
                        module.name,
                        module.base_address,
                    )
                )
        return ranges

    def _scan_addresses(
        self,
        pytype: Type[T],
        bufflength: int,
        addresses: Sequence[int],
        *,
        raise_error: bool,
        memory_regions: Optional[Sequence[MemoryRegion]],
    ) -> Generator[Tuple[int, Optional[T]], None, None]:
        return search_values_by_addresses(
            self.__task,
            pytype,
            bufflength,
            addresses,
            memory_regions=memory_regions,
            raise_error=raise_error,
            pid=self.pid,
        )

    def _scan_values(
        self,
        pytype: Type,
        bufflength: int,
        target_value_bytes: Union[bytes, Tuple[bytes, ...]],
        scan_type: ScanTypesEnum,
        *,
        progress_information: bool,
        writeable_only: bool,
        memory_regions: Optional[Sequence[MemoryRegion]],
        aligned: bool,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        return search_addresses_by_value(
            self.__task,
            pytype,
            bufflength,
            value=None,  # given already encoded, as target_value_bytes
            scan_type=scan_type,
            progress_information=progress_information,
            writeable_only=writeable_only,
            memory_regions=memory_regions,
            pid=self.pid,
            aligned=aligned,
            target_value_bytes=target_value_bytes,
        )

    def _scan_pattern(
        self,
        compiled_pattern: Tuple[Pattern[bytes], int],
        *,
        progress_information: bool,
        memory_regions: Optional[Sequence[MemoryRegion]],
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        return search_addresses_by_pattern(
            self.__task,
            compiled_pattern[0],
            progress_information=progress_information,
            memory_regions=memory_regions,
            pid=self.pid,
            compiled_pattern=compiled_pattern,
        )

    def read_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int] = None,
    ) -> T:
        self._require_open()
        self._require_address(address)
        return read_process_memory(
            self.__task, address, pytype, resolve_bufflength(pytype, bufflength)
        )

    def read_process_memory_into(self, address: int, buffer: object) -> int:
        self._require_open()
        self._require_address(address)
        return read_process_memory_into(self.__task, address, buffer)

    def write_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int] = None,
        value: Union[bool, int, float, str, bytes] = UNSET,
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
        :param bufflength: value size in bytes. Optional — defaults to ``None``,
            which uses the default width for numeric types (int→4, float→8,
            bool→1) and writes the whole value for ``str`` / ``bytes``. For
            ``str`` / ``bytes`` an explicit value is a *maximum* that truncates
            the value (``str`` counts characters, ``bytes`` counts bytes) and
            never pads. Since it is optional, pass ``value`` by keyword when
            omitting it (``write_process_memory(addr, str, value="hi")``).
        :param value: value to be written.
        """
        self._require_open()
        self._require_address(address)
        w_pytype, w_length, w_value = prepare_write(pytype, bufflength, value)
        write_process_memory(self.__task, address, w_pytype, w_length, w_value)
        return value

    def allocate_memory(self, size: int, *, permission=None) -> int:
        self._require_open()
        address = allocate_memory(self.__task, size, permission)
        self.__allocations[address] = size
        return address

    def free_memory(self, address: int, size: int = 0) -> bool:
        self._require_open()
        self._require_address(address)
        # mach_vm_deallocate needs the exact size. Reuse the tracked size when
        # the caller doesn't supply one.
        actual_size = size or self.__allocations.get(address, 0)
        if actual_size <= 0:
            raise ValueError(
                "Unknown allocation at 0x%X — pass an explicit size= to free a "
                "region this object did not allocate." % address
            )
        free_memory(self.__task, address, actual_size)
        self.__allocations.pop(address, None)
        return True
