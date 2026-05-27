# -*- coding: utf-8 -*-
import sys
from abc import ABC, abstractmethod
from typing import (
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    TYPE_CHECKING,
    Union,
)

from ..enums import ScanTypesEnum
from .info import ProcessInfo
from .module_info import ModuleInfo
from .scanning import _PRESORTED_KEY
from .thread_info import ThreadInfo

if TYPE_CHECKING:
    from .pointer_scan import PointerPath
    from .remote_pointer import RemotePointer


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

    @abstractmethod
    def allocate_memory(self, size: int, *, permission=None) -> int:
        """
        Reserve and commit ``size`` bytes inside the target process's address
        space and return the base address of the new region.

        The returned address is owned by the target and survives until you pass
        it to :meth:`free_memory`. Write to it with :meth:`write_process_memory`
        like any other address. The library remembers the size of each
        allocation, so ``free_memory(address)`` works without you tracking it.

        :param size: number of bytes to allocate (rounded up to the OS page
            size by the kernel).
        :param permission: optional, **platform-specific** protection for the
            new region — same spirit as ``OpenProcess(permission=...)``:

            * **Windows**: a ``MemoryProtectionsEnum`` / ``PAGE_*`` value.
              Defaults to ``PAGE_EXECUTE_READWRITE`` (read/write/execute) so the
              region is usable for both data and injected code.
            * **macOS**: a ``VM_PROT_*`` bitmask. ``None`` leaves the Mach
              default (read+write). Requesting execute may fail under the
              hardened runtime (notably RWX on Apple Silicon).
            * **Linux**: not supported — see below.

        :raises NotImplementedError: on Linux, which has no cross-process
            allocation syscall (it would require a ptrace-based code-injection
            engine to make the target call ``mmap`` itself).
        """
        raise NotImplementedError()

    @abstractmethod
    def free_memory(self, address: int, size: int = 0) -> bool:
        """
        Release a region previously returned by :meth:`allocate_memory`.

        :param address: base address returned by :meth:`allocate_memory`.
        :param size: size of the region in bytes. May be left ``0`` to reuse
            the size recorded when the region was allocated (required on macOS,
            ignored on Windows where ``MEM_RELEASE`` frees the whole
            allocation). Pass an explicit size only to free a region this
            object did not allocate.
        :return: ``True`` on success.

        :raises NotImplementedError: on Linux (see :meth:`allocate_memory`).
        """
        raise NotImplementedError()

    def get_pointer(
        self,
        base_address: int,
        offsets: Optional[Sequence[int]] = None,
        *,
        pytype: Type = int,
        bufflength: Optional[int] = None,
        ptr_size: int = 8,
    ) -> "RemotePointer":
        """
        Build a :class:`~PyMemoryEditor.RemotePointer` bound to this process —
        a live, re-resolving handle to a typed value in the target.

        Convenience wrapper around the ``RemotePointer(self, ...)`` constructor;
        see that class for the meaning of every parameter (notably ``offsets``,
        whose ``None`` vs ``[]`` distinction selects a direct handle vs a
        single-dereference chain).

        Example
        -------
        ::

            hp = process.get_pointer(0x14010F4F4, [0x0, 0x158], pytype=int, bufflength=4)
            hp.value -= 10
        """
        from .remote_pointer import RemotePointer

        return RemotePointer(
            self,
            base_address,
            offsets,
            pytype=pytype,
            bufflength=bufflength,
            ptr_size=ptr_size,
        )

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

    def _static_image_ranges(self) -> List[Tuple[int, int, str, int]]:
        """
        Return ``(start, end, module_name, module_base)`` tuples covering the
        address ranges considered *static* (fixed offset from a module base
        across runs) — the valid bases for a pointer chain found by
        :meth:`scan_pointer_paths`.

        Default implementation: one range per loaded module spanning its whole
        image (``base_address`` .. ``base_address + size``). This is correct on
        Windows (``modBaseSize`` is the full image) and Linux (the mapped span
        covers ``.data`` / ``.bss``). macOS overrides this because
        ``ModuleInfo.size`` there is only the ``__TEXT`` segment, which would
        miss the writable ``__DATA`` segments where global pointers live.
        """
        ranges: List[Tuple[int, int, str, int]] = []
        for module in self.get_modules():
            if module.size > 0:
                ranges.append(
                    (
                        module.base_address,
                        module.base_address + module.size,
                        module.name,
                        module.base_address,
                    )
                )
        return ranges

    def scan_pointer_paths(
        self,
        target_address: int,
        *,
        max_depth: int = 5,
        max_offset: int = 0x400,
        ptr_size: int = 8,
        aligned: bool = True,
        writable_only: bool = True,
        static_ranges: Optional[Sequence[Tuple[int, int]]] = None,
        max_results: Optional[int] = None,
        memory_regions: Optional[Sequence[Dict]] = None,
        progress_callback: Optional["Callable[[float], None]"] = None,
    ) -> Generator["PointerPath", None, None]:
        """
        Reverse pointer scan — Cheat Engine's "Pointer scan", the inverse of
        :meth:`resolve_pointer_chain`.

        Given a *dynamic* ``target_address`` (one that changes every run, e.g.
        an address :meth:`search_by_value` just found), discover **static
        pointer paths** that resolve to it: chains
        ``module + offset -> [+o1] -> ... -> +on`` whose base is fixed inside a
        loaded module, so the recipe keeps working across restarts despite
        ASLR. Each yielded :class:`~PyMemoryEditor.PointerPath` plugs straight
        back into :meth:`resolve_pointer_chain` / :class:`RemotePointer`.

        Built entirely on :meth:`get_memory_regions`, :meth:`read_process_memory`
        and :meth:`get_modules`, so it behaves identically on Windows, Linux and
        macOS.

        :param target_address: the dynamic address to find pointer paths to.
        :param max_depth: maximum pointer levels (offsets) in a chain. Deeper
            scans find more paths but cost exponentially more — 1–7 is typical.
        :param max_offset: largest positive offset a single hop may add (the
            struct-size window). Larger values catch fields deeper inside
            objects at the cost of many more candidate paths.
        :param ptr_size: pointer width — 8 for 64-bit targets (default), 4 for
            32-bit.
        :param aligned: only consider pointers at natural alignment (default,
            much faster). Set ``False`` to also scan misaligned slots (slow).
        :param writable_only: build the pointer map from writable memory only
            (default). This is both faster and usually correct — every hop in a
            live chain reads a pointer the program writes (global pointers in
            ``.data``, object fields on the heap). Set ``False`` to also include
            read-only pointers (e.g. vtables), which is slower and noisier.
        :param static_ranges: explicit ``(start, size)`` ranges to treat as
            valid chain bases. Defaults to the image range of every loaded
            module. **macOS note:** ``ModuleInfo.size`` there covers only the
            ``__TEXT`` segment, so global pointers in ``__DATA`` may fall
            outside the default static set — pass ``static_ranges`` explicitly
            (or accept reduced static-base coverage) on macOS.
        :param max_results: stop after yielding this many paths (``None`` = no
            cap). Recommended for shallow exploration of large targets.
        :param memory_regions: optional snapshot from
            :meth:`snapshot_memory_regions` to skip region enumeration.
        :param progress_callback: optional ``callback(fraction)`` invoked as the
            pointer map is built (the long phase), ``fraction`` in ``[0, 1]``.

        Example
        -------
        ::

            hp_addr = next(process.search_by_value(int, 4, 1234))
            for path in process.scan_pointer_paths(hp_addr, max_depth=5, max_results=20):
                print(path)                 # "game.exe"+0x10F4F4 -> [+0x0] -> +0x158
                assert path.resolve(process) == hp_addr

            # In a later run, after the module moved (ASLR):
            live = path.rebase(process).to_pointer(process, pytype=int, bufflength=4)
            live.value = 9999
        """
        from .pointer_scan import (
            AddressRanges,
            build_pointer_map,
            find_pointer_paths,
        )

        if ptr_size not in (4, 8):
            raise ValueError(
                "ptr_size must be 4 (32-bit target) or 8 (64-bit target)."
            )

        if memory_regions is None:
            memory_regions = list(self.get_memory_regions())

        # Pointers may point anywhere readable; chain hops live in writable
        # memory (the program writes them) unless the caller opts into read-only.
        readable = [r for r in memory_regions if r.get("is_readable", True)]
        mapped_ranges = AddressRanges(
            [(r["address"], r["address"] + r["size"]) for r in readable]
        )

        scan_regions = [
            (r["address"], r["size"])
            for r in readable
            if (r.get("is_writable", True) if writable_only else True)
        ]

        # Image ranges drive both static-base detection and module naming. Each
        # entry is (start, end, module_name, module_base). On macOS this spans
        # every Mach-O segment (so global pointers in __DATA count as static),
        # not just __TEXT — see _static_image_ranges.
        image_ranges = self._static_image_ranges()

        if static_ranges is not None:
            static = AddressRanges(
                [(start, start + size) for start, size in static_ranges]
            )
        else:
            static = AddressRanges([(s, e) for s, e, _, _ in image_ranges])

        # Map a static base back to the module that owns it (for ASLR rebasing).
        sorted_images = sorted(image_ranges)

        def module_resolver(address: int) -> Optional[Tuple[str, int]]:
            for start, end, name, base in sorted_images:
                if start <= address < end:
                    return name, base
            return None

        def read_chunk(address: int, size: int) -> Optional[bytes]:
            try:
                return self.read_process_memory(address, bytes, size)
            except Exception:  # noqa: BLE001 — unreadable page mid-scan; skip it
                return None

        values, addresses = build_pointer_map(
            scan_regions,
            read_chunk,
            mapped_ranges,
            ptr_size=ptr_size,
            aligned=aligned,
            progress_callback=progress_callback,
        )

        yield from find_pointer_paths(
            target_address,
            values,
            addresses,
            static.__contains__,
            module_resolver,
            max_depth=max_depth,
            max_offset=max_offset,
            ptr_size=ptr_size,
            max_results=max_results,
        )

    def save_pointer_paths(
        self,
        paths: "Iterable[PointerPath]",
        file: str,
    ) -> None:
        """
        Save pointer paths (from :meth:`scan_pointer_paths`) to a JSON file so
        you can reuse them in a later run with :meth:`rescan_pointer_paths` or
        :meth:`compare_pointer_scans`.

        The file stores each path's module + offsets — the part that survives a
        restart — so it stays valid even though absolute addresses change.

        Example
        -------
        ::

            paths = process.scan_pointer_paths(0x1FA3C140)
            process.save_pointer_paths(paths, "scan1.json")
        """
        import json

        payload = {
            "format": "pymemoryeditor-pointerscan",
            "version": 1,
            "pid": self.pid,
            "paths": [path.to_dict() for path in paths],
        }
        with open(file, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def load_pointer_paths(self, file: str) -> "List[PointerPath]":
        """
        Load pointer paths previously written with :meth:`save_pointer_paths`.

        Returns a list of :class:`~PyMemoryEditor.PointerPath`. Resolve one with
        ``path.rebase(process).resolve(process)`` (or hand it to
        :meth:`rescan_pointer_paths`).
        """
        import json

        from .pointer_scan import PointerPath

        with open(file, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return [PointerPath.from_dict(entry) for entry in payload["paths"]]

    def rescan_pointer_paths(
        self,
        paths: "Union[str, Iterable[PointerPath]]",
        target_address: int,
    ) -> "List[PointerPath]":
        """
        Keep only the saved paths that still reach ``target_address`` in this
        process — Cheat Engine's "pointer rescan".

        Run it after the value moved (a restart, a level reload): each path is
        re-based onto the module's current load address and walked; the ones
        that no longer land on the value are dropped. Repeat across a few runs
        and the list collapses to the reliable static pointers.

        :param paths: a list of :class:`~PyMemoryEditor.PointerPath`, or the
            name of a file saved with :meth:`save_pointer_paths`.
        :param target_address: the value's address **in this run** (find it
            again with :meth:`search_by_value`).
        :return: the surviving paths, already re-based to this run.

        Example
        -------
        ::

            survivors = process.rescan_pointer_paths("scan1.json", new_address)
            process.save_pointer_paths(survivors, "scan2.json")
        """
        from .pointer_scan import PointerPath

        if isinstance(paths, str):
            paths = self.load_pointer_paths(paths)

        survivors: List["PointerPath"] = []
        module_bases: Optional[Dict[str, int]] = None

        for saved in paths:
            try:
                if saved.module is not None and saved.module_offset is not None:
                    # Look modules up once, only if a module-backed path needs it.
                    if module_bases is None:
                        module_bases = {
                            module.name: module.base_address
                            for module in self.get_modules()
                        }
                    base = module_bases.get(saved.module)
                    if base is None:
                        continue  # the path's module isn't loaded in this run
                    live = PointerPath(
                        base_address=base + saved.module_offset,
                        offsets=saved.offsets,
                        module=saved.module,
                        module_offset=saved.module_offset,
                        ptr_size=saved.ptr_size,
                    )
                else:
                    live = saved  # no module: best-effort with the stored base

                if live.resolve(self) == target_address:
                    survivors.append(live)
            except Exception:  # noqa: BLE001 — broken chain / unreadable page: drop it
                continue

        return survivors

    def compare_pointer_scans(
        self,
        *sources: "Union[str, Iterable[PointerPath]]",
    ) -> "List[PointerPath]":
        """
        Intersect several saved scans: return the paths present in **every** one.

        An alternative to :meth:`rescan_pointer_paths` that needs no live target.
        Run a full :meth:`scan_pointer_paths` after each restart, save each, then
        pass the files here — only the paths that showed up in all of them (the
        reliable static pointers) are returned.

        :param sources: two or more file names (from :meth:`save_pointer_paths`)
            and/or lists of :class:`~PyMemoryEditor.PointerPath`.

        Example
        -------
        ::

            stable = process.compare_pointer_scans("scan1.json", "scan2.json", "scan3.json")
        """
        from .pointer_scan import intersect_pointer_paths

        path_lists = [
            self.load_pointer_paths(source) if isinstance(source, str) else list(source)
            for source in sources
        ]
        return intersect_pointer_paths(path_lists)
