# -*- coding: utf-8 -*-
import ctypes
import logging
import operator
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
from ..util import (
    UNSET,
    _check_int_fits,
    prepare_search_target,
    resolve_bufflength,
    resolve_bufflength_for_value,
)
from ..util.pattern import PatternLike, compile_pattern
from ._guard import guard_generator
from .errors import BitnessDetectionError, ProcessIDNotExistsError, PyMemoryEditorError
from .info import ProcessInfo
from .module_info import ModuleInfo
from .region import ADDRESS_SPACE_END, MemoryRegion, MemoryRegionSnapshot
from .thread_info import ThreadInfo
from .util import pid_exists

if TYPE_CHECKING:
    from re import Pattern

    from .pointer_scan import PointerPath
    from .remote_pointer import RemotePointer


_logger = logging.getLogger("PyMemoryEditor")

T = TypeVar("T")

# Identity of the JSON written by ``save_pointer_paths`` and checked by
# ``load_pointer_paths``.
_POINTER_SCAN_FORMAT = "pymemoryeditor-pointerscan"
_POINTER_SCAN_VERSION = 1


class _AddressOutOfRangeError(ValueError, OSError):
    """An address (or a pointer chain step) lies outside the address space.

    A ``ValueError`` as documented, and also an ``OSError`` because the failed
    read of the wrapped address it replaces raised one: callers that guard a
    stale chain or a bad address with ``except OSError`` keep working.
    """


# One past the highest address this host can pass to the OS. ctypes masks an
# address argument to the width of the C type it is converted to instead of
# rejecting it, so a 32-bit Python would turn 0x1_0000_1000 into 0x1000 just as
# a 64-bit one turns 2**64 + 0x1000 into 0x1000.
_HOST_ADDRESS_END = min(ADDRESS_SPACE_END, 1 << (8 * ctypes.sizeof(ctypes.c_void_p)))


class AbstractProcess(ABC):
    """
    Abstract class to represent a process.
    """

    # Each listing / search method and the backend hook its implementation
    # here relies on. A subclass must override one or the other: the hooks
    # are not abstract (see "Backend hooks" below), so this is what still
    # makes an incomplete subclass fail when it is defined rather than with
    # a NotImplementedError on first use.
    _METHOD_HOOKS = (
        ("get_memory_regions", "_iter_memory_regions"),
        ("get_threads", "_iter_threads"),
        ("get_modules", "_iter_modules"),
        ("search_by_addresses", "_scan_addresses"),
        ("search_by_value", "_scan_values"),
        ("search_by_value_between", "_scan_values"),
        ("search_by_pattern", "_scan_pattern"),
    )

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        # An intermediate class that still leaves an abstract method open
        # cannot be instantiated anyway; its concrete subclasses are checked.
        # The open methods are found the way ABCMeta finds them (it has not
        # run yet at this point): this class's own abstract attributes, plus
        # the bases' abstract names this class did not implement.
        open_methods = [
            name for name, value in vars(cls).items()
            if getattr(value, "__isabstractmethod__", False)
        ] + [
            name
            for base in cls.__bases__
            for name in getattr(base, "__abstractmethods__", ())
            if getattr(getattr(cls, name, None), "__isabstractmethod__", False)
        ]
        if open_methods:
            return

        # Overriding a method with anything (a function, a property, a mixin's
        # method) counts as implementing it; assigning AbstractProcess's own
        # function again does not.
        missing: Dict[str, List[str]] = {}
        uses_base = False
        for method, hook in cls._METHOD_HOOKS:
            if getattr(cls, method) is not getattr(AbstractProcess, method):
                continue  # implemented directly, as up to 3.3
            uses_base = True
            if getattr(cls, hook) is getattr(AbstractProcess, hook):
                missing.setdefault(hook, []).append(method)
        problems = [
            "%s (or %s)" % (hook, ", ".join(methods)) for hook, methods in missing.items()
        ]
        if uses_base and cls._require_open is AbstractProcess._require_open:
            problems.append("_require_open")
        if problems:
            raise TypeError(
                "%s must implement %s." % (cls.__name__, "; ".join(problems))
            )

    @abstractmethod
    def __init__(
        self,
        *,
        name: Optional[str] = None,
        pid: Optional[int] = None,
        case_sensitive: bool = True,
        exact_match: bool = True,
        strict_bitness: bool = False,
    ):
        """
        :param name: name of the target process.
        :param pid: process ID.
        :param case_sensitive: when False, name matching ignores case
            (recommended on Windows where process names are case-insensitive).
        :param exact_match: when False, ``name`` is matched as a
            substring — ``"chrome"`` matches ``"chrome.exe"`` / ``"Google Chrome"``.
            If more than one process matches, ``AmbiguousProcessNameError`` is
            raised so you can pick a PID from the list.
        :param strict_bitness: when True, :attr:`is_64bit` raises
            :class:`~PyMemoryEditor.BitnessDetectionError` if the target's
            32-/64-bit width can't be read from its headers, instead of falling
            back to the host word size. Use it when a wrong pointer-width
            default would be worse than a hard failure (the pointer APIs rely on
            it). Check :attr:`is_bitness_certain` for the non-strict signal.
        """
        self._process_info = ProcessInfo()

        if pid is not None:
            self._process_info.pid = pid

        elif name:
            self._process_info.set_name(
                name,
                case_sensitive=case_sensitive,
                exact_match=exact_match,
            )

        else:
            raise TypeError(
                "You must pass an argument to one of these parameters (name, pid)."
            )

        # Cache for the target's bitness — resolved lazily on first access of
        # `is_64bit` / `pointer_size` (a syscall per backend) and reused after.
        self._is_64bit_cache: Optional[bool] = None
        # Whether that resolution read the target's headers (True/False) or fell
        # back to a host-word-size guess (False). Set alongside the cache.
        self._bitness_certain: Optional[bool] = None
        self._strict_bitness = strict_bitness

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    @property
    def pid(self) -> int:
        return self._process_info.pid

    def _target_alive(self) -> bool:
        """
        Whether the target process still exists. The default asks the OS by
        pid; a backend whose handle keeps the pid reserved after the process
        exits (Windows) overrides it with a handle-level check. A zombie (a
        process that exited but whose parent has not reaped it yet) still
        counts as existing on Linux and macOS, so its reads are treated as
        vanished pages until it is reaped.
        """
        return pid_exists(self.pid)

    def _raise_if_target_exited(self) -> None:
        """
        Turn a read failure on a target that has exited into
        :class:`~PyMemoryEditor.ProcessIDNotExistsError`. Backends report that
        read as a plain ``OSError``, the same type a page that vanished
        mid-scan produces; the scan helpers call this before deciding a
        failure is skippable so a dead target is never mistaken for one.
        """
        if not self._target_alive():
            raise ProcessIDNotExistsError(self.pid)

    @staticmethod
    def _require_address(address: int) -> None:
        """
        Refuse an address outside ``[0, host address space)`` before it
        reaches ctypes, which would mask it to the C type's width and read,
        write or free a *different*, wrapped address instead of failing.
        """
        if not 0 <= address < _HOST_ADDRESS_END:
            raise _AddressOutOfRangeError(
                "address %s is outside the %d-bit address space; it would "
                "wrap around to a different address."
                % (
                    ("-0x%X" % -address) if address < 0 else ("0x%X" % address),
                    _HOST_ADDRESS_END.bit_length() - 1,
                )
            )

    @abstractmethod
    def _detect_is_64bit(self) -> Optional[bool]:
        """
        Detect whether the target process is 64-bit. Backend-specific:

        * **Windows** — ``IsWow64Process`` on a 64-bit OS (a WOW64 process is
          32-bit), gated by the native OS architecture.
        * **Linux** — the ``EI_CLASS`` byte of the executable's ELF header
          (read from ``/proc/<pid>/exe`` or a file-backed image mapping).
        * **macOS** — the Mach-O header magic of a loaded image
          (``MH_MAGIC_64`` vs ``MH_MAGIC``).

        Returns ``True``/``False`` when the headers can be read, or ``None`` when
        the bitness is *undeterminable* — :attr:`is_64bit` then either falls back
        to the host word size or raises (see ``strict_bitness``). This is the raw
        mechanism only: implementations must **not** guess or warn here.

        Called once by :attr:`is_64bit`, which caches the result. Implementations
        may assume the process is still open.
        """
        raise NotImplementedError()

    @property
    def is_64bit(self) -> bool:
        """
        ``True`` if the target process is 64-bit, ``False`` if it is 32-bit.

        Detected once on first access (a single syscall per backend — see
        :meth:`_detect_is_64bit`) and cached for the lifetime of this object.
        A process never changes bitness, so the cached value stays valid.

        This is what powers the automatic ``ptr_size`` default of
        :meth:`resolve_pointer_chain`, :meth:`scan_pointer_paths`,
        :meth:`get_pointer` and :class:`~PyMemoryEditor.RemotePointer`: leave
        ``ptr_size`` as ``None`` and the right pointer width (4 or 8) is used.

        When the backend can't read the target's headers, the result depends on
        ``strict_bitness`` (passed to the constructor): the default ``False``
        falls back to the **host** word size and logs a WARNING — convenient,
        but possibly wrong for a cross-bitness target (a 32-bit process on a
        64-bit host) — while ``True`` raises
        :class:`~PyMemoryEditor.BitnessDetectionError`. Either way,
        :attr:`is_bitness_certain` reports whether the value was read or guessed.
        """
        if self._is_64bit_cache is None:
            detected = self._detect_is_64bit()
            if detected is not None:
                self._is_64bit_cache = bool(detected)
                self._bitness_certain = True
            elif self._strict_bitness:
                raise BitnessDetectionError(self.pid)
            else:
                host_is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8
                _logger.warning(
                    "Could not determine the bitness of process %d from its "
                    "headers; assuming the host word size (%d-bit). The "
                    "pointer-width default used by resolve_pointer_chain / "
                    "RemotePointer / scan_pointer_paths may be wrong for a "
                    "cross-bitness target — pass ptr_size explicitly, or open "
                    "the process with strict_bitness=True to raise instead.",
                    self.pid,
                    64 if host_is_64bit else 32,
                )
                self._is_64bit_cache = host_is_64bit
                self._bitness_certain = False
        return self._is_64bit_cache

    @property
    def is_bitness_certain(self) -> bool:
        """
        ``True`` if :attr:`is_64bit` was read from the target's own headers,
        ``False`` if it fell back to a guess of the host word size because they
        couldn't be read.

        When ``False`` the automatic ``ptr_size`` default may be wrong for a
        cross-bitness target — pass ``ptr_size`` explicitly to the pointer APIs,
        or open the process with ``strict_bitness=True`` to turn the guess into
        a :class:`~PyMemoryEditor.BitnessDetectionError` instead. Accessing this
        resolves :attr:`is_64bit` if it hasn't been already.
        """
        self.is_64bit  # force detection (and the strict_bitness check) to run
        return bool(self._bitness_certain)

    @property
    def pointer_size(self) -> int:
        """
        Pointer width of the target process in bytes — ``8`` for a 64-bit
        target, ``4`` for a 32-bit one. Derived from :attr:`is_64bit`.

        Use it as the explicit ``ptr_size`` for the pointer APIs, or simply
        leave ``ptr_size=None`` (the default) to let them read this value.
        """
        return 8 if self.is_64bit else 4

    @abstractmethod
    def close(self) -> bool:
        """
        Close the process handle.
        """
        raise NotImplementedError()

    def get_memory_regions(self) -> Generator[MemoryRegion, None, None]:
        """
        Yield a :class:`~PyMemoryEditor.MemoryRegion` for every memory region
        the process owns.

        Each region carries its base ``address`` and ``size`` plus the portable
        flags ``is_readable`` / ``is_writable`` / ``is_executable`` /
        ``is_shared``, the backing file ``path`` (when known), and the
        platform-specific ``struct`` for advanced introspection.
        """
        self._require_listing()
        return guard_generator(self._iter_memory_regions(), self._require_open)

    def get_threads(self) -> Generator[ThreadInfo, None, None]:
        """
        Yield a :class:`~PyMemoryEditor.ThreadInfo` for every thread running
        inside the target process.

        The fields that each backend can fill in cheaply vary — see
        ``ThreadInfo`` for which attributes may be ``None`` per platform.
        The ``tid`` field's *meaning* is platform-specific (POSIX TID on
        Linux, DWORD TID on Windows, system-wide thread id on macOS).

        A process that has exited is *not* reported uniformly: Linux raises
        :class:`~PyMemoryEditor.ProcessIDNotExistsError` (the object checks its
        pidfd before listing), Windows enumerates nothing and yields an empty
        sequence (its system-wide thread snapshot, filtered by pid, simply comes
        up empty), and macOS raises ``OSError`` because ``task_threads`` fails
        on a dead task. Don't read "no threads" as "still running": check
        liveness separately if that distinction matters. Contrast
        :meth:`get_memory_regions` and :meth:`get_modules`, which do raise
        :class:`~PyMemoryEditor.ProcessIDNotExistsError` on every platform.

        The returned generator is bound to this object: resuming it after
        :meth:`close` raises :class:`~PyMemoryEditor.ClosedProcess`.

        A listing that is *denied* is different from one that is empty: on
        Linux and macOS a target owned by another user raises
        ``PermissionError`` (Linux cannot list ``/proc/<pid>/task``, macOS
        cannot ``task_threads`` a task it has no port for) rather than
        silently yielding nothing.

        Use :attr:`main_thread` for the conventional "main thread" shortcut.
        """
        self._require_listing()
        return guard_generator(self._iter_threads(), self._require_open)

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
        self._require_listing()
        return guard_generator(self._iter_modules(), self._require_open)

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

    def snapshot_memory_regions(self) -> MemoryRegionSnapshot:
        """
        Return a materialized snapshot of the process memory regions.

        Pass the result as the ``memory_regions`` keyword to subsequent calls of
        ``search_by_value``, ``search_by_value_between`` or
        ``search_by_addresses`` to skip the region enumeration. Useful for
        "scan → refine → refine" workflows where the region map doesn't change
        between calls.

        The returned :class:`MemoryRegionSnapshot` is pre-sorted by base
        address; the scan helpers in ``process.scanning`` detect this via
        ``isinstance`` and skip their per-call ``sorted(...)`` step on reuse.
        Slicing or filtering with a list comprehension drops the
        ``MemoryRegionSnapshot`` type (you get a plain ``list``) — the helpers
        then re-sort defensively, which is safe but slower for very large
        region maps.
        """
        regions = sorted(self.get_memory_regions(), key=lambda region: region.address)
        return MemoryRegionSnapshot(regions)

    def search_by_addresses(
        self,
        pytype: Type[T],
        bufflength: Optional[int] = None,
        addresses: Sequence[int] = UNSET,
        *,
        raise_error: bool = False,
        memory_regions: Optional[Sequence[MemoryRegion]] = None,
    ) -> Generator[Tuple[int, Optional[T]], None, None]:
        """
        Search the whole memory space, accessible to the process,
        for the provided list of addresses, returning their values.

        :param bufflength: value size in bytes. Optional — defaults to ``None``,
            which uses the default width for numeric types (int→4, float→8,
            bool→1). ``str`` / ``bytes`` still require an explicit size here:
            unlike a search by value, there is no value to infer the width
            from — only addresses to read. Since ``bufflength`` is optional,
            pass ``addresses`` by keyword when omitting it:
            ``search_by_addresses(int, addresses=[0x1000, 0x1004])``.
            An unusual ``int`` width rounds up to the next C integer type, as
            in :meth:`search_by_value`; only the requested bytes are read, and
            the value is sign-extended — so this method,
            :meth:`read_process_memory` and a scan for the same bytes all
            agree, widths 3, 5, 6 and 7 included.
        :param addresses: the addresses to read. Required.
        :param memory_regions: optional snapshot returned by `snapshot_memory_regions()`.
            Pass it to skip the region enumeration on hot iterative workflows.
        """
        self._require_scanning()
        if addresses is UNSET:
            raise TypeError("addresses is required.")
        scan = self._scan_addresses(
            pytype,
            resolve_bufflength(pytype, bufflength),
            addresses,
            raise_error=raise_error,
            memory_regions=memory_regions,
        )
        return guard_generator(scan, self._require_open)

    def search_by_value(
        self,
        pytype: Type[T],
        bufflength: Optional[int] = None,
        value: Union[bool, int, float, str, bytes] = UNSET,
        scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
        *,
        progress_information: bool = False,
        writeable_only: bool = False,
        memory_regions: Optional[Sequence[MemoryRegion]] = None,
        aligned: bool = True,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        """
        Search the whole memory space, accessible to the process,
        for the provided value, returning the found addresses.

        :param pytype: type of value to be queried (bool, int, float, str or bytes).
        :param bufflength: value size in bytes — typically 1, 2, 4 or 8. For
            ``int``, an unusual width such as 3 or 6 is a real narrow field: it
            rounds up to the next C integer type and the value is
            sign-extended. For ``float`` only 4 and 8 are accepted — IEEE-754
            has no form between them, so a narrower width would reinterpret
            unread bytes as a mantissa and return a plausible-looking number.
            A width wider than the type's largest C representation (over 8 for
            ``int``/``float``, over 1 for ``bool``) is rejected with
            ``ValueError``, because the buffer would be smaller than the
            read. Optional — defaults
            to ``None``: numeric types (int, float, bool) use their default
            width (int→4, float→8, bool→1) and ``str`` / ``bytes`` infer it from
            the encoded length of ``value``. Since it is optional, pass ``value``
            by keyword when omitting it: ``search_by_value(int, value=100)``.
        :param value: value to be queried (bool, int, float, str or bytes).
            Required.
        :param scan_type: the way to compare the values. ``VALUE_BETWEEN`` and
            ``NOT_VALUE_BETWEEN`` are not accepted here and raise ``ValueError``;
            use ``search_by_value_between`` instead.
        :param progress_information: if True, a dictionary with the progress information will be returned.
        :param writeable_only: if True, search only at writeable memory regions.
        :param memory_regions: optional snapshot returned by `snapshot_memory_regions()`.
            Pass it to skip the region enumeration on hot iterative workflows.
        :param aligned: numeric values (``int``, ``float``, ``bool``) at a
            natural width (1, 2, 4 or 8 bytes) are compared at every slot
            aligned to that width, counted from the start of each region --
            the same slots every comparison mode uses, so a refine never drops
            an address the first scan reported, and the way compilers lay
            fields out. Pass ``False`` to compare at every byte instead, for a
            value that may sit at a non-aligned address: a packed struct, a
            number embedded in a byte buffer or string, memory from a custom
            allocator. It costs the typed scan ``bufflength`` passes and
            reports each match once. ``str``, ``bytes`` and an ``int`` at an
            unusual width (3, 5, 6, 7) already match at any byte; the flag
            does not affect them.
        :raises ValueError: if ``scan_type`` is ``VALUE_BETWEEN`` or
            ``NOT_VALUE_BETWEEN``, or if an ``int`` ``value`` does not fit in
            ``bufflength`` bytes.

        .. note::
           This scan always restricts itself to readable, **non-shared**
           regions (``writeable_only`` narrows it further to writable ones).
           Shared / file-backed mappings (libc text, memory-mapped files) are
           always skipped — they're noise a value scan rarely wants, and
           excluding them keeps results identical across platforms. The same
           filter is applied to a caller-supplied ``memory_regions`` list too
           (that argument only skips region *enumeration*, not the filtering),
           so shared regions can't be opted back in.
        """
        self._require_scanning()

        if scan_type in (ScanTypesEnum.VALUE_BETWEEN, ScanTypesEnum.NOT_VALUE_BETWEEN):
            raise ValueError(
                "Use the method search_by_value_between(...) to search within a range of values."
            )

        width = resolve_bufflength_for_value(pytype, bufflength, value)
        scan = self._scan_values(
            pytype,
            width,
            prepare_search_target(pytype, width, value),
            scan_type,
            progress_information=progress_information,
            writeable_only=writeable_only,
            memory_regions=memory_regions,
            aligned=aligned,
        )
        return guard_generator(scan, self._require_open)

    def search_by_pattern(
        self,
        pattern: PatternLike,
        *,
        byte_length: int = 0,
        progress_information: bool = False,
        memory_regions: Optional[Sequence[MemoryRegion]] = None,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        """
        Scan the target's memory for a byte pattern (AOB) — the Cheat Engine /
        IDA technique for locating code or data that moves between builds.

        :param pattern: one of the forms accepted by
            :func:`PyMemoryEditor.util.pattern.compile_pattern` — an IDA-style
            hex string with ``?`` wildcards (``"48 8B ? ? 00"``), a raw bytes
            regex, or a pre-compiled ``re.Pattern[bytes]``.
        :param byte_length: required when ``pattern`` is a regex / pre-compiled
            Pattern — the **maximum** number of bytes one match can consume. It
            drives the chunk overlap so a match straddling a chunk boundary is
            still found (a variable-width regex like ``Player[0-9]+`` has no
            fixed width, so give the largest match you expect). Ignored for
            IDA-style strings (inferred from the token count).
        :param progress_information: if True, yields ``(address, info)``
            tuples (same shape as ``search_by_value``).
        :param memory_regions: optional snapshot from
            ``snapshot_memory_regions()`` to skip region enumeration on
            iterative workflows.
        """
        self._require_scanning()
        scan = self._scan_pattern(
            compile_pattern(pattern, byte_length=byte_length),
            progress_information=progress_information,
            memory_regions=memory_regions,
        )
        return guard_generator(scan, self._require_open)

    def search_by_value_between(
        self,
        pytype: Type[T],
        bufflength: Optional[int] = None,
        start: Union[bool, int, float, str, bytes] = UNSET,
        end: Union[bool, int, float, str, bytes] = UNSET,
        *,
        not_between: bool = False,
        progress_information: bool = False,
        writeable_only: bool = False,
        memory_regions: Optional[Sequence[MemoryRegion]] = None,
        aligned: bool = True,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        """
        Search the whole memory space, accessible to the process,
        for a value within the provided range, returning the found addresses.

        See `search_by_value` for parameter semantics, including ``aligned``.
        ``bufflength`` is likewise optional (defaults to ``None``): for ``str``
        / ``bytes`` it is inferred from the longest of ``start`` / ``end`` (the
        shorter endpoint is NUL-padded to that width). Pass ``start`` / ``end``
        by keyword when omitting ``bufflength``:
        ``search_by_value_between(int, start=10, end=20)``.
        """
        self._require_scanning()

        scan_type = (
            ScanTypesEnum.NOT_VALUE_BETWEEN
            if not_between
            else ScanTypesEnum.VALUE_BETWEEN
        )
        width = resolve_bufflength_for_value(pytype, bufflength, start, end)
        scan = self._scan_values(
            pytype,
            width,
            prepare_search_target(pytype, width, (start, end)),
            scan_type,
            progress_information=progress_information,
            writeable_only=writeable_only,
            memory_regions=memory_regions,
            aligned=aligned,
        )
        return guard_generator(scan, self._require_open)

    # ------------------------------------------------------------------ #
    # Backend hooks
    #
    # The listing and search methods above are written once, here: they check
    # access, validate and encode their arguments at the call (the scans are
    # generators, whose own checks would only run on the first next(), far
    # from the call), and bind the returned generator to this object, so that
    # resuming it after close() raises instead of using a released handle. A
    # backend supplies the access checks and the raw generators below.
    #
    # The hooks are deliberately not abstract: AbstractProcess is public, and a
    # subclass written against the earlier contract -- one that overrides the
    # public listing and search methods itself -- must keep instantiating.
    # Such a subclass never reaches these defaults.
    # ------------------------------------------------------------------ #

    def _require_open(self) -> None:
        """Raise :class:`~PyMemoryEditor.ClosedProcess` once :meth:`close` ran.

        Called before every item a returned generator yields, so it must be
        cheap: an attribute test, no syscall.
        """
        raise NotImplementedError()

    def _require_listing(self) -> None:
        """Raise if the regions, threads or modules cannot be listed now
        (closed, or the target gone where the backend can tell). Defaults to
        :meth:`_require_open`."""
        self._require_open()

    def _require_scanning(self) -> None:
        """Raise if memory cannot be searched now: as :meth:`_require_listing`,
        plus read access where that is a property of the handle. Defaults to
        :meth:`_require_listing`."""
        self._require_listing()

    def _iter_memory_regions(self) -> Generator[MemoryRegion, None, None]:
        """The backend's region walk, for :meth:`get_memory_regions`."""
        raise NotImplementedError()

    def _iter_threads(self) -> Generator[ThreadInfo, None, None]:
        """The backend's thread listing, for :meth:`get_threads`."""
        raise NotImplementedError()

    def _iter_modules(self) -> Generator[ModuleInfo, None, None]:
        """The backend's module listing, for :meth:`get_modules`."""
        raise NotImplementedError()

    def _scan_addresses(
        self,
        pytype: Type[T],
        bufflength: int,
        addresses: Sequence[int],
        *,
        raise_error: bool,
        memory_regions: Optional[Sequence[MemoryRegion]],
    ) -> Generator[Tuple[int, Optional[T]], None, None]:
        """The read behind :meth:`search_by_addresses`, with ``bufflength``
        resolved."""
        raise NotImplementedError()

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
        """The scan behind :meth:`search_by_value` and
        :meth:`search_by_value_between`. ``target_value_bytes`` is the value,
        or the ``(start, end)`` pair of a range scan, already validated and
        encoded."""
        raise NotImplementedError()

    def _scan_pattern(
        self,
        compiled_pattern: Tuple["Pattern[bytes]", int],
        *,
        progress_information: bool,
        memory_regions: Optional[Sequence[MemoryRegion]],
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        """The scan behind :meth:`search_by_pattern`. ``compiled_pattern`` is
        what :func:`~PyMemoryEditor.util.pattern.compile_pattern` returned for
        the pattern."""
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
        :param bufflength: value size in bytes — typically 1, 2, 4 or 8. For
            ``int``, an unusual width such as 3 or 6 rounds up to the next C
            integer type and the value is sign-extended, so it agrees with what
            a scan for the same bytes finds. For ``float`` only 4 and 8 are
            accepted (IEEE-754 has no form between them). A width wider than
            the type's largest C representation (over
            8 for ``int``/``float``, over 1 for ``bool``) raises ``ValueError``,
            because the buffer would be smaller than the read. For numeric types
            (int, float, bool) you may omit this; defaults are int→4, float→8,
            bool→1. str and bytes require an explicit size.

        .. note::
           When ``pytype=str`` the raw bytes are decoded with
           ``errors="replace"``: any byte sequence that is not valid UTF-8
           becomes the Unicode replacement character (``U+FFFD``) instead of
           raising ``UnicodeDecodeError``. This matches ``search_by_addresses``
           and ``convert_from_byte_array``. Callers that need the original
           bytes verbatim (no decoding) should pass ``pytype=bytes``.

        :raises ValueError: if ``pytype`` is unsupported, or ``address`` is
            negative or past the end of the address space (also an
            ``OSError``, so ``except OSError`` still catches it).
        :raises OSError: if the read fails, or returns fewer bytes than
            requested (e.g. the range crosses an unreadable/freed page).
        """
        raise NotImplementedError()

    @abstractmethod
    def read_process_memory_into(self, address: int, buffer: object) -> int:
        """
        Read ``len(buffer)`` bytes from ``address`` directly into a
        pre-allocated, writable ``buffer`` and return the number of bytes read.

        This is the zero-copy counterpart of :meth:`read_process_memory`: where
        that method allocates a fresh object on every call, this one fills a
        buffer you own and reuse. In a tight polling / recording loop that reads
        the same-sized region over and over, reusing one buffer keeps memory use
        constant instead of producing a stream of short-lived objects for the
        garbage collector to reclaim.

        :param address: target memory address (ex: 0x006A9EC0).
        :param buffer: any writable, contiguous buffer-protocol object — a
            ``bytearray``, a ``ctypes`` array, a writable ``memoryview``, a
            ``numpy`` array, etc. Its byte length determines how many bytes are
            read; an element-typed buffer (e.g. a ``numpy`` ``int32`` array) is
            sized in **bytes**, not elements. The bytes are written in place; no
            decoding is performed (this is the raw-``bytes`` read path). Decode
            or reinterpret them yourself afterwards
            (``int.from_bytes`` / ``struct.unpack`` / ``numpy`` views / ...).
        :return: the number of bytes read — always equal to the buffer's byte
            length on success (a short read raises instead, mirroring
            :meth:`read_process_memory`).

        :raises TypeError: if ``buffer`` is not a writable buffer (e.g. an
            immutable ``bytes`` object).
        :raises ValueError: if ``buffer`` is empty or not contiguous, or
            ``address`` is outside the address space (as in
            :meth:`read_process_memory`).
        :raises OSError: if the read fails, or returns fewer bytes than
            requested (e.g. the range crosses an unreadable/freed page).

        Example
        -------
        ::

            buffer = bytearray(16)
            while recording:
                process.read_process_memory_into(addr, buffer)
                handle(buffer)        # same buffer reused every iteration
        """
        raise NotImplementedError()

    @abstractmethod
    def write_process_memory(
        self,
        address: int,
        pytype: Type[T],
        bufflength: Optional[int] = None,
        value: Union[bool, int, float, str, bytes] = UNSET,
    ) -> Union[bool, int, float, str, bytes]:
        """
        Write a value to a memory address.

        :param address: target memory address (ex: 0x006A9EC0).
        :param pytype: type of value to be written into memory (bool, int, float, str or bytes).
        :param bufflength: value size in bytes. Optional — defaults to ``None``.

            * For numeric types (int, float, bool) it is the exact write width;
              leave it as ``None`` to use the default — int→4, float→8, bool→1.
            * For ``str`` / ``bytes`` it is a *maximum* width that truncates the
              value; it never pads. For a ``str`` the cap counts **characters**,
              applied before UTF-8 encoding, so multibyte characters are never
              split: ``write(addr, str, 2, "óólá")`` keeps ``"óó"`` and writes
              its 4 bytes, while ``write(addr, str, 2, "ola")`` writes ``b"ol"``.
              For ``bytes`` the cap counts **bytes**. A value shorter than the
              cap is written as-is (no NUL padding). ``None`` (the default)
              writes the whole value. ``str`` is encoded as UTF-8; no NUL
              terminator is appended.
        :param value: value to be written. Required — since ``bufflength`` is
            optional, pass it by keyword when omitting ``bufflength``::

                write_process_memory(address, str, value="hi")
                write_process_memory(address, int, value=99)

            Positional calls work as well
            (``write_process_memory(address, int, 4, 99)``).
        :raises ValueError: if ``pytype`` is unsupported, or if an ``int``
            ``value`` does not fit in ``bufflength`` bytes (rejected up front
            rather than silently truncated), or if ``address`` is outside the
            address space (as in :meth:`read_process_memory`).
        :raises OSError: if the write fails, or fewer bytes than requested are
            written (e.g. the range crosses an unwritable/freed page).
        :return: the original ``value`` passed in.
        """
        raise NotImplementedError()

    # ------------------------------------------------------------------ #
    # Typed convenience read/write helpers
    # ------------------------------------------------------------------ #
    #
    # Thin, self-documenting wrappers over ``read_process_memory`` /
    # ``write_process_memory`` with the type and byte width baked into the
    # method name — ``read_int(addr)`` instead of
    # ``read_process_memory(addr, int, 4)``. They add no new capability (the
    # generic methods already cover every case) but spell out the exact C
    # type the caller wants, so the IDE can offer them by name and beginners
    # don't have to remember which width and signedness a type uses.
    #
    # Widths are FIXED and identical on every platform and target bitness —
    # ``long``/``ulong`` are always 4 bytes here (matching Win32 ``LONG``),
    # ``longlong``/``ulonglong`` always 8 — so the same call reads the same
    # number of bytes regardless of OS. For a platform-/target-dependent
    # pointer width use :attr:`pointer_size` with the generic methods.
    #
    # ``int`` decodes as *signed* (see ``util.convert.get_c_type_of``), so the
    # signed family delegates straight to it. The unsigned family reads/writes
    # raw bytes and reinterprets them with ``signed=False`` in the target's
    # native byte order (``sys.byteorder`` — the convention the rest of the
    # library follows, e.g. ``resolve_pointer_chain``).

    def _read_unsigned(self, address: int, size: int) -> int:
        raw = self.read_process_memory(address, bytes, size)
        return int.from_bytes(raw, sys.byteorder, signed=False)

    def _write_unsigned(self, address: int, size: int, value: int) -> int:
        # The signed helpers reject a float with TypeError (the ctypes integer
        # setter refuses it), and `int(value)` would truncate 3.7 to 3 and
        # report success. `operator.index` accepts exactly what that setter
        # accepts -- ints, bools, numpy integers -- and raises the same
        # TypeError for everything else.
        integer = operator.index(value)
        # Validate up front so an out-of-range value raises the same clear
        # ValueError as the signed path, instead of int.to_bytes' cryptic
        # OverflowError ("int too big to convert" / "can't convert negative").
        _check_int_fits(integer, size, signed=False)
        raw = integer.to_bytes(size, sys.byteorder, signed=False)
        self.write_process_memory(address, bytes, size, raw)
        return value

    # --- signed integers ---------------------------------------------- #

    def read_char(self, address: int) -> int:
        """Read a signed 8-bit integer (1 byte). See :meth:`read_uchar` for unsigned."""
        return self.read_process_memory(address, int, 1)

    def read_short(self, address: int) -> int:
        """Read a signed 16-bit integer (2 bytes)."""
        return self.read_process_memory(address, int, 2)

    def read_int(self, address: int) -> int:
        """Read a signed 32-bit integer (4 bytes)."""
        return self.read_process_memory(address, int, 4)

    def read_long(self, address: int) -> int:
        """Read a signed 32-bit integer (4 bytes, matching Win32 ``LONG``)."""
        return self.read_process_memory(address, int, 4)

    def read_longlong(self, address: int) -> int:
        """Read a signed 64-bit integer (8 bytes)."""
        return self.read_process_memory(address, int, 8)

    def write_char(self, address: int, value: int) -> int:
        """Write a signed 8-bit integer (1 byte). Returns ``value``."""
        self.write_process_memory(address, int, 1, value)
        return value

    def write_short(self, address: int, value: int) -> int:
        """Write a signed 16-bit integer (2 bytes). Returns ``value``."""
        self.write_process_memory(address, int, 2, value)
        return value

    def write_int(self, address: int, value: int) -> int:
        """Write a signed 32-bit integer (4 bytes). Returns ``value``."""
        self.write_process_memory(address, int, 4, value)
        return value

    def write_long(self, address: int, value: int) -> int:
        """Write a signed 32-bit integer (4 bytes, Win32 ``LONG``). Returns ``value``."""
        self.write_process_memory(address, int, 4, value)
        return value

    def write_longlong(self, address: int, value: int) -> int:
        """Write a signed 64-bit integer (8 bytes). Returns ``value``."""
        self.write_process_memory(address, int, 8, value)
        return value

    # --- unsigned integers -------------------------------------------- #

    def read_uchar(self, address: int) -> int:
        """Read an unsigned 8-bit integer (1 byte, 0..255)."""
        return self._read_unsigned(address, 1)

    def read_ushort(self, address: int) -> int:
        """Read an unsigned 16-bit integer (2 bytes)."""
        return self._read_unsigned(address, 2)

    def read_uint(self, address: int) -> int:
        """Read an unsigned 32-bit integer (4 bytes)."""
        return self._read_unsigned(address, 4)

    def read_ulong(self, address: int) -> int:
        """Read an unsigned 32-bit integer (4 bytes, matching Win32 ``ULONG``)."""
        return self._read_unsigned(address, 4)

    def read_ulonglong(self, address: int) -> int:
        """Read an unsigned 64-bit integer (8 bytes)."""
        return self._read_unsigned(address, 8)

    def write_uchar(self, address: int, value: int) -> int:
        """Write an unsigned 8-bit integer (1 byte). Returns ``value``."""
        return self._write_unsigned(address, 1, value)

    def write_ushort(self, address: int, value: int) -> int:
        """Write an unsigned 16-bit integer (2 bytes). Returns ``value``."""
        return self._write_unsigned(address, 2, value)

    def write_uint(self, address: int, value: int) -> int:
        """Write an unsigned 32-bit integer (4 bytes). Returns ``value``."""
        return self._write_unsigned(address, 4, value)

    def write_ulong(self, address: int, value: int) -> int:
        """Write an unsigned 32-bit integer (4 bytes, Win32 ``ULONG``). Returns ``value``."""
        return self._write_unsigned(address, 4, value)

    def write_ulonglong(self, address: int, value: int) -> int:
        """Write an unsigned 64-bit integer (8 bytes). Returns ``value``."""
        return self._write_unsigned(address, 8, value)

    # --- floating point ----------------------------------------------- #

    def read_float(self, address: int) -> float:
        """Read a 32-bit IEEE-754 float (4 bytes)."""
        return self.read_process_memory(address, float, 4)

    def read_double(self, address: int) -> float:
        """Read a 64-bit IEEE-754 double (8 bytes)."""
        return self.read_process_memory(address, float, 8)

    def write_float(self, address: int, value: float) -> float:
        """Write a 32-bit IEEE-754 float (4 bytes). Returns ``value``."""
        self.write_process_memory(address, float, 4, value)
        return value

    def write_double(self, address: int, value: float) -> float:
        """Write a 64-bit IEEE-754 double (8 bytes). Returns ``value``."""
        self.write_process_memory(address, float, 8, value)
        return value

    # --- boolean ------------------------------------------------------- #

    def read_bool(self, address: int) -> bool:
        """Read a boolean (1 byte)."""
        return self.read_process_memory(address, bool, 1)

    def write_bool(self, address: int, value: bool) -> bool:
        """Write a boolean (1 byte). Returns ``value``."""
        self.write_process_memory(address, bool, 1, value)
        return value

    # --- strings & raw bytes ------------------------------------------ #

    def read_string(self, address: int, byte_count: int) -> str:
        """
        Read exactly ``byte_count`` bytes, decode them as UTF-8 and return the
        text up to the first NUL terminator (C-string semantics).

        Goes through the ``str`` read path, so invalid UTF-8 becomes ``U+FFFD``
        (``errors="replace"``). ``byte_count`` is the field width to read, not an
        upper bound — those bytes must all be readable or an ``OSError`` is
        raised; the NUL terminator and everything after it are then dropped from
        the returned text. To make a shorter :meth:`write_string` read back
        cleanly here, write it with ``null_terminator=True`` (or into an
        already-zeroed field).
        """
        return self.read_process_memory(address, str, byte_count).split("\x00", 1)[0]

    def write_string(
        self, address: int, text: str, *, null_terminator: bool = False
    ) -> str:
        """
        Write ``text`` as a UTF-8 string, writing exactly its bytes and nothing
        else. Pass ``null_terminator=True`` to also append a trailing ``\\x00``
        — useful when overwriting a longer string in place so :meth:`read_string`
        stops where you intend rather than reading the stale tail.

        Multi-byte characters are handled correctly — the whole string is
        encoded and written, so you never have to count bytes yourself.
        Returns ``text``. To cap the write to a maximum number of characters,
        call :meth:`write_process_memory` with ``pytype=str`` and an explicit
        ``bufflength`` instead (it truncates, it does not pad).
        """
        payload = text + "\x00" if null_terminator else text
        self.write_process_memory(address, str, None, payload)
        return text

    def read_bytes(self, address: int, length: int) -> bytes:
        """Read ``length`` raw bytes verbatim (no decoding)."""
        return self.read_process_memory(address, bytes, length)

    def write_bytes(self, address: int, data: bytes) -> bytes:
        """Write the raw byte string ``data`` verbatim. Returns ``data``."""
        self.write_process_memory(address, bytes, len(data), data)
        return data

    @abstractmethod
    def allocate_memory(self, size: int, *, permission: Optional[int] = None) -> int:
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
            the size recorded when the region was allocated. Pass an explicit
            size only to free a region this object did not allocate (on Windows
            it is not passed to the OS, since ``MEM_RELEASE`` frees the whole
            allocation).
        :return: ``True`` on success.

        :raises ValueError: on macOS and Windows, for a region this object did
            not allocate when no ``size`` is given, or for an ``address``
            outside the address space.
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
        ptr_size: Optional[int] = None,
    ) -> "RemotePointer":
        """
        Build a :class:`~PyMemoryEditor.RemotePointer` bound to this process —
        a live, re-resolving handle to a typed value in the target.

        Convenience wrapper around the ``RemotePointer(self, ...)`` constructor;
        see that class for the meaning of every parameter (notably ``offsets``,
        whose ``None`` vs ``[]`` distinction selects a direct handle vs a
        single-dereference chain). Leaving ``ptr_size=None`` lets the pointer
        adopt the target's :attr:`pointer_size` automatically.

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
        ptr_size: Optional[int] = None,
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
        :param ptr_size: pointer width — 8 for 64-bit targets, 4 for 32-bit.
            Leave ``None`` (the default) to use the target's
            :attr:`pointer_size`, detected automatically.

        Example
        -------
        Cheat-Engine cheat table entry::

            "game.exe" + 0x10F4F4 -> [+0x0] -> [+0x158]   ; HP

        Translates to::

            hp_addr = process.resolve_pointer_chain(0x14010F4F4, [0x0, 0x158])
            hp = process.read_process_memory(hp_addr, int, 4)

        :raises ValueError: if ``ptr_size`` is not 4 or 8, or if a pointer plus
            its offset lands outside the 64-bit address space (below zero or at
            ``2**64`` and above) before it is dereferenced — typically a stale
            chain whose hop read NULL followed by a negative offset. That error
            is also an ``OSError``.
        :raises OSError: if a pointer along the chain cannot be read.

        The returned address (the last offset is added *without* a
        dereference) is the plain sum and is not range-checked: a stale chain
        can return a negative number, which no read or write will accept.
        """
        if ptr_size is None:
            ptr_size = self.pointer_size

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
            # ctypes masks an address argument to 64 bits instead of rejecting
            # it, so `ptr + offset` below zero or past 2**64 would silently
            # read a *different*, wrapped address. Refuse it by name instead.
            if not 0 <= addr < ADDRESS_SPACE_END:
                raise _AddressOutOfRangeError(
                    "pointer chain step produced address %s, outside the "
                    "64-bit address space; the chain is stale (a hop read "
                    "NULL or garbage) or an offset is wrong."
                    % (("-0x%X" % -addr) if addr < 0 else ("0x%X" % addr))
                )
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
        max_depth: int = 3,
        max_offset: int = 0x400,
        ptr_size: Optional[int] = None,
        aligned: bool = True,
        writable_only: bool = True,
        static_ranges: Optional[Sequence[Tuple[int, int]]] = None,
        max_results: Optional[int] = None,
        memory_regions: Optional[Sequence[MemoryRegion]] = None,
        progress_callback: Optional["Callable[[float], None]"] = None,
        should_stop: Optional["Callable[[], bool]"] = None,
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
        :param ptr_size: pointer width — 8 for 64-bit targets, 4 for 32-bit.
            Leave ``None`` (the default) to use the target's
            :attr:`pointer_size`, detected automatically.
        :param aligned: only consider pointers at natural alignment (default,
            much faster). Set ``False`` to also scan misaligned slots (slow).
        :param writable_only: build the pointer map from writable memory only
            (default). This is both faster and usually correct — every hop in a
            live chain reads a pointer the program writes (global pointers in
            ``.data``, object fields on the heap). Set ``False`` to also include
            read-only pointers (e.g. vtables), which is slower and noisier.
        :param static_ranges: explicit ``(start, size)`` ranges to treat as
            valid chain bases. Defaults to the image range of every loaded
            module. On macOS this default already spans **every** Mach-O segment
            of each image (not just ``__TEXT``) — see :meth:`_static_image_ranges`,
            which the macOS backend overrides — so global pointers in ``__DATA``
            are covered automatically; you do not need to pass ``static_ranges``
            for them.
        :param max_results: stop after yielding this many paths (``None`` = no
            cap). Recommended for shallow exploration of large targets.
        :param memory_regions: optional snapshot from
            :meth:`snapshot_memory_regions` to skip region enumeration.
        :param progress_callback: optional ``callback(fraction)`` invoked as the
            pointer map is built (the long phase), ``fraction`` in ``[0, 1]``.
        :param should_stop: optional ``should_stop()`` polled during the path
            search; once it returns True the search ends early and no more
            paths are yielded. The search can run a long time between two
            yields, so this is how a caller with a deadline or a cancel button
            bounds it. (To abort the map-building phase, raise from
            ``progress_callback``.)

        :raises ValueError: ``ptr_size`` other than 4 or 8, ``max_depth`` or
            ``max_results`` below 1, or a negative ``max_offset``.
        :raises ClosedProcess: the process was closed (also raised by the
            returned generator once it is).

        Arguments and access are checked at the call, like every ``search_*``
        method; the pointer map is built and walked lazily, as the generator
        is consumed.

        Example
        -------
        ::

            hp_addr = next(process.search_by_value(int, 4, 1234))
            for path in process.scan_pointer_paths(hp_addr, max_depth=3, max_results=20):
                print(path)                 # "game.exe"+0x10F4F4 -> [+0x0] -> +0x158
                assert path.resolve(process) == hp_addr

            # In a later run, after the module moved (ASLR):
            live = path.rebase(process).to_pointer(process, pytype=int, bufflength=4)
            live.value = 9999
        """
        # Validate eagerly, like every search_* method: a bad argument or a
        # closed process raises here, at the call, not on the first next().
        # The map build and path search stay lazy in _iter_pointer_paths.
        #
        # A subclass written against the 3.3 contract implements the listings
        # itself and need not define these hooks (see __init_subclass__): each
        # check runs only where the subclass provides it, instead of hitting
        # the NotImplementedError of the base _require_open.
        cls = type(self)
        guarded = cls._require_open is not AbstractProcess._require_open
        if guarded or cls._require_scanning is not AbstractProcess._require_scanning:
            self._require_scanning()

        if max_depth < 1:
            raise ValueError("max_depth must be at least 1.")
        if max_offset < 0:
            raise ValueError("max_offset must not be negative.")
        if max_results is not None and max_results < 1:
            # 0 would build the whole pointer map only to yield nothing.
            raise ValueError("max_results must be at least 1 (or None for no cap).")

        if ptr_size is None:
            ptr_size = self.pointer_size

        if ptr_size not in (4, 8):
            raise ValueError(
                "ptr_size must be 4 (32-bit target) or 8 (64-bit target)."
            )

        scan = self._iter_pointer_paths(
            target_address,
            max_depth=max_depth,
            max_offset=max_offset,
            ptr_size=ptr_size,
            aligned=aligned,
            writable_only=writable_only,
            static_ranges=static_ranges,
            max_results=max_results,
            memory_regions=memory_regions,
            progress_callback=progress_callback,
            should_stop=should_stop,
        )
        return guard_generator(scan, self._require_open) if guarded else scan

    def _iter_pointer_paths(
        self,
        target_address: int,
        *,
        max_depth: int,
        max_offset: int,
        ptr_size: int,
        aligned: bool,
        writable_only: bool,
        static_ranges: Optional[Sequence[Tuple[int, int]]],
        max_results: Optional[int],
        memory_regions: Optional[Sequence[MemoryRegion]],
        progress_callback: Optional["Callable[[float], None]"],
        should_stop: Optional["Callable[[], bool]"],
    ) -> Generator["PointerPath", None, None]:
        """The lazy body of :meth:`scan_pointer_paths`, run once arguments are
        validated."""
        from .pointer_scan import (
            AddressRanges,
            build_pointer_map,
            find_pointer_paths,
        )

        if memory_regions is None:
            memory_regions = list(self.get_memory_regions())

        # Pointers may point anywhere readable; chain hops live in writable
        # memory (the program writes them) unless the caller opts into read-only.
        readable = [r for r in memory_regions if r.is_readable]
        mapped_ranges = AddressRanges(
            [(r.address, r.address + r.size) for r in readable]
        )

        scan_regions = [
            (r.address, r.size)
            for r in readable
            if (r.is_writable if writable_only else True)
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
            except (PyMemoryEditorError, MemoryError):
                # Closed process, or a host out of memory: neither is a
                # skippable page, and skipping would leave the map incomplete.
                raise
            except Exception:  # noqa: BLE001 — backend read errors vary
                # A page that vanished mid-scan is skippable; a target that
                # exited is not (every backend reports that read as a plain
                # OSError, indistinguishable from a bad page without this).
                self._raise_if_target_exited()
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
            should_stop=should_stop,
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
            "format": _POINTER_SCAN_FORMAT,
            "version": _POINTER_SCAN_VERSION,
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

        :raises ValueError: if the file is not a pointer-scan export written by
            :meth:`save_pointer_paths` (wrong ``format``, an unsupported
            ``version``, or a missing / malformed ``paths`` list). The message
            names the file and the field.
        """
        import json

        from .pointer_scan import PointerPath

        with open(file, "r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if not isinstance(payload, dict):
            raise ValueError(
                "%s is not a pointer-scan export: expected a JSON object, got %s."
                % (file, type(payload).__name__)
            )
        fmt = payload.get("format")
        if fmt != _POINTER_SCAN_FORMAT:
            raise ValueError(
                "%s is not a pointer-scan export: 'format' is %r, expected %r "
                "(files are written by save_pointer_paths)."
                % (file, fmt, _POINTER_SCAN_FORMAT)
            )
        version = payload.get("version")
        if version != _POINTER_SCAN_VERSION:
            raise ValueError(
                "%s uses pointer-scan format version %r; this version of "
                "PyMemoryEditor reads version %r." % (file, version, _POINTER_SCAN_VERSION)
            )
        entries = payload.get("paths")
        if not isinstance(entries, list):
            raise ValueError(
                "%s is missing its 'paths' list (got %s)."
                % (file, "nothing" if entries is None else type(entries).__name__)
            )
        try:
            return [PointerPath.from_dict(entry) for entry in entries]
        except ValueError as error:
            raise ValueError("%s: %s" % (file, error)) from None

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

            survivors = process.rescan_pointer_paths("scan.json", new_address)
            process.save_pointer_paths(survivors, "scan.json")
        """
        from .pointer_scan import PointerPath, first_module_bases

        if isinstance(paths, str):
            paths = self.load_pointer_paths(paths)

        survivors: List["PointerPath"] = []
        module_bases: Optional[Dict[str, int]] = None

        for saved in paths:
            try:
                if saved.module is not None and saved.module_offset is not None:
                    # Look modules up once, only if a module-backed path needs it.
                    if module_bases is None:
                        # The same first-wins rule as PointerPath.rebase.
                        module_bases = first_module_bases(self.get_modules())
                    rebased = saved._rebased_onto(module_bases)
                    if rebased is None:
                        continue  # the path's module isn't loaded in this run
                    live = rebased
                else:
                    live = saved  # no module: best-effort with the stored base

                if live.resolve(self) == target_address:
                    survivors.append(live)
            except (PyMemoryEditorError, MemoryError):
                raise  # closed process / exhausted host: every path would "fail"
            except Exception:  # noqa: BLE001 — broken chain / unreadable page: drop it
                self._raise_if_target_exited()
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

        :param sources: one or more file names (from :meth:`save_pointer_paths`)
            and/or lists of :class:`~PyMemoryEditor.PointerPath`. A single
            source returns its module-backed paths unchanged (the intersection
            of one set is itself); it takes at least two for the comparison to
            narrow anything.
        :raises ValueError: if no source is given.

        Example
        -------
        ::

            stable = process.compare_pointer_scans("scan1.json", "scan2.json", "scan3.json")
        """
        from .pointer_scan import intersect_pointer_paths

        if not sources:
            raise ValueError("compare_pointer_scans() needs at least one source.")

        path_lists = [
            self.load_pointer_paths(source) if isinstance(source, str) else list(source)
            for source in sources
        ]
        return intersect_pointer_paths(path_lists)
