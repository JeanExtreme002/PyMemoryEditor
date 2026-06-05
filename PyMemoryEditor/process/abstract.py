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
from ..util import UNSET
from .info import ProcessInfo
from .module_info import ModuleInfo
from .region import MemoryRegion, MemoryRegionSnapshot
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

        # Cache for the target's bitness — resolved lazily on first access of
        # `is_64bit` / `pointer_size` (a syscall per backend) and reused after.
        self._is_64bit_cache: Optional[bool] = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    @property
    def pid(self) -> int:
        return self._process_info.pid

    @abstractmethod
    def _detect_is_64bit(self) -> bool:
        """
        Detect whether the target process is 64-bit. Backend-specific:

        * **Windows** — ``IsWow64Process`` on a 64-bit OS (a WOW64 process is
          32-bit), gated by the native OS architecture.
        * **Linux** — the ``EI_CLASS`` byte of the executable's ELF header
          (read from ``/proc/<pid>/exe`` or a file-backed image mapping).
        * **macOS** — the Mach-O header magic of a loaded image
          (``MH_MAGIC_64`` vs ``MH_MAGIC``).

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
        """
        if self._is_64bit_cache is None:
            self._is_64bit_cache = bool(self._detect_is_64bit())
        return self._is_64bit_cache

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

    @abstractmethod
    def get_memory_regions(self) -> Generator[MemoryRegion, None, None]:
        """
        Yield a :class:`~PyMemoryEditor.MemoryRegion` for every memory region
        the process owns.

        Each region carries its base ``address`` and ``size`` plus the portable
        flags ``is_readable`` / ``is_writable`` / ``is_executable`` /
        ``is_shared``, the backing file ``path`` (when known), and the
        platform-specific ``struct`` for advanced introspection.
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

    @abstractmethod
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
        :param addresses: the addresses to read. Required.
        :param memory_regions: optional snapshot returned by `snapshot_memory_regions()`.
            Pass it to skip the region enumeration on hot iterative workflows.
        """
        raise NotImplementedError()

    @abstractmethod
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
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        """
        Search the whole memory space, accessible to the process,
        for the provided value, returning the found addresses.

        :param pytype: type of value to be queried (bool, int, float, str or bytes).
        :param bufflength: value size in bytes (1, 2, 4, 8). Optional — defaults
            to ``None``: numeric types (int, float, bool) use their default
            width (int→4, float→8, bool→1) and ``str`` / ``bytes`` infer it from
            the encoded length of ``value``. Since it is optional, pass ``value``
            by keyword when omitting it: ``search_by_value(int, value=100)``.
        :param value: value to be queried (bool, int, float, str or bytes).
            Required.
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
        bufflength: Optional[int] = None,
        start: Union[bool, int, float, str, bytes] = UNSET,
        end: Union[bool, int, float, str, bytes] = UNSET,
        *,
        not_between: bool = False,
        progress_information: bool = False,
        writeable_only: bool = False,
        memory_regions: Optional[Sequence[MemoryRegion]] = None,
    ) -> Generator[Union[int, Tuple[int, dict]], None, None]:
        """
        Search the whole memory space, accessible to the process,
        for a value within the provided range, returning the found addresses.

        See `search_by_value` for parameter semantics. ``bufflength`` is
        likewise optional (defaults to ``None``): for ``str`` / ``bytes`` it is
        inferred from the longest of ``start`` / ``end`` (the shorter endpoint
        is NUL-padded to that width). Pass ``start`` / ``end`` by keyword when
        omitting ``bufflength``: ``search_by_value_between(int, start=10, end=20)``.
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
            now optional, pass it by keyword when omitting ``bufflength``::

                write_process_memory(address, str, value="hi")
                write_process_memory(address, int, value=99)

            Positional calls keep working unchanged
            (``write_process_memory(address, int, 4, 99)``).
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
        raw = int(value).to_bytes(size, sys.byteorder, signed=False)
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
            for path in process.scan_pointer_paths(hp_addr, max_depth=3, max_results=20):
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

        if ptr_size is None:
            ptr_size = self.pointer_size

        if ptr_size not in (4, 8):
            raise ValueError(
                "ptr_size must be 4 (32-bit target) or 8 (64-bit target)."
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
