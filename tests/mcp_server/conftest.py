# -*- coding: utf-8 -*-

"""
A fake target process, so the MCP tools can be tested without a real one.

The library's scan correctness already has a suite (``tests/scan``,
``tests/memory``) that runs against live memory. What these tests need instead
is the *orchestration*: result-set handles, the refine loop's semantics, the
caps, the policy gates, the parsing. Driving that through a real process would
make every assertion depend on whatever the host happens to have in RAM, and
each scan would cost seconds.

So :class:`FakeProcess` implements the slice of the process API the toolset
actually calls, over a couple of ``bytearray`` regions at made-up base
addresses. Values are encoded and decoded with the library's own
``value_to_bytes`` / ``convert_from_byte_array``, and ordered comparisons go
through the library's own ``make_predicate``, so the fake agrees with the real
backends on the parts that are easy to get subtly wrong.

``tests/mcp_server/test_live.py`` covers the real thing (slow-marked), which is
what keeps this fake honest about signatures.

.. warning::
   **If you change how this fake reads, writes or compares a value, change it
   to match the real backends — and check
   ``tests/mcp_server/test_fake_fidelity.py``.**

   Three separate review passes over this package each found a bug that the
   300+ tests here could not catch, and every one of them was a place where
   this fake behaved differently from a real process: it compared scan targets
   without the byte round trip (hiding a ``refine_scan`` that dropped every
   float32 match), its opener ignored the pid, and it padded a capped ``str``
   write where every real backend truncates. A green suite against an
   unfaithful fake is worse than no suite, because it is *believed*.

   ``test_fake_fidelity.py`` runs the same expectations against this fake and
   against a live process, so that class of divergence fails instead of hiding.
"""

import ctypes
import re
import sys
from typing import Any, Dict, Generator, List, Optional, Sequence, Tuple, Type

import pytest

from PyMemoryEditor.enums import ScanTypesEnum
from PyMemoryEditor.mcp import MemoryToolset, ServerConfig
from PyMemoryEditor.process.module_info import ModuleInfo
from PyMemoryEditor.process.region import MemoryRegion, MemoryRegionSnapshot
from PyMemoryEditor.process.thread_info import ThreadInfo
from PyMemoryEditor.util import (
    decode_scan_target,
    get_c_type_of,
    make_predicate,
    prepare_write,
    resolve_bufflength,
    value_to_bytes,
)


#: Base addresses for the fake's regions. Deliberately above 2**32 so any
#: 32-bit truncation in the address plumbing shows up as a wrong answer.
WRITABLE_BASE = 0x1_4000_0000
READONLY_BASE = 0x1_5000_0000
REGION_SIZE = 0x1000


def _decode(raw: bytes, pytype: Type, length: int) -> Any:
    """Decode ``raw`` the way a real backend does.

    Deliberately mirrors the shape of ``read_process_memory`` in all three
    backends: size the buffer from the C type, copy the bytes that were read
    into it, take ``.value``. Building the buffer from ``len(raw)`` instead —
    the obvious-looking shortcut — broke every width narrower than its C type:
    an ``int`` of 3 bytes rounds up to a 4-byte ``c_int32``, which a real target
    reads happily and the fake rejected with "Buffer size too small".
    """
    data = get_c_type_of(pytype, length)
    ctypes.memmove(
        ctypes.addressof(data), raw, min(len(raw), ctypes.sizeof(data))
    )
    if pytype is bytes:
        return bytes(data)
    if pytype is str:
        return bytes(data).decode("utf-8", errors="replace")
    return data.value


def _scan_byte_order(pytype: Type) -> str:
    """The byte order a real scan compares in.

    ``scan_memory`` sets ``byte_order = "big" if is_string else sys.byteorder``
    with ``is_string = pytype is str`` (util/scan.py), because a ``str``
    compares bytewise left to right while numerics compare in host order.

    The fake used ``sys.byteorder`` for everything, which is the same class of
    infidelity as the one below and hid the same bug one level up:
    ``refine_scan`` also decoded text in host order, and with both halves wrong
    in the same direction the equivalence tests passed. Ordered text refines
    happen to be blocked by ``_TEXT_SCAN_TYPES``, so nothing failed -- the fake
    made a guard look like correctness.
    """
    return "big" if pytype is str else sys.byteorder


def _scan_target(pytype: Type, width: int, value: Any) -> Any:
    """The value a real scan compares against, after the byte round trip.

    Not the caller's Python value: ``0.1`` narrowed to 4 bytes reads back as
    ``0.10000000149011612``, and a ``str`` is compared as the integer view of
    its NUL-padded buffer.

    The fake used to compare the raw value here, which made it agree with a
    *buggy* ``refine_scan`` and disagree with every real backend — so the one
    class of bug this module exists to catch was the one it hid.
    """
    return decode_scan_target(
        value_to_bytes(pytype, width, value), _scan_byte_order(pytype), pytype
    )


class FakeProcess:
    """A process-shaped object backed by two in-memory regions."""

    def __init__(self, pid: int = 4242, name: str = "faketarget") -> None:
        self.pid = pid
        self.name = name
        self.closed = False

        self._blocks: List[Tuple[int, bytearray, bool]] = [
            (WRITABLE_BASE, bytearray(REGION_SIZE), True),
            (READONLY_BASE, bytearray(REGION_SIZE), False),
        ]
        self.read_calls = 0
        self.scan_calls = 0

    # --- test-side helpers ------------------------------------------------ #

    def poke(self, address: int, pytype: Type, value: Any, length: Optional[int] = None) -> int:
        """Place a value in the fake's memory and return its address."""
        width = resolve_bufflength(pytype, length)
        raw = value_to_bytes(pytype, width, value)
        block, offset = self._locate(address, len(raw))
        block[offset : offset + len(raw)] = raw
        return address

    def _locate(self, address: int, size: int) -> Tuple[bytearray, int]:
        for base, block, _writable in self._blocks:
            if base <= address and address + size <= base + len(block):
                return block, address - base
        raise OSError("address 0x%X is not mapped in the fake target" % address)

    # --- the API the toolset uses ----------------------------------------- #

    @property
    def is_64bit(self) -> bool:
        return True

    @property
    def pointer_size(self) -> int:
        return 8

    @property
    def is_bitness_certain(self) -> bool:
        return True

    def close(self) -> bool:
        self.closed = True
        return True

    def get_memory_regions(self) -> Generator[MemoryRegion, None, None]:
        for base, block, writable in self._blocks:
            yield MemoryRegion(
                address=base,
                size=len(block),
                is_readable=True,
                is_writable=writable,
                is_executable=not writable,
                is_shared=False,
                path="" if writable else "/fake/libfake.so",
            )

    def snapshot_memory_regions(self) -> MemoryRegionSnapshot:
        return MemoryRegionSnapshot(
            sorted(self.get_memory_regions(), key=lambda region: region.address)
        )

    def get_modules(self) -> Generator[ModuleInfo, None, None]:
        yield ModuleInfo(
            name="faketarget",
            path="/fake/faketarget",
            base_address=READONLY_BASE,
            size=REGION_SIZE,
        )

    def get_threads(self) -> Generator[ThreadInfo, None, None]:
        yield ThreadInfo(tid=101)
        yield ThreadInfo(tid=99)

    def read_process_memory(
        self, address: int, pytype: Type, bufflength: Optional[int] = None
    ) -> Any:
        self.read_calls += 1
        width = resolve_bufflength(pytype, bufflength)
        block, offset = self._locate(address, width)
        return _decode(bytes(block[offset : offset + width]), pytype, width)

    def write_process_memory(
        self,
        address: int,
        pytype: Type,
        bufflength: Optional[int] = None,
        value: Any = None,
    ) -> Any:
        block, _offset = self._locate(address, 1)
        base = next(base for base, candidate, _w in self._blocks if candidate is block)
        writable = next(w for b, _c, w in self._blocks if b == base)
        if not writable:
            raise OSError("region at 0x%X is not writable" % base)

        # `prepare_write` is what all three real backends call, and its
        # contract for str/bytes is cap-and-truncate, never pad. Rolling our
        # own with resolve_bufflength_for_value diverged twice: it *rejected*
        # ("hello", bufflength=3) where a real target writes b"hel", and it
        # NUL-padded ("ola", bufflength=10) to ten bytes where a real target
        # writes three — clobbering seven bytes that `_write_span` correctly
        # reports as outside the undo range.
        w_pytype, width, w_value = prepare_write(pytype, bufflength, value)
        raw = value_to_bytes(w_pytype, width, w_value)
        block, offset = self._locate(address, len(raw))
        block[offset : offset + len(raw)] = raw
        return value

    def _slots(
        self, memory_regions: Optional[Sequence[MemoryRegion]], writable_only: bool
    ) -> Generator[Tuple[int, bytearray, int], None, None]:
        """Yield ``(base, block, size)`` for the regions a scan should cover."""
        wanted = (
            None
            if memory_regions is None
            else {region.address for region in memory_regions}
        )
        for base, block, writable in self._blocks:
            if writable_only and not writable:
                continue
            if wanted is not None and base not in wanted:
                continue
            yield base, block, len(block)

    def search_by_value(
        self,
        pytype: Type,
        bufflength: Optional[int] = None,
        value: Any = None,
        scan_type: ScanTypesEnum = ScanTypesEnum.EXACT_VALUE,
        *,
        progress_information: bool = False,
        writeable_only: bool = False,
        memory_regions: Optional[Sequence[MemoryRegion]] = None,
    ) -> Generator[int, None, None]:
        self.scan_calls += 1
        width = resolve_bufflength(pytype, bufflength)
        target = _scan_target(pytype, width, value)
        predicate = make_predicate(scan_type, target, target, target)

        for base, block, size in self._slots(memory_regions, writeable_only):
            for offset in range(0, size - width + 1):
                raw = bytes(block[offset : offset + width])
                current = decode_scan_target(raw, _scan_byte_order(pytype), pytype)
                try:
                    if predicate(current):
                        yield base + offset
                except TypeError:  # pragma: no cover
                    continue

    def search_by_value_between(
        self,
        pytype: Type,
        bufflength: Optional[int] = None,
        start: Any = None,
        end: Any = None,
        *,
        not_between: bool = False,
        progress_information: bool = False,
        writeable_only: bool = False,
        memory_regions: Optional[Sequence[MemoryRegion]] = None,
    ) -> Generator[int, None, None]:
        scan_type = (
            ScanTypesEnum.NOT_VALUE_BETWEEN if not_between else ScanTypesEnum.VALUE_BETWEEN
        )
        width = resolve_bufflength(pytype, bufflength)
        low = _scan_target(pytype, width, start)
        high = _scan_target(pytype, width, end)
        predicate = make_predicate(scan_type, low, low, high)

        for base, block, size in self._slots(memory_regions, writeable_only):
            for offset in range(0, size - width + 1):
                raw = bytes(block[offset : offset + width])
                current = decode_scan_target(raw, _scan_byte_order(pytype), pytype)
                if predicate(current):
                    yield base + offset

    def search_by_pattern(
        self,
        pattern: Any,
        *,
        byte_length: int = 0,
        progress_information: bool = False,
        memory_regions: Optional[Sequence[MemoryRegion]] = None,
    ) -> Generator[int, None, None]:
        from PyMemoryEditor.util import compile_pattern

        compiled, _length = compile_pattern(pattern, byte_length=byte_length)
        if not isinstance(compiled, re.Pattern):  # pragma: no cover - API drift
            raise ValueError("compile_pattern returned an unexpected object")

        for base, block, _size in self._slots(memory_regions, False):
            for match in compiled.finditer(bytes(block)):
                yield base + match.start()

    def search_by_addresses(
        self,
        pytype: Type,
        bufflength: Optional[int] = None,
        addresses: Sequence[int] = (),
        *,
        raise_error: bool = False,
        memory_regions: Optional[Sequence[MemoryRegion]] = None,
    ) -> Generator[Tuple[int, Any], None, None]:
        width = resolve_bufflength(pytype, bufflength)
        for address in sorted(addresses):
            try:
                yield address, self.read_process_memory(address, pytype, width)
            except OSError:
                yield address, None

    def resolve_pointer_chain(
        self, base_address: int, offsets: Sequence[int], *, ptr_size: Optional[int] = None
    ) -> int:
        size = ptr_size or self.pointer_size
        block, offset = self._locate(base_address, size)
        current = int.from_bytes(bytes(block[offset : offset + size]), "little")

        if not offsets:
            return current
        for hop in offsets[:-1]:
            block, offset = self._locate(current + hop, size)
            current = int.from_bytes(bytes(block[offset : offset + size]), "little")
        return current + offsets[-1]

    def scan_pointer_paths(self, target_address: int, **kwargs: Any) -> Generator:
        callback = kwargs.get("progress_callback")
        if callback is not None:
            callback(1.0)
        return iter(())


def config(**overrides: Any) -> ServerConfig:
    """A :class:`ServerConfig` for tests that are not about the approval gate.

    The server's default mode is *ask*: an unlisted target needs the user's
    live approval, which a bare ``MemoryToolset`` has no channel to request. So
    tests exercising the tools themselves opt out with
    ``allow_any_process=True``, and the ones that *are* about approval build
    their own config explicitly — which also makes the intent obvious at the
    call site.
    """
    overrides.setdefault("allow_any_process", True)
    return ServerConfig(**overrides)


@pytest.fixture
def fake_process() -> FakeProcess:
    return FakeProcess()


@pytest.fixture
def toolset(fake_process: FakeProcess) -> MemoryToolset:
    """A toolset wired to the fake target, with writes enabled."""
    return _toolset_for(fake_process, config(allow_write=True))


def _toolset_for(process: FakeProcess, config: ServerConfig) -> MemoryToolset:
    def opener(**kwargs: Any) -> FakeProcess:
        # Mirror ProcessInfo's own validation. The injected opener used to
        # ignore the pid entirely, so anything the real backend rejects up
        # front looked fine here — the same fidelity gap that let the
        # refine-scan bug through 300 green tests.
        pid = kwargs.get("pid")
        if pid is not None and not isinstance(pid, bool) and isinstance(pid, int):
            if pid < 0:
                raise ValueError("The process ID must be non-negative.")
        return process

    toolset = MemoryToolset(config, open_process=opener)
    # The policy resolves a pid to a name by enumerating real processes; the
    # fake's pid is not among them, so short-circuit that lookup.
    toolset._name_for_pid = lambda pid: process.name  # type: ignore[method-assign]
    return toolset


@pytest.fixture
def make_toolset(fake_process: FakeProcess):
    """Build a toolset on the same fake target with a custom config."""

    def factory(config: ServerConfig) -> MemoryToolset:
        return _toolset_for(fake_process, config)

    return factory


@pytest.fixture
def session(toolset: MemoryToolset) -> Dict[str, Any]:
    """An open session on the fake target."""
    return toolset.open_process(pid=4242)
