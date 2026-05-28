# -*- coding: utf-8 -*-

"""
Cross-platform memory-region descriptor and introspection helpers.

The backend ``get_memory_regions()`` generators yield instances of
:class:`MemoryRegion` — an immutable dataclass that carries:

  - ``address`` / ``size`` of the contiguous block,
  - the portable booleans ``is_readable`` / ``is_writable`` / ``is_executable``
    / ``is_shared``,
  - the backing file ``path`` (when the platform exposes it cheaply),
  - and the original platform descriptor in ``struct`` (a
    ``MEMORY_BASIC_INFORMATION`` on Windows, the privileges-string struct on
    Linux, the VM struct on macOS).

Portable client code never touches ``struct`` — the booleans cover every
read/write/execute/shared question. Backends use :func:`make_region` to build
each instance with all fields populated in one call; the predicate helpers
(``is_region_readable`` etc.) are still exposed for callers that want to apply
the same rules to a hand-built struct.

A presorted snapshot of regions (the one returned by
``snapshot_memory_regions()``) is a :class:`MemoryRegionSnapshot` — a thin
``list`` subclass that signals to the scan helpers in
``process.scanning`` that the per-call ``sorted(...)`` step can be skipped.
"""

from dataclasses import dataclass, field
from typing import Any, List

from ..macos.types import VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE
from ..win32.enums.memory_allocation_states import MemoryAllocationStatesEnum
from ..win32.enums.memory_protections import MemoryProtectionsEnum
from ..win32.enums.memory_types import MemoryTypesEnum


# Composite bitmask of every PAGE_* protection that allows execution. The
# Win32 module already ships PAGE_READABLE / PAGE_READWRITEABLE composites
# for the read and write cases; the execute mask is local because it isn't
# useful enough to MemoryProtectionsEnum to warrant a public name.
_PAGE_EXECUTABLE_MASK = (
    MemoryProtectionsEnum.PAGE_EXECUTE
    | MemoryProtectionsEnum.PAGE_EXECUTE_READ
    | MemoryProtectionsEnum.PAGE_EXECUTE_READWRITE
    | MemoryProtectionsEnum.PAGE_EXECUTE_WRITECOPY
)


@dataclass(frozen=True)
class MemoryRegion:
    """A single memory region in a target process's address space.

    :param address: base address of the region.
    :param size: region size in bytes.
    :param struct: platform-specific descriptor (``MEMORY_BASIC_INFORMATION``
        on Windows / Linux; the macOS VM struct). Portable code should rely on
        the boolean fields below instead of poking at this directly.
    :param is_readable: ``True`` when the region can be read.
    :param is_writable: ``True`` when the region can be written.
    :param is_executable: ``True`` when the region contains executable code.
    :param is_shared: ``True`` when the region is a shared/file-backed mapping.
    :param path: best-effort path of the file backing the region, or ``""``
        when unknown (Linux exposes this directly from ``/proc/<pid>/maps``;
        Windows and macOS would need extra syscalls and report ``""``).
    """

    address: int
    size: int
    struct: Any = field(default=None, repr=False, compare=False)
    is_readable: bool = False
    is_writable: bool = False
    is_executable: bool = False
    is_shared: bool = False
    path: str = ""


class MemoryRegionSnapshot(List[MemoryRegion]):
    """A pre-sorted snapshot of memory regions.

    Returned by :meth:`AbstractProcess.snapshot_memory_regions`. Behaves exactly
    like a plain ``list[MemoryRegion]`` — the only purpose of the subclass is to
    let the scanning helpers in ``process.scanning`` detect via ``isinstance``
    that the input is already sorted by ``address`` and skip the per-call
    ``sorted(...)`` step.

    Slicing or filtering with a list comprehension drops the tag (the result is
    a plain ``list``), which is the safe default: the helpers re-sort
    defensively whenever the input is not a :class:`MemoryRegionSnapshot`.
    """


def is_region_readable(struct: Any) -> bool:
    """True when the platform ``struct`` describes a readable region."""
    # Linux: privileges string contains 'r'.
    if hasattr(struct, "Privileges"):
        return b"r" in bytes(struct.Privileges)

    # macOS: VM_PROT_READ bit.
    if hasattr(struct, "Protection") and hasattr(struct, "Shared"):
        return (struct.Protection & VM_PROT_READ) != 0

    # Windows: Protect bitmask + State must be MEM_COMMIT.
    if hasattr(struct, "Protect") and hasattr(struct, "State"):
        if struct.State != MemoryAllocationStatesEnum.MEM_COMMIT:
            return False
        return (struct.Protect & MemoryProtectionsEnum.PAGE_READABLE) != 0

    return False


def is_region_writable(struct: Any) -> bool:
    """True when the platform ``struct`` describes a writable region."""
    if hasattr(struct, "Privileges"):
        return b"w" in bytes(struct.Privileges)

    if hasattr(struct, "Protection") and hasattr(struct, "Shared"):
        return (struct.Protection & VM_PROT_WRITE) != 0

    if hasattr(struct, "Protect") and hasattr(struct, "State"):
        if struct.State != MemoryAllocationStatesEnum.MEM_COMMIT:
            return False
        return (struct.Protect & MemoryProtectionsEnum.PAGE_READWRITEABLE) != 0

    return False


def is_region_executable(struct: Any) -> bool:
    """True when the platform ``struct`` describes an executable region."""
    if hasattr(struct, "Privileges"):
        return b"x" in bytes(struct.Privileges)

    if hasattr(struct, "Protection") and hasattr(struct, "Shared"):
        return (struct.Protection & VM_PROT_EXECUTE) != 0

    if hasattr(struct, "Protect") and hasattr(struct, "State"):
        if struct.State != MemoryAllocationStatesEnum.MEM_COMMIT:
            return False
        return (struct.Protect & _PAGE_EXECUTABLE_MASK) != 0

    return False


def is_region_shared(struct: Any) -> bool:
    """True when the platform ``struct`` describes a shared mapping."""
    if hasattr(struct, "Privileges"):
        # Linux: 's' for shared, 'p' for private — last char of the privileges string.
        return b"s" in bytes(struct.Privileges)

    if hasattr(struct, "Shared"):
        return bool(struct.Shared)

    if hasattr(struct, "Type"):
        # Windows: MEM_MAPPED indicates a file-backed shared mapping.
        return struct.Type == MemoryTypesEnum.MEM_MAPPED

    return False


def region_path(struct: Any) -> str:
    """
    Best-effort path of the file backing the region, or "" when unknown.

    Linux can derive it from /proc/<pid>/maps (already populated). Win32 and
    macOS would require extra syscalls (GetMappedFileName / proc_regionfilename)
    that the backends don't currently make.
    """
    if hasattr(struct, "Path"):
        try:
            raw = bytes(struct.Path)
        except (TypeError, ValueError):
            return ""
        # Strip embedded NULs (the field is a fixed-size byte buffer).
        end = raw.find(b"\x00")
        if end != -1:
            raw = raw[:end]
        try:
            return raw.decode("utf-8", errors="replace")
        except AttributeError:
            return ""

    return ""


def make_region(address: int, size: int, struct: Any) -> MemoryRegion:
    """Build a fully-populated :class:`MemoryRegion` from a platform struct.

    Backends call this once per region instead of constructing a dict and
    enriching it in a second step. Computing every boolean upfront keeps the
    public type immutable and removes a class of "what fields are populated?"
    bugs that the old enrichment pattern was prone to.
    """
    return MemoryRegion(
        address=address,
        size=size,
        struct=struct,
        is_readable=is_region_readable(struct),
        is_writable=is_region_writable(struct),
        is_executable=is_region_executable(struct),
        is_shared=is_region_shared(struct),
        path=region_path(struct),
    )


def default_scan_filter(region: MemoryRegion, *, writeable_only: bool = False) -> bool:
    """
    Single source of truth for "which regions does a *value* / *pattern* scan
    walk by default".

    Historically each backend rolled its own filter — Win32 excluded
    ``MEM_MAPPED`` via ``Type``, Linux excluded shared via ``'s'`` in
    privileges, and macOS excluded nothing — so the same call returned a
    different set of matches per OS. The portable booleans on
    :class:`MemoryRegion` let one filter cover all three:

    - must be readable (no syscall hops into unreadable pages),
    - if ``writeable_only``, must also be writable,
    - drop shared mappings (libc text, file-backed pages): they're full of
      noise the caller virtually never wants in a value scan, and matching the
      Linux/Win32 historical behavior is the practical default.
    """
    if not region.is_readable:
        return False
    if writeable_only and not region.is_writable:
        return False
    if region.is_shared:
        return False
    return True


def default_address_filter(region: MemoryRegion) -> bool:
    """
    Single source of truth for "which regions does an *address-list* read walk
    by default" (``search_by_addresses`` without a snapshot).

    Crucially this is *not* the same as :func:`default_scan_filter`: when the
    caller hands the library a concrete address, the library has no business
    second-guessing whether the region is "interesting". The only requirement
    is that the region is readable — same on every OS.
    """
    return region.is_readable


__all__ = (
    "MemoryRegion",
    "MemoryRegionSnapshot",
    "default_address_filter",
    "default_scan_filter",
    "is_region_executable",
    "is_region_readable",
    "is_region_shared",
    "is_region_writable",
    "make_region",
    "region_path",
)
