# -*- coding: utf-8 -*-

"""
Cross-platform helpers for memory-region introspection.

`get_memory_regions()` on each backend returns a dict with `address`, `size`
and `struct` keys. The shape of `struct` is platform-specific:

  - Win32: MEMORY_BASIC_INFORMATION_{32,64} with `Protect` (PAGE_* bitmask)
    and `Type` (MEM_PRIVATE / MEM_IMAGE / MEM_MAPPED).
  - Linux: MEMORY_BASIC_INFORMATION with `Privileges` (bytes "rwxp" / "rwxs").
  - macOS: MEMORY_BASIC_INFORMATION with `Protection` (VM_PROT_* bitmask) and
    `Shared` (1 when the region is backed by a shared object).

Portable client code (and the bundled Qt app) only wants the booleans
`is_readable`, `is_writable`, `is_executable`, `is_shared` plus a `path`.
This module provides:

  - the four boolean predicates as functions of a region dict, and
  - `enrich_region(region)` which adds them in place. Backends call this
    inside their `get_memory_regions` loop so callers get the richer view
    for free without having to know how to introspect each struct.

The original `address`, `size`, and `struct` keys remain unchanged for
backward compatibility — existing client code that reaches into the
platform struct directly keeps working.

Constants are imported from the per-OS enum modules instead of being
hardcoded here. The enums themselves are pure-Python so the import is
safe on every supported platform; only the matching predicate branch
actually runs based on the struct shape passed in.
"""

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


REGION_KEYS = (
    "address",
    "size",
    "struct",
    "is_readable",
    "is_writable",
    "is_executable",
    "is_shared",
    "path",
)


def is_region_readable(region: dict) -> bool:
    """True when the region is readable (no syscall — inspects the struct)."""
    info = region["struct"]

    # Linux: privileges string contains 'r'.
    if hasattr(info, "Privileges"):
        return b"r" in bytes(info.Privileges)

    # macOS: VM_PROT_READ bit.
    if hasattr(info, "Protection") and hasattr(info, "Shared"):
        return (info.Protection & VM_PROT_READ) != 0

    # Windows: Protect bitmask + State must be MEM_COMMIT.
    if hasattr(info, "Protect") and hasattr(info, "State"):
        if info.State != MemoryAllocationStatesEnum.MEM_COMMIT:
            return False
        return (info.Protect & MemoryProtectionsEnum.PAGE_READABLE) != 0

    return False


def is_region_writable(region: dict) -> bool:
    info = region["struct"]

    if hasattr(info, "Privileges"):
        return b"w" in bytes(info.Privileges)

    if hasattr(info, "Protection") and hasattr(info, "Shared"):
        return (info.Protection & VM_PROT_WRITE) != 0

    if hasattr(info, "Protect") and hasattr(info, "State"):
        if info.State != MemoryAllocationStatesEnum.MEM_COMMIT:
            return False
        return (info.Protect & MemoryProtectionsEnum.PAGE_READWRITEABLE) != 0

    return False


def is_region_executable(region: dict) -> bool:
    info = region["struct"]

    if hasattr(info, "Privileges"):
        return b"x" in bytes(info.Privileges)

    if hasattr(info, "Protection") and hasattr(info, "Shared"):
        return (info.Protection & VM_PROT_EXECUTE) != 0

    if hasattr(info, "Protect") and hasattr(info, "State"):
        if info.State != MemoryAllocationStatesEnum.MEM_COMMIT:
            return False
        return (info.Protect & _PAGE_EXECUTABLE_MASK) != 0

    return False


def is_region_shared(region: dict) -> bool:
    info = region["struct"]

    if hasattr(info, "Privileges"):
        # Linux: 's' for shared, 'p' for private — last char of the privileges string.
        return b"s" in bytes(info.Privileges)

    if hasattr(info, "Shared"):
        return bool(info.Shared)

    if hasattr(info, "Type"):
        # Windows: MEM_MAPPED indicates a file-backed shared mapping.
        return info.Type == MemoryTypesEnum.MEM_MAPPED

    return False


def region_path(region: dict) -> str:
    """
    Best-effort path of the file backing the region, or "" when unknown.

    Linux can derive it from /proc/<pid>/maps (already populated). Win32 and
    macOS would require extra syscalls (GetMappedFileName / proc_regionfilename)
    that the backends don't currently make.
    """
    info = region["struct"]

    if hasattr(info, "Path"):
        try:
            raw = bytes(info.Path)
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


def enrich_region(region: dict) -> dict:
    """
    Populate `is_readable`, `is_writable`, `is_executable`, `is_shared`, `path`
    on the given region dict in place, then return it.
    """
    region["is_readable"] = is_region_readable(region)
    region["is_writable"] = is_region_writable(region)
    region["is_executable"] = is_region_executable(region)
    region["is_shared"] = is_region_shared(region)
    region["path"] = region_path(region)
    return region


def default_scan_filter(region: dict, *, writeable_only: bool = False) -> bool:
    """
    Single source of truth for "which regions does a *value* / *pattern* scan
    walk by default".

    Historically each backend rolled its own filter — Win32 excluded
    ``MEM_MAPPED`` via ``Type``, Linux excluded shared via ``'s'`` in
    privileges, and macOS excluded nothing — so the same call returned a
    different set of matches per OS. The portable booleans on the region dict
    (populated by :func:`enrich_region`) let one filter cover all three:

    - must be readable (no syscall hops into unreadable pages),
    - if ``writeable_only``, must also be writable,
    - drop shared mappings (libc text, file-backed pages): they're full of
      noise the caller virtually never wants in a value scan, and matching the
      Linux/Win32 historical behavior is the practical default.
    """
    if not region.get("is_readable", False):
        return False
    if writeable_only and not region.get("is_writable", False):
        return False
    if region.get("is_shared", False):
        return False
    return True


def default_address_filter(region: dict) -> bool:
    """
    Single source of truth for "which regions does an *address-list* read walk
    by default" (``search_by_addresses`` without a snapshot).

    Crucially this is *not* the same as :func:`default_scan_filter`: when the
    caller hands the library a concrete address, the library has no business
    second-guessing whether the region is "interesting". The only requirement
    is that the region is readable — same on every OS.
    """
    return bool(region.get("is_readable", False))


__all__ = (
    "REGION_KEYS",
    "default_address_filter",
    "default_scan_filter",
    "enrich_region",
    "is_region_executable",
    "is_region_readable",
    "is_region_shared",
    "is_region_writable",
    "region_path",
)
