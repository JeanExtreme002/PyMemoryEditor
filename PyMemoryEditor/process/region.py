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
"""

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


def _has_attr(obj, name: str) -> bool:
    return hasattr(obj, name)


def is_region_readable(region: dict) -> bool:
    """True when the region is readable (no syscall — inspects the struct)."""
    info = region["struct"]

    # Linux: privileges string contains 'r'.
    if _has_attr(info, "Privileges"):
        return b"r" in bytes(info.Privileges)

    # macOS: VM_PROT_READ bit.
    if _has_attr(info, "Protection") and _has_attr(info, "Shared"):
        return (info.Protection & 0x01) != 0  # VM_PROT_READ

    # Windows: Protect bitmask + State must be MEM_COMMIT.
    if _has_attr(info, "Protect") and _has_attr(info, "State"):
        if info.State != 0x1000:  # MEM_COMMIT
            return False
        # Mask of readable PAGE_* values matching MemoryProtectionsEnum.PAGE_READABLE.
        readable_mask = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80
        return (info.Protect & readable_mask) != 0

    return False


def is_region_writable(region: dict) -> bool:
    info = region["struct"]

    if _has_attr(info, "Privileges"):
        return b"w" in bytes(info.Privileges)

    if _has_attr(info, "Protection") and _has_attr(info, "Shared"):
        return (info.Protection & 0x02) != 0  # VM_PROT_WRITE

    if _has_attr(info, "Protect") and _has_attr(info, "State"):
        if info.State != 0x1000:
            return False
        writable_mask = 0x04 | 0x08 | 0x40 | 0x80
        return (info.Protect & writable_mask) != 0

    return False


def is_region_executable(region: dict) -> bool:
    info = region["struct"]

    if _has_attr(info, "Privileges"):
        return b"x" in bytes(info.Privileges)

    if _has_attr(info, "Protection") and _has_attr(info, "Shared"):
        return (info.Protection & 0x04) != 0  # VM_PROT_EXECUTE

    if _has_attr(info, "Protect") and _has_attr(info, "State"):
        if info.State != 0x1000:
            return False
        executable_mask = 0x10 | 0x20 | 0x40 | 0x80
        return (info.Protect & executable_mask) != 0

    return False


def is_region_shared(region: dict) -> bool:
    info = region["struct"]

    if _has_attr(info, "Privileges"):
        # Linux: 's' for shared, 'p' for private — last char of the privileges string.
        return b"s" in bytes(info.Privileges)

    if _has_attr(info, "Shared"):
        return bool(info.Shared)

    if _has_attr(info, "Type"):
        # Windows: MEM_MAPPED indicates a file-backed shared mapping.
        return info.Type == 0x40000  # MEM_MAPPED

    return False


def region_path(region: dict) -> str:
    """
    Best-effort path of the file backing the region, or "" when unknown.

    Linux can derive it from /proc/<pid>/maps (already populated). Win32 and
    macOS would require extra syscalls (GetMappedFileName / proc_regionfilename)
    that the backends don't currently make.
    """
    info = region["struct"]

    if _has_attr(info, "Path"):
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


__all__ = (
    "REGION_KEYS",
    "enrich_region",
    "is_region_executable",
    "is_region_readable",
    "is_region_shared",
    "is_region_writable",
    "region_path",
)
