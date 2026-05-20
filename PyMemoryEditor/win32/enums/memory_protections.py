# -*- coding: utf-8 -*-
from enum import IntFlag


class MemoryProtectionsEnum(IntFlag):
    """
    Memory protection bitmask (PAGE_* constants).

    Defined as ``IntFlag`` so that combinations (e.g.
    ``PAGE_EXECUTE_READ | PAGE_GUARD``) and bit tests
    (``protect & PAGE_READWRITE``) work without unwrapping ``.value``.

    Reference:
      https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants
    """

    # Disables all access to the committed region of pages. An attempt to read
    # from, write to, or execute the committed region results in an access
    # violation.
    PAGE_NOACCESS = 0x01

    # Enables read-only access to the committed region of pages.
    PAGE_READONLY = 0x02

    # Enables read-only or read/write access to the committed region.
    PAGE_READWRITE = 0x04

    # Enables read-only or copy-on-write access to a mapped view of a file
    # mapping object.
    PAGE_WRITECOPY = 0x08

    # Enables execute access to the committed region of pages.
    PAGE_EXECUTE = 0x10

    # Enables execute or read-only access to the committed region of pages.
    PAGE_EXECUTE_READ = 0x20

    # Enables execute, read-only, or read/write access to the committed region.
    PAGE_EXECUTE_READWRITE = 0x40

    # Enables execute, read-only, or copy-on-write access.
    PAGE_EXECUTE_WRITECOPY = 0x80

    # Pages in the region become guard pages.
    PAGE_GUARD = 0x100

    # Sets all pages to be non-cachable.
    PAGE_NOCACHE = 0x200

    # Sets all pages to be write-combined.
    PAGE_WRITECOMBINE = 0x400

    # CFG: pages are marked as invalid call targets. Note: the Windows SDK
    # defines both PAGE_TARGETS_INVALID (VirtualAlloc) and PAGE_TARGETS_NO_UPDATE
    # (VirtualProtect) at the same bit (0x40000000). Their semantics differ by
    # context (alloc vs. protect), but they share the bit pattern; in an
    # IntFlag this means PAGE_TARGETS_NO_UPDATE resolves to the same member as
    # PAGE_TARGETS_INVALID. That matches Microsoft's bit-level definition and
    # is intentional — it just was previously silent under plain Enum.
    PAGE_TARGETS_INVALID = 0x40000000
    PAGE_TARGETS_NO_UPDATE = 0x40000000  # alias by design (see comment above).

    # Custom composite: bitmask of every protection that allows reads.
    PAGE_READABLE = (
        PAGE_READONLY
        | PAGE_READWRITE
        | PAGE_WRITECOPY
        | PAGE_EXECUTE_READ
        | PAGE_EXECUTE_READWRITE
        | PAGE_EXECUTE_WRITECOPY
    )

    # Custom composite: bitmask of every protection that allows writes.
    PAGE_READWRITEABLE = (
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
