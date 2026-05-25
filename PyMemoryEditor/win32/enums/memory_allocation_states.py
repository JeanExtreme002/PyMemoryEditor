# -*- coding: utf-8 -*-
from enum import IntFlag


class MemoryAllocationStatesEnum(IntFlag):
    """
    Memory allocation state / allocation-time flags.

    Mixes ``MEMORY_BASIC_INFORMATION.State`` values (MEM_COMMIT, MEM_FREE,
    MEM_RESERVE) with VirtualAlloc ``flAllocationType`` flags (MEM_LARGE_PAGES,
    MEM_PHYSICAL, etc.). Using ``IntFlag`` lets callers combine the latter
    while still comparing the former directly.
    """

    # Pages are committed (physical storage backed by RAM or pagefile).
    MEM_COMMIT = 0x1000

    # Pages are free / unallocated.
    MEM_FREE = 0x10000

    # Pages are reserved (no physical storage yet).
    MEM_RESERVE = 0x2000

    # VirtualAlloc flags below — not present in MBI.State, but exposed here
    # since callers occasionally compose them.
    MEM_LARGE_PAGES = 0x20000000
    MEM_PHYSICAL = 0x00400000
    MEM_TOP_DOWN = 0x00100000
    MEM_RESET = 0x00080000
    MEM_RESET_UNDO = 0x1000000
