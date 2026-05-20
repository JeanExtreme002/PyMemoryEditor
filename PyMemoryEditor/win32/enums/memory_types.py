# -*- coding: utf-8 -*-
from enum import IntFlag


class MemoryTypesEnum(IntFlag):
    """
    Memory region type (MEM_* constants from MEMORY_BASIC_INFORMATION.Type).

    These values are mutually exclusive in practice but use distinct bit
    patterns; ``IntFlag`` keeps direct bitwise comparisons working without
    requiring ``.value`` unwrapping.
    """

    # Memory pages within the region are mapped into the view of an image section.
    MEM_IMAGE = 0x1000000

    # Memory pages within the region are mapped into the view of a section.
    MEM_MAPPED = 0x40000

    # Memory pages within the region are private (not shared by other processes).
    MEM_PRIVATE = 0x20000
