# -*- coding: utf-8 -*-
from enum import Enum


class ScanTypesEnum(Enum):
    """
    Enum with scan types. Used by SearchAllMemory function.
    """
    EXACT_VALUE = 0
    BIGGER_THAN = 1
    SMALLER_THAN = 2