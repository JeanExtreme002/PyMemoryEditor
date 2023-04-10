# -*- coding: utf-8 -*-
from enum import Enum


class ScanTypesEnum(Enum):
    """
    Enum with scan types. Used by SearchAllMemory function.
    """
    EXACT_VALUE = 0
    DIFFERENT_THAN = 1
    BIGGER_THAN = 2
    SMALLER_THAN = 3
    BIGGER_THAN_OR_EXACT_VALUE = 4
    SMALLER_THAN_OR_EXACT_VALUE = 5
