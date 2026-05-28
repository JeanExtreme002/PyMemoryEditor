# -*- coding: utf-8 -*-
"""
App-only "Next Scan" comparison types (Cheat Engine's Increased / Decreased /
Changed / Unchanged / *_BY).

These deliberately live in the app rather than in the PyMemoryEditor library:
unlike :class:`~PyMemoryEditor.ScanTypesEnum`, they don't map to a single
full-memory search — they compare each address's *current* value against the
value recorded by the *previous* scan. Only the GUI (which already keeps every
found address's last-read value) has that previous value, so the comparison is
pure app logic layered on top of ``search_by_addresses``.
"""
from enum import Enum
from typing import Any, Union

from PyMemoryEditor import ScanTypesEnum


class NextScanType(Enum):
    """Refine-only comparisons against the previously recorded value."""

    INCREASED_VALUE = "increased_value"  # current > previous
    INCREASED_VALUE_BY = "increased_value_by"  # current == previous + target
    DECREASED_VALUE = "decreased_value"  # current < previous
    DECREASED_VALUE_BY = "decreased_value_by"  # current == previous - target
    CHANGED_VALUE = "changed_value"  # current != previous
    UNCHANGED_VALUE = "unchanged_value"  # current == previous


# A scan type in the app may be either a library comparison or an app-only one.
ScanType = Union[ScanTypesEnum, NextScanType]

# Next-scan-only comparisons that take no user-supplied value (the comparison
# is purely current-vs-previous). The *_BY variants are excluded — they still
# read a delta from the Value field.
NO_VALUE_SCAN_TYPES = frozenset(
    {
        NextScanType.INCREASED_VALUE,
        NextScanType.DECREASED_VALUE,
        NextScanType.CHANGED_VALUE,
        NextScanType.UNCHANGED_VALUE,
    }
)

# *_BY variants: the Value field carries the amount the value changed by.
DELTA_SCAN_TYPES = frozenset(
    {
        NextScanType.INCREASED_VALUE_BY,
        NextScanType.DECREASED_VALUE_BY,
    }
)


def is_next_scan_type(scan_type: Any) -> bool:
    """True if ``scan_type`` is one of the app-only refine comparisons."""
    return isinstance(scan_type, NextScanType)
