# -*- coding: utf-8 -*-

"""Small Qt widgets shared between dialogs.

Centralises tiny helpers (numeric sort items, hex address parsing) that
previously appeared duplicated across several dialog modules.
"""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QStandardItem


class NumericItem(QStandardItem):
    """A QStandardItem that compares by its Qt.UserRole int payload.

    Used by columns showing formatted numbers (sizes, addresses, PIDs) so the
    table sorts by the underlying value rather than the lexical label.
    """

    def __lt__(self, other):
        try:
            return int(self.data(Qt.UserRole)) < int(other.data(Qt.UserRole))
        except (TypeError, ValueError):
            return super().__lt__(other)


def parse_hex_address(text: str) -> Optional[int]:
    """Parse a hex address string (with or without 0x prefix) into an int.

    Returns None on any parse error. Whitespace is tolerated.
    """
    if not text:
        return None
    cleaned = text.strip()
    if not cleaned:
        return None
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    try:
        return int(cleaned, 16)
    except (TypeError, ValueError):
        return None
