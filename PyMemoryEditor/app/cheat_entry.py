# -*- coding: utf-8 -*-
"""
The ``CheatEntry`` dataclass — one row of the cheat table.

Lives in its own module because it is reusable by the import/export helpers
and the background poll worker without dragging in PySide6 widget code.
"""
from dataclasses import dataclass, field
from typing import Any, Dict

from ._widgets import parse_hex_address
from .value_types import VALUE_TYPES, ValueTypeSpec, find_spec


@dataclass
class CheatEntry:
    """A single saved address: description, type, length, freeze state.

    ``last_value`` is excluded from ``__eq__`` because it changes every poll
    tick and would otherwise make two semantically-identical entries compare
    as different just because their displayed values are different.
    """

    description: str
    address: int
    spec_label: str
    length: int
    frozen: bool = False
    frozen_value: Any = None
    # Last value we read from memory — only used to populate the table cell.
    last_value: Any = field(default=None, compare=False)

    @property
    def spec(self) -> ValueTypeSpec:
        spec = find_spec(self.spec_label)
        if spec is None:
            # Fallback — first entry in the catalogue is always the default 4-byte int.
            return VALUE_TYPES[0]
        return spec

    def to_dict(self) -> Dict:
        # Serialise byte values as hex so JSON stays human-readable.
        frozen = self.frozen_value
        if isinstance(frozen, (bytes, bytearray)):
            frozen = frozen.hex()
        return {
            "description": self.description,
            "address": f"0x{self.address:X}",
            "spec": self.spec_label,
            "length": self.length,
            "frozen": self.frozen,
            "frozen_value": frozen,
        }

    @classmethod
    def from_dict(cls, raw: Dict) -> "CheatEntry":
        spec_label = raw.get("spec") or raw.get("spec_label") or VALUE_TYPES[0].label
        spec = find_spec(spec_label) or VALUE_TYPES[0]
        addr_raw = raw["address"]
        if isinstance(addr_raw, str):
            parsed = parse_hex_address(addr_raw)
            if parsed is None:
                raise ValueError(f"Invalid hex address in cheat-table row: {addr_raw!r}")
            address = parsed
        else:
            address = int(addr_raw)
        frozen = raw.get("frozen_value")
        if isinstance(frozen, str) and spec.pytype is bytes:
            try:
                frozen = bytes.fromhex(frozen)
            except ValueError:
                frozen = None
        return cls(
            description=str(raw.get("description") or ""),
            address=address,
            spec_label=spec.label,
            length=int(raw.get("length") or spec.length),
            frozen=bool(raw.get("frozen", False)),
            frozen_value=frozen,
        )


__all__ = ("CheatEntry",)
