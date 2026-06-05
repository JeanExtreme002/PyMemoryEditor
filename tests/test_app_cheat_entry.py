# -*- coding: utf-8 -*-

"""
Functional tests for the cheat-table persistence flow (CheatEntry to/from dict).

The cheat table's JSON import/export — saving freeze targets and reloading them
across sessions — round-trips every row through ``CheatEntry.to_dict`` /
``from_dict``. That serialization is pure logic (no poll thread, so none of the
GUI-teardown flakes the smoke suite warns about), but it carries the contract
the on-disk format depends on: hex addresses, hex-encoded byte values, the
default-spec fallback and the legacy ``spec_label`` key.

``cheat_entry`` imports ``_widgets``, which imports PySide6, so this is skipped
when the ``[app]`` extra isn't installed.
"""

import os

import pytest


pytest.importorskip("PySide6", reason="Cheat-table tests require PySide6 ([app] extra).")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyMemoryEditor.app.cheat_entry import CheatEntry  # noqa: E402
from PyMemoryEditor.app.value_types import VALUE_TYPES  # noqa: E402


def test_round_trips_a_basic_int_entry():
    entry = CheatEntry(
        description="HP",
        address=0x140001000,
        spec_label=VALUE_TYPES[0].label,
        length=4,
        frozen=True,
        frozen_value=999,
    )
    restored = CheatEntry.from_dict(entry.to_dict())

    assert restored.description == "HP"
    assert restored.address == 0x140001000
    assert restored.spec_label == VALUE_TYPES[0].label
    assert restored.length == 4
    assert restored.frozen is True
    assert restored.frozen_value == 999


def test_address_is_serialized_as_hex_string():
    entry = CheatEntry("x", 0xDEAD, VALUE_TYPES[0].label, 4)
    assert entry.to_dict()["address"] == "0xDEAD"


def test_byte_array_frozen_value_round_trips_via_hex():
    bytes_spec = next(s for s in VALUE_TYPES if s.pytype is bytes and not s.is_pattern)
    entry = CheatEntry(
        description="bytes",
        address=0x1000,
        spec_label=bytes_spec.label,
        length=3,
        frozen=True,
        frozen_value=b"\xDE\xAD\xBE",
    )
    payload = entry.to_dict()
    assert payload["frozen_value"] == "deadbe"  # hex-encoded for human-readable JSON

    restored = CheatEntry.from_dict(payload)
    assert restored.frozen_value == b"\xDE\xAD\xBE"


def test_invalid_hex_address_raises():
    with pytest.raises(ValueError):
        CheatEntry.from_dict({"address": "not-hex", "spec": VALUE_TYPES[0].label})


def test_unknown_spec_falls_back_to_default():
    restored = CheatEntry.from_dict({"address": "0x10", "spec": "bogus-label"})
    assert restored.spec_label == VALUE_TYPES[0].label


def test_legacy_spec_label_key_is_accepted():
    # Older saves used "spec_label" instead of "spec".
    restored = CheatEntry.from_dict(
        {"address": "0x10", "spec_label": VALUE_TYPES[0].label}
    )
    assert restored.spec_label == VALUE_TYPES[0].label
