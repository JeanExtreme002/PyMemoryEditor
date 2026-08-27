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


def test_a_zero_width_entry_is_floored_at_the_table_door():
    """
    The AOB pattern spec declares length 0 (the scanner derives the real width
    from the pattern), so every path that falls back to it — a legacy JSON row,
    a bulk type change, a manual add — could mint a zero-byte entry that reads
    back empty forever. add_entry is the single door they all go through.

    Driven against the unbound method with a stub ``self`` so this stays in the
    pure-logic file: constructing a real CheatTable needs a process and starts
    the poll worker.
    """
    pytest.importorskip("PySide6")

    from types import SimpleNamespace

    from PyMemoryEditor.app.cheat_entry import CheatEntry
    from PyMemoryEditor.app.cheat_table import CheatTable

    # A row saved by a build that promoted AOB hits at the spec's 0.
    entry = CheatEntry.from_dict(
        {"address": "0x1000", "spec_label": "AOB Pattern (IDA)", "length": 0}
    )
    assert entry.length == 0  # the row really is zero-width on disk

    table = SimpleNamespace(_entries=[], _rebuild=lambda: None)
    CheatTable.add_entry(table, entry)
    assert table._entries[0].length == 1


@pytest.mark.parametrize(
    "entry_kwargs",
    (
        # Promoted from an AOB scan, added by hand, or loaded from a JSON table
        # written before the substitution existed — all three land in add_entry.
        {"spec_label": "AOB Pattern (IDA)", "length": 5},
        {"spec_label": "AOB Pattern (IDA)", "length": 0},
    ),
)
def test_a_pattern_entry_is_retyped_so_its_cell_round_trips(entry_kwargs):
    """
    An IDA pattern finds an address; it can't hold a value. Its ``parse``
    returns the pattern *text*, so a cell that displays hex would write ASCII
    "00" (0x30 0x30) into the target instead of the byte 0x00 — reported as a
    successful write. add_entry is the one door every entry enters through, so
    the substitution happens there rather than at each producer.
    """
    pytest.importorskip("PySide6")

    from types import SimpleNamespace

    from PyMemoryEditor.app.cheat_entry import CheatEntry
    from PyMemoryEditor.app.cheat_table import CheatTable
    from PyMemoryEditor.app.value_types import parse_value
    from PyMemoryEditor.util.convert import prepare_write

    entry = CheatEntry(description="", address=0x1000, **entry_kwargs)
    assert entry.spec.is_pattern  # what a producer handed over

    table = SimpleNamespace(_entries=[], _rebuild=lambda: None)
    CheatTable.add_entry(table, entry)

    stored = table._entries[0]
    assert stored.spec_label == "Byte Array (Hex)"
    assert stored.length >= 1

    # Editing the cell now writes the byte it displays, not its ASCII spelling.
    value, _ = parse_value(stored.spec, "00", stored.length)
    assert value == b"\x00"
    assert prepare_write(stored.spec.pytype, stored.length, value)[2] == b"\x00"


def test_the_cheat_table_never_offers_a_pattern_as_an_entry_type():
    """The type pickers must not let a user re-introduce what add_entry strips."""
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.cheat_table import HOLDABLE_TYPE_LABELS
    from PyMemoryEditor.app.value_types import VALUE_TYPES, find_spec

    assert HOLDABLE_TYPE_LABELS
    assert not any(find_spec(label).is_pattern for label in HOLDABLE_TYPE_LABELS)
    assert len(HOLDABLE_TYPE_LABELS) == len([s for s in VALUE_TYPES if not s.is_pattern])
