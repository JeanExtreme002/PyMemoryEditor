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
    "text, current, expected",
    (
        # Plain hex writes the bytes it names — the same ones the cell shows.
        ("48 8B 00", None, b"\x48\x8b\x00"),
        # A '?' keeps the byte already there, so a signature can be patched
        # without disturbing the operands around what you meant to change.
        ("48 ? 00", b"\x11\x22\x33", b"\x48\x22\x00"),
        ("? ? ?", b"\xaa\xbb\xcc", b"\xaa\xbb\xcc"),
    ),
)
def test_an_aob_entry_writes_the_bytes_its_cell_displays(text, current, expected):
    """
    ``spec.parse`` answers the scanner's question and returns the pattern
    *text*, which would write the ASCII spelling of the hex the cell displays
    ("00" as 0x30 0x30). The write path asks ``parse_value_for_write``
    instead, which resolves the tokens to the bytes they name.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import find_spec, parse_value_for_write
    from PyMemoryEditor.util.convert import prepare_write

    spec = find_spec("AOB Pattern (IDA)")
    value, _ = parse_value_for_write(spec, text, len(expected), current)
    assert value == expected
    # And survives the encode the backend performs on the way to the process.
    assert prepare_write(spec.pytype, len(expected), value)[2] == expected


def test_an_aob_wildcard_needs_something_to_keep():
    """A '?' means "leave that byte alone", so it needs a byte to leave alone."""
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import find_spec, parse_value_for_write

    spec = find_spec("AOB Pattern (IDA)")
    with pytest.raises(ValueError, match="read at least once"):
        parse_value_for_write(spec, "48 ? 00", 3, None)

    # Read, but not far enough to cover the wildcard's offset.
    with pytest.raises(ValueError, match="nothing to keep"):
        parse_value_for_write(spec, "48 8B ?", 3, b"\x11")


def test_a_regex_entry_writes_its_cell_text_literally():
    """
    A regex names a *set* of byte strings, so the pattern can't be written
    back. The cell shows the text read at the address, so an edit is taken
    literally — the same rule String (UTF-8) follows.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import find_spec, parse_value_for_write

    spec = find_spec("Regex (String)")
    value, _ = parse_value_for_write(spec, "Player01", 64, b"Player42")
    assert value == b"Player01"


def test_every_non_pattern_type_writes_exactly_what_it_searches_for():
    """``parse_write`` exists only where the two questions differ."""
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import VALUE_TYPES

    for spec in VALUE_TYPES:
        assert (spec.parse_write is not None) == spec.is_pattern, spec.label
