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


@pytest.mark.parametrize(
    "label, text",
    (
        ("String (UTF-8)", "hi"),
        ("Byte Array (Hex)", "AA"),
        ("Regex (String)", "hi"),
    ),
)
def test_writing_a_value_never_resizes_the_entry(label, text):
    """
    The cheat table stores the width ``parse_value_for_write`` returns back onto
    the entry (bulk edit), and that width is how many bytes the row *reads* on
    every poll tick. A write must not shrink it to the size of what was typed —
    which is what the pattern specs started doing once they got their own
    ``parse_write``, since Regex accepts a length override.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import (
        find_spec,
        parse_value,
        parse_value_for_write,
    )

    spec = find_spec(label)
    entry_width = 64
    _, write_width = parse_value_for_write(spec, text, entry_width, b"\x00" * 64)

    assert write_width == entry_width
    # And it agrees with what the search path reports for the same override.
    assert write_width == parse_value(spec, text, entry_width)[1]


def test_a_pattern_without_a_length_override_reports_its_own_width():
    """
    An IDA pattern declares no width, so with nothing to honour the write width
    is the pattern's own byte count. Nothing stores it (the spec doesn't accept
    an override, so the cheat table leaves the entry's width alone), but 0 —
    what the search path reports — would be a nonsense buffer size.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import find_spec, parse_value_for_write

    spec = find_spec("AOB Pattern (IDA)")
    assert not spec.accepts_length_override
    _, width = parse_value_for_write(spec, "48 8B ? 00", None, b"\x11" * 8)
    assert width == 4


@pytest.mark.parametrize("stale", (1234, "text", 3.14, True))
def test_a_wildcard_refuses_a_value_left_by_another_type(stale):
    """
    ``current`` is whatever the entry's spec decoded on the last poll tick, and
    a bulk edit that changes the type *and* sets a value uses the new spec on
    the old type's value in the same pass. Anything but bytes has to come back
    as ValueError — the callers only catch that, so a TypeError would escape
    the Qt slot and leave the table un-rebuilt.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import find_spec, parse_value_for_write

    with pytest.raises(ValueError, match="read at least once"):
        parse_value_for_write(find_spec("AOB Pattern (IDA)"), "48 ? 00", 3, stale)


def test_a_pattern_wider_than_its_entry_is_refused():
    """
    prepare_write truncates to the entry's width, so the extra bytes would be
    dropped in silence — while the same edit one byte *short* is rejected by
    the wildcard check. Report the mismatch instead.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import find_spec, parse_value_for_write

    spec = find_spec("AOB Pattern (IDA)")
    with pytest.raises(ValueError, match="Widen the entry"):
        parse_value_for_write(spec, "48 8B 90 90 CC CC CC CC", 5, b"\x11" * 5)

    # Exactly as wide is fine, and so is narrower.
    assert parse_value_for_write(spec, "48 8B 90 90 CC", 5, b"\x11" * 5)[0]
    assert parse_value_for_write(spec, "48 8B", 5, b"\x11" * 5)[0] == b"\x48\x8b"


def test_changing_an_entry_type_forgets_the_value_the_old_one_read():
    """
    A spec's ``format`` only accepts what its own ``pytype`` produces, and
    nothing waits for a fresh poll tick after a type change: formatting an
    Int32's 1234 as a byte array raises TypeError inside a Qt slot, and a frozen
    entry would republish the old type's value under the new ``pytype``.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.cheat_entry import CheatEntry
    from PyMemoryEditor.app.cheat_table import _forget_value_read_as_another_type

    entry = CheatEntry(
        description="", address=0x1000, spec_label="4 Bytes (Int32)", length=4
    )
    entry.last_value = 1234
    entry.frozen_value = 1234

    _forget_value_read_as_another_type(entry)
    entry.spec_label = "Byte Array (Hex)"

    assert entry.last_value is None and entry.frozen_value is None
    assert entry.spec.format(entry.last_value) == ""  # would have raised TypeError


@pytest.mark.parametrize(
    "label, width, too_wide, exactly_wide",
    (
        ("Byte Array (Hex)", 4, "DE AD BE EF 11 22", "DE AD BE EF"),
        ("String (UTF-8)", 4, "abcdef", "abcd"),
        ("Regex (String)", 4, "ABCDEFGH", "ABCD"),
        ("AOB Pattern (IDA)", 4, "DE AD BE EF 11", "DE AD BE EF"),
        # "ábc" is 3 characters but 4 bytes, and an entry's width is a byte
        # count — measuring characters would let it write one byte past.
        ("String (UTF-8)", 3, "ábc", "abc"),
    ),
)
def test_a_value_wider_than_its_entry_is_refused(
    label, width, too_wide, exactly_wide
):
    """
    ``prepare_write`` treats the entry width as a hard truncating cap, so a
    wider value was written short in silence while the cell kept showing all of
    it until the next poll tick. The pattern path already refused this; the two
    variable-width types now do too, so the three behave alike.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import find_spec, parse_value_for_write

    current = b"\x00" * width
    with pytest.raises(ValueError, match="Widen the entry"):
        parse_value_for_write(find_spec(label), too_wide, width, current)

    # Exactly as wide still goes through, at the entry's width.
    value, reported = parse_value_for_write(
        find_spec(label), exactly_wide, width, current
    )
    assert value and reported == width


def test_changing_a_type_releases_the_freeze_instead_of_retargeting_it():
    """
    A type change drops frozen_value, and leaving ``frozen`` ticked would make
    the next poll tick adopt whatever the address happens to hold as the new
    freeze target — the app would start pinning a value the user never chose.
    Releasing the box is visible and re-arming it is one click.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.cheat_entry import CheatEntry
    from PyMemoryEditor.app.cheat_table import _forget_value_read_as_another_type

    entry = CheatEntry(
        description="", address=0x1000, spec_label="4 Bytes (Int32)", length=4
    )
    entry.frozen = True
    entry.frozen_value = 100
    entry.last_value = 100

    _forget_value_read_as_another_type(entry)

    assert not entry.frozen
    assert entry.frozen_value is None and entry.last_value is None


def test_a_row_frozen_before_its_first_read_arms_on_that_read():
    """
    Ticking Active before the first poll leaves frozen with no target — the
    poll worker skips such an entry — so the first value read arms it. That is
    a deliberate user action on an unchanged type, unlike the retype above.
    """
    pytest.importorskip("PySide6")

    from types import SimpleNamespace

    from PyMemoryEditor.app.cheat_entry import CheatEntry
    from PyMemoryEditor.app.cheat_table import CheatTable

    entry = CheatEntry(
        description="", address=0x1000, spec_label="4 Bytes (Int32)", length=4
    )
    entry.frozen = True  # ticked before anything was read

    table = SimpleNamespace(
        _entries=[entry],
        _editing_row=lambda: None,
        _update_value_cell=lambda row, e: None,
        _suspend_signals=False,
    )
    CheatTable._on_values_ready(table, [(0x1000, int, 4, 77)])

    assert entry.frozen_value == 77


def test_re_promoting_an_address_forgets_the_value_its_old_type_read():
    """
    add_entry's "address already exists" branch is the third place a
    spec_label changes — promoting the same address again from a scan or from
    a pointer dialog — and _rebuild formats the cached value through the new
    spec on the way out, so the old type's value has to go here too.
    """
    pytest.importorskip("PySide6")

    from types import SimpleNamespace

    from PyMemoryEditor.app.cheat_entry import CheatEntry
    from PyMemoryEditor.app.cheat_table import CheatTable

    existing = CheatEntry(
        description="", address=0x1000, spec_label="String (UTF-8)", length=8
    )
    existing.last_value = "hello"
    existing.frozen = True
    existing.frozen_value = "hello"

    table = SimpleNamespace(_entries=[existing], _rebuild=lambda: None)
    CheatTable.add_entry(
        table,
        CheatEntry(
            description="", address=0x1000, spec_label="Byte Array (Hex)", length=4
        ),
    )

    stored = table._entries[0]
    assert stored.spec_label == "Byte Array (Hex)"
    assert stored.last_value is None and stored.frozen_value is None
    # _fmt_bytes("hello") would have raised ValueError inside add_entry.
    assert stored.spec.format(stored.last_value) == ""


@pytest.mark.parametrize(
    "old_label, current, expected",
    (
        # Byte Array → AOB keeps what the bytes mean, so the wildcard has
        # something to keep even though the type change forgot the cache.
        ("Byte Array (Hex)", b"\x11\x22\x33\x44", b"\x48\x22\x33\x00"),
        # Int32 → AOB doesn't: those bytes were never read as bytes.
        ("4 Bytes (Int32)", 1234, None),
    ),
)
def test_a_bulk_edit_that_retypes_and_writes_uses_the_value_it_replaced(
    old_label, current, expected
):
    """
    The bulk edit changes the type and writes a value in the same pass, and the
    type change forgets the cached value — so the write has to have captured it
    first, or an IDA '?' finds nothing to keep and every selected row fails.
    A value the new type could never have produced is ignored rather than
    misread, which is why the Int32 case still refuses.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import find_spec, parse_value_for_write

    spec = find_spec("AOB Pattern (IDA)")
    if expected is None:
        with pytest.raises(ValueError, match="read at least once"):
            parse_value_for_write(spec, "48 ? ? 00", 4, current)
    else:
        assert parse_value_for_write(spec, "48 ? ? 00", 4, current)[0] == expected


def test_a_bulk_retype_sizes_the_entry_from_the_value_it_writes():
    """
    A bulk edit that changes the type *and* sets a value has no width field —
    and a multi-row selection offers no "change length" either — so inheriting
    the replaced type's width made a widening retype a dead end: three Int32
    rows retyped to String with "hello" all failed on "the entry holds 4".
    A variable-width spec takes its width from the value instead.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.value_types import find_spec, parse_value_for_write

    spec = find_spec("String (UTF-8)")

    # What the entry inherited from Int32 would have refused it.
    with pytest.raises(ValueError, match="Widen the entry"):
        parse_value_for_write(spec, "hello", 4, None)

    # Sized from the value, as the retype path now asks for.
    value, width = parse_value_for_write(spec, "hello", None, None)
    assert value == "hello" and width == 5


def test_an_entry_width_is_bounded_by_what_a_poll_tick_can_read():
    """
    The poll worker allocates the entry's width for every row on every 100 ms
    tick, so an unbounded field turns one typo into a multi-gigabyte allocation
    that the tick's blanket except swallows and retries forever.
    """
    pytest.importorskip("PySide6")

    from PyMemoryEditor.app.cheat_table import MAX_ENTRY_LENGTH

    # Far above any value a scan produces, far below a problem allocation.
    assert 1024 < MAX_ENTRY_LENGTH <= 16 * 1024 * 1024
