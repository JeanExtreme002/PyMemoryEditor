# -*- coding: utf-8 -*-

"""
Unit tests for the pure pointer-chain field parsers in
PyMemoryEditor/app/_widgets.py (``parse_offsets`` / ``resolve_base_address``).

These used to be trapped inside ``PointerChainDialog._read_offsets`` /
``_resolve_base`` — methods that called ``QMessageBox`` and read widget state,
so the parsing logic (hex offsets, the ``"module"+0xoffset`` base form, the
ASLR module-base lookup) could not be tested without a live dialog. They are
now pure functions; the dialog keeps only the message-box presentation.
"""

import pytest

pytest.importorskip("PySide6")

from PyMemoryEditor.app._widgets import (  # noqa: E402
    parse_offsets,
    resolve_base_address,
)


# --- parse_offsets --------------------------------------------------------- #

def test_parse_offsets_reads_hex_with_and_without_prefix():
    assert parse_offsets(["0x10", "158", "0X0"]) == [0x10, 0x158, 0x0]


def test_parse_offsets_skips_empty_tokens_and_preserves_order():
    assert parse_offsets(["", "0x4", "", "0x8"]) == [0x4, 0x8]


def test_parse_offsets_returns_none_on_a_bad_token():
    assert parse_offsets(["0x4", "zzz"]) is None


def test_parse_offsets_empty_is_empty_list():
    assert parse_offsets([]) == []
    assert parse_offsets(["", ""]) == []


# --- resolve_base_address -------------------------------------------------- #

def _no_modules(_name):
    return None


def test_resolve_plain_hex_base():
    addr, err = resolve_base_address("0x14010F4F4", _no_modules)
    assert err is None
    assert addr == 0x14010F4F4


def test_resolve_module_plus_offset_uses_lookup_and_adds():
    def lookup(name):
        assert name == "game.exe"
        return 0x140000000

    addr, err = resolve_base_address('"game.exe"+0x10F4F4', lookup)
    assert err is None
    assert addr == 0x140000000 + 0x10F4F4


def test_resolve_unknown_module_reports_error():
    addr, err = resolve_base_address("missing.dll+0x10", _no_modules)
    assert addr is None
    assert "not loaded" in err


def test_resolve_bad_offset_reports_error():
    addr, err = resolve_base_address('"game.exe"+zzz', lambda _n: 0x1000)
    assert addr is None
    assert "must be hex" in err


def test_resolve_garbage_base_reports_error():
    addr, err = resolve_base_address("not-an-address", _no_modules)
    assert addr is None
    assert "Base must be hex" in err
