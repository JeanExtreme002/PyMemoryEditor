# -*- coding: utf-8 -*-

"""
Unit tests for PyMemoryEditor.util.pattern.compile_pattern.

These tests don't touch process memory — they validate the pattern compiler
in isolation so a regression in pattern parsing fails fast and clearly
instead of as a no-match in the scan loop.
"""

import re

import pytest

from PyMemoryEditor.util.pattern import compile_pattern


def test_ida_style_basic():
    """A plain hex string compiles and matches its own bytes."""
    pattern, length = compile_pattern("48 8B 90")
    assert length == 3
    assert pattern.search(b"\x48\x8B\x90") is not None
    assert pattern.search(b"\x48\x8B\x91") is None


def test_ida_style_wildcard_single_question():
    """`?` is a one-byte wildcard."""
    pattern, length = compile_pattern("48 ? 90")
    assert length == 3
    assert pattern.search(b"\x48\x00\x90") is not None
    assert pattern.search(b"\x48\xFF\x90") is not None
    # Wildcard must NOT match more or fewer than one byte.
    assert pattern.search(b"\x48\x90") is None


def test_ida_style_wildcard_double_question():
    """`??` is the alternate one-byte wildcard syntax — same semantics as `?`."""
    pattern, length = compile_pattern("48 ?? 90")
    assert length == 3
    assert pattern.search(b"\x48\xAB\x90") is not None


def test_ida_style_multiple_wildcards():
    pattern, length = compile_pattern("DE AD ? ? EF")
    assert length == 5
    assert pattern.search(b"\xDE\xAD\xBE\xEF\xEF") is not None
    assert pattern.search(b"\xDE\xAD\x00\x00\xEF") is not None


def test_ida_style_irregular_whitespace():
    """Multiple spaces/tabs/newlines between tokens are fine."""
    pattern, length = compile_pattern("48   8B\t90\n00")
    assert length == 4
    assert pattern.search(b"\x48\x8B\x90\x00") is not None


def test_ida_style_lowercase_hex():
    """Lower-case hex digits should be accepted as well as upper-case."""
    pattern, length = compile_pattern("de ad be ef")
    assert length == 4
    assert pattern.search(b"\xDE\xAD\xBE\xEF") is not None


def test_ida_style_escapes_regex_specials():
    """
    Bytes like 0x5C (``\\``), 0x28 (``(``) or 0x2E (``.``) are regex
    meta chars. The compiler must escape them so the pattern still matches
    the literal byte and not interpret it as regex syntax.
    """
    # 0x5C, 0x28 and 0x2E are all regex specials.
    pattern, length = compile_pattern("5C 28 2E")
    assert length == 3
    assert pattern.search(b"\x5C\x28\x2E") is not None
    # If 0x2E was left as a regex `.`, the next match would falsely succeed:
    assert pattern.search(b"\x5C\x28\x00") is None


def test_ida_style_rejects_bad_token():
    # Token has the right length but contains non-hex digits — the compiler
    # routes this through bytes.fromhex which raises a different message
    # than the "wrong length" branch above. Match either of the two ValueError
    # phrasings to keep the test resilient to minor message changes.
    with pytest.raises(ValueError, match="(not valid hex|not two hex digits)"):
        compile_pattern("48 8B Z9")


def test_ida_style_rejects_single_digit_token():
    with pytest.raises(ValueError, match="not two hex digits"):
        compile_pattern("48 8 90")


def test_ida_style_rejects_empty():
    with pytest.raises(ValueError, match="Empty pattern"):
        compile_pattern("   ")


def test_bytes_regex_requires_explicit_length():
    """Bytes regex without ``byte_length=`` must error — the source length
    is not a reliable proxy for the matched length."""
    with pytest.raises(ValueError, match="byte_length"):
        compile_pattern(rb"\x48\x8B")


def test_bytes_regex_with_explicit_length():
    """Bytes regex compiles with DOTALL — ``.`` matches any byte (incl. 0x0A)."""
    pattern, length = compile_pattern(rb"\x48\x8B..", byte_length=4)
    assert length == 4
    assert pattern.search(b"\x48\x8B\x0A\x0B") is not None
    # The dot must even match newline bytes (DOTALL is the key):
    assert pattern.search(b"\x48\x8B\n\n") is not None


def test_compiled_pattern_passthrough():
    """Passing an already-compiled re.Pattern returns it unchanged."""
    precompiled = re.compile(rb"\xDE\xAD", re.DOTALL)
    pattern, length = compile_pattern(precompiled, byte_length=2)
    assert pattern is precompiled
    assert length == 2


def test_compiled_pattern_requires_explicit_length():
    precompiled = re.compile(rb"\xDE\xAD", re.DOTALL)
    with pytest.raises(ValueError, match="byte_length"):
        compile_pattern(precompiled)


def test_rejects_unsupported_input_type():
    with pytest.raises(TypeError, match="Pattern must be"):
        compile_pattern(12345)  # type: ignore[arg-type]
