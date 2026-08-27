# -*- coding: utf-8 -*-
"""
Definitions of the value types the UI exposes.

PyMemoryEditor's API takes a raw Python ``type`` (bool, int, float, str, bytes)
and an explicit byte length. This module maps user-friendly labels (1 Byte,
4 Bytes, Float, Double, String UTF-8, Byte Array) to (pytype, length) pairs
and provides the parsing helpers used by the scanner panel.
"""
from dataclasses import dataclass
from typing import Any, Callable, Optional, Tuple


@dataclass(frozen=True)
class ValueTypeSpec:
    """Describes one row in the "Value Type" combo box."""

    label: str
    pytype: type
    length: int
    parse: Callable[[str], Any]
    format: Callable[[Any], str]
    hex_capable: bool = False  # Can the value be entered in hex?
    accepts_length_override: bool = False  # True only for str/bytes
    # When True the scanner panel routes this type through
    # ``process.search_by_pattern`` (AOB / IDA-style hex with wildcards)
    # instead of ``search_by_value`` — the "Value" input becomes the pattern
    # string and the scan-type / length controls are hidden because they
    # don't apply.
    is_pattern: bool = False
    # When True the pattern is a raw *bytes regex* rather than an IDA-style hex
    # string. Implies ``is_pattern``. Unlike the IDA form (whose match width is
    # inferred from the token count), a regex's match width can't be inferred,
    # so the panel keeps the Length field enabled and uses it as the
    # ``byte_length`` (the number of bytes one match consumes) that
    # ``search_by_pattern`` requires for regex input.
    is_regex: bool = False


def _parse_bool(text: str) -> bool:
    t = text.strip().lower()
    if t in ("1", "true", "t", "yes", "y", "on"):
        return True
    if t in ("0", "false", "f", "no", "n", "off"):
        return False
    raise ValueError("Expected a boolean (true/false, 1/0).")


def _parse_int_factory(signed: bool, byte_len: int):
    bits = byte_len * 8
    if signed:
        lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    else:
        lo, hi = 0, (1 << bits) - 1

    def parse(text: str) -> int:
        text = text.strip()
        if not text:
            raise ValueError("Empty value.")
        # Accept 0x… for hex or plain decimal.
        base = 16 if text.lower().startswith("0x") else 10
        n = int(text, base)
        if not (lo <= n <= hi):
            raise ValueError(
                f"Value {n} out of range for {byte_len}-byte {'signed' if signed else 'unsigned'} int."
            )
        return n

    return parse


def _parse_float(text: str) -> float:
    return float(text.strip().replace(",", "."))


def _parse_bytes(text: str) -> bytes:
    """Parse a space-separated hex byte string ("DE AD BE EF") into bytes."""
    cleaned = "".join(text.split())
    if not cleaned:
        raise ValueError("Empty byte array.")
    if len(cleaned) % 2 != 0:
        raise ValueError("Byte array needs an even number of hex digits.")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid byte array: {exc}")


def _parse_str(text: str) -> str:
    """Return the value text verbatim, rejecting an empty one.

    An empty string sizes to a 1-byte NUL buffer, so *scanning* for it matches
    every zeroed byte in the target, and *writing* it is a no-op (``prepare_write``
    truncates to the value and never pads). Neither is what the user meant.
    ``_parse_bytes`` already rejects its own empty input; this keeps the two
    variable-width types consistent.

    The wording stays neutral because this runs on the cheat table's write
    paths too, not only on a scan.
    """
    if not text:
        raise ValueError("Empty value.")
    return text


def _parse_pattern(text: str) -> str:
    """Validate an IDA-style AOB pattern and return it verbatim.

    The scanner passes the string straight to ``process.search_by_pattern``,
    so the parse step is just a "does this compile?" gate that surfaces a
    clear ValueError early — much friendlier than letting the scan worker
    raise mid-iteration with a low-level message.
    """
    from PyMemoryEditor.util.pattern import compile_pattern

    stripped = text.strip()
    if not stripped:
        raise ValueError(
            "Empty pattern. Use IDA syntax: hex bytes separated by spaces, "
            "with '?' as a one-byte wildcard. Example: '48 8B ? ? 00'."
        )
    # Side-effect: raises ValueError on malformed input. We don't keep the
    # compiled regex here — the scanner re-compiles on its end so this is
    # purely for early validation feedback.
    compile_pattern(stripped)
    return stripped


def _parse_regex(text: str) -> bytes:
    """Validate a *text regex* and return it as the UTF-8 ``bytes`` pattern.

    The user types an ordinary string regex — e.g. ``Player[0-9]+`` — which is
    UTF-8 encoded into the bytes pattern that ``search_by_pattern`` matches
    against the target's memory (the library treats string memory as UTF-8).
    Because the match runs against *bytes*, regex metacharacters operate on a
    single **byte**: ``.`` matches one byte (any byte — the scan compiles with
    ``re.DOTALL``) and ``\\d`` / ``[A-Z]`` are ASCII-only. A literal non-ASCII
    character still matches its full UTF-8 byte sequence, but a metacharacter
    like ``.`` only spans one byte of a multibyte character, so quantify those
    with care (e.g. ``.+`` rather than ``.``).

    Like ``_parse_pattern`` this is an early "does this compile?" gate so a
    malformed regex surfaces a clear ValueError in a dialog instead of blowing
    up mid-scan. A regex has no inferable match width, so the scanner pairs this
    value with the Length field as the ``byte_length`` (the max match width).
    """
    if not text.strip():
        raise ValueError(
            "Empty regex. Type a text regex such as 'Player[0-9]+'. "
            "Set Length to the maximum match width in bytes."
        )
    # Encode verbatim (not stripped) so whitespace inside the regex is honored.
    pattern = text.encode("utf-8")
    import re

    try:
        re.compile(pattern, re.DOTALL)
    except re.error as exc:
        raise ValueError(f"Invalid regex: {exc}")
    return pattern


def _fmt_bytes(value: bytes) -> str:
    if value is None:
        return ""
    return " ".join(f"{b:02X}" for b in value)


def _fmt_regex_match(value) -> str:
    """Format a regex result value (the bytes read at the match address).

    The scanner reads ``byte_length`` bytes at each hit; show them as text up
    to the first NUL (C-string style) so a matched string reads cleanly, and
    decode leniently so stray non-text bytes don't blow up the table.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return str(value)


def _fmt_int(value):
    if value is None:
        return ""
    try:
        return str(int(value))
    except (TypeError, ValueError):
        return str(value)


# Order matters — first item is the default selection.
VALUE_TYPES = (
    ValueTypeSpec(
        "4 Bytes (Int32)",
        int,
        4,
        _parse_int_factory(True, 4),
        _fmt_int,
        hex_capable=True,
    ),
    ValueTypeSpec(
        "2 Bytes (Int16)",
        int,
        2,
        _parse_int_factory(True, 2),
        _fmt_int,
        hex_capable=True,
    ),
    ValueTypeSpec(
        "1 Byte  (Int8)",
        int,
        1,
        _parse_int_factory(True, 1),
        _fmt_int,
        hex_capable=True,
    ),
    ValueTypeSpec(
        "8 Bytes (Int64)",
        int,
        8,
        _parse_int_factory(True, 8),
        _fmt_int,
        hex_capable=True,
    ),
    ValueTypeSpec(
        "Float (4 Bytes)",
        float,
        4,
        _parse_float,
        lambda v: "" if v is None else f"{v:g}",
    ),
    ValueTypeSpec(
        "Double (8 Bytes)",
        float,
        8,
        _parse_float,
        lambda v: "" if v is None else f"{v:g}",
    ),
    ValueTypeSpec(
        "Boolean (1 Byte)",
        bool,
        1,
        _parse_bool,
        lambda v: "" if v is None else str(bool(v)),
    ),
    ValueTypeSpec(
        "String (UTF-8)",
        str,
        16,
        _parse_str,
        lambda v: "" if v is None else str(v),
        accepts_length_override=True,
    ),
    ValueTypeSpec(
        "Byte Array (Hex)",
        bytes,
        4,
        _parse_bytes,
        _fmt_bytes,
        accepts_length_override=True,
    ),
    # AOB pattern scan — the "Value" input becomes an IDA-style hex string
    # with '?' wildcards; the scanner panel hides scan-type / length / "Next
    # Scan" because they don't apply.
    ValueTypeSpec(
        "AOB Pattern (IDA)",
        bytes,
        0,
        _parse_pattern,
        lambda v: "" if v is None else (v if isinstance(v, str) else _fmt_bytes(v)),
        accepts_length_override=False,
        is_pattern=True,
    ),
    # Text-regex scan — the "Value" input becomes a string regex (e.g.
    # ``Player[0-9]+``) UTF-8 encoded into the bytes pattern, and the Length
    # field supplies the ``byte_length`` (max match width) that
    # ``search_by_pattern`` requires for regex. Default width is generous so
    # typical string matches aren't clipped at a chunk boundary.
    ValueTypeSpec(
        "Regex (String)",
        bytes,
        64,
        _parse_regex,
        _fmt_regex_match,
        accepts_length_override=True,
        is_pattern=True,
        is_regex=True,
    ),
)


def find_spec(label: str) -> Optional[ValueTypeSpec]:
    for spec in VALUE_TYPES:
        if spec.label == label:
            return spec
    return None


def parse_value(
    spec: ValueTypeSpec, text: str, length_override: Optional[int] = None
) -> Tuple[Any, int]:
    """Parse ``text`` according to ``spec``, returning ``(value, effective_length)``.

    For str/bytes, ``length_override`` lets the user widen/shrink the buffer.
    """
    value = spec.parse(text)
    length = spec.length
    # Pattern types short-circuit the bytes/str length-inference rules below
    # (which would wrongly count the pattern *source* length).
    if spec.is_pattern:
        # A regex's match width can't be inferred, so it comes from the Length
        # field (``byte_length``); fall back to the spec default if unset.
        # An IDA pattern derives its width from the pattern itself, so report 0.
        if spec.is_regex:
            bl = length_override if length_override is not None else spec.length
            return value, max(1, int(bl))
        return value, 0
    if spec.accepts_length_override and length_override is not None:
        length = max(1, int(length_override))
    if spec.pytype is bytes and length_override is None:
        # Default to the value's natural length.
        length = max(1, len(value))
    if spec.pytype is str and length_override is None:
        # Use the UTF-8 byte length, not the character count — multi-byte
        # characters (accents, CJK, emoji) need more bytes than chars and
        # under-allocating would silently truncate the value the user typed.
        length = max(1, len(value.encode("utf-8")))
    return value, length
