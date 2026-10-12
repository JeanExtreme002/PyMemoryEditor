# -*- coding: utf-8 -*-

"""
Pattern compilation for "Array Of Bytes" (AOB) scanning — the technique used
by Cheat Engine, IDA, and most game-hacking tools to locate code/data that
shifts between builds.

Two input shapes are accepted:

1. **IDA-style** string with ``?`` / ``??`` wildcards::

        compile_pattern("48 8B ? ? 00 00")

   Every space-separated token must be either two hex digits (``"48"``) or a
   single/double ``?`` for a one-byte wildcard. Whitespace between tokens is
   free-form. This is the format almost every public AOB recipe online uses.

2. **Raw regex bytes** — passed through unchanged with ``re.DOTALL`` so that
   the regex meta character ``.`` is allowed to match any byte (including
   newlines, which is what you want when scanning binary memory)::

        compile_pattern(rb"\\x48\\x8B..\\x00\\x00")

The function returns a compiled ``re.Pattern[bytes]`` ready to be run against
memory chunks read from the target. A fixed-width pattern (every IDA-style
signature) is scanned for *overlapping* matches, the way a value scan reports
every offset; see :func:`is_fixed_width`.
"""

import logging
import re
from typing import List, Optional, Pattern, Tuple, Union

try:  # The regex parser moved in 3.11; ``sre_parse`` is a deprecated alias there.
    from re import _parser as _regex_parser  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - Python 3.10
    import sre_parse as _regex_parser


_logger = logging.getLogger("PyMemoryEditor")


PatternLike = Union[str, bytes, "re.Pattern[bytes]"]


def compile_pattern(
    pattern: PatternLike,
    *,
    byte_length: int = 0,
) -> Tuple["Pattern[bytes]", int]:
    """Compile ``pattern`` into a bytes ``re.Pattern`` plus the **number of
    bytes** each successful match consumes.

    Returns a ``(compiled_regex, byte_length)`` pair. The second value is the
    width of one match in the target's memory — the scanner uses it to compute
    chunk-overlap so a match straddling a chunk boundary still gets emitted.

    :param pattern: one of:

        * An **IDA-style hex string** with ``?`` / ``??`` wildcards
          (``"48 8B ? ? 00"``) — most cheat-table dumps use this format. Each
          token is one byte; the returned ``byte_length`` equals the number of
          tokens.
        * A **raw bytes regex** (``rb"\\x48\\x8B..\\x00"``). Compiled with
          ``re.DOTALL`` so ``.`` matches any byte. **You must pass**
          ``byte_length=`` for this form — there is no general way to infer
          how many bytes a regex consumes.
        * An **already-compiled** ``re.Pattern[bytes]``: same rule — you must
          pass ``byte_length=``.

    :raises ValueError: malformed IDA-style token, or ``byte_length`` omitted
        for a regex / pre-compiled pattern.
    :raises TypeError: if ``pattern`` is not a ``str``, ``bytes`` or
        ``re.Pattern[bytes]`` — a compiled ``str`` regex included, as it can
        never match process memory.
    """
    if isinstance(pattern, re.Pattern):
        # A str pattern can't match process memory: it would only fail later,
        # deep inside the scan, with "cannot use a string pattern on a
        # bytes-like object".
        if not isinstance(pattern.pattern, bytes):
            raise TypeError(
                "Pattern must be a compiled bytes regex (re.compile(rb'...')), "
                "not a str one."
            )
        if byte_length <= 0:
            raise ValueError(
                "byte_length= is required when passing a pre-compiled regex "
                "(its source length is not the same as the matched length)."
            )
        return pattern, byte_length

    if isinstance(pattern, bytes):
        if byte_length <= 0:
            raise ValueError(
                "byte_length= is required when passing a raw bytes regex "
                "(its source length is not the same as the matched length)."
            )
        return re.compile(pattern, re.DOTALL), byte_length

    if not isinstance(pattern, str):
        raise TypeError(
            "Pattern must be str (IDA-style), bytes (regex) or a "
            "compiled re.Pattern, not %r" % type(pattern).__name__
        )

    tokens = tokenize_pattern(pattern)

    parts = []
    for token in tokens:
        if token is None:
            # Single-byte wildcard. ``.`` together with re.DOTALL matches any
            # byte 0x00-0xFF without special-casing 0x0A.
            parts.append(b".")
            continue
        # Escape the byte so e.g. 0x5C (backslash) or 0x28 ('(') don't get
        # interpreted as regex meta chars.
        parts.append(re.escape(bytes((token,))))

    return re.compile(b"".join(parts), re.DOTALL), len(tokens)


def is_fixed_width(pattern: "Pattern[bytes]") -> bool:
    """True when every match of ``pattern`` is the same number of bytes long.

    The pattern scan reports *overlapping* matches for such a pattern — ``90
    90`` over ``90 90 90`` is found at offsets 0 and 1, exactly what a value
    scan for ``b"\\x90\\x90"`` returns. Every IDA-style signature is fixed
    width, as is a regex like ``rb"\\x48\\x8B.."``.

    A variable-width regex keeps the usual ``re.finditer`` semantics (leftmost,
    non-overlapping): restarting one byte after each match would also report
    every suffix of a variable-length match (``"ohn@example.com"`` after
    ``"john@example.com"``), which is noise, not a new match. Wrap such a
    regex in a lookahead (``(?=...)``) to get every start offset.

    Falls back to ``False`` (non-overlapping) if the pattern cannot be
    analysed.
    """
    try:
        low, high = _regex_parser.parse(pattern.pattern, pattern.flags).getwidth()
    except Exception as exc:  # noqa: BLE001 — private parser API; degrade, never fail a scan
        _logger.debug(
            "is_fixed_width: could not analyse pattern %r (%s); scanning it "
            "for non-overlapping matches.",
            pattern.pattern,
            exc,
        )
        return False
    return bool(low == high)


def tokenize_pattern(pattern: str) -> List[Optional[int]]:
    """Split an IDA-style hex pattern into one entry per byte.

    Each entry is the byte's value, or ``None`` for a ``?`` / ``??`` wildcard.
    ``compile_pattern`` turns these into a regex; the app's cheat table uses
    them to write a signature back, where a wildcard means "leave the byte
    that is already there alone". Both need the same token rules and the same
    error messages, so they share this.

    :raises ValueError: on an empty pattern or a malformed token.
    """
    tokens = pattern.split()
    if not tokens:
        raise ValueError("Empty pattern.")

    parsed: List[Optional[int]] = []
    for token in tokens:
        if token in ("?", "??"):
            parsed.append(None)
            continue
        if len(token) != 2:
            raise ValueError(
                "Pattern token %r is not two hex digits or a '?' wildcard. "
                "Example of a valid pattern: '48 8B ? ? 00'." % token
            )
        try:
            parsed.append(bytes.fromhex(token)[0])
        except ValueError as exc:
            raise ValueError(
                "Pattern token %r is not valid hex: %s" % (token, exc)
            )
    return parsed


# tokenize_pattern and is_fixed_width are deliberately absent: the first exists
# so the scan and write paths share one set of token rules, the second so the
# pattern scan can pick its overlap rule, and nothing outside the package
# consumes either. Exporting them would promise a documented, supported
# surface that neither the guide nor the API reference describes.
__all__ = ("compile_pattern", "PatternLike")
