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

The function returns a compiled ``re.Pattern[bytes]`` ready to be used with
``finditer`` against memory chunks read from the target.
"""

import re
from typing import Pattern, Tuple, Union


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
    """
    if isinstance(pattern, re.Pattern):
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

    tokens = pattern.split()
    if not tokens:
        raise ValueError("Empty pattern.")

    parts = []
    for token in tokens:
        if token in ("?", "??"):
            # Single-byte wildcard. ``.`` together with re.DOTALL matches any
            # byte 0x00-0xFF without special-casing 0x0A.
            parts.append(b".")
            continue
        if len(token) != 2:
            raise ValueError(
                "Pattern token %r is not two hex digits or a '?' wildcard. "
                "Example of a valid pattern: '48 8B ? ? 00'." % token
            )
        try:
            byte = bytes.fromhex(token)
        except ValueError as exc:
            raise ValueError(
                "Pattern token %r is not valid hex: %s" % (token, exc)
            )
        # Escape the byte so e.g. 0x5C (backslash) or 0x28 ('(') don't get
        # interpreted as regex meta chars.
        parts.append(re.escape(byte))

    return re.compile(b"".join(parts), re.DOTALL), len(tokens)


__all__ = ("compile_pattern", "PatternLike")
