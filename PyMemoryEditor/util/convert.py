# -*- coding: utf-8 -*-

from typing import Any, Optional, Tuple, Type, TypeVar, Union, cast
import ctypes


T = TypeVar("T")


# The five Python types the library supports as read/write/scan targets.
# Mirrored by the user-facing error in `_validate_pytype` so the failure
# message points at exactly the set the caller is allowed to pass.
_SUPPORTED_PYTYPES = (bool, int, float, str, bytes)


# Sentinel marking a `value` argument that the caller never supplied. It lets
# `write_process_memory(address, pytype, value=...)` keep `bufflength` optional
# (defaulting to None) while still leaving `value` required — a plain `None`
# default would be ambiguous since None can't be told apart from "not passed",
# and a required positional can't follow an optional one.
class _Unset:
    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "<unset>"


# Typed as ``Any`` so it can stand in as the default for parameters whose real
# type is ``Sequence[int]`` / ``bool | int | ...`` without mypy flagging an
# incompatible default — the sentinel is swapped out (or rejected) before the
# value is ever used as its declared type.
UNSET: Any = _Unset()


def _validate_pytype(pytype: Type) -> None:
    """
    Raise ``ValueError`` when ``pytype`` is not one of the five supported
    primitives. Used at every public read / write / search entry point on
    all three backends so the rejection message stays identical regardless
    of which platform path the caller landed on.
    """
    if pytype not in _SUPPORTED_PYTYPES:
        raise ValueError("The type must be bool, int, float, str or bytes.")


# Default byte widths for numeric Python types when the caller doesn't specify
# `bufflength`. Matches the natural C type used by ctypes for each Python type.
_DEFAULT_BUFFLENGTH = {
    bool: 1,  # c_bool
    int: 4,  # c_int32
    float: 8,  # c_double
}


def _check_int_fits(value: int, length: int, *, signed: bool = True) -> None:
    """
    Reject an ``int`` write whose value does not fit in ``length`` bytes,
    raising a clear ``ValueError`` instead of letting the value be corrupted or
    a raw ``OverflowError`` leak out. Shared by both numeric write paths:

    * the generic / signed path (``write_process_memory(int, ...)`` and the
      ``write_char/short/int/long/longlong`` helpers) routes through
      ``prepare_write`` → ``get_c_type_of(int, length)``, whose fixed-width
      ``c_int*`` ``.value`` setter **silently wraps** out-of-range values
      (``2**40`` into a 4-byte slot stores ``0``) and would then report success
      while having corrupted the target;

    * the unsigned helpers (``write_uchar/ushort/uint/ulong/ulonglong``) route
      through ``AbstractProcess._write_unsigned`` → ``int.to_bytes(signed=False)``,
      which already raises — but as a bare ``OverflowError`` with a cryptic
      message. Validating here gives both paths the same explicit error.

    ``signed`` selects the accepted window for ``length`` bytes:

    * ``signed=True`` (default) accepts the **union** of the signed and unsigned
      ranges — ``[-2**(bits-1), 2**bits - 1]`` — because the generic ``c_int*``
      slot stores either representation by the same bit pattern (``0xFFFFFFFF``
      in a 4-byte field is the bits of ``-1`` and stays allowed);
    * ``signed=False`` accepts the strict unsigned range ``[0, 2**bits - 1]``,
      matching the unsigned helpers' contract (a negative value is rejected).

    ``bool`` is a subclass of ``int`` but is written through its own ``c_bool``
    path, so it never reaches the signed call here. Non-int values for an
    ``int`` write (e.g. a float) are left for the ctypes assignment to reject.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        return

    bits = length * 8
    low = -(1 << (bits - 1)) if signed else 0
    high = (1 << bits) - 1
    if not (low <= value <= high):
        kind = "integer" if signed else "unsigned integer"
        raise ValueError(
            "value %d does not fit in a %d-byte %s (allowed range %d..%d). "
            "Use a wider bufflength to write a larger value."
            % (value, length, kind, low, high)
        )


def resolve_bufflength(pytype: Type, bufflength: Optional[int]) -> int:
    """
    Return a concrete bufflength: the caller-provided value, or the default for
    numeric `pytype` when `bufflength is None`. str and bytes require an
    explicit length since they're variable-width.
    """
    if bufflength is not None:
        return bufflength
    if pytype in _DEFAULT_BUFFLENGTH:
        return _DEFAULT_BUFFLENGTH[pytype]
    raise ValueError(
        "bufflength is required for pytype=%s (only int, float and bool have a default)."
        % pytype.__name__
    )


def resolve_bufflength_for_value(pytype: Type, bufflength: Optional[int], *values) -> int:
    """
    Like :func:`resolve_bufflength`, but for operations that already carry the
    value(s) being matched (the search methods). When ``bufflength`` is ``None``:

    * **numeric / bool** — fall back to the default width (int→4, float→8,
      bool→1), exactly like :func:`resolve_bufflength`;
    * **str / bytes** — infer the width from the longest encoded value instead
      of raising, so ``search_by_value(str, value="hi")`` works without the
      caller counting bytes. ``str`` is encoded as UTF-8. For a range search the
      shorter endpoint is NUL-padded up to this width (the fixed-width
      comparison the backend performs).

    A read can't infer this (it has no value to measure), which is why
    :func:`resolve_bufflength` still requires an explicit size there.
    """
    if any(isinstance(v, _Unset) for v in values):
        raise TypeError("a search value is required (none was provided).")

    if bufflength is not None:
        return bufflength

    if pytype is str or pytype is bytes:
        lengths = []
        for v in values:
            raw = v.encode("utf-8") if isinstance(v, str) else v
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError(
                    "value must be str or bytes when pytype is str/bytes, got %s."
                    % type(v).__name__
                )
            lengths.append(len(raw))
        return max(lengths) if lengths else 0

    return resolve_bufflength(pytype, bufflength)


def prepare_write(
    pytype: Type, bufflength: Optional[int], value
) -> Tuple[Type, int, Any]:
    """
    Normalize a write request into the ``(pytype, length, value)`` triple a
    backend ``WriteProcessMemory`` can hand straight to the OS.

    * **Numeric / bool** — returned unchanged, with ``bufflength`` resolved to
      its default (see :func:`resolve_bufflength`). The backend encodes the
      value via :func:`get_c_type_of` exactly as before.

    * **str / bytes** — the value is encoded to raw bytes (UTF-8 for ``str``)
      and routed through the ``bytes`` path. Here ``bufflength`` is a *maximum*
      width that truncates the value; it never pads:

      - for a ``str`` value the cap counts **characters**, applied *before*
        encoding — ``write(addr, str, 2, "óólá")`` keeps ``"óó"`` and writes
        its 4 UTF-8 bytes, while ``write(addr, str, 2, "ola")`` keeps ``"ol"``
        and writes 2 bytes;
      - for a ``bytes`` value the cap counts **bytes** (there are no
        characters) — ``write(addr, bytes, 2, b"abc")`` writes ``b"ab"``;
      - a value shorter than the cap is written as-is, with no NUL padding —
        ``write(addr, str, 10, "ola")`` writes just ``b"ola"`` (3 bytes);
      - ``bufflength=None`` writes the whole value (no cap).

    The caller is expected to return its *original* ``value`` to the user, so
    this routing through ``bytes`` stays invisible at the public API.
    """
    if isinstance(value, _Unset):
        raise TypeError(
            "write_process_memory() missing required argument: 'value'."
        )

    _validate_pytype(pytype)

    if pytype is str or pytype is bytes:
        if isinstance(value, str):
            # str: bufflength caps the number of *characters*, applied before
            # encoding so multi-byte characters are never split mid-sequence.
            if bufflength is not None:
                value = value[:bufflength]
            raw = value.encode("utf-8")
        elif isinstance(value, (bytes, bytearray)):
            # bytes: bufflength caps the number of *bytes*.
            raw = bytes(value)
            if bufflength is not None:
                raw = raw[:bufflength]
        else:
            raise TypeError(
                "value must be str or bytes when pytype is str/bytes, got %s."
                % type(value).__name__
            )
        return bytes, len(raw), raw

    length = resolve_bufflength(pytype, bufflength)
    if pytype is int:
        _check_int_fits(value, length)
    return pytype, length, value


def convert_from_byte_array(
    byte_array: ctypes.Array, pytype: Type[T], length: int
) -> T:
    """
    Convert a byte array to a Python type.

    String decoding uses errors="replace" so that non-UTF-8 bytes (common in
    raw memory) do not raise UnicodeDecodeError — they become U+FFFD instead.
    Callers that need raw bytes should pass pytype=bytes.
    """
    # cast() reassures mypy that the runtime check above narrows T; without it
    # the generic-return-vs-concrete-bytes/str pair triggers "Incompatible
    # return value type [return-value]" errors.
    if pytype is bytes:
        return cast(T, bytes(byte_array))
    if pytype is str:
        return cast(T, bytes(byte_array).decode("utf-8", errors="replace"))

    c_value = get_c_type_of(pytype, length)

    return c_value.__class__.from_buffer(byte_array).value


def value_to_bytes(pytype: Type, bufflength: int, value) -> bytes:
    """
    Encode a single scan target value as a fixed-width byte string using the
    same ctypes representation the backend will compare against.

    Strings are utf-8 encoded; bytes pass through; numerics are written into a
    ctypes value and cast back. Shared by the three platform backends to avoid
    duplicating ~10 lines per call site.

    An ``int`` target that does not fit in ``bufflength`` bytes is rejected here
    (same check as the write path): otherwise the ``c_int*`` setter would wrap
    it silently — e.g. ``search_by_value(int, value=2**40)`` with the default
    4-byte width would encode the target as ``0`` and quietly match every zeroed
    slot in memory instead of erroring.
    """
    if pytype is int:
        _check_int_fits(value, bufflength)

    target_value = get_c_type_of(pytype, bufflength)
    target_value.value = value.encode() if isinstance(value, str) else value

    target_value_bytes = ctypes.cast(
        ctypes.byref(target_value),
        ctypes.POINTER(ctypes.c_byte * bufflength),
    )
    return bytes(target_value_bytes.contents)


def values_to_bytes(
    pytype: Type,
    bufflength: int,
    value: Union[object, Tuple],
) -> Union[bytes, Tuple[bytes, ...]]:
    """
    Convert either a single value or a tuple of values (for VALUE_BETWEEN /
    NOT_VALUE_BETWEEN) to the corresponding byte form.
    """
    if isinstance(value, tuple):
        return tuple(value_to_bytes(pytype, bufflength, v) for v in value)
    return value_to_bytes(pytype, bufflength, value)


def get_c_type_of(pytype: Type, length: int) -> Any:
    """
    Return a C type of a primitive type of the Python language.

    Return type is `Any` because the function legitimately returns either a
    `ctypes._SimpleCData` subclass instance (for numeric types) or a
    `ctypes.Array[c_char]` (for str/bytes), which don't share a common base
    that mypy can reason about.
    """
    if pytype is str or pytype is bytes:
        return ctypes.create_string_buffer(length)

    elif pytype is int:

        if length == 1:
            return ctypes.c_int8()
        if length == 2:
            return ctypes.c_int16()
        if length <= 4:
            return ctypes.c_int32()
        return ctypes.c_int64()

    elif pytype is float:

        if length == 4:
            return ctypes.c_float()
        return ctypes.c_double()

    elif pytype is bool:
        return ctypes.c_bool()

    else:
        raise ValueError("The type must be bool, int, float, str or bytes.")
