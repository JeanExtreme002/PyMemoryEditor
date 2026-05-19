# -*- coding: utf-8 -*-

from typing import Optional, Tuple, Type, TypeVar, Union
import ctypes


T = TypeVar("T")


# Default byte widths for numeric Python types when the caller doesn't specify
# `bufflength`. Matches the natural C type used by ctypes for each Python type.
_DEFAULT_BUFFLENGTH = {
    bool: 1,    # c_bool
    int: 4,     # c_int32
    float: 8,   # c_double
}


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
        "bufflength is required for pytype=%s (only int, float and bool have a default)." % pytype.__name__
    )


def convert_from_byte_array(byte_array: ctypes.Array, pytype: Type[T], length: int) -> T:
    """
    Convert a byte array to a Python type.

    String decoding uses errors="replace" so that non-UTF-8 bytes (common in
    raw memory) do not raise UnicodeDecodeError — they become U+FFFD instead.
    Callers that need raw bytes should pass pytype=bytes.
    """
    if pytype is bytes: return bytes(byte_array)
    if pytype is str: return bytes(byte_array).decode("utf-8", errors="replace")

    c_value = get_c_type_of(pytype, length)

    return c_value.__class__.from_buffer(byte_array).value


def value_to_bytes(pytype: Type, bufflength: int, value) -> bytes:
    """
    Encode a single scan target value as a fixed-width byte string using the
    same ctypes representation the backend will compare against.

    Strings are utf-8 encoded; bytes pass through; numerics are written into a
    ctypes value and cast back. Shared by the three platform backends to avoid
    duplicating ~10 lines per call site.
    """
    target_value = get_c_type_of(pytype, bufflength)
    target_value.value = value.encode() if isinstance(value, str) else value

    target_value_bytes = ctypes.cast(
        ctypes.byref(target_value), ctypes.POINTER(ctypes.c_byte * bufflength),
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


def get_c_type_of(pytype: Type, length) -> ctypes._SimpleCData:
    """
    Return a C type of a primitive type of the Python language.
    """
    if pytype is str or pytype is bytes: return ctypes.create_string_buffer(length)

    elif pytype is int:

        if length == 1: return ctypes.c_int8()      # 1 Byte
        if length == 2: return ctypes.c_int16()     # 2 Bytes
        if length <= 4: return ctypes.c_int32()     # 4 Bytes
        return ctypes.c_int64()                     # 8 Bytes

    elif pytype is float:

        if length == 4: return ctypes.c_float()     # 4 Bytes
        return ctypes.c_double()                    # 8 Bytes

    elif pytype is bool: return ctypes.c_bool()

    else: raise ValueError("The type must be bool, int, float, str or bytes.")
