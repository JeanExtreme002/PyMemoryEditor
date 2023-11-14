# -*- coding: utf-8 -*-

from .scan import scan_memory, scan_memory_for_exact_value
from typing import Type
import ctypes


def get_c_type_of(pytype: Type, length: int = 1) -> ctypes._SimpleCData:
    """
    Return a C type of a primitive type of the Python language.
    """
    if pytype is str or pytype is bytes: return ctypes.create_string_buffer(length)

    elif pytype is int:

        if length == 1: return ctypes.c_int8()      # 1 Byte
        if length == 2: return ctypes.c_int16()     # 2 Bytes
        if length <= 4: return ctypes.c_int32()     # 4 Bytes
        return ctypes.c_int64()                     # 8 Bytes

    # Float values lose their precision when converted to c_float. For that reason,
    # any float value will be converted to double.
    elif pytype is float: return ctypes.c_double()  # 8 Bytes

    elif pytype is bool: return ctypes.c_bool()

    else: raise ValueError("The type must be bool, int, float, str or bytes.")
