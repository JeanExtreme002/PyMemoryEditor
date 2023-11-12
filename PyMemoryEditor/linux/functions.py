# -*- coding: utf-8 -*-

# Read more about process_vm_(read/write)v here:
# https://man7.org/linux/man-pages/man2/process_vm_readv.2.html

from ctypes import addressof, sizeof
from typing import Type, TypeVar, Union

from ..util import get_c_type_of
from ptrace import libc
from types import iovec


T = TypeVar("T")


def read_memory(
    pid: int,
    address: int,
    pytype: Type[T],
    bufflength: int
) -> T:
    """
    Return a value from a memory address.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    data = get_c_type_of(pytype, bufflength)

    libc.process_vm_readv(
        pid, (iovec * 1)(iovec(addressof(data), sizeof(data))),
        1, (iovec * 1)(iovec(address, sizeof(data))), 1, 0
    )
    return str(data.value) if pytype is str else data.value


def write_memory(
    pid: int,
    address: int,
    pytype: Type[T],
    bufflength: int,
    value: Union[bool, int, float, str, bytes]
) -> T:
    """
    Write a value to a memory address.
    """
    if pytype not in [bool, int, float, str, bytes]:
        raise ValueError("The type must be bool, int, float, str or bytes.")

    data = get_c_type_of(pytype, bufflength)
    data.value = value.encode() if isinstance(value, str) else value

    libc.process_vm_writev(
        pid, (iovec * 1)(iovec(addressof(data), sizeof(data))),
        1, (iovec * 1)(iovec(address, sizeof(data))), 1, 0
    )
    return value
