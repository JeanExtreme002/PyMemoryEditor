# -*- coding: utf-8 -*-

"""
Tests for error paths that the integration suite doesn't exercise.
"""

import ctypes
import os

import pytest

from PyMemoryEditor import (
    ClosedProcess,
    OpenProcess,
    ProcessIDNotExistsError,
    PyMemoryEditorError,
    __version__,
)


def test_version_exposed():
    assert isinstance(__version__, str) and len(__version__) > 0


def test_open_invalid_pid_raises():
    # 2**31 - 1 is a very large pid unlikely to exist; psutil rejects negative.
    with pytest.raises(ProcessIDNotExistsError):
        OpenProcess(pid=2**31 - 1)


def test_all_errors_inherit_from_base():
    assert issubclass(ClosedProcess, PyMemoryEditorError)
    assert issubclass(ProcessIDNotExistsError, PyMemoryEditorError)


def test_no_arguments_raises_type_error():
    with pytest.raises(TypeError):
        OpenProcess()


def test_closed_process_raises_closed():
    process = OpenProcess(pid=os.getpid())
    assert process.close()

    target = ctypes.c_int(123)
    address = ctypes.addressof(target)

    with pytest.raises(ClosedProcess):
        process.read_process_memory(address, int, 4)

    with pytest.raises(ClosedProcess):
        process.write_process_memory(address, int, 4, 7)


def test_invalid_pytype_raises_value_error():
    process = OpenProcess(pid=os.getpid())
    try:
        target = ctypes.c_int(0)
        address = ctypes.addressof(target)
        with pytest.raises(ValueError):
            process.read_process_memory(address, list, 4)
    finally:
        process.close()
