# -*- coding: utf-8 -*-

"""
Windows-only: the Toolhelp32 process/module walks use the Unicode ("W")
structs and entry points.

Regression: ``PROCESSENTRY32`` / ``MODULEENTRY32`` (ANSI) squeezed names and
paths through the active code page and the backend then decoded those bytes
as UTF-8, so any non-ASCII process or module name came back garbled and name
matching failed. The checks run against the test process itself only — a
copy of a system DLL with a non-ASCII file name is loaded into it, looked up,
and unloaded.
"""

import ctypes
import os
import shutil
import sys

import pytest


if sys.platform != "win32":
    pytest.skip("Windows-only module", allow_module_level=True)


from PyMemoryEditor.win32 import functions as win  # noqa: E402
from PyMemoryEditor.win32.types import MODULEENTRY32W, PROCESSENTRY32W  # noqa: E402


_IS_64BIT = ctypes.sizeof(ctypes.c_void_p) == 8


def test_entry_structs_have_the_documented_wide_sizes():
    # sizeof(PROCESSENTRY32W) / sizeof(MODULEENTRY32W) from <tlhelp32.h>.
    # Process32FirstW / Module32FirstW reject any other dwSize.
    assert ctypes.sizeof(PROCESSENTRY32W) == (568 if _IS_64BIT else 556)
    assert ctypes.sizeof(MODULEENTRY32W) == (1080 if _IS_64BIT else 1064)


def _own_exe_names():
    names = {os.path.basename(sys.executable).lower()}
    base = getattr(sys, "_base_executable", None)
    if base:
        names.add(os.path.basename(base).lower())
    return names


def test_process_walk_finds_this_python_by_its_exe_name():
    entries = [name for pid, name in win.GetProcesses() if pid == os.getpid()]

    assert len(entries) == 1
    assert isinstance(entries[0], str)
    assert entries[0].lower() in _own_exe_names()


def test_module_walk_of_self_returns_str_names_and_full_paths():
    modules = list(win.GetModules(os.getpid()))

    assert modules
    for module in modules:
        assert isinstance(module.name, str)
        assert isinstance(module.path, str)
    exes = [m for m in modules if m.name.lower() in _own_exe_names()]
    assert exes, "this Python's executable is missing from its own modules"
    exe = exes[0]
    assert os.path.isabs(exe.path)
    assert os.path.basename(exe.path).lower() == exe.name.lower()


def test_module_walk_keeps_non_ascii_names_intact(tmp_path):
    # Non-ASCII outside any single ANSI code page: the ANSI struct turned
    # these into "?" on every runner.
    name = "pme_t\u00e9st_\u65e5\u672c_\u0436.dll"
    source = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "version.dll")
    if not os.path.isfile(source):
        pytest.skip("System32\\version.dll not found")
    copy = tmp_path / name
    shutil.copyfile(source, copy)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LoadLibraryW.argtypes = (ctypes.c_wchar_p,)
    kernel32.LoadLibraryW.restype = ctypes.c_void_p
    kernel32.FreeLibrary.argtypes = (ctypes.c_void_p,)
    kernel32.FreeLibrary.restype = ctypes.c_int

    handle = kernel32.LoadLibraryW(str(copy))
    if not handle:
        pytest.skip("could not load the DLL copy (err=%d)" % ctypes.get_last_error())
    try:
        matches = [m for m in win.GetModules(os.getpid()) if m.name.lower() == name.lower()]
        assert len(matches) == 1
        assert matches[0].base_address == handle
        # samefile, not string equality: %TEMP% on CI runners is an 8.3 short
        # path, and the loader may report either spelling.
        assert os.path.samefile(matches[0].path, str(copy))
    finally:
        kernel32.FreeLibrary(handle)
