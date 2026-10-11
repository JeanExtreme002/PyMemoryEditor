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

Process names come from the kernel's Unicode process list, so they are exact.
Module entries do not: Toolhelp32 builds them from the loader's module list
in ANSI (``RTL_PROCESS_MODULE_INFORMATION.FullPathName``) even for the "W"
calls, so a module name is exact only for characters in the system's ANSI
code page — anything else comes back as ``?``. The module test therefore
uses characters from that code page.
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


def _ansi_code_page_letters():
    """Non-ASCII letters the system's ANSI code page can represent."""
    code_page = "cp%d" % ctypes.windll.kernel32.GetACP()
    letters = []
    for char in "\u00e9\u00f1\u00fc\u00e7\u0436\u03b1\u65e5\u672c":
        try:
            char.encode(code_page)
        except (LookupError, UnicodeEncodeError):
            continue
        letters.append(char)
    return letters


def test_module_walk_keeps_non_ascii_names_intact(tmp_path):
    # The old code decoded the ANSI bytes as UTF-8, so even a code-page
    # letter such as "é" (0xE9 in cp1252) came back as U+FFFD.
    letters = _ansi_code_page_letters()
    if not letters:
        pytest.skip("the ANSI code page has none of the candidate letters")
    name = "pme_t%sst_%s.dll" % (letters[0], "".join(letters[1:3]))
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
        modules = list(win.GetModules(os.getpid()))
        matches = [m for m in modules if m.name.lower() == name.lower()]
        assert len(matches) == 1, "loaded as %r" % [
            (m.name, m.path) for m in modules if m.base_address == handle
        ]
        assert matches[0].base_address == handle
        # samefile, not string equality: %TEMP% on CI runners is an 8.3 short
        # path, and the loader may report either spelling.
        assert os.path.samefile(matches[0].path, str(copy))
    finally:
        kernel32.FreeLibrary(handle)
