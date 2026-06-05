# -*- coding: utf-8 -*-

"""
Cross-platform tests for the native process enumeration that backs
``OpenProcess(process_name=...)`` — the per-platform ``(pid, name)`` source
(``CreateToolhelp32Snapshot`` on Windows, ``/proc`` on Linux, libproc on
macOS) exposed through ``PyMemoryEditor.process.util`` — plus the native
``pid_exists`` probe. These exercise the real OS code paths (no mocking; the
mocked ``util`` layer is covered separately in ``test_process_lookup.py``).
"""

import os
import sys

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor.process.util import (  # noqa: E402
    _iter_processes,
    get_process_ids_by_process_name,
    pid_exists,
)


def _own_name() -> str:
    for pid, name in _iter_processes():
        if pid == os.getpid():
            return name or ""
    return ""


def test_iter_processes_yields_pid_name_pairs():
    """Every row is an ``(int pid >= 0, str name)`` pair and the list is non-empty."""
    rows = list(_iter_processes())
    assert rows, "expected at least one process"
    for pid, name in rows:
        assert isinstance(pid, int)
        assert pid >= 0
        assert isinstance(name, str)


def test_enumeration_includes_self():
    """The current process must appear in the enumeration."""
    pids = [pid for pid, _ in _iter_processes()]
    assert os.getpid() in pids


def test_current_process_has_a_name():
    """A process can always read its own name (proc_name/comm/szExeFile)."""
    name = _own_name()
    assert name, "expected a non-empty name for the current process"
    # The exact spelling is platform-specific (e.g. "python3.11" / "python.exe"
    # / "Python", and Linux truncates comm to 15 chars), so assert only that the
    # backend produced a clean executable basename — decoded, no path
    # separators, no embedded NUL — rather than a brittle exact match.
    assert "\x00" not in name
    assert "/" not in name and "\\" not in name


def test_pids_are_unique():
    """A snapshot lists each pid at most once."""
    pids = [pid for pid, _ in _iter_processes()]
    assert len(pids) == len(set(pids)), "duplicate pids in enumeration"


def test_pid_exists_true_for_self():
    assert pid_exists(os.getpid()) is True


def test_pid_exists_false_for_dead_pid():
    # 2**31 - 1 is a very large pid extremely unlikely to be live.
    assert pid_exists(2**31 - 1) is False


def test_pid_exists_false_for_negative_pid():
    assert pid_exists(-1) is False


def test_resolve_own_name_includes_self():
    """Resolving the current process's name returns a list containing our pid."""
    name = _own_name()
    if not name:
        pytest.skip("could not read this process's name on this platform")

    pids = get_process_ids_by_process_name(name, exact_match=True)
    assert os.getpid() in pids


def test_case_insensitive_match_finds_self_native():
    """Case-insensitive matching works end-to-end on the native enumeration."""
    name = _own_name()
    if not name:
        pytest.skip("could not read this process's name on this platform")
    swapped = name.swapcase()
    if swapped == name:
        pytest.skip("process name has no alphabetic characters to swap")

    # A list (≥1) — other processes may share the name; we only require ours.
    pids = get_process_ids_by_process_name(
        swapped, exact_match=True, case_sensitive=False
    )
    assert os.getpid() in pids


def test_substring_match_finds_self_native():
    """Substring (exact_match=False) matching works on the native enumeration."""
    name = _own_name()
    if not name or len(name) <= 2:
        pytest.skip("process name too short for a substring test")

    substring = name[: max(2, len(name) // 2)]
    pids = get_process_ids_by_process_name(substring, exact_match=False)
    assert os.getpid() in pids
