# -*- coding: utf-8 -*-

"""
Cross-platform tests for process's name lookup logic, exercising
AmbiguousProcessNameError and the case_sensitive flag without depending on
real processes existing under known names.
"""

import pytest

from PyMemoryEditor import AmbiguousProcessNameError
from PyMemoryEditor.process import util as lookup


@pytest.fixture
def fake_process_iter(monkeypatch):
    """Replace the native process enumerator with one returning a fixed list.

    The seam is ``util._iter_processes``, which yields ``(pid, name)`` pairs
    (the per-platform native enumerator: Toolhelp on Windows, /proc on Linux,
    libproc on macOS). Tests supply their own ``(name, pid)`` rows.
    """

    def install(processes):
        rows = [(pid, name) for name, pid in processes]
        monkeypatch.setattr(lookup, "_iter_processes", lambda: iter(rows))

    return install


def test_returns_none_when_no_match(fake_process_iter):
    fake_process_iter([("chrome", 1), ("firefox", 2)])
    assert lookup.get_process_id_by_name("missing.exe") is None


def test_returns_pid_on_single_match(fake_process_iter):
    fake_process_iter([("chrome", 1), ("firefox", 2)])
    assert lookup.get_process_id_by_name("chrome") == 1


def test_raises_ambiguous_on_multiple_matches(fake_process_iter):
    fake_process_iter(
        [
            ("python", 100),
            ("python", 200),
            ("bash", 300),
        ]
    )
    with pytest.raises(AmbiguousProcessNameError) as exc:
        lookup.get_process_id_by_name("python")

    assert exc.value.pids == [100, 200]
    assert exc.value.process_name == "python"


def test_case_sensitive_default_distinguishes(fake_process_iter):
    fake_process_iter([("Notepad.exe", 42)])
    assert lookup.get_process_id_by_name("notepad.exe") is None
    assert lookup.get_process_id_by_name("Notepad.exe") == 42


def test_case_insensitive_matches(fake_process_iter):
    fake_process_iter([("Notepad.exe", 42)])
    assert (
        lookup.get_process_id_by_name("notepad.exe", case_sensitive=False) == 42
    )
    assert (
        lookup.get_process_id_by_name("NOTEPAD.EXE", case_sensitive=False) == 42
    )


def test_get_process_ids_returns_full_list(fake_process_iter):
    fake_process_iter(
        [
            ("python", 100),
            ("python", 200),
        ]
    )
    pids = lookup.get_process_ids_by_name("python")
    assert pids == [100, 200]


def test_empty_name_rows_are_tolerated(fake_process_iter):
    """A process with an empty name (macOS can yield this) must not crash the
    lookup, and must not spuriously match a non-empty query."""
    fake_process_iter([("", 1), ("chrome", 2)])
    assert lookup.get_process_id_by_name("chrome") == 2
    assert lookup.get_process_id_by_name("") == 1


def test_ambiguous_error_has_args_and_str():
    """Regression: errors used to lose information because __init__ didn't call super()."""
    err = AmbiguousProcessNameError("python", [100, 200])
    assert err.args  # must not be empty
    assert "python" in str(err)
    assert "100" in str(err)
