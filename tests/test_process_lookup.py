# -*- coding: utf-8 -*-

"""
Cross-platform tests for process_name lookup logic, exercising
AmbiguousProcessNameError and the case_sensitive flag without depending on
real processes existing under known names.
"""

import pytest

from PyMemoryEditor import AmbiguousProcessNameError
from PyMemoryEditor.process import util as lookup


class _FakeProcess:
    """Stand-in for psutil.Process used by process_iter(["name", "pid"])."""

    def __init__(self, name: str, pid: int):
        self.info = {"name": name, "pid": pid}


@pytest.fixture
def fake_process_iter(monkeypatch):
    """Replace psutil.process_iter with a callable returning the provided list."""

    def install(processes):
        monkeypatch.setattr(
            lookup.psutil,
            "process_iter",
            lambda fields=None: iter(processes),
        )

    return install


def test_returns_none_when_no_match(fake_process_iter):
    fake_process_iter([_FakeProcess("chrome", 1), _FakeProcess("firefox", 2)])
    assert lookup.get_process_id_by_process_name("missing.exe") is None


def test_returns_pid_on_single_match(fake_process_iter):
    fake_process_iter([_FakeProcess("chrome", 1), _FakeProcess("firefox", 2)])
    assert lookup.get_process_id_by_process_name("chrome") == 1


def test_raises_ambiguous_on_multiple_matches(fake_process_iter):
    fake_process_iter(
        [
            _FakeProcess("python", 100),
            _FakeProcess("python", 200),
            _FakeProcess("bash", 300),
        ]
    )
    with pytest.raises(AmbiguousProcessNameError) as exc:
        lookup.get_process_id_by_process_name("python")

    assert exc.value.pids == [100, 200]
    assert exc.value.process_name == "python"


def test_case_sensitive_default_distinguishes(fake_process_iter):
    fake_process_iter([_FakeProcess("Notepad.exe", 42)])
    assert lookup.get_process_id_by_process_name("notepad.exe") is None
    assert lookup.get_process_id_by_process_name("Notepad.exe") == 42


def test_case_insensitive_matches(fake_process_iter):
    fake_process_iter([_FakeProcess("Notepad.exe", 42)])
    assert (
        lookup.get_process_id_by_process_name("notepad.exe", case_sensitive=False) == 42
    )
    assert (
        lookup.get_process_id_by_process_name("NOTEPAD.EXE", case_sensitive=False) == 42
    )


def test_get_process_ids_returns_full_list(fake_process_iter):
    fake_process_iter(
        [
            _FakeProcess("python", 100),
            _FakeProcess("python", 200),
        ]
    )
    pids = lookup.get_process_ids_by_process_name("python")
    assert pids == [100, 200]


def test_ambiguous_error_has_args_and_str():
    """Regression: errors used to lose information because __init__ didn't call super()."""
    err = AmbiguousProcessNameError("python", [100, 200])
    assert err.args  # must not be empty
    assert "python" in str(err)
    assert "100" in str(err)
