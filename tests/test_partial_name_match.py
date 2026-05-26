# -*- coding: utf-8 -*-

"""
Tests for the ``exact_match`` flag on process-name lookup. Uses ``psutil``
directly to derive the current process's real name from the OS, then
verifies that:

* an exact-name lookup finds it,
* a partial (substring) lookup finds it,
* a substring lookup that cannot match anything returns nothing.

Avoids relying on a specific executable being installed.
"""

import os
import sys

import psutil
import pytest

from PyMemoryEditor.process.util import (
    get_process_id_by_process_name,
    get_process_ids_by_process_name,
)


_OWN_PROCESS_NAME = psutil.Process(os.getpid()).name() or ""


@pytest.fixture(scope="module")
def own_name():
    """The OS-reported name of the test process (e.g. ``python3.12``)."""
    if not _OWN_PROCESS_NAME:
        pytest.skip("psutil cannot read this process's name on this platform")
    return _OWN_PROCESS_NAME


def test_exact_match_finds_self(own_name):
    pids = get_process_ids_by_process_name(own_name, exact_match=True)
    assert os.getpid() in pids


def test_exact_match_does_not_find_substring(own_name):
    """Substring of the name must NOT match in exact mode."""
    if len(own_name) <= 2:
        pytest.skip("process name too short to test substring rejection")
    substring = own_name[: len(own_name) // 2]
    if substring == own_name:
        pytest.skip("substring equals full name")
    pids = get_process_ids_by_process_name(substring, exact_match=True)
    assert os.getpid() not in pids


def test_partial_match_finds_self_by_substring(own_name):
    """A leading substring of the name must match when exact_match=False."""
    if len(own_name) <= 2:
        pytest.skip("process name too short to test substring matching")
    substring = own_name[: max(2, len(own_name) // 2)]
    pids = get_process_ids_by_process_name(substring, exact_match=False)
    assert os.getpid() in pids


def test_partial_match_case_insensitive(own_name):
    """Combined with case_sensitive=False, swapping case still matches."""
    swapped = own_name.swapcase()
    if swapped == own_name:
        pytest.skip("process name has no alphabetic characters")
    pids = get_process_ids_by_process_name(
        swapped, exact_match=False, case_sensitive=False
    )
    assert os.getpid() in pids


def test_partial_match_no_results_for_garbage():
    """An impossible substring returns an empty list, not a false positive."""
    garbage = "definitely_not_a_real_process_name_zzzzzzz_42"
    pids = get_process_ids_by_process_name(garbage, exact_match=False)
    assert pids == []


def test_get_single_returns_none_for_garbage():
    """The single-result helper returns None when no process matches."""
    garbage = "definitely_not_a_real_process_name_zzzzzzz_42"
    assert (
        get_process_id_by_process_name(garbage, exact_match=False) is None
    )


@pytest.mark.skipif(
    sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"),
    reason="Platform not supported by PyMemoryEditor",
)
def test_openprocess_accepts_exact_match_kwarg(own_name):
    """OpenProcess plumbs exact_match through to the lookup."""
    from PyMemoryEditor import OpenProcess

    # Don't lean on a known unique name — only that the kwarg is accepted
    # without raising TypeError and the resulting PID is ours when the name
    # is unique enough to match exactly one process.
    pids = get_process_ids_by_process_name(own_name, exact_match=True)
    if len(pids) != 1:
        pytest.skip(
            "more than one process shares this name; OpenProcess would raise "
            "AmbiguousProcessNameError — not what this test is checking"
        )

    process = OpenProcess(process_name=own_name, exact_match=True)
    try:
        assert process.pid == os.getpid()
    finally:
        process.close()
