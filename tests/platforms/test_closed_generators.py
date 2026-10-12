# -*- coding: utf-8 -*-

"""
Cross-platform: a listing or scan generator does not outlive ``close()``.

Each backend generator captures the raw handle (Windows), task port (macOS)
or pid (Linux) when it is created, and the open check used to run only at
that moment. A generator kept past ``close()`` then went on using a released
handle — on Windows the freed handle value is handed to the next
``OpenProcess``, so ``next()`` could silently read a *different* process.
Every generator now re-checks the open state before each resume and raises
``ClosedProcess``.

Only the test process itself is opened.
"""

import ctypes
import os

import pytest

from PyMemoryEditor import ClosedProcess, OpenProcess
from PyMemoryEditor.process._guard import guard_generator


_SENTINEL = 0x5EED_C0DE_1234_ABCD


@pytest.fixture
def process():
    proc = OpenProcess(pid=os.getpid())
    try:
        yield proc
    finally:
        proc.close()


@pytest.fixture
def sentinels():
    # Two copies so a value / pattern scan has a match left after the first.
    return [ctypes.c_uint64(_SENTINEL), ctypes.c_uint64(_SENTINEL)]


def _scans(process):
    pattern = " ".join("%02X" % byte for byte in _SENTINEL.to_bytes(8, "little"))
    return {
        "get_memory_regions": lambda: process.get_memory_regions(),
        "get_modules": lambda: process.get_modules(),
        "get_threads": lambda: process.get_threads(),
        "search_by_value": lambda: process.search_by_value(
            int, 8, _SENTINEL, writeable_only=True
        ),
        "search_by_value_between": lambda: process.search_by_value_between(
            int, 8, _SENTINEL, _SENTINEL, writeable_only=True
        ),
        "search_by_pattern": lambda: process.search_by_pattern(pattern),
    }


@pytest.mark.parametrize(
    "method",
    (
        "get_memory_regions",
        "get_modules",
        "get_threads",
        "search_by_value",
        "search_by_value_between",
        "search_by_pattern",
    ),
)
def test_a_suspended_generator_raises_after_close(process, sentinels, method):
    generator = _scans(process)[method]()
    next(generator)  # suspended at its first item

    process.close()

    with pytest.raises(ClosedProcess):
        next(generator)


def test_an_address_read_generator_raises_after_close(process, sentinels):
    addresses = [ctypes.addressof(value) for value in sentinels]
    generator = process.search_by_addresses(int, 8, addresses)
    assert next(generator)[0] == min(addresses)

    process.close()

    with pytest.raises(ClosedProcess):
        next(generator)


def test_a_generator_left_unstarted_raises_after_close(process):
    generator = process.get_memory_regions()

    process.close()

    with pytest.raises(ClosedProcess):
        next(generator)


def test_a_fully_consumed_generator_still_works_before_close(process):
    assert list(process.get_memory_regions())


# --- guard_generator itself ---------------------------------------------------


def test_guard_checks_before_every_resume_and_closes_the_inner_generator():
    state = {"open": True, "inner_closed": False, "checks": 0}

    def require_open():
        state["checks"] += 1
        if not state["open"]:
            raise ClosedProcess()

    def inner():
        try:
            yield 1
            yield 2
            yield 3
        finally:
            state["inner_closed"] = True

    guarded = guard_generator(inner(), require_open)
    assert next(guarded) == 1
    assert next(guarded) == 2
    assert state["checks"] == 2

    state["open"] = False
    with pytest.raises(ClosedProcess):
        next(guarded)
    # The inner generator's own cleanup (snapshot handles, ...) still ran.
    assert state["inner_closed"]


def test_guard_passes_items_and_exceptions_through_unchanged():
    def inner():
        yield "a"
        raise ValueError("boom")

    guarded = guard_generator(inner(), lambda: None)
    assert next(guarded) == "a"
    with pytest.raises(ValueError, match="boom"):
        next(guarded)


def test_closing_the_guard_closes_the_inner_generator():
    closed = []

    def inner():
        try:
            yield 1
            yield 2
        finally:
            closed.append(True)

    guarded = guard_generator(inner(), lambda: None)
    next(guarded)
    guarded.close()
    assert closed == [True]


# --- argument errors surface at the call, not on the first next() ------------


def test_an_out_of_range_value_raises_at_call_time(process):
    with pytest.raises(ValueError):
        process.search_by_value(int, value=2**40)  # no next()


def test_an_out_of_range_bound_raises_at_call_time(process):
    with pytest.raises(ValueError):
        process.search_by_value_between(int, start=0, end=2**40)


def test_a_malformed_pattern_raises_at_call_time(process):
    with pytest.raises(ValueError):
        process.search_by_pattern("ZZ ??")


def test_validation_runs_before_the_closed_guard(process):
    # A valid call still returns a guarded generator.
    generator = process.search_by_value(int, value=1, writeable_only=True)
    process.close()
    with pytest.raises(ClosedProcess):
        next(generator)
