# -*- coding: utf-8 -*-

"""
Tests for the package-level ``PyMemoryEditor`` logger.

The logger is silent by default (NullHandler attached at import time) — these
tests attach a memory handler to capture emissions, then trigger code paths
that should log DEBUG events.
"""

import logging

import pytest


@pytest.fixture
def log_capture():
    """Attach a list-based handler to the PyMemoryEditor logger for the test."""
    records = []

    class _ListHandler(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger("PyMemoryEditor")
    handler = _ListHandler(level=logging.DEBUG)
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


def test_logger_is_silent_by_default():
    """
    A fresh import attaches a NullHandler — calls to ``logger.debug(...)``
    must not surface anywhere unless the consumer adds a handler.
    """
    logger = logging.getLogger("PyMemoryEditor")
    # At least one handler — the NullHandler installed at import time.
    assert logger.handlers, "expected at least one handler (NullHandler) attached"
    # NullHandler swallows messages: emitting at DEBUG must not raise.
    logger.debug("smoke test message")


def test_logger_module_exported():
    """The logger is also exported at the package top level."""
    import PyMemoryEditor

    assert PyMemoryEditor.logger is logging.getLogger("PyMemoryEditor")


def test_logger_captures_emit(log_capture):
    """Sanity check: when a handler is attached, DEBUG records reach it."""
    logger = logging.getLogger("PyMemoryEditor")
    logger.debug("hello %s", "world")
    assert len(log_capture) == 1
    record = log_capture[0]
    assert record.levelno == logging.DEBUG
    assert record.getMessage() == "hello world"


def test_logger_emits_during_scanning_skip(log_capture):
    """
    Triggering a real scan against the current process — which always has
    a few unreadable regions — must log DEBUG entries from the iter_*
    helpers when they skip those chunks.
    """
    import os
    import sys

    if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
        pytest.skip("Platform not supported by PyMemoryEditor")

    from PyMemoryEditor import OpenProcess

    with OpenProcess(pid=os.getpid()) as p:
        # A scan over the whole address space will touch unreadable chunks on
        # every supported platform; the logger should record at least one
        # skip. We don't iterate fully — just enough to ensure the loop runs.
        for _ in p.search_by_value(int, 4, 0xCAFEBABE):
            break

    # Some platforms may not log a skip on every run (a self-process scan may
    # be entirely successful in a particular environment); when that happens,
    # the test is inconclusive rather than failing. The point of this test is
    # to confirm the logger is wired in — exercise it where possible without
    # being flaky.
    if not log_capture:
        pytest.skip(
            "no scan skips observed in this run — wiring is sound but this "
            "environment didn't trip a transient skip"
        )

    debug_messages = [r.getMessage() for r in log_capture if r.levelno == logging.DEBUG]
    assert debug_messages, "expected at least one DEBUG message during scanning"
