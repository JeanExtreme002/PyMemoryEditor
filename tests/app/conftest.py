# -*- coding: utf-8 -*-

"""Shared setup for the GUI app tests."""

import gc

import pytest


@pytest.fixture(autouse=True)
def _collect_garbage_on_the_test_thread():
    """Keep the cyclic collector out of the tests' QThread workers.

    The app does this with ``MainThreadGarbageCollector`` (``app/_gc.py``), but
    the tests build widgets and workers without going through ``main()``. An
    automatic collection inside a worker can free reference cycles that hold
    the GUI thread's Qt objects -- left over from this or an earlier test --
    and destroy them from the wrong thread, which crashed the pytest worker on
    CI (segfault on macOS, access violation on Windows). So automatic
    collection is off during each test, and the garbage is collected here, on
    the test's own thread, at teardown.
    """
    was_enabled = gc.isenabled()
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        gc.collect()
        if was_enabled:
            gc.enable()
