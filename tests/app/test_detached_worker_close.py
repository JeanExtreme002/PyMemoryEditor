# -*- coding: utf-8 -*-

"""
Tests for ``call_when_detached_workers_finish`` in ``PyMemoryEditor/app/_widgets.py``.

``shutdown_worker_thread`` deliberately *detaches* a worker that blows its join
timeout instead of destroying it — otherwise the closing dialog would take a
running QThread down with it and abort the process. The consequence is a thread
that can still be inside a backend read after its dialog is gone, so whatever
releases the process handle it reads through (``MainWindow._change_process``)
has to wait for it rather than pull the ground out from under it.

Skipped when ``PySide6`` isn't installed (the runtime dependency is opt-in via
the ``app`` extra).
"""

import os
import time

import pytest


pytest.importorskip("PySide6", reason="App tests require PySide6 (install with [app] extra).")

# Offscreen platform plugin: no display server needed, runs on CI.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qapp():
    """A single QApplication for the module (Qt allows only one per process)."""
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _spin_until(qapp, predicate, timeout_ms=5000) -> bool:
    """Pump the event loop until ``predicate`` holds (or the timeout expires)."""
    from PySide6.QtCore import QElapsedTimer

    elapsed = QElapsedTimer()
    elapsed.start()
    while elapsed.elapsed() < timeout_ms:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(0.005)
    return predicate()


@pytest.fixture
def slow_worker(qapp):
    """A worker that ignores the join timeout, so shutdown has to detach it."""
    from PySide6.QtCore import QThread

    class _WedgedWorker(QThread):
        def __init__(self):
            super().__init__()
            self.busy_ms = 400
            # Python-side completion flag. Assertions must not call isRunning()
            # after the worker finishes: the detach machinery reaps it (a
            # deleteLater on the C++ object), and touching the wrapper then
            # raises "Internal C++ object already deleted".
            self.ran_to_completion = False

        def run(self):
            # Stands in for a backend read that can't be interrupted — the only
            # reason `shutdown_worker_thread` ever detaches anything.
            QThread.msleep(self.busy_ms)
            self.ran_to_completion = True

    workers = []

    def _factory():
        worker = _WedgedWorker()
        workers.append(worker)
        return worker

    yield _factory

    for worker in workers:
        try:
            worker.wait(5000)
        except RuntimeError:
            # Already reaped: a detached worker deleteLater()s itself once it
            # finishes, which leaves the Python wrapper pointing at nothing.
            pass
    qapp.processEvents()


def test_closes_inline_when_nothing_is_detached(qapp):
    """The normal path: no wedged worker, so the handle is released right away."""
    from PyMemoryEditor.app._widgets import (
        call_when_detached_workers_finish,
        wait_for_detached_workers,
    )

    # Precondition: nothing wedged from an earlier test. A finished worker may
    # still sit in the registry waiting for its reaper, which doesn't count —
    # and touching such a wrapper directly can hit an already-deleted C++
    # object, so ask through the guarded helper.
    assert wait_for_detached_workers(0) is True

    closed = []
    call_when_detached_workers_finish(lambda: closed.append(True))
    assert closed == [True]  # synchronous, not deferred to the event loop


def test_the_close_waits_for_a_detached_worker(qapp, slow_worker):
    """A worker that outlived its join must not have the handle closed under it."""
    from PyMemoryEditor.app._widgets import (
        _DETACHED_WORKERS,
        call_when_detached_workers_finish,
        shutdown_worker_thread,
    )

    worker = slow_worker()
    worker.start()
    assert _spin_until(qapp, worker.isRunning, 2000)

    # A 0 ms join can't stop it, so shutdown detaches it — the situation
    # _change_process has to survive.
    shutdown_worker_thread(worker, wait_ms=0)
    assert worker in _DETACHED_WORKERS
    assert worker.isRunning()

    closed = []
    call_when_detached_workers_finish(lambda: closed.append(True))
    assert closed == []  # still reading — the handle must stay open

    assert _spin_until(qapp, lambda: bool(closed))
    assert closed == [True]
    assert worker.ran_to_completion


def test_the_blocking_wait_reports_whether_the_workers_finished(qapp, slow_worker):
    """App exit has no event loop left, so it needs the blocking sibling.

    ``QThread.wait`` works without a loop; ``finished`` would never be
    delivered, so ``call_when_detached_workers_finish`` can't be used there.
    """
    from PyMemoryEditor.app._widgets import (
        shutdown_worker_thread,
        wait_for_detached_workers,
    )

    assert wait_for_detached_workers(0) is True  # nothing detached

    worker = slow_worker()
    worker.busy_ms = 600
    worker.start()
    assert _spin_until(qapp, worker.isRunning, 2000)
    shutdown_worker_thread(worker, wait_ms=0)

    # Too short: the caller must leave the handle alone rather than close it
    # under a live read.
    assert wait_for_detached_workers(50) is False
    assert worker.isRunning()

    # Long enough: the worker is done, so the handle is safe to release.
    assert wait_for_detached_workers(3000) is True
    assert worker.ran_to_completion


def test_the_close_fires_once_for_several_detached_workers(qapp, slow_worker):
    """Two wedged workers, one close — and only after the slower one is done."""
    from PyMemoryEditor.app._widgets import (
        call_when_detached_workers_finish,
        shutdown_worker_thread,
    )

    quick, slow = slow_worker(), slow_worker()
    quick.busy_ms, slow.busy_ms = 200, 800
    quick.start()
    slow.start()
    assert _spin_until(qapp, lambda: quick.isRunning() and slow.isRunning(), 2000)

    shutdown_worker_thread(quick, wait_ms=0)
    shutdown_worker_thread(slow, wait_ms=0)

    closed = []
    call_when_detached_workers_finish(lambda: closed.append(True))

    assert _spin_until(qapp, lambda: quick.ran_to_completion, 3000)
    qapp.processEvents()
    assert closed == []  # the other one is still reading

    assert _spin_until(qapp, lambda: bool(closed))
    assert closed == [True]  # exactly once, not once per worker
