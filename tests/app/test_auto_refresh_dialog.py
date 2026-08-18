# -*- coding: utf-8 -*-

"""
Tests for ``PyMemoryEditor/app/_auto_refresh_dialog.py``.

Regression cover for issue #74: these dialogs poll every 300–1000 ms and used to
report every failed fetch with a modal. A modal runs a nested event loop, so the
timer kept firing underneath and the dialogs stacked — hundreds of them.

The contract now: a failure is reported only when it changes what the user sees
— the first fetch (empty window) or the one that makes the poll give up (frozen
table) — and never twice for the same error.

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


def _spin(qapp, milliseconds: int) -> None:
    """Pump the event loop for a while, so timers fire and workers land."""
    from PySide6.QtCore import QElapsedTimer

    elapsed = QElapsedTimer()
    elapsed.start()
    while elapsed.elapsed() < milliseconds:
        qapp.processEvents()
        time.sleep(0.005)


@pytest.fixture
def short_grace(monkeypatch):
    """Shrink the give-up window so the timing tests stay sub-second."""
    from PyMemoryEditor.app import _auto_refresh_dialog

    monkeypatch.setattr(_auto_refresh_dialog, "_FAILURE_GRACE_MS", 150)
    return 150


@pytest.fixture(scope="module")
def dialog_parent(qapp):
    """A hidden parent, so Qt owns the dialogs instead of Python's GC.

    A parentless QDialog dies with the test's reference, taking its worker
    children with it while the event queue may still hold events for them —
    which segfaulted a *later* test's ``qtbot.wait``. Never deleted on purpose:
    a teardown here would recreate that window.
    """
    from PySide6.QtWidgets import QWidget

    return QWidget()


@pytest.fixture
def make_dialog(qapp, dialog_parent):
    """Factory for an ``AutoRefreshTableDialog`` whose fetch can be made to fail.

    Closed at the end of each test (that exercises the teardown) but owned by
    ``dialog_parent``, not destroyed mid-session.
    """
    from PyMemoryEditor.app._auto_refresh_dialog import AutoRefreshTableDialog

    class _Dialog(AutoRefreshTableDialog):
        def __init__(self, interval_ms, failing):
            super().__init__(
                object(), refresh_interval_ms=interval_ms, parent=dialog_parent
            )
            self.failing = failing
            self.flapping = False
            self.fetches = 0
            self.errors = []
            self.rendered = 0
            self.gave_up = 0

        def _fetch_data(self):
            # Runs on the worker thread, like the real enumerations.
            self.fetches += 1
            if self.flapping:
                self.failing = not self.failing
            if self.failing:
                raise RuntimeError('The process ID "4242" does not exist.')
            return ["ok"]

        def _on_data_ready(self, data):
            self.rendered += 1

        def _on_data_failed(self, message):
            # Stands in for the subclasses' QMessageBox.critical.
            self.errors.append(message)

        def _on_polling_stopped(self):
            # Stands in for the subclasses' "auto-refresh stopped" label.
            self.gave_up += 1

    dialogs = []

    def _factory(interval_ms=50, failing=False):
        dialog = _Dialog(interval_ms, failing)
        dialog.refresh()
        dialog._start_auto_refresh()
        _spin(qapp, 100)  # let the first fetch land
        dialogs.append(dialog)
        return dialog

    yield _factory

    for dialog in dialogs:
        dialog.close()
    _spin(qapp, 50)


def test_a_target_that_dies_is_reported_once(qapp, short_grace, make_dialog):
    """A target that fails on every tick must produce a single error report."""
    dialog = make_dialog()
    assert dialog.errors == []
    assert dialog.rendered > 0

    dialog.failing = True
    _spin(qapp, 600)

    # Without the fix this grew by one modal per 50 ms tick — and because each
    # modal runs a nested event loop, the timer kept firing and they stacked.
    assert len(dialog.errors) == 1
    assert "does not exist" in dialog.errors[0]


def test_polling_stops_when_failures_persist(qapp, short_grace, make_dialog):
    """A dead target isn't coming back under the same handle — stop polling."""
    dialog = make_dialog()
    dialog.failing = True
    _spin(qapp, 600)

    assert dialog._auto_timer is not None and not dialog._auto_timer.isActive()
    fetches = dialog.fetches
    _spin(qapp, 300)
    # Bounded work: it gives up instead of burning a worker per tick forever.
    assert dialog.fetches == fetches
    # And it says so exactly once, so the frozen table isn't silently stale.
    assert dialog.gave_up == 1


def test_a_flapping_target_never_stacks_dialogs(qapp, make_dialog):
    """Fail / succeed / fail / succeed must stay silent, not pop a modal a tick.

    Reporting every failure looked safe because the same error is never reported
    twice — but each success cleared that latch, so an alternating target popped
    a modal per failure, nesting event loops until the stack blew up.
    """
    dialog = make_dialog()
    dialog.flapping = True
    _spin(qapp, 800)

    assert dialog.errors == []
    assert dialog.gave_up == 0
    assert dialog._auto_timer.isActive()  # a healing target keeps polling
    assert dialog.rendered > 1  # and keeps rendering its good ticks


def test_the_first_fetch_failure_is_reported_immediately(qapp, make_dialog):
    """Nothing to look at but the error, so don't sit on it for the grace window."""
    dialog = make_dialog(failing=True)  # broken before the window ever filled

    assert len(dialog.errors) == 1
    assert dialog.gave_up == 0  # reported on its own merit, not by giving up
    assert dialog._auto_timer.isActive()


def test_failures_inside_the_grace_window_are_not_reported(make_dialog):
    """A blip (a snapshot that fails while the target loads images) stays quiet.

    Driven through the handlers: racing a 50 ms poll to land an exact number of
    failures would only make the test flaky.
    """
    dialog = make_dialog()

    for _ in range(5):
        dialog._handle_failed("transient")
    assert dialog.errors == []
    assert dialog.gave_up == 0
    assert dialog._auto_timer.isActive()

    dialog._handle_ready(["ok"])  # healed
    assert dialog._failing_since is None  # the streak clock resets


def test_explicit_refresh_re_arms_the_poll_and_the_error_latch(
    qapp, short_grace, make_dialog
):
    """Reopening the dialog (the main window calls ``refresh()``) resumes it."""
    dialog = make_dialog()
    dialog.failing = True
    _spin(qapp, 600)
    assert len(dialog.errors) == 1
    assert not dialog._auto_timer.isActive()

    dialog.failing = False
    dialog.refresh()
    _spin(qapp, 200)
    assert dialog._auto_timer.isActive()
    assert len(dialog.errors) == 1

    # A later give-up is reported again — the latch was cleared, not sealed.
    dialog.failing = True
    _spin(qapp, 600)
    assert len(dialog.errors) == 2
    assert dialog.gave_up == 2


def test_the_close_button_tears_the_dialog_down(qapp, make_dialog):
    """The Close button calls accept(), which delivers no QCloseEvent.

    The teardown used to live in ``closeEvent`` alone, so dismissing a polling
    dialog the normal way left it hidden and *still polling*, leaking a thread
    per open/close cycle.
    """
    dialog = make_dialog()
    assert dialog._auto_timer.isActive()
    fetches = dialog.fetches

    dialog.accept()  # exactly what the Close button is wired to
    _spin(qapp, 300)

    assert not dialog.isVisible()
    assert not dialog._auto_timer.isActive()
    assert dialog.fetches == fetches
    assert dialog._worker is None


def test_escape_tears_the_dialog_down_too(qapp, make_dialog):
    """Esc reaches reject(), the other half of done().

    A real key event, not a ``reject()`` call: Esc is handled inside ``QDialog``
    on the C++ side, so this proves the override is reached through Qt's virtual
    dispatch.
    """
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest

    dialog = make_dialog()
    dialog.show()
    _spin(qapp, 50)
    fetches = dialog.fetches

    QTest.keyClick(dialog, Qt.Key_Escape)
    _spin(qapp, 300)

    assert not dialog.isVisible()
    assert not dialog._auto_timer.isActive()
    assert dialog.fetches == fetches
    assert dialog._worker is None


def test_teardown_runs_once_however_the_dialog_is_dismissed(qapp, make_dialog):
    """close() → closeEvent → reject() → done() must not tear down twice."""
    dialog = make_dialog()
    calls = []
    real_teardown = dialog._teardown
    dialog._teardown = lambda: (calls.append(True), real_teardown())[1]

    dialog.close()
    _spin(qapp, 100)
    dialog.accept()  # a second dismissal must be a no-op

    assert calls == [True]


def test_a_late_finished_does_not_retire_the_worker_that_replaced_it(make_dialog):
    """``finished`` is queued and can land after the next tick started a fetch.

    Retiring ``self._worker`` blindly dropped the reference to the *running*
    replacement and scheduled it for deletion — that aborts the process.
    """
    dialog = make_dialog()
    dialog._start_fetch()
    current = dialog._worker
    assert current is not None

    class _Stale:
        def __init__(self):
            self.deleted = False

        def deleteLater(self):
            self.deleted = True

    stale = _Stale()
    dialog._on_worker_finished(stale)

    assert dialog._worker is current  # still tracked, still joinable
    assert stale.deleted  # and the one that really finished is retired


def test_nothing_fetches_after_the_dialog_was_torn_down(qapp, make_dialog):
    """The teardown latch is one-way, so a fetch started later is unjoinable."""
    dialog = make_dialog()
    dialog.accept()
    _spin(qapp, 100)
    fetches = dialog.fetches

    dialog.refresh()  # a stale caller poking a dismissed dialog
    _spin(qapp, 200)

    assert dialog.fetches == fetches
    assert dialog._worker is None
    assert not dialog._auto_timer.isActive()


def test_threads_dialog_treats_an_empty_enumeration_as_a_dead_target(
    qapp, short_grace, dialog_parent
):
    """Linux and Windows report an exited process as *no threads*, not an error,
    so the window would sit at "0 thread(s)" forever."""
    from PyMemoryEditor.app.threads_dialog import ThreadsDialog
    from PyMemoryEditor.process.thread_info import ThreadInfo

    alive = [ThreadInfo(tid=1, start_address=None, state="S", priority=20, raw="1")]
    state = {"threads": alive}

    class _Process:
        pid = 4242

        def get_threads(self):
            return iter(state["threads"])

    reported = []
    dialog = ThreadsDialog(_Process(), parent=dialog_parent)
    dialog._on_data_failed = lambda message: reported.append(message)
    try:
        _spin(qapp, 400)
        assert dialog._model.rowCount() == 1
        assert reported == []

        state["threads"] = []  # the target exits
        # 300 ms poll: one tick to see the empty list, another to call it, and
        # the grace window on top before it is worth telling the user.
        _spin(qapp, 1400)

        assert len(reported) == 1
        assert "exited" in reported[0]
    finally:
        dialog.close()
        _spin(qapp, 50)


def test_threads_dialog_tolerates_a_single_empty_enumeration(qapp, dialog_parent):
    """One empty snapshot is not proof of death: ``Thread32First`` can come up
    dry on a live process, and the first fetch is reported immediately."""
    from PyMemoryEditor.app.threads_dialog import ThreadsDialog
    from PyMemoryEditor.process.thread_info import ThreadInfo

    alive = [ThreadInfo(tid=1, start_address=None, state="S", priority=20, raw="1")]
    state = {"threads": [], "calls": 0}

    class _Process:
        pid = 4242

        def get_threads(self):
            state["calls"] += 1
            # Empty once, then healthy again.
            return iter(state["threads"] if state["calls"] > 1 else [])

    reported = []
    dialog = ThreadsDialog(_Process(), parent=dialog_parent)
    dialog._on_data_failed = lambda message: reported.append(message)
    try:
        state["threads"] = alive
        _spin(qapp, 500)

        assert reported == []  # the blip healed, nobody was told anything
        assert dialog._model.rowCount() == 1
        assert dialog._auto_timer.isActive()
    finally:
        dialog.close()
        _spin(qapp, 50)


def test_hex_viewer_stops_polling_and_logs_once_on_a_dead_target(
    qapp, dialog_parent, caplog, monkeypatch
):
    """The Hex Viewer is the other polling window, and it never gave up.

    Against a dead target every tick logged a warning — up to 20 a second at the
    50 ms floor, straight into the Log Console.
    """
    import logging

    from PyMemoryEditor.app import memory_viewer_dialog as mv

    monkeypatch.setattr(mv, "_FAILURE_GRACE_MS", 150)

    class _Process:
        pid = 4242

        def read_process_memory(self, address, pytype, length):
            raise OSError("the process is gone")

    viewer = mv.MemoryViewerDialog(
        _Process(), address=0x1000, length=64, parent=dialog_parent
    )
    try:
        viewer._interval_spin.setValue(50)
        with caplog.at_level(logging.WARNING, logger="PyMemoryEditor"):
            viewer._auto_btn.setChecked(True)  # the user opts into polling
            _spin(qapp, 600)

        warnings = [r for r in caplog.records if "Hex viewer read failed" in r.message]
        assert len(warnings) == 1  # once per streak, not once per tick
        assert not viewer._timer.isActive()
        assert not viewer._auto_btn.isChecked()  # and the button says so
        assert "auto-refresh stopped" in viewer._status.text()
    finally:
        viewer.close()
        _spin(qapp, 50)


def test_shutdown_really_disconnects_the_worker(qapp, dialog_parent, make_dialog):
    """`worker.disconnect()` is a no-op in PySide6 — it raises TypeError.

    `shutdown_worker_thread` swallowed that, so nothing was ever disconnected.
    The four-argument static form is the one that works for slots that are bound
    methods of the owning dialog.
    """
    from PyMemoryEditor.app._auto_refresh_dialog import _DataWorker
    from PyMemoryEditor.app._widgets import shutdown_worker_thread

    dialog = make_dialog()
    # Quiesce the dialog first: with its own poll running, a result already in
    # flight would land during the pump below and move the counters for reasons
    # that have nothing to do with this test.
    dialog._auto_timer.stop()
    _spin(qapp, 100)
    rendered, errors = dialog.rendered, len(dialog.errors)

    worker = _DataWorker(lambda: ["x"], dialog)
    worker.ready.connect(dialog._handle_ready)
    worker.failed.connect(dialog._handle_failed)

    shutdown_worker_thread(worker, wait_ms=0)
    worker.ready.emit(["late"])
    worker.failed.emit("late failure")
    qapp.processEvents()

    assert dialog.rendered == rendered
    assert len(dialog.errors) == errors


def test_a_dismissed_dialog_reports_nothing(qapp, make_dialog):
    """The same hazard from the receiving end: a delivery already queued when
    the teardown ran must not pop a modal over a window that is gone."""
    dialog = make_dialog()
    dialog.accept()
    _spin(qapp, 50)

    dialog._handle_failed("late failure")
    dialog._handle_ready(["late"])

    assert dialog.errors == []
    assert dialog.gave_up == 0
