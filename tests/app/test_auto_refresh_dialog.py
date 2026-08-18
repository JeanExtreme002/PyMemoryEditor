# -*- coding: utf-8 -*-

"""
Tests for ``PyMemoryEditor/app/_auto_refresh_dialog.py``.

Regression cover for issue #74: the Memory Map / Modules / Threads dialogs poll
the target every 300–1000 ms and report a failed fetch with a *modal* dialog.
Once the target exits (or its handle is closed by File → Change Process) every
tick fails, and because a modal runs a nested event loop the timer keeps firing
while it's up — the app ended up with hundreds of stacked, focus-stealing error
boxes and had to be killed from another terminal.

The contract now: a failure is reported only when it changes what the user sees
— the first fetch (empty window) or the one that makes the poll give up after
``_FAILURE_GRACE_MS`` of continuous failure (frozen table) — and never twice for
the same error. Failures in between heal quietly, which is what keeps a target
failing on alternating ticks from stacking a modal per failure.

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

    A parentless QDialog is owned by its Python wrapper: it is destroyed the
    instant the test's reference goes away, taking its worker children with it
    while the event queue may still hold events for them. That left the process
    crashing later — a segfault inside a *different* test's ``qtbot.wait``.
    Parenting them here keeps every object alive until the module is done, so
    nothing is freed underneath a queued event.

    Deliberately never deleted: the process is about to exit anyway, and a
    teardown here would recreate the very window this avoids.
    """
    from PySide6.QtWidgets import QWidget

    return QWidget()


@pytest.fixture
def make_dialog(qapp, dialog_parent):
    """Factory for an ``AutoRefreshTableDialog`` whose fetch can be made to fail.

    Dialogs are closed at the end of each test — that is what exercises the
    teardown — but stay owned by ``dialog_parent`` (see there) rather than being
    destroyed mid-session.
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

    The regression this guards: reporting every failure looked safe because the
    same error is never reported twice in a row — but each success cleared that
    latch, so an alternating target popped a modal per failure, each one nesting
    an event loop inside the previous modal until the stack blew up.
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

    Driven through the handlers rather than the timer: what matters is the
    failure *sequence*, and racing a 50 ms poll to land an exact number of
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
    dialog the normal way left it hidden and *still polling* — unreachable
    (the main window drops its reference on ``finished``), leaking a thread per
    open/close cycle, and with its worker absent from the detached registry that
    keeps the process handle alive while something is still reading.
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

    Driven as a real key event rather than a ``reject()`` call: Esc is handled
    inside ``QDialog`` on the C++ side, so this is what proves the override is
    reached through Qt's virtual dispatch and not just from Python.
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
    """``finished`` is queued and can land after the next tick started a new fetch.

    Retiring ``self._worker`` blindly there dropped the reference to the
    *running* replacement and scheduled it for deletion — destroying a live
    QThread aborts the process, and the teardown could no longer join it.
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


def test_an_explicit_refresh_reports_its_failure_immediately(qapp, make_dialog):
    """A retry the user asked for answers now, not after the grace window."""
    dialog = make_dialog()  # production grace: 3 s
    dialog.failing = True

    dialog.refresh()
    _spin(qapp, 200)

    assert len(dialog.errors) == 1
    assert dialog.gave_up == 0  # reported on its own merit, not by giving up
    assert dialog._auto_timer.isActive()


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
    """Linux and Windows report an exited process as *no threads*, not an error.

    Without this the window would sit at "0 thread(s)" against a dead target —
    never reporting, never giving up — while the Memory Map and Modules windows
    beside it say the process is gone.
    """
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
        _spin(qapp, 600)

        assert len(reported) == 1
        assert "exited" in reported[0]
    finally:
        dialog.close()
        _spin(qapp, 50)


def test_hex_viewer_stops_polling_and_logs_once_on_a_dead_target(
    qapp, dialog_parent, caplog, monkeypatch
):
    """The Hex Viewer is the other polling window, and it never gave up.

    Its reads fail every tick against a dead target, and each one logged a
    warning — up to 20 a second at the 50 ms floor, straight into the Log
    Console. Same defect as issue #74, reported through the logger instead of a
    modal.
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
