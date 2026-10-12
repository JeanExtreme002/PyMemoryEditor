# -*- coding: utf-8 -*-

"""
``MainWindow`` lifecycle against a target that goes away, and the guard on
closing a window whose cheat table still has entries.

The window is built against a fake process whose pid is the test process
(so the psutil-based heartbeat can stamp it) and whose reads never touch
memory. Liveness is driven by monkeypatching ``_target_is_alive`` rather than
by killing anything.

Skipped without ``PySide6`` / ``pytest-qt`` (``app`` and ``dev`` extras).
"""

import os

import pytest


pytest.importorskip("PySide6", reason="App tests require PySide6 (install with [app] extra).")
pytest.importorskip("pytestqt", reason="pytest-qt is required for these tests.")

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _FakeProcess:
    """Enough of ``AbstractProcess`` for the window to build and idle."""

    def __init__(self):
        self.pid = os.getpid()
        self.closed = False

    def read_process_memory(self, address, pytype, length):
        return 0

    def write_process_memory(self, address, pytype, length, value):
        return value

    def search_by_addresses(self, pytype, length, addresses):
        return iter(())

    def get_memory_regions(self):
        return iter(())

    # First-scan behaviour, set per test: the hits it yields, an optional hook
    # run after the first one (to cancel mid-scan), or an error to raise.
    scan_hits = ()
    after_first_hit = None
    scan_error = None

    def search_by_value(self, pytype, length, value, scan_type, **_kwargs):
        if self.scan_error is not None:
            raise self.scan_error
        for index, address in enumerate(self.scan_hits):
            if index == 1 and self.after_first_hit is not None:
                self.after_first_hit()
            yield address, {"progress": 0.5}

    def close(self):
        self.closed = True


@pytest.fixture
def window(qtbot, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    from PyMemoryEditor.app.main_window import MainWindow

    # Modal dialogs would block an offscreen run; record them instead.
    shown = []
    monkeypatch.setattr(
        QMessageBox, "warning", lambda *args, **kwargs: shown.append(args[1:3])
    )
    monkeypatch.setattr(MainWindow, "confirm_close_with_entries", False)

    win = MainWindow(_FakeProcess())
    win._heartbeat.stop()  # the tests drive liveness checks by hand
    win.shown_dialogs = shown
    qtbot.addWidget(win)
    yield win
    win.close()


def test_a_dead_target_locks_the_scanner_and_idles_the_poller(window):
    assert not window._scanner._busy
    assert window._cheat._publish_timer.isActive()

    window._target_is_alive = lambda: False
    window._check_process_alive()

    assert window._target_dead
    assert window._scanner._busy
    assert window._cheat.is_polling_paused()
    assert not window._cheat._publish_timer.isActive()
    assert window._cheat._poller._snapshot == []
    assert window.shown_dialogs and window.shown_dialogs[0][0] == "Process exited"


def test_a_finishing_worker_does_not_unlock_a_dead_target(window):
    """
    Regression: ``_cleanup_worker`` (run when any scan worker finishes) used
    to call ``_set_busy(False)`` unconditionally, handing the scan controls
    back against a dead handle right after the heartbeat had locked them.
    """
    window._target_is_alive = lambda: False
    window._check_process_alive()
    assert window._scanner._busy

    window._cleanup_worker()

    assert window._scanner._busy
    assert window._worker is None


def test_a_finishing_worker_unlocks_a_live_target(window):
    window._set_busy(True)
    window._cleanup_worker()
    assert not window._scanner._busy


def test_pausing_the_poller_refuses_queued_writes_and_resumes_cleanly(window):
    from PyMemoryEditor.app.cheat_entry import CheatEntry

    cheat = window._cheat
    cheat.add_entry(
        CheatEntry(description="", address=0x1000, spec_label="4 Bytes (Int32)", length=4)
    )
    cheat.set_polling_paused(True)
    assert cheat._poller._pending_writes == []

    # An inline edit while paused is dropped rather than queued.
    item = cheat._table.item(0, cheat.COL_VALUE)
    item.setText("42")
    assert cheat._poller._pending_writes == []

    cheat.set_polling_paused(False)
    assert cheat._publish_timer.isActive()
    assert not cheat.is_polling_paused()
    # Resuming republished the entries to the worker straight away.
    assert [row[0] for row in cheat._poller._snapshot] == [0x1000]

    item.setText("43")
    assert [w[0] for w in cheat._poller._pending_writes] == [0x1000]


def test_closing_with_entries_asks_and_can_be_cancelled(window, monkeypatch):
    from PySide6.QtGui import QCloseEvent
    from PySide6.QtWidgets import QMessageBox

    from PyMemoryEditor.app.cheat_entry import CheatEntry
    from PyMemoryEditor.app.main_window import MainWindow

    monkeypatch.setattr(MainWindow, "confirm_close_with_entries", True)
    asked = []

    def _question(_parent, title, text, *_args, **_kwargs):
        asked.append((title, text))
        return QMessageBox.StandardButton.Cancel

    monkeypatch.setattr(QMessageBox, "question", _question)

    # Empty table: no question, close goes ahead.
    event = QCloseEvent()
    assert window._confirm_discard_cheat_table()
    assert asked == []

    window._cheat.add_entry(
        CheatEntry(description="", address=0x1000, spec_label="4 Bytes (Int32)", length=4)
    )
    window.closeEvent(event)
    assert not event.isAccepted()
    assert len(asked) == 1 and "1 entry" in asked[0][1]
    # The window is still fully alive: nothing was torn down.
    assert window._cheat._publish_timer.isActive()

    monkeypatch.setattr(
        QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Discard
    )
    event = QCloseEvent()
    window.closeEvent(event)
    assert event.isAccepted()


def test_promoting_an_over_long_width_is_reported_not_raised(window, monkeypatch):
    """
    The scanner's width field allows more than the cheat table's
    MAX_ENTRY_LENGTH; add_entry refuses such a width with ValueError. Raised
    inside the promote slot that would only reach the user as the generic
    excepthook dialog and leave part of the selection added.
    """
    from PySide6.QtWidgets import QMessageBox

    from PyMemoryEditor.app.cheat_table import MAX_ENTRY_LENGTH
    from PyMemoryEditor.app.value_types import find_spec

    warnings = []
    monkeypatch.setattr(
        QMessageBox, "warning", lambda *args, **kwargs: warnings.append(args[2])
    )
    monkeypatch.setattr(
        window._scanner,
        "current_spec_and_length",
        lambda: (find_spec("String (UTF-8)"), MAX_ENTRY_LENGTH + 1),
    )

    window._promote_to_cheat_table([0x1000, 0x2000])

    assert window._cheat.entry_count() == 0
    assert len(warnings) == 1 and str(MAX_ENTRY_LENGTH) in warnings[0]

    window._promote_resolved_address(0x3000, "String (UTF-8)", MAX_ENTRY_LENGTH + 1, "pointer chain")

    assert window._cheat.entry_count() == 0
    assert len(warnings) == 2


def _int32_request():
    from PyMemoryEditor import ScanTypesEnum
    from PyMemoryEditor.app.scan_worker import ScanRequest
    from PyMemoryEditor.app.value_types import find_spec

    return ScanRequest(
        spec=find_spec("4 Bytes (Int32)"), length=4,
        scan_type=ScanTypesEnum.EXACT_VALUE, value=1,
    )


def _run_first_scan(window, qtbot, monkeypatch):
    """Run a First Scan to its end; return (worker, auto-refresh calls)."""
    refreshes = []
    monkeypatch.setattr(window._scanner, "use_snapshot_cache", lambda: False)
    monkeypatch.setattr(window, "_on_update_values", lambda request: refreshes.append(request))
    window._on_first_scan(_int32_request())
    worker = window._worker
    qtbot.waitUntil(lambda: window._worker is None, timeout=5000)
    return worker, refreshes


def _is_deleted(qobject):
    import shiboken6
    from PySide6.QtCore import QCoreApplication, QEvent

    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    return not shiboken6.isValid(qobject)


def test_a_completed_first_scan_refreshes_values_and_frees_its_worker(
    window, qtbot, monkeypatch
):
    """
    The finished worker used to be dropped but never deleted: a child of the
    window, each scan's QThread (with the address list it was handed) lived
    until the window closed.
    """
    window._process.scan_hits = (0x1000, 0x2000, 0x3000)
    worker, refreshes = _run_first_scan(window, qtbot, monkeypatch)

    assert window._results_model.count() == 3
    assert len(refreshes) == 1
    assert _is_deleted(worker)
    assert not window._scanner._busy


def test_a_cancelled_first_scan_does_not_start_updating_values(
    window, qtbot, monkeypatch
):
    """
    ``finished`` drove the "Updating values…" refresh unconditionally, so
    Cancel on a First Scan immediately started another scan.
    """
    window._process.scan_hits = (0x1000, 0x2000, 0x3000)
    window._process.after_first_hit = lambda: window._worker.cancel()
    worker, refreshes = _run_first_scan(window, qtbot, monkeypatch)

    assert refreshes == []
    assert _is_deleted(worker)
    assert not window._scanner._busy


def test_a_failed_first_scan_reports_once(window, qtbot, monkeypatch):
    """A scan error was followed by the refresh failing too: two dialogs."""
    from PySide6.QtWidgets import QMessageBox

    errors = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: errors.append(args[2]))
    window._process.scan_error = OSError("target exited")
    worker, refreshes = _run_first_scan(window, qtbot, monkeypatch)

    assert refreshes == []
    assert len(errors) == 1 and "target exited" in errors[0]
    assert _is_deleted(worker)


def test_shutting_down_a_first_scan_disconnects_snapshot_ready(window):
    """``_shutdown_worker`` unhooked every signal but snapshot_ready."""
    from PyMemoryEditor.app.scan_worker import FirstScanWorker

    worker = FirstScanWorker(window._process, _int32_request(), window)
    # Wired like _on_first_scan does (every signal has a slot).
    for signal in (worker.chunk_ready, worker.progress, worker.status, worker.error,
                   worker.finished_ok, worker.finished):
        signal.connect(lambda *_args: None)
    worker.snapshot_ready.connect(window._on_snapshot_ready)
    window._worker = worker
    window._shutdown_worker()

    worker.snapshot_ready.emit(["stale"])  # same thread: would be a direct call
    assert window._region_snapshot is None


def test_closing_a_tool_dialog_frees_it(window, qtbot):
    """
    The tool dialogs are children of the window and were rebuilt on every
    open, but a closed one was only forgotten, never deleted — each
    close/reopen kept another instance alive.
    """
    window._open_log_console()
    first = window._log_console_dialog
    first.close()
    assert window._log_console_dialog is None
    assert _is_deleted(first)

    window._open_log_console()
    second = window._log_console_dialog
    assert second is not None
    second.reject()  # Esc / Close button path: done(), no close event
    assert window._log_console_dialog is None
    assert _is_deleted(second)
