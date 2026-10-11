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
