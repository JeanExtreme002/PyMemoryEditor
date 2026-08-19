# -*- coding: utf-8 -*-

"""
Tests for ``PyMemoryEditor/app/open_process_dialog.py``.

Regression cover for issue #75 and its neighbours: the picker's re-enumeration
tick used to move the viewport, overwrite the "Process:" field, and — via the
Filter box — retarget the selection at a process the user never chose.

The contract: only a real pick — clicking a row, arrowing onto one, or
double-clicking one — may write to the "Process:" field or change what the picker
targets. A refresh tick and a filter keystroke must leave both alone, along with
the scroll position.

Skipped when ``PySide6`` isn't installed (the runtime dependency is opt-in via
the ``app`` extra).
"""

import os
from typing import List, Tuple

import pytest


pytest.importorskip("PySide6", reason="App tests require PySide6 (install with [app] extra).")

# Offscreen platform plugin: no display server needed, runs on CI.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qapp():
    """A single QApplication for the module (Qt allows only one per process)."""
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _rows(count: int) -> List[Tuple[int, str, int, str]]:
    """Rows shaped like ``_ProcessListWorker.rows_ready`` emits them."""
    return [(1000 + i, f"proc{i:03d}", 1024 * (i + 1), "user") for i in range(count)]


@pytest.fixture
def dialog(qapp, monkeypatch):
    """A shown picker whose own enumeration is inert.

    The real worker walks the live process table on a thread, so its results
    could land mid-test; the tests call ``_on_rows_ready`` directly instead,
    which is what a refresh tick does once the scan returns.
    """
    from PyMemoryEditor.app import open_process_dialog

    class _InertWorker(open_process_dialog._ProcessListWorker):
        def run(self) -> None:
            return

    monkeypatch.setattr(open_process_dialog, "_ProcessListWorker", _InertWorker)

    dlg = open_process_dialog.OpenProcessDialog()
    dlg._refresh_timer.stop()  # refreshes are driven by hand below
    dlg.show()
    qapp.processEvents()
    try:
        yield dlg
    finally:
        dlg.close()
        dlg.deleteLater()
        qapp.processEvents()


def test_refresh_keeps_the_scroll_position_after_a_row_was_clicked(qapp, dialog):
    """The #75 repro: click a row, scroll away, wait for a tick."""
    rows = _rows(300)
    dialog._on_rows_ready(rows)
    dialog._table.selectRow(2)
    qapp.processEvents()

    scrollbar = dialog._table.verticalScrollBar()
    scrollbar.setValue(150)
    qapp.processEvents()
    assert scrollbar.value() == 150, "the list must be scrollable for this to mean anything"

    dialog._on_rows_ready(rows)  # the auto-refresh tick
    qapp.processEvents()
    assert scrollbar.value() == 150

    # The property behind that number: the restored selection stayed off-screen.
    selected = dialog._table.selectionModel().selectedRows()
    assert selected, "the tick is supposed to restore the selection"
    row_rect = dialog._table.visualRect(selected[0])
    assert not row_rect.intersects(dialog._table.viewport().rect())


def test_refresh_still_restores_the_selection(qapp, dialog):
    """Preserving the viewport must not cost the selection the picker keeps."""
    rows = _rows(300)
    dialog._on_rows_ready(rows)
    dialog._table.selectRow(2)
    qapp.processEvents()

    selected_pid = dialog._selected_pid()
    assert selected_pid is not None

    dialog._on_rows_ready(rows)
    qapp.processEvents()
    assert dialog._selected_pid() == selected_pid


def test_refresh_does_not_overwrite_a_typed_process_name(qapp, dialog):
    """A tick must not refill the entry the user typed into."""
    rows = _rows(300)
    dialog._on_rows_ready(rows)
    dialog._table.selectRow(2)
    qapp.processEvents()
    assert dialog._entry.text(), "clicking a row is supposed to fill the entry"

    dialog._entry.setText("notepad.exe")
    dialog._on_rows_ready(rows)
    qapp.processEvents()
    assert dialog._entry.text() == "notepad.exe"


def test_clicking_a_row_still_fills_the_entry(qapp, dialog):
    """A click is a pick: the refresh guard must not swallow it too."""
    dialog._on_rows_ready(_rows(300))
    qapp.processEvents()

    dialog._table.selectRow(2)
    qapp.processEvents()
    assert dialog._entry.text() == str(dialog._selected_pid())


def test_double_clicking_a_row_opens_that_row(qapp, dialog, monkeypatch):
    """The double-click wins over the entry, which is all ``_try_open`` reads."""
    dialog._on_rows_ready(_rows(300))
    dialog._table.selectRow(2)
    qapp.processEvents()
    clicked_pid = dialog._selected_pid()

    dialog._entry.setText("notepad.exe")
    opened = []
    monkeypatch.setattr(dialog, "_try_open", lambda: opened.append(dialog._entry.text()))

    dialog._table.doubleClicked.emit(dialog._proxy.index(2, dialog.COL_PID))
    qapp.processEvents()
    assert opened == [str(clicked_pid)]


def test_filtering_away_the_selection_drops_it_instead_of_retargeting(qapp, dialog):
    """Qt remaps a selection whose row the filter hid; the picker must not follow."""
    dialog._on_rows_ready(_rows(300))
    dialog._table.selectRow(120)
    qapp.processEvents()
    picked_pid = dialog._selected_pid()
    assert picked_pid is not None

    dialog._entry.setText("notepad.exe")
    dialog._filter_edit.setText("proc12")  # hides the picked row
    qapp.processEvents()

    assert dialog._selected_pid() is None, "a hidden pick must not survive as another row"
    assert dialog._entry.text() == "notepad.exe"

    # And the tick that follows must not resurrect it either.
    dialog._on_rows_ready(_rows(300))
    qapp.processEvents()
    assert dialog._entry.text() == "notepad.exe"


def test_filtering_keeps_a_selection_that_survives_the_filter(qapp, dialog):
    """Dropping the selection is only right when the filter actually hides it."""
    from PySide6.QtCore import Qt

    rows = _rows(300)
    dialog._on_rows_ready(rows)

    # proc129 stays visible under the "proc12" filter (proc120..proc129 match).
    target_pid = 1129
    for row in range(dialog._proxy.rowCount()):
        index = dialog._proxy.index(row, dialog.COL_PID)
        if dialog._proxy.data(index, Qt.UserRole) == target_pid:
            dialog._table.selectRow(row)
            break
    qapp.processEvents()
    assert dialog._selected_pid() == target_pid

    dialog._filter_edit.setText("proc12")
    qapp.processEvents()
    assert dialog._selected_pid() == target_pid


def test_arrowing_onto_a_row_fills_the_entry(qapp, dialog):
    """Arrowing onto a row is a pick too, so it must reach the entry."""
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest

    dialog._on_rows_ready(_rows(300))
    dialog._table.selectRow(2)
    qapp.processEvents()
    before = dialog._entry.text()

    dialog._table.setFocus()
    QTest.keyClick(dialog._table, Qt.Key_Down)
    qapp.processEvents()

    assert dialog._entry.text() == str(dialog._selected_pid())
    assert dialog._entry.text() != before


def test_refresh_under_an_active_filter_keeps_the_selection(qapp, dialog):
    """A tick under a filter must find the picked PID among the *filtered* rows."""
    rows = _rows(300)
    dialog._on_rows_ready(rows)
    dialog._table.selectRow(2)
    qapp.processEvents()
    picked_pid = dialog._selected_pid()
    assert picked_pid is not None

    # `_rows` pairs PID 1000 + i with the name "proc{i:03d}".
    dialog._filter_edit.setText(f"proc{picked_pid - 1000:03d}")
    qapp.processEvents()
    assert dialog._proxy.rowCount() == 1
    assert dialog._selected_pid() == picked_pid

    dialog._on_rows_ready(rows)  # the auto-refresh tick
    qapp.processEvents()
    assert dialog._selected_pid() == picked_pid
