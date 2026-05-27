# -*- coding: utf-8 -*-
"""
Threads dialog — exposes ``process.get_threads()``.

Shows every thread the target process currently has, in a sortable table,
with optional auto-refresh. The intent mirrors Cheat Engine's "Process →
Threads" window: you don't typically *act* on threads directly, but seeing
them is useful for introspection (how many workers does this game have?
is the main thread alive?). The optional auto-refresh polls at ~1 Hz so
you can watch threads come and go.

Lives alongside the existing Memory Map dialog — same shape, same patterns
(background worker, toolbar with Refresh, sortable table, Close button).
"""
from typing import List, Optional

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
)

from PyMemoryEditor import AbstractProcess, ThreadInfo

from ._widgets import NumericItem


class _ThreadsWorker(QThread):
    """Background thread that runs ``process.get_threads()`` off the UI."""

    threads_ready = Signal(object)  # List[ThreadInfo]
    threads_failed = Signal(str)

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process

    def run(self) -> None:
        try:
            threads = list(self._process.get_threads())
        except Exception as exc:  # noqa: BLE001
            self.threads_failed.emit(str(exc))
            return
        self.threads_ready.emit(threads)


class ThreadsDialog(QDialog):
    """Lists the output of ``get_threads()`` in a sortable table."""

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process
        self._threads: List[ThreadInfo] = []
        self._worker: Optional[_ThreadsWorker] = None

        self.setWindowTitle(f"Threads — PID {process.pid}")
        self.resize(640, 520)

        self._build_ui()
        self.refresh()

        # Auto-refresh at a fixed 300ms — threads spawn and exit often, so a
        # brisk cadence lets the user watch the churn live. The refresh() guard
        # self-throttles if an enumeration takes longer than this interval.
        self._timer = QTimer(self)
        self._timer.setInterval(300)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        header = QLabel(
            f"<span style='font-size:16px;font-weight:700;'>Threads</span>"
            f" &nbsp;<span style='color:#6E7681;'>PID {self._process.pid}</span>"
        )
        header.setTextFormat(Qt.RichText)
        layout.addWidget(header)

        self._count_label = QLabel("")
        self._count_label.setObjectName("hint")
        layout.addWidget(self._count_label)

        bar = QHBoxLayout()
        bar.setSpacing(8)

        bar.addStretch(1)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        bar.addWidget(close_btn)
        layout.addLayout(bar)

        self._model = QStandardItemModel(0, 4, self)
        self._model.setHorizontalHeaderLabels(
            ["TID", "State", "Priority", "Notes"]
        )

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )
        layout.addWidget(self._table, 1)

    def refresh(self) -> None:
        # Skip if an enumeration is in flight — the 300ms timer would otherwise
        # stack workers; this self-throttles to however long get_threads() takes.
        if self._worker is not None and self._worker.isRunning():
            return

        # Loading hint only before the first list; the periodic refresh updates
        # the count silently to avoid flicker.
        if not self._threads:
            self._count_label.setText("Enumerating threads…")

        worker = _ThreadsWorker(self._process, self)
        worker.threads_ready.connect(self._on_threads_ready)
        worker.threads_failed.connect(self._on_threads_failed)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def _on_threads_ready(self, threads) -> None:
        self._threads = list(threads)

        # Preserve selection + scroll across the rebuild (the list refreshes
        # every 300ms; losing them would make the table unusable).
        prior_tid = None
        selected_rows = self._table.selectionModel().selectedRows()
        if selected_rows:
            item = self._model.item(selected_rows[0].row(), 0)
            if item is not None:
                prior_tid = item.data(Qt.UserRole)
        scroll_value = self._table.verticalScrollBar().value()

        self._model.setRowCount(0)
        for info in self._threads:
            tid_item = NumericItem(str(info.tid))
            tid_item.setData(int(info.tid), Qt.UserRole)
            tid_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            state_item = QStandardItem(info.state if info.state is not None else "—")

            priority_text = "—" if info.priority is None else str(info.priority)
            priority_item = NumericItem(priority_text)
            if info.priority is not None:
                priority_item.setData(int(info.priority), Qt.UserRole)
            priority_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            notes_text = ""
            if info.start_address is not None:
                notes_text = f"start=0x{info.start_address:X}"
            notes_item = QStandardItem(notes_text)

            self._model.appendRow(
                [tid_item, state_item, priority_item, notes_item]
            )

        main = min((t.tid for t in self._threads), default=None)
        main_str = f" · main TID {main}" if main is not None else ""
        self._count_label.setText(
            f"{len(self._threads):,} thread(s){main_str}"
        )

        # Restore the user's selection + scroll so the periodic refresh doesn't
        # clear what they had highlighted or jump the table around.
        if prior_tid is not None:
            self._select_tid(prior_tid)
        self._table.verticalScrollBar().setValue(scroll_value)

    def _select_tid(self, tid: int) -> None:
        """Re-select the row whose TID matches (no scrolling)."""
        for row in range(self._model.rowCount()):
            if self._model.item(row, 0).data(Qt.UserRole) == tid:
                self._table.selectRow(row)
                return

    def _on_threads_failed(self, message: str) -> None:
        self._count_label.setText("Failed to enumerate threads.")
        QMessageBox.critical(
            self, "Threads", f"Failed to enumerate threads:\n\n{message}"
        )

    def _on_worker_finished(self) -> None:
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.deleteLater()

    def closeEvent(self, event):  # noqa: N802 — Qt naming
        self._timer.stop()
        if self._worker is not None and self._worker.isRunning():
            try:
                self._worker.threads_ready.disconnect()
                self._worker.threads_failed.disconnect()
                self._worker.finished.disconnect()
            except (RuntimeError, TypeError):
                pass
            self._worker.wait(1000)
        super().closeEvent(event)
