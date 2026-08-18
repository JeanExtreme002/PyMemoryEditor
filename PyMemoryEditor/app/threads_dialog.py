# -*- coding: utf-8 -*-
"""
Threads dialog — exposes ``process.get_threads()``.

Shows every thread the target process currently has, in a sortable table,
with optional auto-refresh. The intent mirrors Cheat Engine's "Process →
Threads" window: you don't typically *act* on threads directly, but seeing
them is useful for introspection (how many workers does this game have?
is the main thread alive?). The auto-refresh polls every 300 ms so you can
watch threads come and go.

Lives alongside the Memory Map and Modules dialogs — same shape, same patterns
(shared ``AutoRefreshTableDialog`` base: background worker + auto-refresh timer,
sortable table, Close button).
"""
from typing import List

from PySide6.QtCore import Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
)

from PyMemoryEditor import AbstractProcess, ThreadInfo

from ._auto_refresh_dialog import AutoRefreshTableDialog
from ._widgets import NumericItem


class ThreadsDialog(AutoRefreshTableDialog):
    """Lists the output of ``get_threads()`` in a sortable table."""

    def __init__(self, process: AbstractProcess, parent=None):
        # Auto-refresh at a brisk 300ms — threads spawn and exit often, so a
        # quick cadence lets the user watch the churn live. The refresh() guard
        # self-throttles if an enumeration takes longer than the interval.
        super().__init__(process, refresh_interval_ms=300, parent=parent)
        self._threads: List[ThreadInfo] = []
        self._empty_streak = 0  # see _fetch_data; worker thread only

        self.setWindowTitle(f"Threads — PID {process.pid}")
        self.resize(640, 520)

        self._build_ui()
        self.refresh()
        self._start_auto_refresh()

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

    def _set_loading_hint(self) -> None:
        self._count_label.setText("Enumerating threads…")

    def _fetch_data(self):
        threads = list(self._process.get_threads())
        # A live process always has a thread, but `get_threads` reports an
        # exited one as an empty list on Linux/Windows (only macOS raises) —
        # so the window would sit at "0 thread(s)" forever while Memory Map and
        # Modules say the process is gone. Two in a row before saying so: an
        # empty snapshot is legal-but-rare on a live process, and the first
        # fetch is reported the moment it fails.
        if not threads:
            self._empty_streak += 1
            if self._empty_streak >= 2:
                raise RuntimeError(
                    "The process reported no threads — it has most likely exited."
                )
            return threads
        self._empty_streak = 0
        return threads

    def _on_data_ready(self, threads) -> None:
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
            item = self._model.item(row, 0)
            if item is not None and item.data(Qt.UserRole) == tid:
                self._table.selectRow(row)
                return

    def _on_data_failed(self, message: str) -> None:
        self._count_label.setText("Failed to enumerate threads.")
        QMessageBox.critical(
            self, "Threads", f"Failed to enumerate threads:\n\n{message}"
        )

    def _on_polling_stopped(self) -> None:
        self._count_label.setText(
            "Failed to enumerate threads — auto-refresh stopped. "
            "Close and reopen this window to retry."
        )
