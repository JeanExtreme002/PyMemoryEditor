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
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
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

        # Auto-refresh timer; off by default. The interval is matched to the
        # main window's heartbeat so the user only sees consistent data even
        # if both fire on the same tick.
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)

        self.refresh()

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

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self.refresh)
        bar.addWidget(self._refresh_btn)

        bar.addStretch(1)

        self._auto_check = QCheckBox("Auto-refresh")
        self._auto_check.setToolTip(
            "Poll get_threads() at the interval below. Threads die and "
            "spawn often — leaving this on lets you watch the churn."
        )
        self._auto_check.toggled.connect(self._toggle_auto_refresh)
        bar.addWidget(self._auto_check)

        bar.addWidget(QLabel("ms:"))
        self._interval_spin = QSpinBox()
        self._interval_spin.setRange(200, 10000)
        self._interval_spin.setSingleStep(100)
        self._interval_spin.setValue(1000)
        self._interval_spin.valueChanged.connect(self._sync_timer)
        bar.addWidget(self._interval_spin)

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
        if self._worker is not None and self._worker.isRunning():
            return

        self._set_busy(True)
        self._count_label.setText("Enumerating threads…")

        worker = _ThreadsWorker(self._process, self)
        worker.threads_ready.connect(self._on_threads_ready)
        worker.threads_failed.connect(self._on_threads_failed)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def _set_busy(self, busy: bool) -> None:
        self._refresh_btn.setEnabled(not busy)

    def _on_threads_ready(self, threads) -> None:
        self._threads = list(threads)
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

    def _on_threads_failed(self, message: str) -> None:
        self._count_label.setText("Failed to enumerate threads.")
        QMessageBox.critical(
            self, "Threads", f"Failed to enumerate threads:\n\n{message}"
        )

    def _on_worker_finished(self) -> None:
        self._set_busy(False)
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.deleteLater()

    def _toggle_auto_refresh(self, on: bool) -> None:
        if on:
            self._sync_timer()
        else:
            self._timer.stop()

    def _sync_timer(self) -> None:
        self._timer.setInterval(int(self._interval_spin.value()))
        if self._auto_check.isChecked() and not self._timer.isActive():
            self._timer.start()

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
