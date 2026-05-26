# -*- coding: utf-8 -*-
"""
Modules dialog — exposes ``process.get_modules()``.

Lists every module (the main executable plus each loaded shared library) the
target process has mapped, with its name, base address, size and backing path.
The toolbar lets the user:

* refresh the list,
* filter by name / path (a real process loads hundreds of modules),
* copy a module's base address,
* jump straight into the hex viewer at the module base.

The base address is the most useful field here: combined with a static offset
(``base + offset``) it survives ASLR, which is exactly what the Pointer Chain
tool consumes. Lives alongside the Memory Map and Threads dialogs — same shape,
same patterns (background worker, sortable table, Close button).
"""
from typing import List, Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QGuiApplication, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
)

from PyMemoryEditor import AbstractProcess, ModuleInfo

from ._widgets import NumericItem
from .memory_map_dialog import _format_size


class _ModulesWorker(QThread):
    """Background thread that runs ``process.get_modules()`` off the UI."""

    modules_ready = Signal(object)  # List[ModuleInfo]
    modules_failed = Signal(str)

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process

    def run(self) -> None:
        try:
            modules = list(self._process.get_modules())
        except Exception as exc:  # noqa: BLE001
            self.modules_failed.emit(str(exc))
            return
        self.modules_ready.emit(modules)


class ModulesDialog(QDialog):
    """Shows the output of ``get_modules()`` in a sortable, filterable table."""

    # qulonglong: 64-bit addresses overflow Qt's default (C++ signed 32-bit) int.
    open_hex_viewer = Signal("qulonglong", "qulonglong")  # (address, length)

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process
        self._modules: List[ModuleInfo] = []
        self._worker: Optional[_ModulesWorker] = None

        self.setWindowTitle(f"Modules — PID {process.pid}")
        self.resize(820, 560)

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        header = QLabel(
            f"<span style='font-size:16px;font-weight:700;'>Modules</span>"
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

        self._copy_btn = QPushButton("Copy Base Address")
        self._copy_btn.clicked.connect(self._copy_selected_address)
        bar.addWidget(self._copy_btn)

        self._hex_btn = QPushButton("Open in Hex Viewer")
        self._hex_btn.clicked.connect(self._emit_hex_viewer_request)
        bar.addWidget(self._hex_btn)

        bar.addStretch(1)

        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filter by name or path…")
        self._filter_edit.setClearButtonEnabled(True)
        self._filter_edit.setFixedWidth(220)
        self._filter_edit.textChanged.connect(self._apply_filter)
        bar.addWidget(self._filter_edit)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        bar.addWidget(close_btn)
        layout.addLayout(bar)

        # Column 4 (raw size) is hidden — it only exists so the Size column
        # sorts by the underlying byte count rather than the formatted label.
        self._model = QStandardItemModel(0, 5, self)
        self._model.setHorizontalHeaderLabels(
            ["Name", "Base Address", "Size", "Path", "Size (Bytes)"]
        )

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self._table.setColumnHidden(4, True)
        self._table.doubleClicked.connect(lambda _i: self._emit_hex_viewer_request())
        layout.addWidget(self._table, 1)

    def refresh(self) -> None:
        # Don't stack workers — if a refresh is in flight, ignore the click.
        if self._worker is not None and self._worker.isRunning():
            return

        self._count_label.setText("Enumerating modules…")
        self._set_busy(True)

        worker = _ModulesWorker(self._process, self)
        worker.modules_ready.connect(self._on_modules_ready)
        worker.modules_failed.connect(self._on_modules_failed)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def _set_busy(self, busy: bool) -> None:
        self._refresh_btn.setEnabled(not busy)
        self._copy_btn.setEnabled(not busy)
        self._hex_btn.setEnabled(not busy)

    def _on_modules_ready(self, modules) -> None:
        self._modules = list(modules)
        self._apply_filter()

    def _apply_filter(self) -> None:
        """Repopulate the table from the cached module list, honoring the filter."""
        needle = self._filter_edit.text().strip().lower()

        # Sorting is re-applied by the view; disable it while we rebuild so the
        # model isn't re-sorted on every appendRow (also avoids row shuffling).
        self._table.setSortingEnabled(False)
        self._model.setRowCount(0)

        shown = 0
        for module in self._modules:
            if needle and needle not in module.name.lower() and needle not in module.path.lower():
                continue
            shown += 1

            name_item = QStandardItem(module.name or "—")

            base = int(module.base_address)
            base_item = NumericItem(f"0x{base:016X}")
            base_item.setData(base, Qt.UserRole)

            size = int(module.size)
            size_item = NumericItem(_format_size(size))
            size_item.setData(size, Qt.UserRole)
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            path_item = QStandardItem(module.path or "")

            raw_size_item = NumericItem(str(size))
            raw_size_item.setData(size, Qt.UserRole)

            self._model.appendRow(
                [name_item, base_item, size_item, path_item, raw_size_item]
            )

        self._table.setSortingEnabled(True)

        total = len(self._modules)
        if needle:
            self._count_label.setText(f"{shown:,} of {total:,} module(s) shown")
        else:
            self._count_label.setText(f"{total:,} module(s)")

    def _on_modules_failed(self, message: str) -> None:
        self._count_label.setText("Failed to enumerate modules.")
        QMessageBox.critical(
            self, "Modules", f"Failed to enumerate modules:\n\n{message}"
        )

    def _on_worker_finished(self) -> None:
        self._set_busy(False)
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.deleteLater()

    def _selected_module(self) -> Optional[dict]:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        base = self._model.item(row, 1).data(Qt.UserRole)
        size = self._model.item(row, 2).data(Qt.UserRole)
        return {"base_address": int(base), "size": int(size)}

    def _copy_selected_address(self) -> None:
        module = self._selected_module()
        if module is None:
            QMessageBox.information(self, "Modules", "Select a module first.")
            return
        QGuiApplication.clipboard().setText(f"{module['base_address']:X}")

    def _emit_hex_viewer_request(self) -> None:
        module = self._selected_module()
        if module is None:
            QMessageBox.information(self, "Modules", "Select a module first.")
            return
        # Cap the initial view to keep the hex widget responsive on big modules.
        size = min(module["size"] or 4096, 4096)
        self.open_hex_viewer.emit(module["base_address"], size)

    def closeEvent(self, event):  # noqa: N802 — Qt naming
        # If the enumeration is still in flight, let it finish but unhook our
        # slots so a late emit doesn't touch a destroyed dialog.
        if self._worker is not None and self._worker.isRunning():
            try:
                self._worker.modules_ready.disconnect()
                self._worker.modules_failed.disconnect()
                self._worker.finished.disconnect()
            except (RuntimeError, TypeError):
                pass
            self._worker.wait(1000)
        super().closeEvent(event)
