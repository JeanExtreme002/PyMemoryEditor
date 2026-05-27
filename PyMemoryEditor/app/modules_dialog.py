# -*- coding: utf-8 -*-
"""
Modules dialog — exposes ``process.get_modules()``.

Lists every module (the main executable plus each loaded shared library) the
target process has mapped, with its name, base address, size and backing path.
The dialog lets the user:

* filter by name / path (a real process loads hundreds of modules),
* right-click a module to copy its name, base address or path,
* jump straight into the hex viewer at the module base.

The list auto-refreshes every 1000 ms, so modules loaded/unloaded at runtime
appear without a manual refresh.

The base address is the most useful field here: combined with a static offset
(``base + offset``) it survives ASLR, which is exactly what the Pointer Chain
tool consumes. Lives alongside the Memory Map and Threads dialogs — same shape,
same patterns (background worker, sortable table, Close button).
"""
from typing import List, Optional

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QGuiApplication, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
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

        # Auto-refresh so modules loaded/unloaded at runtime appear without a
        # manual refresh. The refresh() guard self-throttles if an enumeration
        # takes longer than this interval.
        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(1000)
        self._auto_timer.timeout.connect(self.refresh)
        self._auto_timer.start()

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
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self._table, 1)

    def refresh(self) -> None:
        # Skip if an enumeration is already in flight — the 1000ms auto-refresh
        # timer would otherwise stack workers. This self-throttles to however
        # long get_modules() actually takes.
        if self._worker is not None and self._worker.isRunning():
            return

        # Loading hint only before the first list; on the periodic refresh the
        # count updates silently to avoid flicker.
        if not self._modules:
            self._count_label.setText("Enumerating modules…")

        worker = _ModulesWorker(self._process, self)
        worker.modules_ready.connect(self._on_modules_ready)
        worker.modules_failed.connect(self._on_modules_failed)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def _on_modules_ready(self, modules) -> None:
        self._modules = list(modules)
        self._apply_filter()

    def _apply_filter(self) -> None:
        """Repopulate the table from the cached module list, honoring the filter."""
        needle = self._filter_edit.text().strip().lower()

        # Preserve selection + scroll across the rebuild (the list auto-refreshes
        # every 1000ms; losing them would make the table unusable).
        prior_selection = None
        selected_rows = self._table.selectionModel().selectedRows()
        if selected_rows:
            item = self._model.item(selected_rows[0].row(), 1)
            if item is not None:
                prior_selection = item.data(Qt.UserRole)
        scroll_value = self._table.verticalScrollBar().value()

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

        # Restore the user's selection + scroll, so the periodic refresh doesn't
        # clear what they had highlighted or jump the table around.
        if prior_selection is not None:
            self._select_address(prior_selection)
        self._table.verticalScrollBar().setValue(scroll_value)

    def _select_address(self, address: int) -> None:
        """Re-select the row whose base address matches (no scrolling)."""
        for row in range(self._model.rowCount()):
            if self._model.item(row, 1).data(Qt.UserRole) == address:
                self._table.selectRow(row)
                return

    def _on_modules_failed(self, message: str) -> None:
        self._count_label.setText("Failed to enumerate modules.")
        QMessageBox.critical(
            self, "Modules", f"Failed to enumerate modules:\n\n{message}"
        )

    def _on_worker_finished(self) -> None:
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

    def _show_context_menu(self, pos) -> None:
        """Right-click menu on a module row: copy its name, address or path."""
        index = self._table.indexAt(pos)
        if not index.isValid():
            return
        self._table.selectRow(index.row())  # operate on the clicked row
        menu = self._build_context_menu(index.row())
        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _build_context_menu(self, row: int) -> QMenu:
        """Build the row's right-click menu (Copy Name / Address / Path).

        Each action copies via ``triggered`` so the behavior is identical
        whether the menu is shown or driven programmatically.
        """
        name = self._model.item(row, 0).text()
        address = int(self._model.item(row, 1).data(Qt.UserRole))
        path = self._model.item(row, 3).text()

        menu = QMenu(self)

        copy_name = menu.addAction("Copy Name")
        copy_name.setEnabled(bool(name) and name != "—")
        copy_name.triggered.connect(lambda: self._copy_text(name))

        copy_address = menu.addAction("Copy Address")
        copy_address.triggered.connect(lambda: self._copy_text(f"{address:X}"))

        copy_path = menu.addAction("Copy Path")
        # Modules usually have a path; keep the entry visible but disabled when
        # the backend couldn't resolve one.
        copy_path.setEnabled(bool(path))
        copy_path.triggered.connect(lambda: self._copy_text(path))
        return menu

    def _copy_text(self, text: str) -> None:
        QGuiApplication.clipboard().setText(text)

    def _emit_hex_viewer_request(self) -> None:
        module = self._selected_module()
        if module is None:
            QMessageBox.information(self, "Modules", "Select a module first.")
            return
        # Cap the initial view to keep the hex widget responsive on big modules.
        size = min(module["size"] or 4096, 4096)
        self.open_hex_viewer.emit(module["base_address"], size)

    def closeEvent(self, event):  # noqa: N802 — Qt naming
        self._auto_timer.stop()
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
