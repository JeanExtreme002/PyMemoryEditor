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

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QGuiApplication, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
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

from ._auto_refresh_dialog import AutoRefreshTableDialog
from ._widgets import MONOSPACE_FAMILY, NumericItem
from .memory_map_dialog import _format_size


class ModulesDialog(AutoRefreshTableDialog):
    """Shows the output of ``get_modules()`` in a sortable, filterable table."""

    # qulonglong: 64-bit addresses overflow Qt's default (C++ signed 32-bit) int.
    open_hex_viewer = Signal("qulonglong", "qulonglong")  # (address, length)
    resolve_pointer_chain = Signal("qulonglong")  # module base address

    def __init__(self, process: AbstractProcess, parent=None):
        # Auto-refresh so modules loaded/unloaded at runtime appear without a
        # manual refresh; the refresh() guard self-throttles on a slow target.
        super().__init__(process, refresh_interval_ms=1000, parent=parent)
        self._modules: List[ModuleInfo] = []

        self.setWindowTitle(f"Modules — PID {process.pid}")
        self.resize(820, 560)

        self._build_ui()
        self.refresh()
        self._start_auto_refresh()

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

    def _set_loading_hint(self) -> None:
        self._count_label.setText("Enumerating modules…")

    def _fetch_data(self):
        return list(self._process.get_modules())

    def _on_data_ready(self, modules) -> None:
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

        mono_font = QFont(MONOSPACE_FAMILY, 10)

        shown = 0
        for module in self._modules:
            if needle and needle not in module.name.lower() and needle not in module.path.lower():
                continue
            shown += 1

            name_item = QStandardItem(module.name or "—")

            base = int(module.base_address)
            base_item = NumericItem(f"0x{base:016X}")
            base_item.setFont(mono_font)
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
            count_text = f"{shown:,} of {total:,} module(s) shown"
        else:
            count_text = f"{total:,} module(s)"
        # A filter keystroke rebuilds this line long after the poll gave up —
        # without the suffix the stale table would look live again.
        if self._polling_gave_up:
            count_text += " · auto-refresh stopped"
        self._count_label.setText(count_text)

        # Restore the user's selection + scroll, so the periodic refresh doesn't
        # clear what they had highlighted or jump the table around.
        if prior_selection is not None:
            self._select_address(prior_selection)
        self._table.verticalScrollBar().setValue(scroll_value)

    def _select_address(self, address: int) -> None:
        """Re-select the row whose base address matches (no scrolling)."""
        for row in range(self._model.rowCount()):
            item = self._model.item(row, 1)
            if item is not None and item.data(Qt.UserRole) == address:
                self._table.selectRow(row)
                return

    def _on_data_failed(self, message: str) -> None:
        self._count_label.setText("Failed to enumerate modules.")
        QMessageBox.critical(
            self, "Modules", f"Failed to enumerate modules:\n\n{message}"
        )

    def _on_polling_stopped(self) -> None:
        self._count_label.setText(
            "Failed to enumerate modules — auto-refresh stopped. "
            "Close and reopen this window to retry."
        )

    def _selected_module(self) -> Optional[dict]:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        base_item = self._model.item(row, 1)
        size_item = self._model.item(row, 2)
        if base_item is None or size_item is None:
            return None
        base = base_item.data(Qt.UserRole)
        size = size_item.data(Qt.UserRole)
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

        menu.addSeparator()
        resolve_chain = menu.addAction("Resolve pointer chain from base…")
        resolve_chain.setToolTip(
            "Open the Pointer Chain tool with this module's base address filled "
            "in — then add the module offset and the chain offsets."
        )
        resolve_chain.triggered.connect(
            lambda: self.resolve_pointer_chain.emit(address)
        )
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
