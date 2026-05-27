# -*- coding: utf-8 -*-
"""
The "Found Addresses" table.

Built on a Qt model/view so we can stream hundreds of thousands of results
into it without freezing the UI. The model keeps an internal address→row
index so the scan worker's chunked updates can patch existing rows in O(1).
"""
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QAction, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QMenu,
    QTableView,
    QWidget,
)

from .value_types import ValueTypeSpec


COL_ADDRESS = 0
COL_VALUE = 1
COL_PREVIOUS = 2


class ResultsModel(QAbstractTableModel):
    """Table of {address: (current_value, previous_value)} entries."""

    HEADERS = ("Address", "Value", "Previous")

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._addresses: List[int] = []
        self._values: List[Any] = []
        self._previous: List[Any] = []
        self._index: Dict[int, int] = {}
        self._spec: Optional[ValueTypeSpec] = None

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._addresses)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else 3

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole
    ):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return section + 1

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self._addresses):
            return None

        row = index.row()
        col = index.column()

        if role == Qt.DisplayRole:
            if col == COL_ADDRESS:
                return f"0x{self._addresses[row]:X}"
            if col == COL_VALUE:
                return self._format(self._values[row])
            if col == COL_PREVIOUS:
                return self._format(self._previous[row])
            return None

        if role == Qt.TextAlignmentRole:
            return int(Qt.AlignVCenter | Qt.AlignLeft)

        if role == Qt.ForegroundRole and col == COL_VALUE:
            if self._values[row] is None:
                return QColor(0xFF, 0x85, 0x85)  # unreadable / dead address
            if (
                self._previous[row] is not None
                and self._values[row] != self._previous[row]
            ):
                return QColor(0x66, 0xE0, 0xAA)  # changed value highlight
        return None

    def _format(self, value: Any) -> str:
        if value is None:
            return "—"
        if self._spec is not None:
            try:
                return self._spec.format(value)
            except Exception:
                return repr(value)
        return repr(value)

    def set_value_spec(self, spec: ValueTypeSpec) -> None:
        self._spec = spec
        if self._addresses:
            self.dataChanged.emit(
                self.index(0, COL_VALUE),
                self.index(len(self._addresses) - 1, COL_PREVIOUS),
            )

    def clear(self) -> None:
        self.beginResetModel()
        self._addresses.clear()
        self._values.clear()
        self._previous.clear()
        self._index.clear()
        self.endResetModel()

    def append_chunk(self, chunk: List[Tuple[int, Any]]) -> None:
        """Append newly-discovered addresses (used by FirstScanWorker)."""
        if not chunk:
            return
        first = len(self._addresses)
        self.beginInsertRows(QModelIndex(), first, first + len(chunk) - 1)
        for address, value in chunk:
            self._index[address] = len(self._addresses)
            self._addresses.append(address)
            self._values.append(value)
            self._previous.append(None)
        self.endInsertRows()

    def patch_values(self, chunk: List[Tuple[int, Any, bool]]) -> None:
        """
        Apply a chunk produced by RefineScanWorker. Each entry is
        ``(address, current_value, keep?)``. Rows where keep=False are removed.
        """
        if not chunk:
            return

        rows_to_drop: List[int] = []
        for address, current, keep in chunk:
            row = self._index.get(address)
            if row is None:
                continue
            if not keep:
                rows_to_drop.append(row)
                continue
            self._previous[row] = self._values[row]
            self._values[row] = current
            top_left = self.index(row, COL_VALUE)
            bottom_right = self.index(row, COL_PREVIOUS)
            self.dataChanged.emit(top_left, bottom_right)

        if rows_to_drop:
            self._drop_rows(sorted(set(rows_to_drop), reverse=True))

    def _drop_rows(self, rows: List[int]) -> None:
        for row in rows:
            if row < 0 or row >= len(self._addresses):
                continue
            self.beginRemoveRows(QModelIndex(), row, row)
            address = self._addresses.pop(row)
            self._values.pop(row)
            self._previous.pop(row)
            self._index.pop(address, None)
            self.endRemoveRows()
        # Rebuild the index after a batch of removals to keep it consistent.
        self._index = {addr: idx for idx, addr in enumerate(self._addresses)}

    def address_at(self, row: int) -> Optional[int]:
        if 0 <= row < len(self._addresses):
            return self._addresses[row]
        return None

    def value_at(self, row: int) -> Any:
        if 0 <= row < len(self._addresses):
            return self._values[row]
        return None

    def all_addresses(self) -> List[int]:
        return list(self._addresses)

    def count(self) -> int:
        return len(self._addresses)


class ResultsView(QTableView):
    """Pre-configured QTableView for the results model."""

    promote_to_cheat_table = Signal(list)  # list[int]
    # qulonglong: 64-bit address overflows Qt's default int (C++ signed 32-bit).
    open_in_hex_viewer = Signal("qulonglong")
    pointer_scan_for_address = Signal("qulonglong")  # target address

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSortingEnabled(False)  # streaming inserts → custom sorting is expensive
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(
            COL_ADDRESS, QHeaderView.ResizeToContents
        )
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    def _show_context_menu(self, pos) -> None:
        rows = sorted({idx.row() for idx in self.selectedIndexes()})
        if not rows:
            return
        model: ResultsModel = self.model()
        menu = QMenu(self)

        promote = QAction(
            f"Add {len(rows)} address(es) to cheat table",
            self,
        )
        promote.triggered.connect(
            lambda: self.promote_to_cheat_table.emit(
                [model.address_at(r) for r in rows if model.address_at(r) is not None]
            )
        )
        menu.addAction(promote)

        if len(rows) == 1:
            hex_action = QAction("Open in hex viewer…", self)
            hex_action.triggered.connect(
                lambda: self.open_in_hex_viewer.emit(model.address_at(rows[0]))
            )
            menu.addAction(hex_action)

            copy_action = QAction("Copy address", self)
            copy_action.triggered.connect(lambda: self._copy_address(rows[0]))
            menu.addAction(copy_action)

            menu.addSeparator()
            pointer_scan = QAction("Pointer scan for this address…", self)
            pointer_scan.triggered.connect(
                lambda: self.pointer_scan_for_address.emit(model.address_at(rows[0]))
            )
            menu.addAction(pointer_scan)

        menu.exec(self.viewport().mapToGlobal(pos))

    def _copy_address(self, row: int) -> None:
        from PySide6.QtGui import QGuiApplication

        model: ResultsModel = self.model()
        addr = model.address_at(row)
        if addr is None:
            return
        QGuiApplication.clipboard().setText(f"{addr:X}")
