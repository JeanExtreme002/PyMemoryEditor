# -*- coding: utf-8 -*-
"""
The "Found Addresses" table.

Built on a Qt model/view so we can stream hundreds of thousands of results
into it without freezing the UI. The model keeps an internal address→row
index so the scan worker's chunked updates can patch existing rows in O(1).
"""
from bisect import bisect_left
from itertools import compress
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QAction, QColor, QPainter, QPalette
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

# Above this many contiguous runs of dropped rows, `_drop_rows` resets the
# model instead of announcing each run (see its docstring).
_RESET_RUN_THRESHOLD = 256


def _contiguous_runs(rows: List[int]) -> List[Tuple[int, int]]:
    """Collapse ascending, unique row numbers into ``(first, last)`` runs.

    ``[1, 2, 3, 7, 9, 10]`` → ``[(1, 3), (7, 7), (9, 10)]``. Qt's row-change
    signals take a range, so announcing a run at a time instead of a row at a
    time is what keeps a large refine from flooding the view.
    """
    runs: List[Tuple[int, int]] = []
    if not rows:
        return runs
    start = prev = rows[0]
    for row in rows[1:]:
        if row == prev + 1:
            prev = row
            continue
        runs.append((start, prev))
        start = prev = row
    runs.append((start, prev))
    return runs


class ResultsModel(QAbstractTableModel):
    """Table of {address: (current_value, previous_value)} entries."""

    HEADERS = ("Address", "Value", "Previous")

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._addresses: List[int] = []
        self._values: List[Any] = []
        self._previous: List[Any] = []
        # address → the row it held when the index was last built (its "base"
        # row). Rows dropped since then are listed, ascending, in ``_removed``:
        # an address's current row is its base minus the dropped rows above it
        # (see ``_row_of``). Rebuilding the whole dict after every refine chunk
        # would make a refine quadratic in the result count.
        self._index: Dict[int, int] = {}
        self._removed: List[int] = []
        # Set when an address was appended twice: the base-row bookkeeping
        # assumes one row per address, so _drop_rows falls back to a rebuild.
        self._duplicates = False
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
        self._removed.clear()
        self._duplicates = False
        self.endResetModel()

    def _row_of(self, address: int) -> Optional[int]:
        """Current row of ``address``, or None if it isn't in the model."""
        base = self._index.get(address)
        if base is None or not self._removed:
            return base
        return base - bisect_left(self._removed, base)

    def _reindex(self) -> None:
        """Rebuild the address index from the lists (one O(n) pass)."""
        self._index = {addr: idx for idx, addr in enumerate(self._addresses)}
        self._removed = []
        self._duplicates = len(self._index) != len(self._addresses)

    def append_chunk(self, chunk: List[Tuple[int, Any]]) -> None:
        """Append newly-discovered addresses (used by FirstScanWorker)."""
        if not chunk:
            return
        if self._removed:
            # New rows get base rows past every old one only on a fresh index.
            self._reindex()
        first = len(self._addresses)
        self.beginInsertRows(QModelIndex(), first, first + len(chunk) - 1)
        for address, value in chunk:
            if address in self._index:
                self._duplicates = True
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
        rows_changed: List[int] = []
        for address, current, keep in chunk:
            row = self._row_of(address)
            if row is None:
                continue
            if not keep:
                rows_to_drop.append(row)
                continue
            self._previous[row] = self._values[row]
            self._values[row] = current
            rows_changed.append(row)

        # One dataChanged per contiguous run of patched rows rather than one
        # per row: the view repaints on every emit, and a refine chunk is a
        # few thousand rows, so per-row emits would turn each chunk into a
        # redraw storm.
        for first, last in _contiguous_runs(sorted(set(rows_changed))):
            self.dataChanged.emit(
                self.index(first, COL_VALUE), self.index(last, COL_PREVIOUS)
            )

        if rows_to_drop:
            self._drop_rows(sorted(set(rows_to_drop)))

    def _drop_rows(self, rows: List[int]) -> None:
        """Remove ``rows`` (ascending, unique) from the model.

        Removals are announced per contiguous run — one ``beginRemoveRows``/
        ``endRemoveRows`` pair for ``[first, last]`` — so a refine that drops
        a block of neighbours costs one signal, not one per row. Past
        ``_RESET_RUN_THRESHOLD`` runs (a refine that keeps a sparse scatter of
        a huge result set) the model is reset instead: one O(n) rebuild and
        one repaint, at the price of the view's selection. One pair plus a
        mid-list ``list.pop`` per row would be quadratic: a refine dropping
        900k of 1M rows would do 900k pops and fire 900k signals.
        """
        count = len(self._addresses)
        rows = [row for row in rows if 0 <= row < count]
        if not rows:
            return

        runs = _contiguous_runs(rows)
        # Base rows of the dropped addresses, recorded before the lists shift
        # (rows are ascending, so these come out ascending too).
        dropped_bases: List[int] = []
        if not self._duplicates:
            for row in rows:
                base = self._index.pop(self._addresses[row], None)
                if base is not None:
                    dropped_bases.append(base)

        if len(runs) > _RESET_RUN_THRESHOLD:
            # Compact only the window the dropped rows span: a refine walks the
            # rows in order, so that window is about one chunk wide, and the
            # rest of the list is shifted by a single memmove rather than
            # copied element by element.
            lo, hi = rows[0], rows[-1] + 1
            mask = bytearray(b"\x01") * (hi - lo)
            for row in rows:
                mask[row - lo] = 0
            self.beginResetModel()
            for column in (self._addresses, self._values, self._previous):
                column[lo:hi] = list(compress(column[lo:hi], mask))
            self._forget_dropped(dropped_bases)
            self.endResetModel()
            return

        # Highest run first so the row numbers announced for later runs are
        # still valid when the view receives them — removing [100, 110] does
        # not shift the rows of [10, 20], but the reverse would.
        for first, last in reversed(runs):
            self.beginRemoveRows(QModelIndex(), first, last)
            # Lists are trimmed per run so that, between endRemoveRows calls,
            # rowCount()/data() agree with what the view was told.
            del self._addresses[first:last + 1]
            del self._values[first:last + 1]
            del self._previous[first:last + 1]
            self.endRemoveRows()

        self._forget_dropped(dropped_bases)

    def _forget_dropped(self, dropped_bases: List[int]) -> None:
        """Fold a drop's base rows into the index bookkeeping.

        Merging two ascending lists is linear and runs in C, unlike rebuilding
        the whole dict; the dict itself is rebuilt only once more rows have
        been dropped than remain, so its cost is amortised over those drops.
        """
        if self._duplicates:
            self._reindex()
            return
        if dropped_bases:
            if not self._removed or dropped_bases[0] > self._removed[-1]:
                self._removed.extend(dropped_bases)
            else:
                self._removed = sorted(self._removed + dropped_bases)
        if len(self._removed) > len(self._addresses):
            self._reindex()

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

    def value_map(self) -> Dict[int, Any]:
        """
        Snapshot of {address: current_value}, used as the baseline for the
        Increased/Decreased/Changed/Unchanged "Next Scan" comparisons.
        """
        return {addr: self._values[i] for i, addr in enumerate(self._addresses)}

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
        self.horizontalHeader().setStretchLastSection(False)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)
        # Double-click promotes the row to the cheat table — the same quick
        # gesture the Memory Map / Modules / Pointer Scan tables already use.
        self.doubleClicked.connect(self._on_double_clicked)

    def _on_double_clicked(self, index) -> None:
        if not index.isValid():
            return
        model: ResultsModel = self.model()
        address = model.address_at(index.row())
        if address is not None:
            self.promote_to_cheat_table.emit([address])

    def keyPressEvent(self, event) -> None:
        # Enter/Return promotes the selected rows to the cheat table — the
        # keyboard equivalent of double-clicking or the context-menu action,
        # so the table is fully usable without the mouse.
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            model: ResultsModel = self.model()
            if model is not None:
                rows = sorted({idx.row() for idx in self.selectedIndexes()})
                addresses = [
                    model.address_at(r)
                    for r in rows
                    if model.address_at(r) is not None
                ]
                if addresses:
                    self.promote_to_cheat_table.emit(addresses)
                    return
        super().keyPressEvent(event)

    def setModel(self, model) -> None:
        super().setModel(model)
        # Per-section resize modes only stick once a model is attached (the
        # header rebuilds its sections on setModel and resets them otherwise).
        # Address hugs its fixed-width hex content; Value and Previous split the
        # remaining width evenly so neither — least of all the less-important
        # Previous column — swallows the whole row.
        header = self.horizontalHeader()
        # Floor every section's width so Address doesn't collapse to a few
        # characters for short addresses; ResizeToContents still grows it for
        # long 64-bit ones. Value/Previous are Stretch and always exceed this.
        header.setMinimumSectionSize(120)
        header.setSectionResizeMode(COL_ADDRESS, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(COL_VALUE, QHeaderView.Stretch)
        header.setSectionResizeMode(COL_PREVIOUS, QHeaderView.Stretch)

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        model = self.model()
        if model is not None and model.rowCount() > 0:
            return
        # Empty-state guidance painted over the viewport so the large blank
        # table reads as "ready and waiting" rather than broken.
        painter = QPainter(self.viewport())
        painter.setPen(self.palette().color(QPalette.PlaceholderText))
        painter.drawText(
            self.viewport().rect(),
            int(Qt.AlignCenter),
            "Found addresses will appear here.",
        )
        painter.end()

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
            # Looked up when the action fires, not when the menu opens: a
            # refine running in the background can drop the row while the
            # menu's nested event loop is up, and emitting None on a
            # qulonglong signal is a TypeError inside a Qt slot.
            hex_action = QAction("Open in hex viewer…", self)
            hex_action.triggered.connect(
                lambda: self._emit_for_row(self.open_in_hex_viewer, rows[0])
            )
            menu.addAction(hex_action)

            copy_action = QAction("Copy address", self)
            copy_action.triggered.connect(lambda: self._copy_address(rows[0]))
            menu.addAction(copy_action)

            menu.addSeparator()
            pointer_scan = QAction("Pointer scan for this address…", self)
            pointer_scan.triggered.connect(
                lambda: self._emit_for_row(self.pointer_scan_for_address, rows[0])
            )
            menu.addAction(pointer_scan)

        menu.exec(self.viewport().mapToGlobal(pos))

    def _emit_for_row(self, signal, row: int) -> None:
        """Emit ``signal`` with the address at ``row``, or nothing if it is gone."""
        model: ResultsModel = self.model()
        address = model.address_at(row) if model is not None else None
        if address is not None:
            signal.emit(address)

    def _copy_address(self, row: int) -> None:
        from PySide6.QtGui import QGuiApplication

        model: ResultsModel = self.model()
        addr = model.address_at(row)
        if addr is None:
            return
        QGuiApplication.clipboard().setText(f"{addr:X}")
