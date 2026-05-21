# -*- coding: utf-8 -*-
"""
The "cheat table" — Cheat Engine's lower pane.

Holds rows the user has saved off (description, address, type, length, value,
plus a freeze checkbox). A background :class:`_CheatPollWorker` thread polls
every active entry at ~10 Hz, re-writing frozen values with
``process.write_process_memory`` so the target can't change them back.
Non-frozen rows are merely read on the same tick so the displayed value
stays fresh.

This module hosts only the Qt widget; the dataclass and the worker thread
live in ``cheat_entry.py`` and ``cheat_poll_worker.py`` respectively. The
``CheatEntry`` and ``_CheatPollWorker`` names are re-exported from here for
backward compatibility with code (and tests) that imported them from this
module before the split.
"""
import copy
import json
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from PyMemoryEditor import AbstractProcess

from ._widgets import parse_hex_address
from .cheat_entry import CheatEntry
from .cheat_poll_worker import TICK_INTERVAL_MS, _CheatPollWorker
from .value_types import VALUE_TYPES, ValueTypeSpec, find_spec, parse_value


# Re-exported for backward compatibility with callers that imported the
# poll-interval constant from this module before the split.
_TICK_INTERVAL_MS = TICK_INTERVAL_MS


class CheatTable(QWidget):
    """Bottom pane: saved addresses, freezing, manual edits."""

    COL_ACTIVE = 0
    COL_DESCRIPTION = 1
    COL_ADDRESS = 2
    COL_TYPE = 3
    COL_VALUE = 4

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process
        self._entries: List[CheatEntry] = []
        self._suspend_signals = False

        self._build_ui()

        # Spin up the background poller that owns the read/freeze syscalls so
        # the UI thread isn't blocked when the target is slow.
        self._poller = _CheatPollWorker(process, self)
        self._poller.values_ready.connect(self._on_values_ready)
        self._poller.start()

        # A short cadence to push fresh entry snapshots into the worker. This
        # is far cheaper than the previous QTimer that did real syscalls — it
        # only copies a small list of tuples.
        self._publish_timer = QTimer(self)
        self._publish_timer.setInterval(TICK_INTERVAL_MS)
        self._publish_timer.timeout.connect(self._publish_snapshot_to_worker)
        self._publish_timer.start()

    def closeEvent(self, event):  # noqa: N802 — Qt naming
        self._poller.stop()
        self._poller.wait(1000)
        super().closeEvent(event)

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Toolbar
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._add_btn = QPushButton("Add Address Manually…")
        self._add_btn.clicked.connect(self._on_add_manually)
        bar.addWidget(self._add_btn)

        self._remove_btn = QPushButton("Remove Selected")
        self._remove_btn.setObjectName("danger")
        self._remove_btn.clicked.connect(self._on_remove_selected)
        bar.addWidget(self._remove_btn)

        self._clear_btn = QPushButton("Clear Table")
        self._clear_btn.clicked.connect(self._on_clear)
        bar.addWidget(self._clear_btn)

        bar.addStretch(1)

        self._import_btn = QPushButton("Import…")
        self._import_btn.clicked.connect(self._on_import)
        bar.addWidget(self._import_btn)

        self._export_btn = QPushButton("Export…")
        self._export_btn.clicked.connect(self._on_export)
        bar.addWidget(self._export_btn)

        layout.addLayout(bar)

        # Table
        self._table = QTableWidget(0, 5, self)
        self._table.setHorizontalHeaderLabels(
            ["Active", "Description", "Address", "Type", "Value"]
        )
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(
            self.COL_ACTIVE, QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            self.COL_DESCRIPTION, QHeaderView.Stretch
        )
        self._table.horizontalHeader().setSectionResizeMode(
            self.COL_ADDRESS, QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            self.COL_TYPE, QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            self.COL_VALUE, QHeaderView.Stretch
        )
        self._table.cellChanged.connect(self._on_cell_changed)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self._table, 1)

    # ----------------------------------------------------------- API

    def add_entry(self, entry: CheatEntry) -> None:
        # If the address already exists, just refresh its description/type.
        for existing in self._entries:
            if existing.address == entry.address:
                existing.description = entry.description or existing.description
                existing.spec_label = entry.spec_label
                existing.length = entry.length
                self._rebuild()
                return

        self._entries.append(entry)
        self._rebuild()

    def add_addresses(
        self,
        addresses: List[int],
        spec: ValueTypeSpec,
        length: int,
        description: str = "",
    ) -> None:
        """Convenience used by the scanner panel to bulk-promote rows."""
        for addr in addresses:
            self.add_entry(
                CheatEntry(
                    description=description,
                    address=int(addr),
                    spec_label=spec.label,
                    length=int(length),
                )
            )

    def entries(self) -> List[CheatEntry]:
        return list(self._entries)

    # ----------------------------------------------------------- table sync

    def _rebuild(self) -> None:
        self._suspend_signals = True
        try:
            self._table.setRowCount(len(self._entries))
            for row, entry in enumerate(self._entries):
                self._write_row(row, entry)
        finally:
            self._suspend_signals = False

    def _write_row(self, row: int, entry: CheatEntry) -> None:
        """Populate every cell of a row from scratch — used by _rebuild only."""
        check = QTableWidgetItem()
        check.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        check.setCheckState(Qt.Checked if entry.frozen else Qt.Unchecked)
        check.setTextAlignment(Qt.AlignCenter)
        check.setToolTip("Toggle to freeze the value — Cheat Engine style.")
        self._table.setItem(row, self.COL_ACTIVE, check)

        desc = QTableWidgetItem(entry.description)
        self._table.setItem(row, self.COL_DESCRIPTION, desc)

        addr = QTableWidgetItem(f"0x{entry.address:X}")
        addr.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        addr.setTextAlignment(Qt.AlignVCenter | Qt.AlignRight)
        self._table.setItem(row, self.COL_ADDRESS, addr)

        type_label = entry.spec_label
        if entry.spec.accepts_length_override:
            type_label += f"  · {entry.length}B"
        type_item = QTableWidgetItem(type_label)
        type_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        self._table.setItem(row, self.COL_TYPE, type_item)

        value_item = QTableWidgetItem(self._value_text_for(entry))
        value_item.setToolTip("Double-click to write a new value into the process.")
        self._table.setItem(row, self.COL_VALUE, value_item)

    def _value_text_for(self, entry: CheatEntry) -> str:
        if entry.frozen and entry.frozen_value is not None:
            return entry.spec.format(entry.frozen_value)
        if entry.last_value is None:
            return ""
        return entry.spec.format(entry.last_value)

    def _update_value_cell(self, row: int, entry: CheatEntry) -> None:
        """Update only the value cell of an existing row, allocating nothing new."""
        item = self._table.item(row, self.COL_VALUE)
        if item is None:
            # Row hasn't been built yet — fall back to a full rebuild for this row.
            self._write_row(row, entry)
            return
        new_text = self._value_text_for(entry)
        if item.text() != new_text:
            item.setText(new_text)

    def _on_cell_changed(self, row: int, column: int) -> None:
        if self._suspend_signals or row >= len(self._entries):
            return

        entry = self._entries[row]
        item = self._table.item(row, column)

        if column == self.COL_ACTIVE:
            entry.frozen = item.checkState() == Qt.Checked
            if entry.frozen and entry.frozen_value is None:
                entry.frozen_value = entry.last_value
            return

        if column == self.COL_DESCRIPTION:
            entry.description = item.text()
            return

        if column == self.COL_VALUE:
            text = item.text().strip()
            if not text:
                # Treat empty as "unfreeze and clear" — no-op.
                return
            try:
                value, _length = parse_value(entry.spec, text, entry.length)
            except ValueError as exc:
                QMessageBox.warning(self, "Invalid Value", str(exc))
                self._suspend_signals = True
                item.setText(
                    entry.spec.format(entry.last_value)
                    if entry.last_value is not None
                    else ""
                )
                self._suspend_signals = False
                return

            try:
                self._process.write_process_memory(
                    entry.address, entry.spec.pytype, entry.length, value
                )
            except Exception as exc:  # noqa: BLE001
                QMessageBox.critical(
                    self, "Write Failed", f"{type(exc).__name__}: {exc}"
                )
                return

            entry.last_value = value
            if entry.frozen:
                entry.frozen_value = value

    # ----------------------------------------------------------- ticking

    def _publish_snapshot_to_worker(self) -> None:
        """Hand the worker a fresh immutable snapshot of every entry."""
        snapshot = [
            (
                entry.address,
                entry.spec.pytype,
                entry.length,
                copy.copy(entry.frozen_value),
                bool(entry.frozen),
            )
            for entry in self._entries
        ]
        self._poller.update_snapshot(snapshot)

    def _on_values_ready(self, results) -> None:
        """Apply worker-produced values to the UI table (UI thread).

        Entries are matched by (address, pytype, length) instead of row index
        because rows can be reordered or deleted between the worker's snapshot
        and this signal being delivered.
        """
        if not results:
            return

        editing_row = self._editing_row()

        # Index entries by their identity tuple to apply values in O(N+M).
        entries_by_key: Dict[Tuple[int, type, int], int] = {}
        for row, entry in enumerate(self._entries):
            entries_by_key[(entry.address, entry.spec.pytype, entry.length)] = row

        self._suspend_signals = True
        try:
            for address, pytype, length, value in results:
                row = entries_by_key.get((address, pytype, length))
                if row is None:
                    # Entry was deleted (or its spec/length changed) between
                    # snapshot and signal — skip silently.
                    continue
                if row == editing_row:
                    # Don't clobber whatever the user is typing.
                    continue
                entry = self._entries[row]
                entry.last_value = value
                self._update_value_cell(row, entry)
        finally:
            self._suspend_signals = False

    def _editing_row(self) -> int:
        """Return the row currently being edited, or -1 if none."""
        if self._table.state() != QAbstractItemView.EditingState:
            return -1
        index = self._table.currentIndex()
        return index.row() if index.isValid() else -1

    # ----------------------------------------------------------- toolbar

    def _on_add_manually(self) -> None:
        entry = prompt_for_manual_entry(self)
        if entry is not None:
            self.add_entry(entry)

    def _on_remove_selected(self) -> None:
        rows = sorted(
            {idx.row() for idx in self._table.selectedIndexes()}, reverse=True
        )
        if not rows:
            return
        for row in rows:
            if 0 <= row < len(self._entries):
                self._entries.pop(row)
        self._rebuild()

    def _on_clear(self) -> None:
        if not self._entries:
            return
        if (
            QMessageBox.question(
                self, "Clear cheat table", "Remove every saved address?"
            )
            != QMessageBox.Yes
        ):
            return
        self._entries.clear()
        self._rebuild()

    def _show_context_menu(self, pos) -> None:
        row = self._table.rowAt(pos.y())
        if row < 0 or row >= len(self._entries):
            return
        menu = QMenu(self)
        copy_addr = QAction("Copy address", self)
        copy_addr.triggered.connect(lambda: self._copy_address(row))
        menu.addAction(copy_addr)

        change_type = QAction("Change value type…", self)
        change_type.triggered.connect(lambda: self._change_type(row))
        menu.addAction(change_type)

        change_len = QAction("Change buffer length…", self)
        change_len.triggered.connect(lambda: self._change_length(row))
        menu.addAction(change_len)

        menu.addSeparator()

        remove = QAction("Remove", self)
        remove.triggered.connect(self._on_remove_selected)
        menu.addAction(remove)

        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _copy_address(self, row: int) -> None:
        from PySide6.QtGui import QGuiApplication

        QGuiApplication.clipboard().setText(f"{self._entries[row].address:X}")

    def _change_type(self, row: int) -> None:
        labels = [s.label for s in VALUE_TYPES]
        current = (
            labels.index(self._entries[row].spec_label)
            if self._entries[row].spec_label in labels
            else 0
        )
        chosen, ok = QInputDialog.getItem(
            self, "Value type", "Pick a type:", labels, current, False
        )
        if not ok:
            return
        self._entries[row].spec_label = chosen
        spec = find_spec(chosen) or VALUE_TYPES[0]
        if not spec.accepts_length_override:
            self._entries[row].length = spec.length
        self._rebuild()

    def _change_length(self, row: int) -> None:
        new, ok = QInputDialog.getInt(
            self,
            "Buffer length",
            "Length (bytes):",
            value=self._entries[row].length,
            minValue=1,
            maxValue=1024,
        )
        if not ok:
            return
        self._entries[row].length = int(new)
        self._rebuild()

    # ----------------------------------------------------------- import / export

    def _on_export(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export cheat table",
            "cheat_table.json",
            "JSON files (*.json);;All files (*)",
        )
        if not filename:
            return
        payload = {"entries": [entry.to_dict() for entry in self._entries]}
        with open(filename, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def _on_import(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Import cheat table",
            "",
            "JSON files (*.json);;All files (*)",
        )
        if not filename:
            return
        try:
            with open(filename, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            QMessageBox.critical(self, "Import", f"Could not read file:\n\n{exc}")
            return

        raw_entries = payload.get("entries") if isinstance(payload, dict) else payload
        if not isinstance(raw_entries, list):
            QMessageBox.warning(self, "Import", "Expected a JSON list of entries.")
            return

        for raw in raw_entries:
            try:
                self.add_entry(CheatEntry.from_dict(raw))
            except (KeyError, ValueError) as exc:
                # Surface but don't abort the whole import on one bad row.
                QMessageBox.warning(self, "Import", f"Skipped a bad entry: {exc}")


# --------------------------------------------------------------------------- manual-add helper


def prompt_for_manual_entry(parent) -> Optional[CheatEntry]:
    """Sequential QInputDialog flow for the "Add Address Manually" button."""
    description, ok = QInputDialog.getText(
        parent, "Add address", "Description (optional):"
    )
    if not ok:
        return None

    addr_text, ok = QInputDialog.getText(
        parent, "Add address", "Address (hex, e.g. 7FFE...):"
    )
    if not ok or not addr_text.strip():
        return None

    address = parse_hex_address(addr_text)
    if address is None:
        QMessageBox.warning(parent, "Add address", "Invalid hex address.")
        return None

    labels = [s.label for s in VALUE_TYPES]
    spec_label, ok = QInputDialog.getItem(
        parent, "Add address", "Value type:", labels, 0, False
    )
    if not ok:
        return None
    spec = find_spec(spec_label) or VALUE_TYPES[0]

    length = spec.length
    if spec.accepts_length_override:
        length, ok = QInputDialog.getInt(
            parent,
            "Add address",
            "Buffer length (bytes):",
            value=spec.length,
            minValue=1,
            maxValue=1024,
        )
        if not ok:
            return None

    return CheatEntry(
        description=description,
        address=address,
        spec_label=spec.label,
        length=int(length),
    )


__all__ = (
    "CheatEntry",
    "CheatTable",
    "_CheatPollWorker",
    "prompt_for_manual_entry",
)
