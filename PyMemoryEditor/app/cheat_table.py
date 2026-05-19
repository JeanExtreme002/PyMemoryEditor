# -*- coding: utf-8 -*-
"""
The "cheat table" — Cheat Engine's lower pane.

Holds rows the user has saved off (description, address, type, length, value,
plus a freeze checkbox). A :class:`QTimer` polls every frozen row at ~10 Hz,
re-writing its frozen value with ``process.write_process_memory`` so the
target can't change it back. Non-frozen rows are merely read on the same
tick so the displayed value stays fresh.
"""
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

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

from PyMemoryEditor.process import AbstractProcess

from .value_types import VALUE_TYPES, ValueTypeSpec, find_spec, parse_value


@dataclass
class CheatEntry:
    description: str
    address: int
    spec_label: str
    length: int
    frozen: bool = False
    frozen_value: Any = None
    # Last value we read from memory — only used to populate the table cell.
    last_value: Any = field(default=None, compare=False)

    @property
    def spec(self) -> ValueTypeSpec:
        spec = find_spec(self.spec_label)
        if spec is None:
            # Fallback — first entry in the catalogue is always the default 4-byte int.
            return VALUE_TYPES[0]
        return spec

    def to_dict(self) -> Dict:
        # Serialise byte values as hex so JSON stays human-readable.
        frozen = self.frozen_value
        if isinstance(frozen, (bytes, bytearray)):
            frozen = frozen.hex()
        return {
            "description": self.description,
            "address": f"0x{self.address:X}",
            "spec": self.spec_label,
            "length": self.length,
            "frozen": self.frozen,
            "frozen_value": frozen,
        }

    @classmethod
    def from_dict(cls, raw: Dict) -> "CheatEntry":
        spec_label = raw.get("spec") or raw.get("spec_label") or VALUE_TYPES[0].label
        spec = find_spec(spec_label) or VALUE_TYPES[0]
        addr_raw = raw["address"]
        if isinstance(addr_raw, str):
            address = int(addr_raw, 16)
        else:
            address = int(addr_raw)
        frozen = raw.get("frozen_value")
        if isinstance(frozen, str) and spec.pytype is bytes:
            try:
                frozen = bytes.fromhex(frozen)
            except ValueError:
                frozen = None
        return cls(
            description=str(raw.get("description") or ""),
            address=address,
            spec_label=spec.label,
            length=int(raw.get("length") or spec.length),
            frozen=bool(raw.get("frozen", False)),
            frozen_value=frozen,
        )


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

        # Re-read every entry's current value at 10 Hz so the user sees live
        # values, and re-write frozen entries on the same tick.
        self._tick = QTimer(self)
        self._tick.setInterval(100)
        self._tick.timeout.connect(self._tick_values)
        self._tick.start()

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

    def _tick_values(self) -> None:
        if not self._entries:
            return

        # Don't clobber the cell the user is currently typing into.
        editing_index = (
            self._table.currentIndex()
            if self._table.state() == QAbstractItemView.EditingState
            else None
        )
        editing_row = (
            editing_index.row()
            if editing_index is not None and editing_index.isValid()
            else -1
        )

        self._suspend_signals = True
        try:
            for row, entry in enumerate(self._entries):
                if row == editing_row:
                    continue

                try:
                    current = self._process.read_process_memory(
                        entry.address, entry.spec.pytype, entry.length
                    )
                except Exception:
                    current = None

                if entry.frozen and entry.frozen_value is not None:
                    try:
                        self._process.write_process_memory(
                            entry.address,
                            entry.spec.pytype,
                            entry.length,
                            entry.frozen_value,
                        )
                        current = entry.frozen_value
                    except Exception:
                        pass

                entry.last_value = current
                self._update_value_cell(row, entry)
        finally:
            self._suspend_signals = False

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

    addr_text = addr_text.strip()
    if addr_text.lower().startswith("0x"):
        addr_text = addr_text[2:]
    try:
        address = int(addr_text, 16)
    except ValueError:
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
