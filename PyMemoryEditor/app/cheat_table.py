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
import logging
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
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

# Child of "PyMemoryEditor" — the Log Console captures these via propagation.
_LOG = logging.getLogger(__name__)


class CheatTable(QWidget):
    """Bottom pane: saved addresses, freezing, manual edits."""

    # qulonglong: 64-bit addresses overflow Qt's signed-32-bit default.
    pointer_scan_for_address = Signal("qulonglong")  # target address

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

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        # Small top inset so the toolbar buttons don't sit flush against the
        # vertical splitter handle above.
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(8)

        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._add_btn = QPushButton("Add Address Manually…")
        self._add_btn.clicked.connect(self._on_add_manually)
        bar.addWidget(self._add_btn)

        self._edit_btn = QPushButton("Edit Selected…")
        self._edit_btn.clicked.connect(self._on_edit_selected)
        bar.addWidget(self._edit_btn)

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
        check.setToolTip("Toggle to freeze the value.")
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
                _LOG.warning(
                    "Cheat-table write failed at 0x%X (%s, %dB): %s: %s",
                    entry.address,
                    entry.spec.pytype.__name__,
                    entry.length,
                    type(exc).__name__,
                    exc,
                )
                return

            entry.last_value = value
            if entry.frozen:
                entry.frozen_value = value

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
                matched_row = entries_by_key.get((address, pytype, length))
                if matched_row is None:
                    # Entry was deleted (or its spec/length changed) between
                    # snapshot and signal — skip silently.
                    continue
                row = matched_row
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

    def _on_add_manually(self) -> None:
        entry = prompt_for_manual_entry(self)
        if entry is not None:
            self.add_entry(entry)

    def _selected_rows(self) -> List[int]:
        """Return unique selected row indices in ascending order."""
        return sorted({idx.row() for idx in self._table.selectedIndexes()})

    def _active_rows(self) -> List[int]:
        """Return row indices whose Active (freeze) checkbox is checked."""
        return [i for i, entry in enumerate(self._entries) if entry.frozen]

    def _target_rows(self) -> List[int]:
        """Rows that bulk operations should act on.

        Union of "selected by mouse" and "Active checkbox checked" — the
        latter is the natural way to flag a row for a bulk edit in this UI,
        because drag-selecting rows doesn't toggle Active for you. Falling
        back to the mouse selection alone keeps the workflow that doesn't
        involve freezing anything working too.
        """
        return sorted(set(self._selected_rows()) | set(self._active_rows()))

    def _on_remove_selected(self) -> None:
        rows = sorted(self._selected_rows(), reverse=True)
        if not rows:
            return
        for row in rows:
            if 0 <= row < len(self._entries):
                self._entries.pop(row)
        self._rebuild()

    def _on_edit_selected(self) -> None:
        """Bulk-edit description / type / value across every targeted row.

        "Targeted" = rows the user highlighted with the mouse, plus any rows
        whose Active checkbox is on — so flipping Active is a valid way to
        opt rows into the bulk operation without having to drag-select them.
        """
        rows = [r for r in self._target_rows() if 0 <= r < len(self._entries)]
        if not rows:
            QMessageBox.information(
                self,
                "Edit selected",
                "Select rows in the cheat table (or tick their Active "
                "checkbox) before using Edit Selected.",
            )
            return

        entries = [self._entries[r] for r in rows]
        dialog = _BulkEditDialog(entries, self)
        if dialog.exec() != QDialog.Accepted:
            return

        plan = dialog.result_plan()
        if plan is None:
            return

        failures: List[Tuple[int, str]] = []
        self._suspend_signals = True
        try:
            for entry in entries:
                if plan.description is not None:
                    entry.description = plan.description

                if plan.spec is not None:
                    entry.spec_label = plan.spec.label
                    if not plan.spec.accepts_length_override:
                        entry.length = plan.spec.length

                if plan.value_text is not None:
                    spec = entry.spec
                    try:
                        value, effective_length = parse_value(
                            spec, plan.value_text, entry.length
                        )
                    except ValueError as exc:
                        failures.append((entry.address, str(exc)))
                        continue

                    if spec.accepts_length_override:
                        entry.length = effective_length

                    try:
                        self._process.write_process_memory(
                            entry.address, spec.pytype, entry.length, value
                        )
                    except Exception as exc:  # noqa: BLE001
                        failures.append(
                            (entry.address, f"{type(exc).__name__}: {exc}")
                        )
                        continue

                    entry.last_value = value
                    if entry.frozen:
                        entry.frozen_value = value
        finally:
            self._suspend_signals = False

        self._rebuild()

        if failures:
            preview = "\n".join(
                f"0x{addr:X}: {msg}" for addr, msg in failures[:10]
            )
            extra = "" if len(failures) <= 10 else f"\n…and {len(failures) - 10} more."
            QMessageBox.warning(
                self,
                "Edit selected",
                f"{len(failures)} of {len(rows)} row(s) failed:\n\n{preview}{extra}",
            )

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

        selected = self._selected_rows()
        multi = len(selected) > 1

        if multi:
            # Drag-selected several rows — the single-row actions don't make
            # sense here, so show only the two bulk actions.
            edit_selected = QAction(f"Edit selected ({len(selected)})…", self)
            edit_selected.triggered.connect(self._on_edit_selected)
            menu.addAction(edit_selected)

            menu.addSeparator()

            remove = QAction("Remove", self)
            remove.triggered.connect(self._on_remove_selected)
            menu.addAction(remove)
        else:
            copy_addr = QAction("Copy address", self)
            copy_addr.triggered.connect(lambda: self._copy_address(row))
            menu.addAction(copy_addr)

            pointer_scan = QAction("Pointer scan for this address…", self)
            pointer_scan.triggered.connect(
                lambda: self.pointer_scan_for_address.emit(self._entries[row].address)
            )
            menu.addAction(pointer_scan)

            change_type = QAction("Change value type…", self)
            change_type.triggered.connect(lambda: self._change_type(row))
            menu.addAction(change_type)

            change_len = QAction("Change buffer length…", self)
            change_len.triggered.connect(lambda: self._change_length(row))
            menu.addAction(change_len)

            # Active-checked rows still count as "selected" for the bulk edit,
            # so surface the action with the right count when applicable.
            targets = self._target_rows()
            edit_label = (
                f"Edit selected ({len(targets)})…"
                if len(targets) > 1
                else "Edit selected…"
            )
            edit_selected = QAction(edit_label, self)
            edit_selected.triggered.connect(self._on_edit_selected)
            menu.addAction(edit_selected)

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


class _BulkEditPlan:
    """What a successful bulk-edit dialog accept resolves to.

    ``None`` means "don't touch that field on the selected rows".
    """

    __slots__ = ("description", "spec", "value_text")

    def __init__(
        self,
        description: Optional[str],
        spec: Optional[ValueTypeSpec],
        value_text: Optional[str],
    ) -> None:
        self.description = description
        self.spec = spec
        self.value_text = value_text


class _BulkEditDialog(QDialog):
    """Dialog that lets the user retype description / type / value at once.

    Each field has a leading "Apply" checkbox so the user can pick exactly
    which attributes to overwrite on the selected rows. Unchecked fields are
    left untouched.
    """

    def __init__(self, entries: List[CheatEntry], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit selected")
        self._plan: Optional[_BulkEditPlan] = None

        # Use the first entry's current state to pre-fill defaults — saves a
        # round-trip for the common "I just want to tweak this one value"
        # path that still goes through the bulk dialog.
        first = entries[0]
        spec = first.spec

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        layout.addWidget(
            QLabel(
                f"{len(entries)} row(s) selected. "
                "Check a field to overwrite it; leave unchecked to keep "
                "each row's current value."
            )
        )

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self._desc_chk = QCheckBox("Set description")
        self._desc_edit = QLineEdit(first.description)
        self._desc_edit.setEnabled(False)
        self._desc_chk.toggled.connect(self._desc_edit.setEnabled)
        form.addRow(self._desc_chk, self._desc_edit)

        self._type_chk = QCheckBox("Set value type")
        self._type_combo = QComboBox()
        for s in VALUE_TYPES:
            self._type_combo.addItem(s.label)
        if first.spec_label in (s.label for s in VALUE_TYPES):
            self._type_combo.setCurrentText(first.spec_label)
        self._type_combo.setEnabled(False)
        self._type_chk.toggled.connect(self._type_combo.setEnabled)
        form.addRow(self._type_chk, self._type_combo)

        self._value_chk = QCheckBox("Set value")
        self._value_edit = QLineEdit()
        if first.last_value is not None:
            try:
                self._value_edit.setText(spec.format(first.last_value))
            except Exception:  # noqa: BLE001 — defensive: bad formatter shouldn't kill the dialog
                pass
        self._value_edit.setEnabled(False)
        self._value_chk.toggled.connect(self._value_edit.setEnabled)
        form.addRow(self._value_chk, self._value_edit)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel, parent=self
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _current_spec(self) -> Optional[ValueTypeSpec]:
        if not self._type_chk.isChecked():
            return None
        return find_spec(self._type_combo.currentText())

    def _on_accept(self) -> None:
        if (
            not self._desc_chk.isChecked()
            and not self._type_chk.isChecked()
            and not self._value_chk.isChecked()
        ):
            QMessageBox.information(
                self,
                "Edit selected",
                "Check at least one field to apply, or press Cancel.",
            )
            return

        description = self._desc_edit.text() if self._desc_chk.isChecked() else None
        value_text = self._value_edit.text() if self._value_chk.isChecked() else None

        self._plan = _BulkEditPlan(
            description=description,
            spec=self._current_spec(),
            value_text=value_text,
        )
        self.accept()

    def result_plan(self) -> Optional[_BulkEditPlan]:
        return self._plan


__all__ = (
    "CheatEntry",
    "CheatTable",
    "_CheatPollWorker",
    "prompt_for_manual_entry",
)
