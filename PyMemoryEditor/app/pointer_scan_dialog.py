# -*- coding: utf-8 -*-
"""
Pointer-scan dialog — exposes ``process.scan_pointer_paths()``.

This is the inverse of the Pointer Chain dialog and mirrors Cheat Engine's
"Pointer scan for this address": given a *dynamic* address (one that changes
every run, e.g. an address a fresh scan just found), it discovers **static
pointer paths** that resolve to it — chains of the form
``"module"+0xXXXX -> [+0x0] -> +0x158`` whose base is fixed inside a loaded
module, so the recipe survives a restart despite ASLR.

The map-building phase reads a lot of memory, so the scan runs on a
:class:`PointerScanWorker` thread (same pattern as the scan workers and the
Modules dialog) with live progress and a Stop button. Each discovered path is
resolved + read on the worker thread and streamed to a Cheat-Engine-style
results table:

    Pointer Path                          | Base          | Offsets    | Resolves To | Value
    "game.exe"+0x10F4F4 -> [+0x0] -> +0x158| game.exe+10F4F4| 0x0, 0x158 | 0x1FA3C140  | 1234

Double-click (or right-click → Add to cheat table) promotes a path's resolved
address into the cheat table via the same signal the Pointer Chain dialog uses,
so it survives into the freeze/refresh loop.
"""
import json
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QGuiApplication, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableView,
    QVBoxLayout,
)

from PyMemoryEditor import AbstractProcess, PointerPath
from PyMemoryEditor.process.pointer_scan import intersect_pointer_paths

from ._widgets import NumericItem, parse_hex_address
from .value_types import VALUE_TYPES, ValueTypeSpec, find_spec


_LOG = logging.getLogger(__name__)

# Monospace stack used elsewhere in the app for address/value text.
_MONO = "Menlo, Consolas, Courier New"

# Stream resolved paths to the table in batches this size, so a scan that finds
# thousands of paths updates the UI smoothly instead of one row at a time.
_UI_BATCH = 200


class _PointerScanCancelled(Exception):
    """Raised from the progress callback to abort a scan mid-map-build."""


@dataclass
class PointerScanRequest:
    """Everything the worker needs to run one pointer scan."""

    target_address: int
    max_depth: int
    max_offset: int
    ptr_size: int
    writable_only: bool
    aligned: bool
    max_results: Optional[int]
    spec: ValueTypeSpec
    length: int


# One row destined for the table: the path plus the values resolved/read on the
# worker thread (so the UI thread never touches process memory).
_ResultRow = Tuple[PointerPath, Optional[int], str, bool]


class PointerScanWorker(QThread):
    """Runs ``scan_pointer_paths`` off the UI thread, streaming results."""

    progress = Signal(float)  # 0.0 … 100.0 (map-building phase)
    status = Signal(str)
    error = Signal(str)
    rows_ready = Signal(list)  # list[_ResultRow]
    finished_ok = Signal(int)  # total paths found

    def __init__(
        self, process: AbstractProcess, request: PointerScanRequest, parent=None
    ):
        super().__init__(parent)
        self._process = process
        self._request = request
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def _on_map_progress(self, fraction: float) -> None:
        # Abort the (uninterruptible-from-outside) map build by raising; the
        # generator unwinds and run() catches the cancellation cleanly.
        if self._cancelled:
            raise _PointerScanCancelled()
        self.progress.emit(fraction * 100.0)

    def run(self) -> None:
        req = self._request
        try:
            self.status.emit("Building pointer map…")
            generator = self._process.scan_pointer_paths(
                req.target_address,
                max_depth=req.max_depth,
                max_offset=req.max_offset,
                ptr_size=req.ptr_size,
                aligned=req.aligned,
                writable_only=req.writable_only,
                max_results=req.max_results,
                progress_callback=self._on_map_progress,
            )

            batch: List[_ResultRow] = []
            count = 0
            searching_announced = False

            for path in generator:
                if self._cancelled:
                    break

                if not searching_announced:
                    # First path means the map is built and the walk has begun.
                    self.progress.emit(100.0)
                    self.status.emit("Searching for pointer paths…")
                    searching_announced = True

                resolved, value_text, valid = self._resolve_and_read(path, req)
                batch.append((path, resolved, value_text, valid))
                count += 1

                if len(batch) >= _UI_BATCH:
                    self.rows_ready.emit(batch)
                    batch = []
                    self.status.emit(f"Found {count:,} pointer path(s)…")

            if batch:
                self.rows_ready.emit(batch)

            if self._cancelled:
                self.status.emit(f"Stopped — {count:,} pointer path(s) found.")
            self.finished_ok.emit(count)
        except _PointerScanCancelled:
            self.status.emit("Pointer scan cancelled.")
            self.finished_ok.emit(0)
        except Exception as exc:  # noqa: BLE001 — surface every backend error to the UI
            _LOG.warning("Pointer scan failed: %s: %s", type(exc).__name__, exc)
            self.error.emit(f"{type(exc).__name__}: {exc}")

    def _resolve_and_read(
        self, path: PointerPath, req: PointerScanRequest
    ) -> Tuple[Optional[int], str, bool]:
        """Walk the path now and read its value — both off the UI thread.

        ``valid`` is True when the freshly-resolved address still equals the
        target (the pointer map can go stale between build and resolve).
        """
        try:
            resolved = path.resolve(self._process)
        except Exception:  # noqa: BLE001 — a hop went invalid since the map was built
            return None, "<unresolved>", False

        valid = resolved == req.target_address
        try:
            value = self._process.read_process_memory(
                resolved, req.spec.pytype, req.length
            )
            text = req.spec.format(value)
        except Exception as exc:  # noqa: BLE001
            text = f"<read failed: {type(exc).__name__}>"
        return resolved, text, valid


class PointerRescanWorker(QThread):
    """
    Re-resolve a set of previously-saved pointer paths against the live process
    and keep only those that still resolve to ``target_address``.

    This is Cheat Engine's "Pointer rescan": after the target moves (a restart,
    a level reload), the stable paths are exactly the ones that survive being
    replayed against the new address. Iterating it collapses thousands of
    candidates down to the few reliable static pointers.

    Emits the same signals as :class:`PointerScanWorker` so the dialog can wire
    both uniformly.
    """

    progress = Signal(float)
    status = Signal(str)
    error = Signal(str)
    rows_ready = Signal(list)  # list[_ResultRow]
    finished_ok = Signal(int)

    def __init__(
        self,
        process: AbstractProcess,
        paths: List[PointerPath],
        target_address: int,
        spec: ValueTypeSpec,
        length: int,
        parent=None,
    ):
        super().__init__(parent)
        self._process = process
        self._paths = paths
        self._target = target_address
        self._spec = spec
        self._length = length
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            # One name→base lookup so rebasing each saved path is O(1).
            module_bases = {m.name: m.base_address for m in self._process.get_modules()}

            batch: List[_ResultRow] = []
            total = len(self._paths) or 1
            kept = 0

            for index, saved in enumerate(self._paths):
                if self._cancelled:
                    break

                live = self._rebase(saved, module_bases)
                if live is not None:
                    resolved, value_text, valid = self._resolve_and_read(live)
                    if valid:
                        batch.append((live, resolved, value_text, True))
                        kept += 1

                if len(batch) >= _UI_BATCH:
                    self.rows_ready.emit(batch)
                    batch = []
                if index % _UI_BATCH == 0:
                    self.progress.emit((index / total) * 100.0)
                    self.status.emit(
                        f"Checked {index:,}/{len(self._paths):,}, kept {kept:,}…"
                    )

            if batch:
                self.rows_ready.emit(batch)

            self.progress.emit(100.0)
            self.finished_ok.emit(kept)
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("Pointer rescan failed: %s: %s", type(exc).__name__, exc)
            self.error.emit(f"{type(exc).__name__}: {exc}")

    def _rebase(self, saved: PointerPath, module_bases: dict) -> Optional[PointerPath]:
        """Move a saved path onto the live module base, or None if not rebasable."""
        if saved.module is not None and saved.module_offset is not None:
            base = module_bases.get(saved.module)
            if base is None:
                return None  # module not loaded in this run — drop the path
            return PointerPath(
                base_address=base + saved.module_offset,
                offsets=saved.offsets,
                module=saved.module,
                module_offset=saved.module_offset,
                ptr_size=saved.ptr_size,
            )
        # No module: the absolute base is only a best-effort guess post-restart.
        return saved

    def _resolve_and_read(
        self, path: PointerPath
    ) -> Tuple[Optional[int], str, bool]:
        try:
            resolved = path.resolve(self._process)
        except Exception:  # noqa: BLE001
            return None, "<unresolved>", False
        if resolved != self._target:
            return resolved, "", False
        try:
            value = self._process.read_process_memory(
                resolved, self._spec.pytype, self._length
            )
            text = self._spec.format(value)
        except Exception as exc:  # noqa: BLE001
            text = f"<read failed: {type(exc).__name__}>"
        return resolved, text, True


# Result-table columns.
_COL_PATH = 0
_COL_BASE = 1
_COL_MODULE_OFFSET = 2
_COL_OFFSETS = 3
_COL_RESOLVED = 4
_COL_VALUE = 5


class PointerScanDialog(QDialog):
    """Reverse pointer scan with a Cheat-Engine-style result table."""

    # qulonglong: 64-bit addresses overflow Qt's signed-32-bit default.
    add_to_cheat_table = Signal(
        "qulonglong", str, int
    )  # (resolved_address, spec_label, length)
    open_hex_viewer = Signal("qulonglong", "qulonglong")  # (address, length)

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process
        self._worker: Optional[QThread] = None
        self._target_address: Optional[int] = None

        self.setWindowTitle(f"Pointer Scan — PID {process.pid}")
        self.resize(880, 600)

        self._build_ui()

    # ----------------------------------------------------------------- UI --- #

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        header = QLabel(
            "<span style='font-size:16px;font-weight:700;'>Pointer Scan</span>"
        )
        header.setTextFormat(Qt.RichText)
        layout.addWidget(header)

        hint = QLabel(
            "Find static pointer paths that resolve to a dynamic address. The "
            "discovered paths (module + offsets) survive a process restart — "
            "the same recipe Cheat Engine exports. Tip: right-click a scan "
            "result and choose “Pointer scan for this address”."
        )
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        # --- scan parameters ------------------------------------------------ #
        form = QFormLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        self._target_edit = QLineEdit()
        self._target_edit.setPlaceholderText("e.g. 0x1FA3C140 (hex)")
        self._target_edit.setFont(QFont(_MONO, 10))
        form.addRow("Target address:", self._target_edit)

        self._depth_spin = QSpinBox()
        self._depth_spin.setRange(1, 12)
        self._depth_spin.setValue(5)
        self._depth_spin.setToolTip(
            "Maximum pointer levels (offsets) in a chain. Deeper finds more "
            "paths but costs exponentially more time."
        )
        form.addRow("Max level (depth):", self._depth_spin)

        self._offset_edit = QLineEdit("0x400")
        self._offset_edit.setFont(QFont(_MONO, 10))
        self._offset_edit.setToolTip(
            "Largest offset a single hop may add (the struct-size window). "
            "Larger catches fields deeper in objects but multiplies candidates."
        )
        form.addRow("Max offset:", self._offset_edit)

        self._ptr_size_combo = QComboBox()
        self._ptr_size_combo.addItem("8 bytes (64-bit)", 8)
        self._ptr_size_combo.addItem("4 bytes (32-bit)", 4)
        form.addRow("Pointer size:", self._ptr_size_combo)

        self._max_results_spin = QSpinBox()
        self._max_results_spin.setRange(0, 1_000_000)
        self._max_results_spin.setValue(100)
        self._max_results_spin.setSpecialValueText("Unlimited")
        self._max_results_spin.setToolTip(
            "Stop after this many paths (0 = unlimited). A cap keeps the first "
            "scan fast on large targets."
        )
        form.addRow("Max results:", self._max_results_spin)

        # Value type + length — used to read each path's value and to carry the
        # type into the cheat table on promotion.
        self._value_type_combo = QComboBox()
        for spec in VALUE_TYPES:
            if spec.is_pattern:
                continue  # reading a value "as a pattern" is meaningless here
            self._value_type_combo.addItem(spec.label)
        self._value_type_combo.currentTextChanged.connect(self._on_value_type_changed)
        form.addRow("Read value as:", self._value_type_combo)

        self._length_spin = QSpinBox()
        self._length_spin.setRange(1, 1024)
        self._length_spin.setValue(4)
        self._length_spin.setSuffix("  bytes")
        form.addRow("Length:", self._length_spin)

        self._writable_check = QCheckBox(
            "Writable memory only (faster; covers typical chains)"
        )
        self._writable_check.setChecked(True)
        self._writable_check.setToolTip(
            "Every hop in a live chain reads a pointer the program writes "
            "(global pointers in .data, object fields on the heap), so writable "
            "memory captures the usual cases. Uncheck to also include read-only "
            "pointers (e.g. vtables) — slower and noisier."
        )
        form.addRow("", self._writable_check)

        self._aligned_check = QCheckBox("Aligned pointers only (recommended)")
        self._aligned_check.setChecked(True)
        self._aligned_check.setToolTip(
            "Only consider pointers at natural alignment — far faster and how "
            "compilers lay pointers out. Uncheck to also scan misaligned slots."
        )
        form.addRow("", self._aligned_check)

        layout.addLayout(form)

        # --- action buttons ------------------------------------------------- #
        button_row = QHBoxLayout()
        self._scan_btn = QPushButton("Scan")
        self._scan_btn.setObjectName("secondary")
        self._scan_btn.setDefault(True)
        self._scan_btn.clicked.connect(self._on_scan)
        button_row.addWidget(self._scan_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setObjectName("danger")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._on_stop)
        button_row.addWidget(self._stop_btn)

        _equal_height = "padding: 7px 14px; min-height: 20px;"

        self._rescan_btn = QPushButton("Rescan from saved…")
        self._rescan_btn.setStyleSheet(_equal_height)
        self._rescan_btn.setToolTip(
            "Load a previously exported scan and keep only the paths that still "
            "resolve to the target address above — Cheat Engine's pointer "
            "rescan. Run it after the target moved (a restart / level reload) to "
            "narrow the list down to the stable static pointers."
        )
        self._rescan_btn.clicked.connect(self._on_rescan_from_saved)
        button_row.addWidget(self._rescan_btn)

        self._compare_btn = QPushButton("Intersect saved scans…")
        self._compare_btn.setStyleSheet(_equal_height)
        self._compare_btn.setToolTip(
            "Select 2+ exported scans — keeps only the paths present in every "
            "file. Do a full pointer scan after each restart, export each, then "
            "intersect them here to find the paths that survived every run — no "
            "live target needed."
        )
        self._compare_btn.clicked.connect(self._on_compare_saved)
        button_row.addWidget(self._compare_btn)

        self._export_btn = QPushButton("Export…")
        self._export_btn.setStyleSheet(_equal_height)
        self._export_btn.setToolTip(
            "Save the current pointer paths to a JSON file (module + offsets), "
            "so you can rescan against them in a later run."
        )
        self._export_btn.setEnabled(False)
        self._export_btn.clicked.connect(self._on_export)
        button_row.addWidget(self._export_btn)

        button_row.addStretch(1)

        self._count_label = QLabel("")
        self._count_label.setObjectName("hint")
        button_row.addWidget(self._count_label)

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(_equal_height)
        close_btn.clicked.connect(self.accept)
        button_row.addWidget(close_btn)

        layout.addLayout(button_row)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        layout.addWidget(self._progress)

        # --- results table -------------------------------------------------- #
        self._model = QStandardItemModel(0, 6, self)
        self._model.setHorizontalHeaderLabels(
            ["Pointer Path", "Base", "Module Offset", "Offsets", "Resolves To", "Value"]
        )

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setMinimumHeight(170)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            _COL_PATH, QHeaderView.Stretch
        )
        self._table.horizontalHeader().setSectionResizeMode(
            _COL_BASE, QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            _COL_MODULE_OFFSET, QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            _COL_RESOLVED, QHeaderView.ResizeToContents
        )
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.doubleClicked.connect(lambda _i: self._add_selected_to_cheat())
        layout.addWidget(self._table, 1)

        self._on_value_type_changed(self._value_type_combo.currentText())

    # ------------------------------------------------------------ helpers --- #

    def set_target_address(self, address: int) -> None:
        """Prefill the target field (used by the “scan for this address” entry)."""
        self._target_address = int(address)
        self._target_edit.setText(f"0x{int(address):X}")

    def _current_spec(self) -> Tuple[ValueTypeSpec, int]:
        spec = find_spec(self._value_type_combo.currentText()) or VALUE_TYPES[0]
        length = self._length_spin.value() if spec.accepts_length_override else spec.length
        return spec, int(length)

    def _on_value_type_changed(self, label: str) -> None:
        spec = find_spec(label)
        if spec is None:
            return
        self._length_spin.setEnabled(spec.accepts_length_override)
        if not spec.accepts_length_override:
            self._length_spin.setValue(spec.length)

    # -------------------------------------------------------------- scan --- #

    def _on_scan(self) -> None:
        if self._worker is not None:
            return

        target = parse_hex_address(self._target_edit.text())
        if target is None:
            QMessageBox.warning(
                self,
                "Pointer Scan",
                "Enter a target address in hex (e.g. 0x1FA3C140).",
            )
            return

        max_offset = parse_hex_address(self._offset_edit.text())
        if max_offset is None or max_offset <= 0:
            QMessageBox.warning(
                self, "Pointer Scan", "Max offset must be a positive hex value."
            )
            return

        self._target_address = target
        spec, length = self._current_spec()
        max_results = self._max_results_spin.value() or None

        if max_results is None:
            proceed = QMessageBox.question(
                self,
                "Pointer Scan",
                "Max results is set to Unlimited. On a large target this can "
                "produce a very large number of paths and take a long time.\n\n"
                "Run anyway?",
            )
            if proceed != QMessageBox.StandardButton.Yes:
                return

        request = PointerScanRequest(
            target_address=target,
            max_depth=self._depth_spin.value(),
            max_offset=max_offset,
            ptr_size=int(self._ptr_size_combo.currentData()),
            writable_only=self._writable_check.isChecked(),
            aligned=self._aligned_check.isChecked(),
            max_results=max_results,
            spec=spec,
            length=length,
        )

        self._model.setRowCount(0)
        self._set_scanning(True)
        self._progress.setValue(0)
        self._count_label.setText("")

        self._start_worker(PointerScanWorker(self._process, request, self))

    def _start_worker(self, worker: QThread) -> None:
        """Wire the shared worker signals and start it (scan or rescan)."""
        worker.progress.connect(lambda p: self._progress.setValue(int(p)))
        worker.status.connect(self._count_label.setText)
        worker.rows_ready.connect(self._append_rows)
        worker.error.connect(self._on_error)
        worker.finished_ok.connect(self._on_finished_ok)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def _on_stop(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self._count_label.setText("Stopping…")

    def _set_scanning(self, scanning: bool) -> None:
        self._scan_btn.setEnabled(not scanning)
        self._stop_btn.setEnabled(scanning)
        self._rescan_btn.setEnabled(not scanning)
        self._compare_btn.setEnabled(not scanning)
        self._export_btn.setEnabled(not scanning and self._model.rowCount() > 0)
        for widget in (
            self._target_edit,
            self._depth_spin,
            self._offset_edit,
            self._ptr_size_combo,
            self._max_results_spin,
            self._value_type_combo,
            self._writable_check,
            self._aligned_check,
        ):
            widget.setEnabled(not scanning)
        # Length only enabled when scanning stopped *and* the spec allows it.
        if not scanning:
            self._on_value_type_changed(self._value_type_combo.currentText())
        else:
            self._length_spin.setEnabled(False)

    def _append_rows(self, rows: List[_ResultRow]) -> None:
        from PySide6.QtGui import QColor

        for path, resolved, value_text, valid in rows:
            path_item = QStandardItem(str(path))
            path_item.setFont(QFont(_MONO, 10))
            # Stash the PointerPath itself for promotion / copy / hex-view.
            path_item.setData(path, Qt.UserRole)

            if path.module is not None and path.module_offset is not None:
                base_text = f"{path.module}+0x{path.module_offset:X}"
            else:
                base_text = f"0x{path.base_address:X}"
            base_item = QStandardItem(base_text)
            base_item.setFont(QFont(_MONO, 10))

            # Dedicated column for the static module offset — the value you add
            # to the module base in the Pointer Chain tool. "—" for module-less
            # paths (a custom static range), which have no portable offset.
            module_offset_item = QStandardItem(
                f"0x{path.module_offset:X}" if path.module_offset is not None else "—"
            )
            module_offset_item.setFont(QFont(_MONO, 10))

            offsets_item = QStandardItem(
                ", ".join(f"0x{o:X}" for o in path.offsets)
            )
            offsets_item.setFont(QFont(_MONO, 10))

            resolved_item = NumericItem(
                f"0x{resolved:X}" if resolved is not None else "—"
            )
            resolved_item.setData(resolved if resolved is not None else -1, Qt.UserRole)
            resolved_item.setFont(QFont(_MONO, 10))

            value_item = QStandardItem(value_text)
            value_item.setFont(QFont(_MONO, 10))

            # A path that no longer resolves to the target (map went stale) is
            # dimmed so the user trusts the still-valid ones first.
            if not valid:
                for item in (
                    path_item,
                    base_item,
                    module_offset_item,
                    offsets_item,
                    resolved_item,
                    value_item,
                ):
                    item.setForeground(QColor(0xFF, 0x85, 0x85))

            self._model.appendRow(
                [
                    path_item,
                    base_item,
                    module_offset_item,
                    offsets_item,
                    resolved_item,
                    value_item,
                ]
            )

    def _on_error(self, message: str) -> None:
        QMessageBox.critical(self, "Pointer Scan", message)
        self._count_label.setText("Scan failed.")

    def _on_finished_ok(self, count: int) -> None:
        self._progress.setValue(100)
        shown = self._model.rowCount()
        if count == 0 and shown == 0:
            self._count_label.setText(
                "No pointer paths found. Try a higher depth or max offset, or "
                "uncheck “Writable memory only”."
            )
        else:
            self._count_label.setText(f"{shown:,} pointer path(s).")
        self._export_btn.setEnabled(shown > 0)

    def _on_worker_finished(self) -> None:
        worker = self._worker
        self._worker = None
        self._set_scanning(False)
        if worker is not None:
            worker.deleteLater()

    # ----------------------------------------------------------- actions --- #

    def _selected_path(self) -> Optional[PointerPath]:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._model.item(rows[0].row(), _COL_PATH)
        return item.data(Qt.UserRole) if item is not None else None

    def _show_context_menu(self, pos) -> None:
        index = self._table.indexAt(pos)
        if not index.isValid():
            return
        self._table.selectRow(index.row())
        path = self._selected_path()
        if path is None:
            return

        menu = QMenu(self)
        add_action = menu.addAction("Add to cheat table")
        add_action.triggered.connect(self._add_selected_to_cheat)

        hex_action = menu.addAction("Resolve & open in hex viewer")
        hex_action.triggered.connect(self._open_selected_in_hex)

        menu.addSeparator()
        copy_path = menu.addAction("Copy pointer path")
        copy_path.triggered.connect(lambda: QGuiApplication.clipboard().setText(str(path)))

        copy_offsets = menu.addAction("Copy offsets")
        copy_offsets.triggered.connect(
            lambda: QGuiApplication.clipboard().setText(
                ", ".join(f"0x{o:X}" for o in path.offsets)
            )
        )
        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _resolve_selected(self) -> Optional[int]:
        """Re-walk the selected path now (fresh), reporting failures to the user."""
        path = self._selected_path()
        if path is None:
            return None
        try:
            return path.resolve(self._process)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(
                self,
                "Pointer Scan",
                "Could not resolve this path now — one of its pointers is no "
                f"longer valid.\n\n{type(exc).__name__}: {exc}",
            )
            return None

    def _add_selected_to_cheat(self) -> None:
        resolved = self._resolve_selected()
        if resolved is None:
            return
        spec, length = self._current_spec()
        self.add_to_cheat_table.emit(resolved, spec.label, length)

    def _open_selected_in_hex(self) -> None:
        resolved = self._resolve_selected()
        if resolved is None:
            return
        _, length = self._current_spec()
        self.open_hex_viewer.emit(resolved, max(256, length))

    # ------------------------------------------------- export / rescan --- #

    def _all_paths(self) -> List[PointerPath]:
        """Collect the PointerPath stashed on every row (column 0, UserRole)."""
        paths: List[PointerPath] = []
        for row in range(self._model.rowCount()):
            item = self._model.item(row, _COL_PATH)
            if item is not None:
                path = item.data(Qt.UserRole)
                if isinstance(path, PointerPath):
                    paths.append(path)
        return paths

    def _on_export(self) -> None:
        paths = self._all_paths()
        if not paths:
            QMessageBox.information(self, "Pointer Scan", "Nothing to export yet.")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export pointer scan",
            "pointer_scan.json",
            "Pointer scan (*.json);;All files (*)",
        )
        if not filename:
            return

        payload = {
            "format": "pymemoryeditor-pointerscan",
            "version": 1,
            "pid": self._process.pid,
            "target_address": (
                "0x%X" % self._target_address
                if self._target_address is not None
                else None
            ),
            "paths": [path.to_dict() for path in paths],
        }
        try:
            with open(filename, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except OSError as exc:
            QMessageBox.critical(self, "Pointer Scan", f"Could not write file:\n\n{exc}")
            return
        self._count_label.setText(f"Exported {len(paths):,} path(s) to {filename}.")

    def _on_rescan_from_saved(self) -> None:
        if self._worker is not None:
            return

        target = parse_hex_address(self._target_edit.text())
        if target is None:
            QMessageBox.warning(
                self,
                "Pointer Rescan",
                "Enter the current target address (hex) first — rescan keeps "
                "only the saved paths that still resolve to it.",
            )
            return

        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Rescan from saved pointer scan",
            "",
            "Pointer scan (*.json);;All files (*)",
        )
        if not filename:
            return

        try:
            with open(filename, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            paths = [PointerPath.from_dict(entry) for entry in payload["paths"]]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            QMessageBox.critical(
                self,
                "Pointer Rescan",
                f"Could not read a pointer scan from this file:\n\n{exc}",
            )
            return

        if not paths:
            QMessageBox.information(
                self, "Pointer Rescan", "The file contains no pointer paths."
            )
            return

        self._target_address = target
        spec, length = self._current_spec()

        self._model.setRowCount(0)
        self._set_scanning(True)
        self._progress.setValue(0)
        self._count_label.setText(f"Rescanning {len(paths):,} saved path(s)…")

        self._start_worker(
            PointerRescanWorker(self._process, paths, target, spec, length, self)
        )

    def _load_paths_file(self, filename: str) -> Optional[List[PointerPath]]:
        """Load a saved scan, or show an error and return None."""
        try:
            with open(filename, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            return [PointerPath.from_dict(entry) for entry in payload["paths"]]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            QMessageBox.critical(
                self,
                "Compare scans",
                f"Could not read a pointer scan from\n{filename}:\n\n{exc}",
            )
            return None

    def _on_compare_saved(self) -> None:
        if self._worker is not None:
            return

        filenames, _ = QFileDialog.getOpenFileNames(
            self,
            "Compare saved pointer scans (select 2 or more)",
            "",
            "Pointer scan (*.json);;All files (*)",
        )
        if not filenames:
            return
        if len(filenames) < 2:
            QMessageBox.information(
                self,
                "Compare scans",
                "Select at least two exported scans — the result is the set of "
                "paths present in all of them.",
            )
            return

        path_lists: List[List[PointerPath]] = []
        for filename in filenames:
            paths = self._load_paths_file(filename)
            if paths is None:
                return  # error already reported
            path_lists.append(paths)

        survivors = intersect_pointer_paths(path_lists)

        self._model.setRowCount(0)
        if not survivors:
            self._count_label.setText(
                f"No path is common to all {len(filenames)} scans."
            )
            self._export_btn.setEnabled(False)
            return

        # Intersection is by recipe (ASLR-independent) and needs no live target.
        # For display, rebase each survivor onto the current process and read its
        # value — best effort; a path that can't resolve now is still a valid
        # member of the intersection and is kept (shown dimmed / "—").
        module_bases = {m.name: m.base_address for m in self._process.get_modules()}
        spec, length = self._current_spec()

        rows: List[_ResultRow] = []
        for saved in survivors:
            base = module_bases.get(saved.module)
            live = (
                PointerPath(
                    base_address=base + saved.module_offset,
                    offsets=saved.offsets,
                    module=saved.module,
                    module_offset=saved.module_offset,
                    ptr_size=saved.ptr_size,
                )
                if base is not None and saved.module_offset is not None
                else saved
            )
            try:
                resolved = live.resolve(self._process)
                value = self._process.read_process_memory(resolved, spec.pytype, length)
                text = spec.format(value)
                valid = True
            except Exception:  # noqa: BLE001 — display only; membership already decided
                resolved, text, valid = None, "—", False
            rows.append((live, resolved, text, valid))

        self._append_rows(rows)
        self._count_label.setText(
            f"{len(survivors):,} path(s) common to {len(filenames)} scans."
        )
        self._export_btn.setEnabled(True)

    def closeEvent(self, event):  # noqa: N802 — Qt naming
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            try:
                self._worker.rows_ready.disconnect()
                self._worker.progress.disconnect()
                self._worker.status.disconnect()
                self._worker.finished_ok.disconnect()
            except (RuntimeError, TypeError):
                pass
            self._worker.wait(2000)
        super().closeEvent(event)
