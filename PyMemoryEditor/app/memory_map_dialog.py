# -*- coding: utf-8 -*-
"""
Memory-map dialog — exposes ``process.get_memory_regions()``.

Lists every memory region the target process holds, with address, size,
protection flags (decoded into a human "R W X" string), shared/private state,
and the backing path on Linux. The toolbar buttons let the user:

* refresh the snapshot,
* copy a base address,
* jump straight into the hex viewer at any region.

The dialog also publishes its last snapshot so the main window can reuse it
as the ``memory_regions`` kwarg to subsequent scans.
"""
import sys
from typing import Dict, List, Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QGuiApplication, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
)

from PyMemoryEditor import AbstractProcess

from ._widgets import NumericItem


class _SnapshotWorker(QThread):
    """Background thread that runs ``snapshot_memory_regions()`` off the UI."""

    snapshot_ready = Signal(object)  # List[Dict]
    snapshot_failed = Signal(str)

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process

    def run(self) -> None:
        try:
            snapshot = self._process.snapshot_memory_regions()
        except Exception as exc:  # noqa: BLE001
            self.snapshot_failed.emit(str(exc))
            return
        self.snapshot_ready.emit(snapshot)


def _format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    s = float(size)
    for unit in units:
        if s < 1024 or unit == units[-1]:
            return f"{s:,.1f} {unit}" if unit != "B" else f"{int(s):,} B"
        s /= 1024
    return f"{size:,} B"


def _decode_protection(region: Dict) -> str:
    """
    Translate the platform-specific protection field into a short ``R W X`` /
    ``private``-style string. Falls back to the raw int if we can't recognise it.
    """
    struct = region.get("struct")

    if sys.platform == "win32":
        # Windows: the low byte of Protect is one of the mutually-exclusive
        # PAGE_* base values, and the upper bits carry modifiers like
        # PAGE_GUARD (0x100), PAGE_NOCACHE (0x200), PAGE_WRITECOMBINE (0x400).
        try:
            value = int(getattr(struct, "Protect", 0))
        except Exception:
            return "-"

        base_names = {
            0x01: "NA",  # PAGE_NOACCESS
            0x02: "R",  # PAGE_READONLY
            0x04: "RW",  # PAGE_READWRITE
            0x08: "RW-cow",  # PAGE_WRITECOPY
            0x10: "X",  # PAGE_EXECUTE
            0x20: "RX",  # PAGE_EXECUTE_READ
            0x40: "RWX",  # PAGE_EXECUTE_READWRITE
            0x80: "RWX-cow",  # PAGE_EXECUTE_WRITECOPY
        }
        modifiers = []
        if value & 0x100:
            modifiers.append("guard")
        if value & 0x200:
            modifiers.append("nocache")
        if value & 0x400:
            modifiers.append("writecombine")

        label = base_names.get(value & 0xFF, hex(value))
        if modifiers:
            label = f"{label} +{','.join(modifiers)}"
        return label

    if sys.platform == "darwin":
        # macOS vm_prot_t bitfield: 1=R, 2=W, 4=X
        try:
            value = int(getattr(struct, "Protection", 0))
            mx = int(getattr(struct, "MaxProtection", value))
        except Exception:
            return "-"
        cur = "".join(
            [
                "R" if value & 1 else "-",
                "W" if value & 2 else "-",
                "X" if value & 4 else "-",
            ]
        )
        maxp = "".join(
            [
                "R" if mx & 1 else "-",
                "W" if mx & 2 else "-",
                "X" if mx & 4 else "-",
            ]
        )
        return f"{cur} (max {maxp})"

    # Linux: privileges is a 4-char string like "rw-p".
    try:
        privileges = struct.Privileges
        if isinstance(privileges, bytes):
            privileges = privileges.decode("latin-1", "replace")
        return privileges or "-"
    except Exception:
        return "-"


def _region_path(region: Dict) -> str:
    """On Linux, surface the backing file path (so the user sees [stack], [heap] etc)."""
    return region.get("path") or ""


def _region_shared(region: Dict) -> str:
    if "is_shared" not in region:
        return "—"
    return "Shared" if region["is_shared"] else "Private"


class MemoryMapDialog(QDialog):
    """Shows the output of ``get_memory_regions()`` in a sortable table."""

    # qulonglong: 64-bit addresses overflow Qt's default int (C++ signed 32-bit).
    open_hex_viewer = Signal("qulonglong", "qulonglong")  # (address, length)

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process
        self._snapshot: List[Dict] = []
        self._worker: Optional[_SnapshotWorker] = None

        self.setWindowTitle(f"Memory Map — PID {process.pid}")
        self.resize(900, 580)

        self._build_ui()
        self.refresh()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        header = QLabel(
            f"<span style='font-size:16px;font-weight:700;'>Memory Map</span>"
            f" &nbsp;<span style='color:#9A9DB4;'>PID {self._process.pid}</span>"
        )
        header.setTextFormat(Qt.RichText)
        layout.addWidget(header)

        self._count_label = QLabel("")
        self._count_label.setObjectName("hint")
        layout.addWidget(self._count_label)

        # Toolbar
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self.refresh)
        bar.addWidget(self._refresh_btn)

        self._copy_btn = QPushButton("Copy Address")
        self._copy_btn.clicked.connect(self._copy_selected_address)
        bar.addWidget(self._copy_btn)

        self._hex_btn = QPushButton("Open in Hex Viewer")
        self._hex_btn.clicked.connect(self._emit_hex_viewer_request)
        bar.addWidget(self._hex_btn)

        bar.addStretch(1)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        bar.addWidget(close_btn)
        layout.addLayout(bar)

        # Table
        self._model = QStandardItemModel(0, 6, self)
        self._model.setHorizontalHeaderLabels(
            [
                "Base Address",
                "Size",
                "Protection",
                "Shared",
                "Path / Notes",
                "Region Size (Bytes)",
            ]
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
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self._table.setColumnHidden(5, True)  # raw size column used only for sorting
        self._table.doubleClicked.connect(lambda _i: self._emit_hex_viewer_request())
        layout.addWidget(self._table, 1)

    # ----------------------------------------------------------- behaviour

    def snapshot(self) -> List[Dict]:
        """Return the cached region snapshot so the scanner can reuse it."""
        return list(self._snapshot)

    def refresh(self) -> None:
        # Don't stack workers — if a previous refresh is in flight, ignore the
        # click. The UI is already disabled, so this is just a safety net.
        if self._worker is not None and self._worker.isRunning():
            return

        self._count_label.setText("Loading memory regions…")
        self._set_busy(True)

        worker = _SnapshotWorker(self._process, self)
        worker.snapshot_ready.connect(self._on_snapshot_ready)
        worker.snapshot_failed.connect(self._on_snapshot_failed)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def _set_busy(self, busy: bool) -> None:
        self._copy_btn.setEnabled(not busy)
        self._hex_btn.setEnabled(not busy)
        # The Refresh button is the first widget added to the toolbar — keep a
        # named reference instead of fishing through the layout.
        self._refresh_btn.setEnabled(not busy)

    def _on_snapshot_ready(self, snapshot) -> None:
        self._snapshot = list(snapshot)
        self._model.setRowCount(0)
        total_bytes = 0
        for region in self._snapshot:
            addr = int(region["address"])
            size = int(region["size"])
            total_bytes += size

            addr_item = NumericItem(f"0x{addr:016X}")
            addr_item.setData(addr, Qt.UserRole)

            size_item = NumericItem(_format_size(size))
            size_item.setData(size, Qt.UserRole)
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            prot_item = QStandardItem(_decode_protection(region))
            shared_item = QStandardItem(_region_shared(region))

            path = _region_path(region) or ""
            path_item = QStandardItem(path)

            raw_size_item = NumericItem(str(size))
            raw_size_item.setData(size, Qt.UserRole)

            self._model.appendRow(
                [addr_item, size_item, prot_item, shared_item, path_item, raw_size_item]
            )

        self._count_label.setText(
            f"{len(self._snapshot):,} regions · {_format_size(total_bytes)} of virtual address space mapped"
        )

    def _on_snapshot_failed(self, message: str) -> None:
        self._count_label.setText("Failed to read memory regions.")
        QMessageBox.critical(
            self, "Memory Map", f"Failed to read memory regions:\n\n{message}"
        )

    def _on_worker_finished(self) -> None:
        self._set_busy(False)
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.deleteLater()

    def closeEvent(self, event):  # noqa: N802 — Qt naming
        # If the snapshot is still in flight, let it finish without holding
        # the UI hostage but unhook our slots so a late emit doesn't touch
        # a destroyed dialog.
        if self._worker is not None and self._worker.isRunning():
            try:
                self._worker.snapshot_ready.disconnect()
                self._worker.snapshot_failed.disconnect()
                self._worker.finished.disconnect()
            except (RuntimeError, TypeError):
                pass
            self._worker.wait(1000)
        super().closeEvent(event)

    def _selected_region(self) -> Optional[Dict]:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        addr = self._model.item(row, 0).data(Qt.UserRole)
        size = self._model.item(row, 1).data(Qt.UserRole)
        return {"address": int(addr), "size": int(size)}

    def _copy_selected_address(self) -> None:
        region = self._selected_region()
        if region is None:
            QMessageBox.information(self, "Memory Map", "Select a region first.")
            return
        QGuiApplication.clipboard().setText(f"{region['address']:X}")

    def _emit_hex_viewer_request(self) -> None:
        region = self._selected_region()
        if region is None:
            QMessageBox.information(self, "Memory Map", "Select a region first.")
            return
        # Cap the initial view to keep the hex widget responsive on huge regions.
        size = min(region["size"], 4096)
        self.open_hex_viewer.emit(region["address"], size)
