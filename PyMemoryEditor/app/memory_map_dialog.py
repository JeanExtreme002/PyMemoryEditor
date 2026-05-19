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

from PySide6.QtCore import Qt, Signal
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

from PyMemoryEditor.process import AbstractProcess


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
        privileges = struct.Privileges  # type: ignore[attr-defined]
        if isinstance(privileges, bytes):
            privileges = privileges.decode("latin-1", "replace")
        return privileges or "-"
    except Exception:
        return "-"


def _region_path(region: Dict) -> str:
    """On Linux, surface the backing file path (so the user sees [stack], [heap] etc)."""
    struct = region.get("struct")
    try:
        path = getattr(struct, "Path", None)
    except Exception:
        return ""
    if not path:
        return ""
    if isinstance(path, bytes):
        path = path.decode("utf-8", "replace")
    return path


def _region_shared(region: Dict) -> str:
    struct = region.get("struct")
    try:
        if sys.platform == "darwin":
            return "Shared" if int(getattr(struct, "Shared", 0)) else "Private"
        if sys.platform == "linux":
            privileges = getattr(struct, "Privileges", b"") or b""
            if isinstance(privileges, bytes):
                privileges = privileges.decode("latin-1", "replace")
            return "Shared" if "s" in privileges else "Private"
    except Exception:
        pass
    return "—"


class _Numeric(QStandardItem):
    def __lt__(self, other):
        try:
            return int(self.data(Qt.UserRole)) < int(other.data(Qt.UserRole))
        except (TypeError, ValueError):
            return super().__lt__(other)


class MemoryMapDialog(QDialog):
    """Shows the output of ``get_memory_regions()`` in a sortable table."""

    open_hex_viewer = Signal(int, int)  # (address, length)

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process
        self._snapshot: List[Dict] = []

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

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        bar.addWidget(refresh_btn)

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
        try:
            self._snapshot = self._process.snapshot_memory_regions()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self, "Memory Map", f"Failed to read memory regions:\n\n{exc}"
            )
            return

        self._model.setRowCount(0)
        total_bytes = 0
        for region in self._snapshot:
            addr = int(region["address"])
            size = int(region["size"])
            total_bytes += size

            addr_item = _Numeric(f"0x{addr:016X}")
            addr_item.setData(addr, Qt.UserRole)

            size_item = _Numeric(_format_size(size))
            size_item.setData(size, Qt.UserRole)
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            prot_item = QStandardItem(_decode_protection(region))
            shared_item = QStandardItem(_region_shared(region))

            path = _region_path(region) or ""
            path_item = QStandardItem(path)

            raw_size_item = _Numeric(str(size))
            raw_size_item.setData(size, Qt.UserRole)

            self._model.appendRow(
                [addr_item, size_item, prot_item, shared_item, path_item, raw_size_item]
            )

        self._count_label.setText(
            f"{len(self._snapshot):,} regions · {_format_size(total_bytes)} of virtual address space mapped"
        )

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
