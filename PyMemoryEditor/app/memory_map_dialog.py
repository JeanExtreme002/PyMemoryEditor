# -*- coding: utf-8 -*-
"""
Memory-map dialog — exposes ``process.get_memory_regions()``.

Lists every memory region the target process holds, with address, size,
protection flags (decoded into a human "R W X" string), shared/private state,
and the backing path on Linux. The toolbar buttons let the user:

* copy a base address,
* jump straight into the hex viewer at any region,
* allocate / free memory in the target (Windows & macOS).

The region list auto-refreshes every 1000 ms, so allocations and frees (and any
other mapping changes in the target) show up without a manual refresh. The
dialog also publishes its last snapshot so the main window can reuse it as the
``memory_regions`` kwarg to subsequent scans.
"""
import sys
from typing import Dict, List, Optional

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QFont, QGuiApplication, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
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


# Unit multipliers for the allocate size selector (binary, 1 KB = 1024 B).
_SIZE_UNITS = (
    ("B", 1),
    ("KB", 1024),
    ("MB", 1024 ** 2),
    ("GB", 1024 ** 3),
    ("TB", 1024 ** 4),
)


def _parse_amount(text: str) -> Optional[float]:
    """Parse a positive amount (the number part of a size). None if invalid.

    The unit (B/KB/MB/…) is chosen separately, so this only validates the
    numeric value and allows fractions like ``1.5``.
    """
    cleaned = text.strip().replace("_", "").replace(",", "")
    if not cleaned:
        return None
    try:
        value = float(cleaned)
    except ValueError:
        return None
    return value if value > 0 else None


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

        # allocate/free are a Windows/macOS capability (Linux raises
        # NotImplementedError); the controls are disabled there.
        self._supported = not sys.platform.startswith("linux")
        # When set, the address to re-select after the next refresh finishes
        # (so a freshly allocated region is highlighted once the map reloads).
        self._pending_select: Optional[int] = None

        self.setWindowTitle(f"Memory Map — PID {process.pid}")
        self.resize(900, 580)

        self._build_ui()
        self.refresh()

        # Auto-refresh the region list so allocations / frees (and any other
        # mapping changes in the target) appear without a manual refresh. The
        # refresh() guard self-throttles if a snapshot takes longer than this.
        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(1000)
        self._auto_timer.timeout.connect(self.refresh)
        self._auto_timer.start()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        header = QLabel(
            f"<span style='font-size:16px;font-weight:700;'>Memory Map</span>"
            f" &nbsp;<span style='color:#6E7681;'>PID {self._process.pid}</span>"
        )
        header.setTextFormat(Qt.RichText)
        layout.addWidget(header)

        self._count_label = QLabel("")
        self._count_label.setObjectName("hint")
        layout.addWidget(self._count_label)

        # Top bar: actions on the current selection + a filter box. They all
        # operate on the selected row, so they sit together above the table.
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._hex_btn = QPushButton("Open in Hex Viewer")
        self._hex_btn.clicked.connect(self._emit_hex_viewer_request)
        bar.addWidget(self._hex_btn)

        self._free_btn = QPushButton("Free Selected")
        self._free_btn.setObjectName("danger")
        self._free_btn.clicked.connect(self._on_free_selected)
        bar.addWidget(self._free_btn)

        bar.addStretch(1)

        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filter by path or address…")
        self._filter_edit.setClearButtonEnabled(True)
        self._filter_edit.setFixedWidth(240)
        self._filter_edit.textChanged.connect(lambda _text: self._populate())
        bar.addWidget(self._filter_edit)

        layout.addLayout(bar)

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
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self._table, 1)

        # Footer: the lone "create" action (Allocate) on the left, Close on the
        # right. Both are pinned below the table, so they stay reachable no
        # matter how long the region list is — only the table scrolls.
        footer = QHBoxLayout()
        footer.setSpacing(8)
        footer.addWidget(QLabel("Size:"))

        self._size_edit = QLineEdit()
        self._size_edit.setPlaceholderText("amount")
        self._size_edit.setFont(QFont("Menlo, Consolas, Courier New", 10))
        self._size_edit.setFixedWidth(140)
        self._size_edit.returnPressed.connect(self._on_allocate)
        footer.addWidget(self._size_edit)

        self._unit_combo = QComboBox()
        for unit_label, factor in _SIZE_UNITS:
            self._unit_combo.addItem(unit_label, factor)
        self._unit_combo.setCurrentText("KB")
        footer.addWidget(self._unit_combo)

        self._allocate_btn = QPushButton("Allocate")
        self._allocate_btn.setObjectName("secondary")
        self._allocate_btn.clicked.connect(self._on_allocate)
        footer.addWidget(self._allocate_btn)

        footer.addStretch(1)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        footer.addWidget(close_btn)

        # Wrap the footer row + a short caption explaining the allocate/free
        # feature, shown right under the size input.
        footer_box = QVBoxLayout()
        footer_box.setSpacing(4)
        footer_box.addLayout(footer)

        caption = QLabel(
            "Reserve a new block of memory in the target process — it appears "
            "in the map above."
        )
        caption.setObjectName("hint")
        caption.setWordWrap(True)
        footer_box.addWidget(caption)

        layout.addLayout(footer_box)

        if not self._supported:
            # Memory-region viewing still works on Linux; only allocate/free do
            # not (no cross-process allocation syscall).
            unsupported_tip = (
                "Allocating / freeing memory in another process is not "
                "supported on Linux."
            )
            for widget in (
                self._free_btn,
                self._size_edit,
                self._unit_combo,
                self._allocate_btn,
            ):
                widget.setEnabled(False)
                widget.setToolTip(unsupported_tip)

        # The theme's #danger / #secondary rules add `padding: 7px 14px;
        # min-height: 20px`, making "Free Selected" and "Allocate" taller than
        # the neutral buttons and the inputs (which use the plain QPushButton
        # `padding: 5px 12px`). Override just those box-model properties — with
        # the same selector so it wins as the later rule — to match the plain
        # padding. The themed colors live in separate #danger / #secondary
        # rules and are left untouched.
        self._free_btn.setStyleSheet(
            "QPushButton#danger { padding: 5px 12px; min-height: 0px; }"
        )
        self._allocate_btn.setStyleSheet(
            "QPushButton#secondary { padding: 5px 12px; min-height: 0px; }"
        )

    def snapshot(self) -> List[Dict]:
        """Return the cached region snapshot so the scanner can reuse it."""
        return list(self._snapshot)

    def refresh(self) -> None:
        # Skip if a snapshot is already in flight — the 1000ms auto-refresh timer
        # would otherwise stack workers on a slow (huge) target. This makes the
        # refresh self-throttle to however long a snapshot actually takes.
        if self._worker is not None and self._worker.isRunning():
            return

        # Only show the loading hint before the first snapshot; on the periodic
        # refresh the count label updates silently to avoid flicker. The action
        # controls stay enabled — disabling them every 1000ms would be unusable.
        if not self._snapshot:
            self._count_label.setText("Loading memory regions…")

        worker = _SnapshotWorker(self._process, self)
        worker.snapshot_ready.connect(self._on_snapshot_ready)
        worker.snapshot_failed.connect(self._on_snapshot_failed)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def _on_snapshot_ready(self, snapshot) -> None:
        self._snapshot = list(snapshot)
        self._populate()

    def _populate(self) -> None:
        """(Re)build the table from the cached snapshot, honoring the filter."""
        needle = self._filter_edit.text().strip().lower()

        # Preserve the user's selection and scroll position across the rebuild —
        # the table repopulates every 1000ms, and losing them would make it
        # impossible to keep a row selected or stay scrolled where you were.
        prior_selection = None
        selected_rows = self._table.selectionModel().selectedRows()
        if selected_rows:
            selected_item = self._model.item(selected_rows[0].row(), 0)
            if selected_item is not None:
                prior_selection = selected_item.data(Qt.UserRole)
        scroll_value = self._table.verticalScrollBar().value()

        total = len(self._snapshot)
        total_bytes = sum(int(region["size"]) for region in self._snapshot)

        # Disable sorting while rebuilding so the model isn't re-sorted on every
        # appendRow (and rows don't shuffle mid-build).
        self._table.setSortingEnabled(False)
        self._model.setRowCount(0)

        shown = 0
        for region in self._snapshot:
            addr = int(region["address"])
            size = int(region["size"])
            path = _region_path(region) or ""

            if needle and needle not in path.lower() and needle not in f"0x{addr:x}":
                continue
            shown += 1

            addr_item = NumericItem(f"0x{addr:016X}")
            addr_item.setData(addr, Qt.UserRole)

            size_item = NumericItem(_format_size(size))
            size_item.setData(size, Qt.UserRole)
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            prot_item = QStandardItem(_decode_protection(region))
            shared_item = QStandardItem(_region_shared(region))
            path_item = QStandardItem(path)

            raw_size_item = NumericItem(str(size))
            raw_size_item.setData(size, Qt.UserRole)

            self._model.appendRow(
                [addr_item, size_item, prot_item, shared_item, path_item, raw_size_item]
            )

        self._table.setSortingEnabled(True)

        if needle:
            self._count_label.setText(
                f"{shown:,} of {total:,} regions shown · "
                f"{_format_size(total_bytes)} mapped"
            )
        else:
            self._count_label.setText(
                f"{total:,} regions · "
                f"{_format_size(total_bytes)} of virtual address space mapped"
            )

        # Restore the view. A just-allocated region wins and is scrolled into
        # view; otherwise re-select whatever was selected before and keep the
        # scroll position, so the 1000ms refresh doesn't jump the table around.
        if self._pending_select is not None:
            self._select_address(self._pending_select, scroll=True)
            self._pending_select = None
        else:
            if prior_selection is not None:
                self._select_address(prior_selection, scroll=False)
            self._table.verticalScrollBar().setValue(scroll_value)

    def _select_address(self, address: int, *, scroll: bool = True) -> None:
        """Select the row whose base address equals ``address`` (if present)."""
        for row in range(self._model.rowCount()):
            if self._model.item(row, 0).data(Qt.UserRole) == address:
                self._table.selectRow(row)
                if scroll:
                    self._table.scrollTo(self._model.index(row, 0))
                return

    def _on_snapshot_failed(self, message: str) -> None:
        self._count_label.setText("Failed to read memory regions.")
        QMessageBox.critical(
            self, "Memory Map", f"Failed to read memory regions:\n\n{message}"
        )

    def _on_worker_finished(self) -> None:
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.deleteLater()

    def closeEvent(self, event):  # noqa: N802 — Qt naming
        self._auto_timer.stop()
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

    def _show_context_menu(self, pos) -> None:
        """Right-click menu on a region row: copy its address or backing path."""
        index = self._table.indexAt(pos)
        if not index.isValid():
            return
        self._table.selectRow(index.row())  # operate on the clicked row
        menu = self._build_context_menu(index.row())
        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _build_context_menu(self, row: int) -> QMenu:
        """Build the row's right-click menu (Copy Address / Copy Path).

        Each action copies via ``triggered`` so the behavior is identical
        whether the menu is shown or driven programmatically.
        """
        address = int(self._model.item(row, 0).data(Qt.UserRole))
        path = self._model.item(row, 4).text()

        menu = QMenu(self)
        copy_address = menu.addAction("Copy Address")
        copy_address.triggered.connect(lambda: self._copy_text(f"{address:X}"))

        copy_path = menu.addAction("Copy Path")
        # No path for anonymous regions (and macOS doesn't expose paths) — keep
        # the entry visible for consistency but disabled when there's nothing.
        copy_path.setEnabled(bool(path))
        copy_path.triggered.connect(lambda: self._copy_text(path))
        return menu

    def _copy_text(self, text: str) -> None:
        QGuiApplication.clipboard().setText(text)

    def _emit_hex_viewer_request(self) -> None:
        region = self._selected_region()
        if region is None:
            QMessageBox.information(self, "Memory Map", "Select a region first.")
            return
        # Cap the initial view to keep the hex widget responsive on huge regions.
        size = min(region["size"], 4096)
        self.open_hex_viewer.emit(region["address"], size)

    def _on_allocate(self) -> None:
        amount = _parse_amount(self._size_edit.text())
        if amount is None:
            QMessageBox.warning(
                self,
                "Allocate",
                "Enter a positive amount (e.g. 4 or 1.5) and pick a unit.",
            )
            return

        factor = int(self._unit_combo.currentData())
        size = int(amount * factor)
        if size <= 0:
            QMessageBox.warning(
                self,
                "Allocate",
                "That amount rounds down to 0 bytes — pick a larger value or unit.",
            )
            return

        try:
            address = self._process.allocate_memory(size)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self,
                "Allocate",
                f"Could not allocate {size} byte(s):\n\n{type(exc).__name__}: {exc}",
            )
            return

        QMessageBox.information(
            self, "Memory allocated", f"Allocated memory at 0x{address:X}."
        )
        self._size_edit.clear()
        # Reload the map so the new region appears, then select it.
        self._pending_select = int(address)
        self.refresh()

    def _on_free_selected(self) -> None:
        region = self._selected_region()
        if region is None:
            QMessageBox.information(self, "Memory Map", "Select a region to free first.")
            return

        address = region["address"]
        reply = QMessageBox.warning(
            self,
            "Free memory",
            f"Free the region at 0x{address:X}?\n\n"
            "This releases memory previously reserved with Allocate. Only "
            "regions allocated through this tool can be freed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        # No size argument: the process reuses the size it recorded at allocation
        # time. The OS often coalesces a fresh allocation with neighbours in the
        # region map, so the *displayed* size can be larger than what we
        # allocated — freeing that wider span would target memory we don't own.
        try:
            self._process.free_memory(address)
        except ValueError:
            # macOS: address isn't a tracked allocation (unknown size). Refuse
            # rather than guess a size and risk tearing down unrelated memory.
            QMessageBox.warning(
                self,
                "Free memory",
                f"0x{address:X} was not allocated through this tool, so its size "
                "is unknown and it can't be freed here. Use the Allocate box to "
                "create regions you can free.",
            )
            return
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self,
                "Free memory",
                f"Could not free 0x{address:X}:\n\n{type(exc).__name__}: {exc}",
            )
            return

        self.refresh()
