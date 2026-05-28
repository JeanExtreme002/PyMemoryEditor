# -*- coding: utf-8 -*-
"""
Main application window — Cheat-Engine inspired layout.

Layout:

    +------------------------------------------------------------+
    |  Process: <name>  PID <pid>           [ Change ] [ Map ]   |
    +-------------------+----------------------------------------+
    | Scanner panel     |  Found addresses (model/view, streams) |
    | (left, fixed-ish) |                                        |
    |                   +----------------------------------------+
    |                   |  Cheat table (saved addresses, freeze) |
    +-------------------+----------------------------------------+
    |  Progress bar  |  Status text                              |
    +------------------------------------------------------------+
"""
import json
import logging
import sys
from typing import List, Optional, Union

import psutil

from PySide6.QtCore import Qt, QSettings, QTimer, Signal
from PySide6.QtGui import QAction, QActionGroup, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from PyMemoryEditor import AbstractProcess, __version__

from ._icon import app_icon
from .application import DEFAULT_THEME_ID, THEMES, apply_theme
from .cheat_entry import CheatEntry
from .cheat_table import CheatTable
from .log_console_dialog import LogConsoleDialog
from .memory_map_dialog import MemoryMapDialog
from .memory_viewer_dialog import MemoryViewerDialog
from .modules_dialog import ModulesDialog
from .pointer_chain_dialog import PointerChainDialog
from .pointer_scan_dialog import PointerScanDialog
from .results_view import ResultsModel, ResultsView
from .scan_worker import FirstScanWorker, RefineScanWorker, ScanRequest
from .scanner_panel import ScannerPanel
from .threads_dialog import ThreadsDialog


# Child of "PyMemoryEditor" — the Log Console captures these via propagation.
_LOG = logging.getLogger(__name__)

# Cadence at which we poll psutil to check the target process is still alive.
# 2 s is brisk enough that a dead target's cleanup happens before the user
# tries to refine a scan, but slow enough to keep the cost negligible.
_HEARTBEAT_INTERVAL_MS = 2000

# Maximum time we'll wait for a running worker thread to finish on shutdown.
_WORKER_SHUTDOWN_WAIT_MS = 2000


class MainWindow(QMainWindow):

    closing = Signal()

    def __init__(self, process: AbstractProcess):
        super().__init__()
        self._process = process
        self._worker: Optional[Union[FirstScanWorker, RefineScanWorker]] = None
        self._region_snapshot: Optional[list] = None
        self._memory_map: Optional[MemoryMapDialog] = None
        self._hex_viewers: List[MemoryViewerDialog] = []

        self._proc_name = self._read_proc_name()
        self.setWindowTitle(self._window_title())
        self.setWindowIcon(app_icon())
        self.resize(1280, 780)

        # Lazy slots for the new dialogs — instantiated on first open,
        # cached so subsequent opens reuse the same window (matches the
        # behavior of the existing memory_map dialog).
        self._threads_dialog: Optional[ThreadsDialog] = None
        self._modules_dialog: Optional[ModulesDialog] = None
        self._pointer_chain_dialog: Optional[PointerChainDialog] = None
        self._pointer_scan_dialog: Optional[PointerScanDialog] = None
        self._log_console_dialog: Optional[LogConsoleDialog] = None

        self._build_ui()

        # Heartbeat — make sure the target process is still alive. If it
        # disappears we tear down the freeze timer + lock the scanner so the
        # user gets a clean message instead of cryptic OSErrors.
        self._heartbeat = QTimer(self)
        self._heartbeat.setInterval(_HEARTBEAT_INTERVAL_MS)
        self._heartbeat.timeout.connect(self._check_process_alive)
        self._heartbeat.start()

    def _build_ui(self) -> None:
        central = QWidget(self)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        bar = QHBoxLayout()
        bar.setSpacing(10)

        title = QLabel("PyMemoryEditor")
        title.setStyleSheet("font-size:18px;font-weight:700;")
        bar.addWidget(title)

        version = QLabel(f"v{__version__}")
        version.setObjectName("hint")
        bar.addWidget(version)

        bar.addStretch(1)

        self._process_badge = QLabel(self._process_badge_text())
        self._process_badge.setObjectName("processBadge")
        bar.addWidget(self._process_badge)

        change_btn = QPushButton("Change Process…")
        change_btn.clicked.connect(self._change_process)
        bar.addWidget(change_btn)
        outer.addLayout(bar)

        outer_splitter = QSplitter(Qt.Horizontal)
        outer_splitter.setHandleWidth(4)
        outer_splitter.setChildrenCollapsible(False)

        self._scanner = ScannerPanel()
        self._scanner.first_scan_requested.connect(self._on_first_scan)
        self._scanner.next_scan_requested.connect(self._on_next_scan)
        self._scanner.update_values_requested.connect(self._on_update_values)
        self._scanner.new_scan_requested.connect(self._on_new_scan)
        self._scanner.cancel_requested.connect(self._on_cancel)
        outer_splitter.addWidget(self._scanner)

        # Right: results table + cheat table stacked. We keep the splitter on
        # self because _change_process needs to swap the cheat-table widget,
        # and QSplitter has its own widget management (no Q*Layout).
        self._right_splitter = QSplitter(Qt.Vertical)
        right_splitter = self._right_splitter
        right_splitter.setHandleWidth(4)
        right_splitter.setChildrenCollapsible(False)

        # The right (vertical) splitter sits flush against the outer
        # (horizontal) splitter handle, which makes the two divider lines
        # touch at a "T" intersection. We wrap it in a container with a
        # left inset so the horizontal divider has a small gap from the
        # vertical one.
        right_container = QWidget()
        right_container_layout = QHBoxLayout(right_container)
        right_container_layout.setContentsMargins(8, 0, 0, 0)
        right_container_layout.setSpacing(0)
        right_container_layout.addWidget(right_splitter)

        # Results — small bottom margin so the table doesn't sit flush
        # against the right splitter handle.
        results_wrap = QWidget()
        results_layout = QVBoxLayout(results_wrap)
        results_layout.setContentsMargins(0, 0, 0, 4)
        results_layout.setSpacing(6)

        self._results_label = QLabel("No scan yet. Press First Scan to begin.")
        self._results_label.setObjectName("hint")
        results_layout.addWidget(self._results_label)

        self._results_model = ResultsModel(self)
        self._results_view = ResultsView()
        self._results_view.setModel(self._results_model)
        self._results_view.promote_to_cheat_table.connect(self._promote_to_cheat_table)
        self._results_view.open_in_hex_viewer.connect(self._open_hex_viewer)
        self._results_view.pointer_scan_for_address.connect(
            self._open_pointer_scan_dialog
        )
        results_layout.addWidget(self._results_view, 1)

        right_splitter.addWidget(results_wrap)

        self._cheat = CheatTable(self._process)
        self._cheat.pointer_scan_for_address.connect(self._open_pointer_scan_dialog)
        right_splitter.addWidget(self._cheat)
        right_splitter.setSizes([520, 260])

        outer_splitter.addWidget(right_container)
        outer_splitter.setSizes([320, 1040])
        outer.addWidget(outer_splitter, 1)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setTextVisible(True)
        outer.addWidget(self._progress)

        self.setCentralWidget(central)

        self._build_menu_and_toolbar()

        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("Ready.")

    def _build_menu_and_toolbar(self) -> None:
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("&File")
        export_results = QAction("Export Results…", self)
        export_results.setShortcut(QKeySequence("Ctrl+E"))
        export_results.triggered.connect(self._export_results)
        file_menu.addAction(export_results)

        change_proc = QAction("Change Process…", self)
        change_proc.setShortcut(QKeySequence("Ctrl+O"))
        change_proc.triggered.connect(self._change_process)
        file_menu.addAction(change_proc)
        file_menu.addSeparator()
        quit_action = QAction("Quit", self)
        quit_action.setShortcut(QKeySequence.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        tools_menu = menu_bar.addMenu("&Tools")
        memory_map_action = QAction("Memory Map…", self)
        memory_map_action.setShortcut(QKeySequence("Ctrl+M"))
        memory_map_action.triggered.connect(self._open_memory_map)
        tools_menu.addAction(memory_map_action)

        hex_viewer_action = QAction("Hex Viewer…", self)
        hex_viewer_action.setShortcut(QKeySequence("Ctrl+H"))
        hex_viewer_action.triggered.connect(lambda: self._open_hex_viewer(0))
        tools_menu.addAction(hex_viewer_action)

        threads_action = QAction("Threads…", self)
        threads_action.setShortcut(QKeySequence("Ctrl+T"))
        threads_action.triggered.connect(self._open_threads_dialog)
        tools_menu.addAction(threads_action)

        modules_action = QAction("Modules…", self)
        modules_action.setShortcut(QKeySequence("Ctrl+Shift+M"))
        modules_action.triggered.connect(self._open_modules_dialog)
        tools_menu.addAction(modules_action)

        pointer_chain_action = QAction("Resolve Pointer Chain…", self)
        pointer_chain_action.setShortcut(QKeySequence("Ctrl+Shift+P"))
        pointer_chain_action.triggered.connect(self._open_pointer_chain_dialog)
        tools_menu.addAction(pointer_chain_action)

        pointer_scan_action = QAction("Pointer Scan…", self)
        pointer_scan_action.setShortcut(QKeySequence("Ctrl+Shift+S"))
        pointer_scan_action.triggered.connect(lambda: self._open_pointer_scan_dialog())
        tools_menu.addAction(pointer_scan_action)

        tools_menu.addSeparator()

        log_console_action = QAction("Log Console…", self)
        log_console_action.setShortcut(QKeySequence("Ctrl+L"))
        log_console_action.triggered.connect(self._open_log_console)
        tools_menu.addAction(log_console_action)

        refresh_snapshot = QAction("Refresh Region Snapshot", self)
        refresh_snapshot.triggered.connect(self._refresh_region_snapshot)
        tools_menu.addAction(refresh_snapshot)

        help_menu = menu_bar.addMenu("&Help")
        about = QAction("About", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)

        toolbar = QToolBar("Main", self)
        toolbar.setMovable(False)
        toolbar.addAction(memory_map_action)
        toolbar.addAction(modules_action)
        toolbar.addAction(hex_viewer_action)
        toolbar.addAction(pointer_chain_action)
        toolbar.addAction(pointer_scan_action)
        toolbar.addSeparator()
        toolbar.addAction(export_results)

        # Push the theme switcher all the way to the right.
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)
        toolbar.addWidget(self._build_theme_button())

        self.addToolBar(toolbar)

    def _build_theme_button(self) -> QToolButton:
        """Toolbar button that opens a menu of dark themes (Kali, Dracula, …)."""
        button = QToolButton(self)
        button.setText("Theme")
        button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        button.setToolTip("Switch color theme")

        menu = QMenu(button)
        current_id = str(QSettings().value("theme", DEFAULT_THEME_ID))
        self._theme_actions = QActionGroup(self)
        self._theme_actions.setExclusive(True)

        for theme_id, theme in THEMES.items():
            action = QAction(theme.name, self, checkable=True)
            action.setData(theme_id)
            if theme_id == current_id:
                action.setChecked(True)
            # Bind theme_id at lambda-definition time so each menu entry
            # captures its own id instead of the loop variable.
            action.triggered.connect(
                lambda _checked=False, tid=theme_id: self._on_theme_changed(tid)
            )
            self._theme_actions.addAction(action)
            menu.addAction(action)

        button.setMenu(menu)
        return button

    def _on_theme_changed(self, theme_id: str) -> None:
        apply_theme(QApplication.instance(), theme_id)
        QSettings().setValue("theme", theme_id)

    def _on_first_scan(self, request: ScanRequest) -> None:
        if self._worker is not None:
            return

        # Build a cached region snapshot the first time the user asks for one.
        if self._scanner.use_snapshot_cache() and self._region_snapshot is None:
            try:
                self._region_snapshot = self._process.snapshot_memory_regions()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(
                    self,
                    "Memory regions",
                    f"Could not cache memory regions ({exc}). Continuing without cache.",
                )
                self._region_snapshot = None

        request.memory_regions = (
            self._region_snapshot if self._scanner.use_snapshot_cache() else None
        )

        self._results_model.clear()
        self._results_model.set_value_spec(request.spec)
        self._set_busy(True)
        self._progress.setValue(0)
        self._status.showMessage("Scanning…")

        worker = FirstScanWorker(self._process, request, self)
        # Block the worker on each chunk so the UI event loop has room to
        # service the Cancel button click between chunks — otherwise the
        # queued chunk_ready signals can starve mouse events.
        worker.chunk_ready.connect(
            self._on_first_chunk, Qt.ConnectionType.BlockingQueuedConnection
        )
        worker.progress.connect(self._progress.setValue)
        worker.status.connect(self._status.showMessage)
        worker.error.connect(self._on_worker_error)
        worker.finished_ok.connect(self._on_first_scan_done)
        # Connection order matters: _cleanup_worker must clear self._worker
        # before _fill_initial_values runs, otherwise the busy guard in
        # _on_update_values rejects the auto-refresh.
        worker.finished.connect(self._cleanup_worker)
        worker.finished.connect(lambda: self._fill_initial_values(request))
        self._worker = worker
        worker.start()

    def _on_next_scan(self, request: ScanRequest) -> None:
        if self._worker is not None:
            return
        if self._results_model.count() == 0:
            QMessageBox.information(
                self, "Next Scan", "No results yet — run First Scan first."
            )
            return

        request.memory_regions = (
            self._region_snapshot if self._scanner.use_snapshot_cache() else None
        )
        self._results_model.set_value_spec(request.spec)

        self._set_busy(True)
        self._progress.setValue(0)
        self._status.showMessage("Refining…")

        worker = RefineScanWorker(
            self._process,
            request,
            self._results_model.all_addresses(),
            filter_only=True,
            # Baseline for the Increased/Decreased/Changed/Unchanged comparisons.
            previous_values=self._results_model.value_map(),
            parent=self,
        )
        worker.chunk_ready.connect(
            self._results_model.patch_values,
            Qt.ConnectionType.BlockingQueuedConnection,
        )
        worker.progress.connect(self._progress.setValue)
        worker.status.connect(self._status.showMessage)
        worker.error.connect(self._on_worker_error)
        worker.finished_ok.connect(self._on_refine_done)
        worker.finished.connect(self._cleanup_worker)
        self._worker = worker
        worker.start()

    def _on_update_values(self, request: ScanRequest) -> None:
        if self._worker is not None:
            return
        if self._results_model.count() == 0:
            return

        request.memory_regions = (
            self._region_snapshot if self._scanner.use_snapshot_cache() else None
        )
        self._results_model.set_value_spec(request.spec)

        self._set_busy(True)
        self._progress.setValue(0)
        self._status.showMessage("Updating values…")

        worker = RefineScanWorker(
            self._process,
            request,
            self._results_model.all_addresses(),
            filter_only=False,
            parent=self,
        )
        worker.chunk_ready.connect(
            self._results_model.patch_values,
            Qt.ConnectionType.BlockingQueuedConnection,
        )
        worker.progress.connect(self._progress.setValue)
        worker.status.connect(self._status.showMessage)
        worker.error.connect(self._on_worker_error)
        worker.finished_ok.connect(self._on_refresh_done)
        worker.finished.connect(self._cleanup_worker)
        self._worker = worker
        worker.start()

    def _fill_initial_values(self, request: ScanRequest) -> None:
        # If the first-scan worker dropped or had zero hits, skip the refresh.
        if self._results_model.count() == 0:
            return
        # Don't recurse into another scan if the user has already triggered one.
        if self._worker is not None:
            return
        # AOB pattern matches don't have a "current value" the way a numeric
        # scan does — read_process_memory with the spec's (bytes, length=0)
        # would error, and even with a non-zero length the bytes are the same
        # ones the pattern already located. Skip the auto-refresh and leave
        # the value column empty — the user can promote rows to the cheat
        # table for a live preview there.
        if request.spec.is_pattern:
            return
        self._on_update_values(request)

    def _on_new_scan(self) -> None:
        if self._worker is not None:
            return
        self._results_model.clear()
        self._scanner.set_has_results(False)
        self._progress.setValue(0)
        self._results_label.setText("No scan yet. Press First Scan to begin.")
        self._status.showMessage("Ready.")

    def _on_cancel(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self._status.showMessage("Cancelling…")

    def _on_first_chunk(self, chunk) -> None:
        self._results_model.append_chunk(chunk)
        self._results_label.setText(f"{self._results_model.count():,} addresses found.")

    def _on_first_scan_done(self, count: int) -> None:
        self._results_label.setText(f"{self._results_model.count():,} addresses found.")
        if count == 0:
            self._scanner.set_has_results(False)
        else:
            self._scanner.set_has_results(True)

    def _on_refine_done(self, kept: int) -> None:
        self._results_label.setText(f"{self._results_model.count():,} addresses left.")
        self._scanner.set_has_results(self._results_model.count() > 0)

    def _on_refresh_done(self, _kept: int) -> None:
        self._results_label.setText(
            f"{self._results_model.count():,} addresses found."
        )
        self._scanner.set_has_results(self._results_model.count() > 0)

    def _on_worker_error(self, message: str) -> None:
        _LOG.error("Scan worker error: %s", message)
        QMessageBox.critical(self, "Scan error", message)
        self._status.showMessage(message)

    def _cleanup_worker(self) -> None:
        self._worker = None
        self._set_busy(False)

    def _set_busy(self, busy: bool) -> None:
        self._scanner.set_busy(busy)

    def _promote_to_cheat_table(self, addresses: List[int]) -> None:
        if not addresses:
            return
        spec, length = self._scanner.current_spec_and_length()
        self._cheat.add_addresses(addresses, spec, length, description="")
        self._status.showMessage(f"Added {len(addresses)} address(es) to cheat table.")

    def _open_memory_map(self) -> None:
        if self._memory_map is None:
            self._memory_map = MemoryMapDialog(self._process, self)
            self._memory_map.open_hex_viewer.connect(self._open_hex_viewer_with_size)
            self._memory_map.finished.connect(self._on_memory_map_closed)
        else:
            self._memory_map.refresh()
        self._memory_map.show()
        self._memory_map.raise_()
        self._memory_map.activateWindow()

    def _on_memory_map_closed(self, _result: int) -> None:
        # Adopt the dialog's snapshot as the cached one — the user pressed
        # Refresh in there, the data is fresh.
        if self._memory_map is not None:
            snap = self._memory_map.snapshot()
            if snap:
                self._region_snapshot = snap
        self._memory_map = None

    def _open_threads_dialog(self) -> None:
        if self._threads_dialog is None:
            self._threads_dialog = ThreadsDialog(self._process, self)
            self._threads_dialog.finished.connect(self._on_threads_dialog_closed)
        else:
            self._threads_dialog.refresh()
        self._threads_dialog.show()
        self._threads_dialog.raise_()
        self._threads_dialog.activateWindow()

    def _on_threads_dialog_closed(self, _result: int) -> None:
        self._threads_dialog = None

    def _open_modules_dialog(self) -> None:
        if self._modules_dialog is None:
            self._modules_dialog = ModulesDialog(self._process, self)
            self._modules_dialog.open_hex_viewer.connect(
                self._open_hex_viewer_with_size
            )
            self._modules_dialog.resolve_pointer_chain.connect(
                self._on_module_resolve_chain
            )
            self._modules_dialog.finished.connect(self._on_modules_dialog_closed)
        else:
            self._modules_dialog.refresh()
        self._modules_dialog.show()
        self._modules_dialog.raise_()
        self._modules_dialog.activateWindow()

    def _on_modules_dialog_closed(self, _result: int) -> None:
        self._modules_dialog = None

    def _open_pointer_chain_dialog(self) -> None:
        if self._pointer_chain_dialog is None:
            self._pointer_chain_dialog = PointerChainDialog(self._process, self)
            self._pointer_chain_dialog.add_to_cheat_table.connect(
                self._on_pointer_chain_promote
            )
            self._pointer_chain_dialog.finished.connect(
                self._on_pointer_chain_dialog_closed
            )
        self._pointer_chain_dialog.show()
        self._pointer_chain_dialog.raise_()
        self._pointer_chain_dialog.activateWindow()

    def _on_pointer_chain_dialog_closed(self, _result: int) -> None:
        self._pointer_chain_dialog = None

    def _on_module_resolve_chain(self, base_address: int) -> None:
        """Open the Pointer Chain tool with a module's base address prefilled."""
        self._open_pointer_chain_dialog()
        self._pointer_chain_dialog.set_base_address(int(base_address))

    def _on_pointer_chain_promote(
        self, address: int, spec_label: str, length: int
    ) -> None:
        """Promote a resolved pointer-chain address into the cheat table."""
        entry = CheatEntry(
            description="",
            address=int(address),
            spec_label=spec_label,
            length=int(length),
        )
        self._cheat.add_entry(entry)
        self._status.showMessage(
            f"Added 0x{address:X} to cheat table (from pointer chain)."
        )

    def _open_pointer_scan_dialog(self, address: int = 0) -> None:
        """Open the Pointer Scan dialog, optionally prefilled with an address.

        ``address`` is passed by the results view's "Pointer scan for this
        address" entry (Cheat Engine's workflow); the menu/toolbar action opens
        it blank.
        """
        if self._pointer_scan_dialog is None:
            self._pointer_scan_dialog = PointerScanDialog(self._process, self)
            self._pointer_scan_dialog.add_to_cheat_table.connect(
                self._on_pointer_scan_promote
            )
            self._pointer_scan_dialog.open_hex_viewer.connect(
                self._open_hex_viewer_with_size
            )
            self._pointer_scan_dialog.finished.connect(
                self._on_pointer_scan_dialog_closed
            )
        if address:
            self._pointer_scan_dialog.set_target_address(int(address))
        self._pointer_scan_dialog.show()
        self._pointer_scan_dialog.raise_()
        self._pointer_scan_dialog.activateWindow()

    def _on_pointer_scan_dialog_closed(self, _result: int) -> None:
        self._pointer_scan_dialog = None

    def _on_pointer_scan_promote(
        self, address: int, spec_label: str, length: int
    ) -> None:
        """Promote a resolved pointer-scan path's address into the cheat table."""
        entry = CheatEntry(
            description="",
            address=int(address),
            spec_label=spec_label,
            length=int(length),
        )
        self._cheat.add_entry(entry)
        self._status.showMessage(
            f"Added 0x{address:X} to cheat table (from pointer scan)."
        )

    def _open_log_console(self) -> None:
        if self._log_console_dialog is None:
            self._log_console_dialog = LogConsoleDialog(self)
            self._log_console_dialog.finished.connect(
                self._on_log_console_closed
            )
        self._log_console_dialog.show()
        self._log_console_dialog.raise_()
        self._log_console_dialog.activateWindow()

    def _on_log_console_closed(self, _result: int) -> None:
        self._log_console_dialog = None

    def _open_hex_viewer(self, address: int) -> None:
        self._open_hex_viewer_with_size(address, 256)

    def _open_hex_viewer_with_size(self, address: int, size: int) -> None:
        viewer = MemoryViewerDialog(
            self._process, address=address, length=size, parent=self
        )
        viewer.setAttribute(Qt.WA_DeleteOnClose, True)
        viewer.destroyed.connect(
            lambda _o=None, v=viewer: (
                self._hex_viewers.remove(v) if v in self._hex_viewers else None
            )
        )
        self._hex_viewers.append(viewer)
        viewer.show()

    def _refresh_region_snapshot(self) -> None:
        try:
            self._region_snapshot = self._process.snapshot_memory_regions()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Memory regions", f"Failed: {exc}")
            return
        self._status.showMessage(
            f"Cached {len(self._region_snapshot):,} memory regions."
        )

    def _export_results(self) -> None:
        if self._results_model.count() == 0:
            QMessageBox.information(
                self, "Export", "No results to export — run a scan first."
            )
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export results",
            "scan_results.json",
            "JSON files (*.json);;All files (*)",
        )
        if not filename:
            return

        payload = {
            "process": {
                "pid": self._process.pid,
                "name": self._proc_name,
            },
            "addresses": [
                {
                    "address": f"0x{self._results_model.address_at(i):X}",
                    "value": _safe_for_json(self._results_model.value_at(i)),
                }
                for i in range(self._results_model.count())
            ],
        }
        try:
            with open(filename, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except OSError as exc:
            QMessageBox.critical(self, "Export", f"Could not write file:\n\n{exc}")
            return
        self._status.showMessage(
            f"Exported {self._results_model.count():,} addresses to {filename}."
        )

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About PyMemoryEditor",
            f"<b>PyMemoryEditor</b> v{__version__}<br>"
            f"PyMemoryEditor App — Cheat Engine-style memory scanner.<br><br>"
            f"<b>Platform:</b> {sys.platform}<br>"
            f"<b>Target process:</b> PID {self._process.pid} ({self._proc_name})<br><br>"
            "Source: <a href='https://github.com/JeanExtreme002/PyMemoryEditor'>"
            "github.com/JeanExtreme002/PyMemoryEditor</a>",
        )

    def _process_badge_text(self) -> str:
        return f"PID {self._process.pid}  ·  {self._proc_name}"

    def _window_title(self) -> str:
        # Qt prepends QGuiApplication.applicationDisplayName to the window
        # title on Windows/Linux; including it here would duplicate it.
        return f"PID {self._process.pid} · {self._proc_name}"

    def _read_proc_name(self) -> str:
        try:
            return psutil.Process(self._process.pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "<unknown>"

    def _check_process_alive(self) -> None:
        if not psutil.pid_exists(self._process.pid):
            self._heartbeat.stop()
            self._scanner.set_busy(True)
            self._status.showMessage("Target process exited — operations disabled.")
            QMessageBox.warning(
                self,
                "Process exited",
                "The target process has exited. Open another process via File → Change Process…",
            )

    def _change_process(self) -> None:
        from .open_process_dialog import OpenProcessDialog

        if self._worker is not None:
            QMessageBox.information(
                self, "Change process", "Wait for the current scan to finish first."
            )
            return

        picker = OpenProcessDialog(self)
        if picker.exec() != picker.DialogCode.Accepted or picker.process is None:
            return

        try:
            self._process.close()
        except Exception:
            pass

        self._process = picker.process
        self._proc_name = self._read_proc_name()
        self.setWindowTitle(self._window_title())
        self._process_badge.setText(self._process_badge_text())
        self._region_snapshot = None
        self._results_model.clear()
        self._scanner.set_has_results(False)

        # Tear down auxiliary dialogs that hold a reference to the old
        # process — reopening them rebuilds against the new target.
        for dialog_attr in (
            "_threads_dialog",
            "_modules_dialog",
            "_pointer_chain_dialog",
            "_pointer_scan_dialog",
        ):
            existing = getattr(self, dialog_attr, None)
            if existing is not None:
                existing.close()
                setattr(self, dialog_attr, None)
        # Replace the cheat table — old entries point at the previous process.
        # QSplitter has no QLayout, so we use its native replaceWidget(index).
        old_cheat = self._cheat
        old_index = self._right_splitter.indexOf(old_cheat)
        self._cheat = CheatTable(self._process)
        self._cheat.pointer_scan_for_address.connect(self._open_pointer_scan_dialog)
        if old_index >= 0:
            self._right_splitter.replaceWidget(old_index, self._cheat)
        else:
            self._right_splitter.addWidget(self._cheat)
        old_cheat.setParent(None)
        old_cheat.deleteLater()
        self._heartbeat.start()
        self._status.showMessage(f"Now targeting PID {self._process.pid}.")

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self._worker.wait(_WORKER_SHUTDOWN_WAIT_MS)
        self._heartbeat.stop()
        self.closing.emit()
        super().closeEvent(event)


def _safe_for_json(value) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return repr(value)
