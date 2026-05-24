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
import sys
from typing import List, Optional, Union

import psutil

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStatusBar,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from PyMemoryEditor import AbstractProcess, __version__

from ._icon import app_icon
from .cheat_table import CheatTable
from .memory_map_dialog import MemoryMapDialog
from .memory_viewer_dialog import MemoryViewerDialog
from .results_view import ResultsModel, ResultsView
from .scan_worker import FirstScanWorker, RefineScanWorker, ScanRequest
from .scanner_panel import ScannerPanel


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

        self._build_ui()

        # Heartbeat — make sure the target process is still alive. If it
        # disappears we tear down the freeze timer + lock the scanner so the
        # user gets a clean message instead of cryptic OSErrors.
        self._heartbeat = QTimer(self)
        self._heartbeat.setInterval(_HEARTBEAT_INTERVAL_MS)
        self._heartbeat.timeout.connect(self._check_process_alive)
        self._heartbeat.start()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        central = QWidget(self)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        # Process badge bar
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

        # Splitter for scanner + (results / cheat table)
        outer_splitter = QSplitter(Qt.Horizontal)
        outer_splitter.setHandleWidth(2)
        outer_splitter.setChildrenCollapsible(False)

        # Left: scanner panel
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
        right_splitter.setHandleWidth(2)
        right_splitter.setChildrenCollapsible(False)

        # Results
        results_wrap = QWidget()
        results_layout = QVBoxLayout(results_wrap)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(6)

        self._results_label = QLabel("No scan yet. Press First Scan to begin.")
        self._results_label.setObjectName("hint")
        results_layout.addWidget(self._results_label)

        self._results_model = ResultsModel(self)
        self._results_view = ResultsView()
        self._results_view.setModel(self._results_model)
        self._results_view.promote_to_cheat_table.connect(self._promote_to_cheat_table)
        self._results_view.open_in_hex_viewer.connect(self._open_hex_viewer)
        results_layout.addWidget(self._results_view, 1)

        right_splitter.addWidget(results_wrap)

        # Cheat table
        self._cheat = CheatTable(self._process)
        right_splitter.addWidget(self._cheat)
        right_splitter.setSizes([520, 260])

        outer_splitter.addWidget(right_splitter)
        outer_splitter.setSizes([320, 1040])
        outer.addWidget(outer_splitter, 1)

        # Progress + status
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setTextVisible(True)
        outer.addWidget(self._progress)

        self.setCentralWidget(central)

        # Menu bar and toolbar
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
        toolbar.addAction(hex_viewer_action)
        toolbar.addSeparator()
        toolbar.addAction(export_results)
        self.addToolBar(toolbar)

    # ----------------------------------------------------------- scanner glue

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
        worker.chunk_ready.connect(self._on_first_chunk)
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
            parent=self,
        )
        worker.chunk_ready.connect(self._results_model.patch_values)
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
        worker.chunk_ready.connect(self._results_model.patch_values)
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
            f"{self._results_model.count():,} addresses — values refreshed."
        )
        self._scanner.set_has_results(self._results_model.count() > 0)

    def _on_worker_error(self, message: str) -> None:
        QMessageBox.critical(self, "Scan error", message)
        self._status.showMessage(message)

    def _cleanup_worker(self) -> None:
        self._worker = None
        self._set_busy(False)

    def _set_busy(self, busy: bool) -> None:
        self._scanner.set_busy(busy)

    # ----------------------------------------------------------- cheat table

    def _promote_to_cheat_table(self, addresses: List[int]) -> None:
        if not addresses:
            return
        spec, length = self._scanner.current_spec_and_length()
        self._cheat.add_addresses(addresses, spec, length, description="")
        self._status.showMessage(f"Added {len(addresses)} address(es) to cheat table.")

    # ----------------------------------------------------------- dialogs

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

    # ----------------------------------------------------------- file ops

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

    # ----------------------------------------------------------- about / process info

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About PyMemoryEditor",
            f"<b>PyMemoryEditor</b> v{__version__}<br>"
            f"Qt app — Cheat Engine-style memory scanner.<br><br>"
            f"<b>Platform:</b> {sys.platform}<br>"
            f"<b>Target process:</b> PID {self._process.pid} ({self._proc_name})<br><br>"
            "Source: <a href='https://github.com/JeanExtreme002/PyMemoryEditor'>"
            "github.com/JeanExtreme002/PyMemoryEditor</a>",
        )

    def _process_badge_text(self) -> str:
        return f"PID {self._process.pid}  ·  {self._proc_name}"

    def _window_title(self) -> str:
        return f"PyMemoryEditor — Qt App  (PID {self._process.pid} · {self._proc_name})"

    def _read_proc_name(self) -> str:
        try:
            return psutil.Process(self._process.pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "<unknown>"

    def _check_process_alive(self) -> None:
        if not psutil.pid_exists(self._process.pid):
            self._heartbeat.stop()
            self._scanner.set_busy(True)  # disable scan controls
            self._status.showMessage("Target process exited — operations disabled.")
            QMessageBox.warning(
                self,
                "Process exited",
                "The target process has exited. Open another process via File → Change Process…",
            )

    # ----------------------------------------------------------- change / close

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
        # Replace the cheat table — old entries point at the previous process.
        # QSplitter has no QLayout, so we use its native replaceWidget(index).
        old_cheat = self._cheat
        old_index = self._right_splitter.indexOf(old_cheat)
        self._cheat = CheatTable(self._process)
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
