# -*- coding: utf-8 -*-
"""
Cheat-Engine-style "Open Process" dialog.

Lists all visible processes via psutil and lets the user pick one — either by
clicking a row, typing a PID, or typing a process name (with an optional
case-insensitive toggle, surfacing the library's ``case_sensitive`` flag).
"""
import ctypes
import sys
from typing import Callable, List, Optional, Tuple

import psutil

from PySide6.QtCore import QModelIndex, QSortFilterProxyModel, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from PyMemoryEditor import (
    AbstractProcess,
    AmbiguousProcessNameError,
    OpenProcess,
    ProcessIDNotExistsError,
    ProcessNotFoundError,
    __version__,
)

from ._icon import app_icon
from ._widgets import NumericItem


if sys.platform == "win32":
    from PyMemoryEditor import ProcessOperationsEnum

    _APP_PERMISSION = (
        ProcessOperationsEnum.PROCESS_VM_READ.value
        | ProcessOperationsEnum.PROCESS_VM_WRITE.value
        | ProcessOperationsEnum.PROCESS_VM_OPERATION.value
        | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION.value
    )
else:
    # The Linux/macOS backends ignore the ``permission`` kwarg.
    _APP_PERMISSION = None


# macOS: psutil's rss includes shared framework pages, so it over-reports vs.
# Activity Monitor's "Memory" column (which uses phys_footprint). proc_pid_rusage
# exposes phys_footprint directly and doesn't need task_for_pid.
def _build_macos_phys_footprint() -> Optional[Callable[[int], int]]:
    if sys.platform != "darwin":
        return None
    try:
        from PyMemoryEditor.macos.libsystem import (
            RUSAGE_INFO_V0,
            libsystem,
            rusage_info_v0,
        )
    except (OSError, AttributeError):
        return None

    def _impl(pid: int) -> int:
        info = rusage_info_v0()
        if libsystem.proc_pid_rusage(pid, RUSAGE_INFO_V0, ctypes.byref(info)) != 0:
            return -1
        return int(info.ri_phys_footprint)

    return _impl


_macos_phys_footprint: Optional[Callable[[int], int]] = _build_macos_phys_footprint()


def _open_kwargs():
    return {"permission": _APP_PERMISSION} if _APP_PERMISSION is not None else {}


def _human_kb(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    units = ["KB", "MB", "GB", "TB"]
    n = float(size_bytes)
    for unit in units:
        n /= 1024
        if n < 1024:
            return f"{n:,.1f} {unit}"
    return f"{n:,.1f} PB"


# How long the auto-refresh waits between process-list re-enumerations.
_REFRESH_INTERVAL_MS = 3000


class _ProcessListWorker(QThread):
    """Enumerate processes via psutil on a background thread.

    psutil.process_iter walks /proc (Linux), uses Win32 toolhelp APIs
    (Windows) or proc_listallpids (macOS). On systems with many processes
    that scan is noticeable, and doing it on a UI tick blocks input until
    it finishes.
    """

    rows_ready = Signal(object)  # List[Tuple[int, str, int, str]]

    def run(self) -> None:
        rows: List[Tuple[int, str, int, str]] = []
        transient = (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess)
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                info = proc.info
                name = (info.get("name") or "").strip() or f"<pid {info['pid']}>"
                user = info.get("username") or ""
                pid = int(info["pid"])
                mem = -1
                if _macos_phys_footprint is not None:
                    mem = _macos_phys_footprint(pid)
                if mem < 0:
                    try:
                        # RSS — physical memory in use. VMS on macOS is useless
                        # here: the kernel reserves huge virtual ranges for
                        # dyld/frameworks/malloc zones, so every process looks
                        # like 100s of GB.
                        mem = proc.memory_info().rss
                    except transient:
                        mem = 0
                rows.append((pid, name, mem, user))
            except transient:
                continue

        rows.sort(key=lambda r: r[1].lower())
        self.rows_ready.emit(rows)


class _ProcessSortProxy(QSortFilterProxyModel):
    """Proxy that defers comparison to the source items' ``__lt__``.

    Why: the default ``QSortFilterProxyModel.lessThan`` compares
    ``Qt.DisplayRole`` strings, which sorts numeric columns
    lexicographically ("10" < "2"). Delegating to the source item lets
    [[NumericItem]] sort by its underlying int payload.
    """

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:  # noqa: N802 — Qt naming
        source = self.sourceModel()
        left_item = source.itemFromIndex(left) if source is not None else None
        right_item = source.itemFromIndex(right) if source is not None else None
        if left_item is None or right_item is None:
            return super().lessThan(left, right)
        return left_item < right_item


class OpenProcessDialog(QDialog):
    """Process picker. Returns the opened ``AbstractProcess`` via ``.process``."""

    COL_PID = 0
    COL_NAME = 1
    COL_MEMORY = 2
    COL_USER = 3

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.process: Optional[AbstractProcess] = None
        self._scan_worker: Optional[_ProcessListWorker] = None

        self.setWindowTitle("PyMemoryEditor App — Select a Process")
        self.setWindowIcon(app_icon())
        self.setMinimumSize(720, 520)

        self._build_ui()
        self._populate_processes()

        # Refresh every few seconds so newly-launched processes appear without
        # the user having to hit "Refresh".
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(_REFRESH_INTERVAL_MS)
        self._refresh_timer.timeout.connect(self._populate_processes)
        self._refresh_timer.start()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        header = QLabel(
            f"<span style='font-size:18px;font-weight:700;'>Open Process</span>"
            f" &nbsp;<span style='color:#6E7681;'>PyMemoryEditor v{__version__}</span>"
        )
        header.setTextFormat(Qt.RichText)
        layout.addWidget(header)

        hint = QLabel(
            "Pick a target process from the list, or type a PID / process name below."
        )
        hint.setObjectName("hint")
        layout.addWidget(hint)

        # Filter bar
        filter_row = QHBoxLayout()
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filter by name, PID or user…")
        self._filter_edit.textChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self._filter_edit, 1)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._populate_processes)
        filter_row.addWidget(refresh_btn)
        layout.addLayout(filter_row)

        # Process table
        self._model = QStandardItemModel(0, 4, self)
        self._model.setHorizontalHeaderLabels(
            ["PID", "Process Name", "Memory (RSS)", "User"]
        )

        self._proxy = _ProcessSortProxy(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self._proxy.setFilterKeyColumn(-1)  # search every column

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            self.COL_NAME, QHeaderView.Stretch
        )
        self._table.doubleClicked.connect(lambda _i: self._try_open())
        self._table.selectionModel().selectionChanged.connect(
            self._on_selection_changed
        )
        layout.addWidget(self._table, 1)

        # Manual entry row
        manual_row = QHBoxLayout()
        manual_row.addWidget(QLabel("Process:"))
        self._entry = QLineEdit()
        self._entry.setPlaceholderText("PID (e.g. 1234) or name (e.g. notepad.exe)")
        self._entry.returnPressed.connect(self._try_open)
        manual_row.addWidget(self._entry, 1)

        self._case_checkbox = QCheckBox("Case-sensitive name lookup")
        self._case_checkbox.setChecked(False)
        self._case_checkbox.setToolTip(
            "When unchecked, OpenProcess(process_name=…) is called with "
            "case_sensitive=False — useful on Windows where process names "
            "are case-insensitive."
        )
        manual_row.addWidget(self._case_checkbox)
        layout.addLayout(manual_row)

        # Buttons
        button_row = QHBoxLayout()
        button_row.addStretch(1)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_row.addWidget(cancel_btn)

        self._open_btn = QPushButton("Open Process")
        self._open_btn.setObjectName("primary")
        self._open_btn.setDefault(True)
        self._open_btn.clicked.connect(self._try_open)
        button_row.addWidget(self._open_btn)

        layout.addLayout(button_row)

    # ----------------------------------------------------------- behaviour

    def _populate_processes(self) -> None:
        """Start a background scan; skip if one is already in flight.

        The previous (auto) tick may still be running when the user hits
        Refresh — let the in-flight scan finish instead of stacking workers.
        """
        if self._scan_worker is not None and self._scan_worker.isRunning():
            return

        worker = _ProcessListWorker(self)
        worker.rows_ready.connect(self._on_rows_ready)
        worker.finished.connect(self._on_scan_finished)
        self._scan_worker = worker
        worker.start()

    def _on_rows_ready(self, rows) -> None:
        selected_pid = self._selected_pid()

        self._model.setRowCount(0)
        for pid, name, mem, user in rows:
            pid_item = NumericItem(str(pid))
            pid_item.setData(pid, Qt.UserRole)
            pid_item.setTextAlignment(Qt.AlignCenter)

            name_item = QStandardItem(name)
            name_item.setData(pid, Qt.UserRole)

            mem_item = NumericItem(_human_kb(mem) if mem else "—")
            mem_item.setData(mem, Qt.UserRole)
            mem_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            user_item = QStandardItem(user)

            self._model.appendRow([pid_item, name_item, mem_item, user_item])

        # Restore selection
        if selected_pid is not None:
            for row in range(self._proxy.rowCount()):
                idx = self._proxy.index(row, self.COL_PID)
                if self._proxy.data(idx, Qt.UserRole) == selected_pid:
                    self._table.selectRow(row)
                    break

    def _on_scan_finished(self) -> None:
        worker = self._scan_worker
        self._scan_worker = None
        if worker is not None:
            worker.deleteLater()

    def closeEvent(self, event):  # noqa: N802 — Qt naming
        self._refresh_timer.stop()
        if self._scan_worker is not None and self._scan_worker.isRunning():
            try:
                self._scan_worker.rows_ready.disconnect()
                self._scan_worker.finished.disconnect()
            except (RuntimeError, TypeError):
                pass
            self._scan_worker.wait(1000)
        super().closeEvent(event)

    def _on_filter_changed(self, text: str) -> None:
        self._proxy.setFilterFixedString(text)

    def _on_selection_changed(self, *_args) -> None:
        pid = self._selected_pid()
        if pid is not None:
            self._entry.setText(str(pid))

    def _selected_pid(self) -> Optional[int]:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        return self._proxy.data(
            self._proxy.index(rows[0].row(), self.COL_PID), Qt.UserRole
        )

    def _try_open(self) -> None:
        entry = self._entry.text().strip()
        if not entry:
            QMessageBox.warning(
                self, "Open Process", "Type a PID or process name first."
            )
            return

        kwargs = _open_kwargs()

        # Try PID first when the entry parses as an int.
        try:
            pid = int(entry)
        except ValueError:
            pid = None

        try:
            if pid is not None:
                self.process = OpenProcess(pid=pid, **kwargs)
            else:
                self.process = OpenProcess(
                    process_name=entry,
                    case_sensitive=self._case_checkbox.isChecked(),
                    **kwargs,
                )
        except ProcessIDNotExistsError:
            QMessageBox.critical(
                self, "Open Process", f"No process with PID {pid} is running."
            )
            return
        except ProcessNotFoundError:
            QMessageBox.critical(
                self,
                "Open Process",
                f"No process named {entry!r} was found.\n\n"
                "Tip: untick 'Case-sensitive name lookup' if the OS doesn't care about case.",
            )
            return
        except AmbiguousProcessNameError as exc:
            QMessageBox.critical(
                self,
                "Open Process",
                f"Multiple processes match {entry!r}:\n\n{exc}\n\nPick a row in the list instead.",
            )
            return
        except PermissionError as exc:
            QMessageBox.critical(
                self,
                "Open Process",
                f"Permission denied opening that process.\n\n{exc}\n\n"
                "On Linux you may need to run with sudo (or relax /proc/sys/kernel/yama/ptrace_scope).\n"
                "On macOS the Python binary needs the com.apple.security.cs.debugger entitlement.\n"
                "On Windows try running as Administrator.",
            )
            return
        except OSError as exc:
            QMessageBox.critical(
                self, "Open Process", f"Could not open process:\n\n{exc}"
            )
            return

        self.accept()
