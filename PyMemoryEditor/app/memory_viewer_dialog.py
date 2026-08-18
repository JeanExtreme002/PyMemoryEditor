# -*- coding: utf-8 -*-
"""
Hex viewer over ``process.read_process_memory(addr, bytes, length)``.

Polls the chosen address range at a configurable interval (Cheat Engine-style
"auto-refresh") so the user can watch values change live.
"""
import logging
from typing import Optional

from PySide6.QtCore import QElapsedTimer, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)

from PyMemoryEditor import AbstractProcess

from ._auto_refresh_dialog import _FAILURE_GRACE_MS, _DataWorker
from ._widgets import TearsDownOnClose, parse_hex_address, shutdown_worker_thread


# Child of the "PyMemoryEditor" logger, so the Log Console (which attaches a
# handler to "PyMemoryEditor") picks these up via propagation.
_LOG = logging.getLogger(__name__)

_BYTES_PER_LINE = 16


def _format_hex_dump(base: int, data: bytes) -> str:
    lines = []
    for i in range(0, len(data), _BYTES_PER_LINE):
        chunk = data[i : i + _BYTES_PER_LINE]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        # Pad so the ASCII column aligns even on short final lines.
        hex_part = hex_part.ljust(_BYTES_PER_LINE * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:016X}  {hex_part}  {ascii_part}")
    return "\n".join(lines)


class MemoryViewerDialog(TearsDownOnClose, QDialog):
    """Hex viewer + auto-refresh, with a "write bytes back" button."""

    def __init__(
        self, process: AbstractProcess, address: int = 0, length: int = 256, parent=None
    ):
        super().__init__(parent)
        self._process = process
        # In-flight read worker (None when idle). Reads run off the UI thread.
        self._worker: Optional[_DataWorker] = None

        self.setWindowTitle(f"Memory Viewer — PID {process.pid}")
        self.resize(820, 560)

        self._build_ui()
        if address:
            self._addr_edit.setText(f"{address:X}")
        self._size_spin.setValue(length)
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        top = QHBoxLayout()
        top.addWidget(QLabel("Address (hex):"))
        self._addr_edit = QLineEdit()
        self._addr_edit.setPlaceholderText("e.g. 7FFEE60AB000")
        self._addr_edit.returnPressed.connect(self.refresh)
        top.addWidget(self._addr_edit, 1)

        top.addWidget(QLabel("Length:"))
        self._size_spin = QSpinBox()
        self._size_spin.setRange(1, 65536)
        self._size_spin.setValue(256)
        self._size_spin.setSingleStep(16)
        top.addWidget(self._size_spin)

        spin_h = self._size_spin.sizeHint().height()

        refresh_btn = QPushButton("Read")
        refresh_btn.setObjectName("secondary")
        refresh_btn.setStyleSheet(
            f"min-height: 0px; max-height: {spin_h}px; padding: 2px 14px;"
        )
        refresh_btn.setFixedHeight(spin_h)
        refresh_btn.clicked.connect(self.refresh)
        top.addWidget(refresh_btn)
        layout.addLayout(top)

        auto_row = QHBoxLayout()
        self._auto_btn = QPushButton("Auto-refresh: Off")
        self._auto_btn.setCheckable(True)
        self._auto_btn.toggled.connect(self._toggle_auto)
        auto_row.addWidget(self._auto_btn)

        auto_row.addWidget(QLabel("Interval (ms):"))
        self._interval_spin = QSpinBox()
        self._interval_spin.setRange(50, 5000)
        self._interval_spin.setSingleStep(50)
        self._interval_spin.setValue(500)
        self._interval_spin.valueChanged.connect(self._sync_timer)
        auto_row.addWidget(self._interval_spin)

        auto_row.addStretch(1)

        write_btn = QPushButton("Write Hex Below…")
        write_btn.clicked.connect(self._write_bytes)
        auto_row.addWidget(write_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        auto_row.addWidget(close_btn)
        layout.addLayout(auto_row)

        self._dump = QPlainTextEdit()
        self._dump.setReadOnly(True)
        self._dump.setFont(QFont("Menlo, Consolas, Courier New", 11))
        self._dump.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(self._dump, 1)

        edit_row = QHBoxLayout()
        edit_row.addWidget(
            QLabel("Write hex (space-separated, starts at the address above):")
        )
        self._write_edit = QLineEdit()
        self._write_edit.setPlaceholderText("e.g. DE AD BE EF")
        self._write_edit.setFont(QFont("Menlo, Consolas, Courier New", 11))
        edit_row.addWidget(self._write_edit, 1)
        layout.addLayout(edit_row)

        self._status = QLabel("")
        self._status.setObjectName("hint")
        layout.addWidget(self._status)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)

        # Failure bookkeeping, same shape as the auto-refresh dialogs: a dead
        # target used to log a warning every tick forever (~20/s at the 50 ms
        # floor). Keyed by (address, size, message) so moving the viewer to
        # another failing range still gets logged.
        self._last_failure: Optional[tuple] = None
        self._failing_since: Optional[QElapsedTimer] = None

    def _parse_address(self) -> Optional[int]:
        text = self._addr_edit.text().strip()
        if not text:
            return None
        # Try hex first (with or without `0x`); fall back to decimal so callers
        # that paste a plain integer still work.
        addr = parse_hex_address(text)
        if addr is not None:
            return addr
        try:
            return int(text)
        except (TypeError, ValueError):
            return None

    def refresh(self) -> None:
        # Skip if a read is still running. The auto-refresh timer fires this
        # repeatedly, and a large length (up to 65536) on a slow target
        # (notably macOS Mach-VM) takes long enough that running it on the UI
        # thread froze input — so the read now runs on a worker, and this guard
        # self-throttles the cadence to the real read time instead of stacking
        # workers.
        if self._worker is not None and self._worker.isRunning():
            return
        addr = self._parse_address()
        if addr is None:
            self._status.setText("Enter a hex address first.")
            return
        size = int(self._size_spin.value())
        process = self._process

        def fetch():
            # Runs in the worker thread — never touches Qt widgets. addr/size
            # travel back in the result so the rendered dump stays labelled with
            # the range actually read even if the user edits the fields mid-read.
            # Errors are returned (not raised) so the one result handler renders
            # them with the same message/log the synchronous path produced.
            try:
                data = process.read_process_memory(addr, bytes, size)
                # A backend returning a non-buffer object would make bytes(data)
                # raise — keep that conversion inside the guard so it surfaces as
                # a "Read failed" status rather than crashing the worker.
                if not isinstance(data, (bytes, bytearray)):
                    data = bytes(data)
                return addr, size, bytes(data), None
            except Exception as exc:  # noqa: BLE001 — surface every backend error
                return addr, size, None, exc

        worker = _DataWorker(fetch, self)
        worker.ready.connect(self._on_read_result)
        worker.finished.connect(lambda w=worker: self._on_worker_finished(w))
        self._worker = worker
        worker.start()

    def _on_read_result(self, result) -> None:
        """Render a finished read (UI thread). ``result`` is the fetch tuple."""
        addr, size, data, exc = result
        if exc is not None:
            self._dump.setPlainText("")
            message = f"{type(exc).__name__}: {exc}"

            # First tick of a streak only.
            if (addr, size, message) != self._last_failure:
                self._last_failure = (addr, size, message)
                _LOG.warning(
                    "Hex viewer read failed at 0x%X (%d bytes): %s",
                    addr,
                    size,
                    message,
                )

            gave_up = False
            if self._failing_since is None:
                self._failing_since = QElapsedTimer()
                self._failing_since.start()
            elif (
                self._failing_since.elapsed() >= _FAILURE_GRACE_MS
                and self._auto_btn.isChecked()
            ):
                # Off through the button's own slot, so the UI can't claim to
                # be refreshing while it isn't.
                gave_up = True
                self._auto_btn.setChecked(False)

            self._status.setText(
                f"Read failed: {message}"
                + (" — auto-refresh stopped." if gave_up else "")
            )
            return

        self._last_failure = None
        self._failing_since = None
        self._dump.setPlainText(_format_hex_dump(addr, data))
        self._status.setText(f"Read {len(data):,} bytes from 0x{addr:X}")

    def _on_worker_finished(self, worker) -> None:
        """Retire the worker that just finished — and only that one.

        ``finished`` is queued and can land after the next tick started a
        replacement (50 ms interval floor here, so they overlap easily).
        Clearing ``self._worker`` blindly would ``deleteLater()`` that running
        worker — destroying a live QThread aborts the process.
        """
        if worker is self._worker:
            self._worker = None
        worker.deleteLater()

    def _toggle_auto(self, on: bool) -> None:
        self._auto_btn.setText("Auto-refresh: On" if on else "Auto-refresh: Off")
        if on:
            # Turning it back on is a retry: fresh grace window.
            self._failing_since = None
            self._sync_timer()
        else:
            self._timer.stop()

    def _sync_timer(self) -> None:
        self._timer.setInterval(int(self._interval_spin.value()))
        if self._auto_btn.isChecked() and not self._timer.isActive():
            self._timer.start()
        elif self._auto_btn.isChecked():
            self._timer.start()

    def _write_bytes(self) -> None:
        addr = self._parse_address()
        if addr is None:
            QMessageBox.warning(self, "Memory Viewer", "Enter a target address first.")
            return
        text = self._write_edit.text().strip()
        if not text:
            QMessageBox.warning(
                self, "Memory Viewer", "Type the bytes you'd like to write."
            )
            return
        cleaned = "".join(text.split())
        if len(cleaned) % 2 != 0:
            QMessageBox.warning(
                self, "Memory Viewer", "Hex string must have an even number of digits."
            )
            return
        try:
            data = bytes.fromhex(cleaned)
        except ValueError as exc:
            QMessageBox.warning(self, "Memory Viewer", f"Invalid hex: {exc}")
            return
        try:
            self._process.write_process_memory(addr, bytes, len(data), data)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self, "Memory Viewer", f"Write failed:\n\n{type(exc).__name__}: {exc}"
            )
            _LOG.warning(
                "Hex viewer write failed at 0x%X (%d bytes): %s: %s",
                addr,
                len(data),
                type(exc).__name__,
                exc,
            )
            return
        self._status.setText(f"Wrote {len(data)} bytes to 0x{addr:X}.")
        self.refresh()

    def _teardown(self) -> None:
        self._timer.stop()
        # Unhook + join the read worker; if it's still wedged in a backend call
        # it's detached rather than destroyed under us (same safety the
        # auto-refresh dialogs use).
        shutdown_worker_thread(self._worker, wait_ms=1000)
        self._worker = None
