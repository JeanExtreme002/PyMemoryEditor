# -*- coding: utf-8 -*-
"""
Hex viewer over ``process.read_process_memory(addr, bytes, length)``.

Polls the chosen address range at a configurable interval (Cheat Engine-style
"auto-refresh") so the user can watch values change live.
"""
from typing import Optional

from PySide6.QtCore import QTimer
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

from PyMemoryEditor.process import AbstractProcess


_BYTES_PER_LINE = 16


def _format_hex_dump(base: int, data: bytes) -> str:
    lines = []
    for i in range(0, len(data), _BYTES_PER_LINE):
        chunk = data[i:i + _BYTES_PER_LINE]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        # Pad so the ASCII column aligns even on short final lines.
        hex_part = hex_part.ljust(_BYTES_PER_LINE * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:016X}  {hex_part}  {ascii_part}")
    return "\n".join(lines)


class MemoryViewerDialog(QDialog):
    """Hex viewer + auto-refresh, with a "write bytes back" button."""

    def __init__(
        self, process: AbstractProcess, address: int = 0, length: int = 256, parent=None
    ):
        super().__init__(parent)
        self._process = process

        self.setWindowTitle(f"Memory Viewer — PID {process.pid}")
        self.resize(820, 560)

        self._build_ui()
        if address:
            self._addr_edit.setText(f"{address:X}")
        self._size_spin.setValue(length)
        self.refresh()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Address row
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

        refresh_btn = QPushButton("Read")
        refresh_btn.setObjectName("primary")
        refresh_btn.clicked.connect(self.refresh)
        top.addWidget(refresh_btn)
        layout.addLayout(top)

        # Auto-refresh row
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
        layout.addLayout(auto_row)

        # Hex dump
        self._dump = QPlainTextEdit()
        self._dump.setReadOnly(True)
        self._dump.setFont(QFont("Menlo, Consolas, Courier New", 11))
        self._dump.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(self._dump, 1)

        # Editable hex line
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

    # ----------------------------------------------------------- behaviour

    def _parse_address(self) -> Optional[int]:
        text = self._addr_edit.text().strip()
        if not text:
            return None
        # int(text, 16) already accepts the "0x"/"0X" prefix, so no need to
        # strip it manually. Fall back to base-10 for callers that paste a
        # decimal value.
        try:
            return int(text, 16)
        except ValueError:
            try:
                return int(text)
            except ValueError:
                return None

    def refresh(self) -> None:
        addr = self._parse_address()
        if addr is None:
            self._status.setText("Enter a hex address first.")
            return
        size = int(self._size_spin.value())
        try:
            data = self._process.read_process_memory(addr, bytes, size)
        except Exception as exc:  # noqa: BLE001 — surface every backend error
            self._dump.setPlainText("")
            self._status.setText(f"Read failed: {type(exc).__name__}: {exc}")
            return

        if not isinstance(data, (bytes, bytearray)):
            data = bytes(data)
        self._dump.setPlainText(_format_hex_dump(addr, bytes(data)))
        self._status.setText(f"Read {len(data):,} bytes from 0x{addr:X}")

    def _toggle_auto(self, on: bool) -> None:
        self._auto_btn.setText("Auto-refresh: On" if on else "Auto-refresh: Off")
        if on:
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
            return
        self._status.setText(f"Wrote {len(data)} bytes to 0x{addr:X}.")
        self.refresh()

    def closeEvent(self, event) -> None:
        self._timer.stop()
        super().closeEvent(event)
