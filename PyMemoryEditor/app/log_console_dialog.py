# -*- coding: utf-8 -*-
"""
Log console — a live view of the ``PyMemoryEditor`` logger.

The library logs DEBUG events when scanning helpers skip transient pages
(unmapped, no-access, partial reads) and WARNING when something
recovers-but-leaks state (macOS mach_vm_protect couldn't restore). This
dialog attaches a custom :class:`logging.Handler` to the ``PyMemoryEditor``
logger and streams records into a read-only text view — useful to
understand what the library is doing during a noisy scan without dropping
to the terminal.

Cross-thread emit safety: the underlying scan workers run on QThreads. The
``Handler.emit`` method runs on whichever thread called the logger, so we
hop to the UI thread via a ``Qt.QueuedConnection`` signal before touching
the widget.
"""
import logging
from typing import Optional

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)


_LOGGER_NAME = "PyMemoryEditor"

# Levels offered in the UI, in increasing order of severity.
_LEVELS = (
    ("DEBUG", logging.DEBUG),
    ("INFO", logging.INFO),
    ("WARNING", logging.WARNING),
    ("ERROR", logging.ERROR),
)


class _QtLogSignal(QObject):
    """Tiny QObject that owns the cross-thread signal.

    A ``logging.Handler`` is not itself a QObject and can't carry signals;
    composing one here keeps the handler thread-safe (emit happens via Qt's
    queued event loop) without inheriting from two unrelated base classes.
    """

    line_emitted = Signal(str)


class _QtLogHandler(logging.Handler):
    """``logging.Handler`` that forwards formatted records to a Qt signal."""

    def __init__(self) -> None:
        super().__init__()
        self.bridge = _QtLogSignal()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = self.format(record)
        except Exception:  # noqa: BLE001 — never let logging crash callers
            return
        # The signal is connected with Qt.QueuedConnection by the dialog so
        # the actual widget update happens on the UI thread.
        self.bridge.line_emitted.emit(line)


class LogConsoleDialog(QDialog):
    """Live view of the PyMemoryEditor logger."""

    # The dialog can be opened/closed repeatedly; we attach the handler on
    # open and detach on close so the library doesn't keep growing handler
    # lists across sessions.

    def __init__(self, parent=None):
        super().__init__(parent)
        self._handler: Optional[_QtLogHandler] = None
        self._logger = logging.getLogger(_LOGGER_NAME)
        # Snapshot the logger's level so we can put it back on close — the
        # user opening this dialog should not silently raise the global
        # verbosity for code that runs after the dialog is dismissed.
        self._previous_level = self._logger.level

        self.setWindowTitle("PyMemoryEditor — Log Console")
        self.resize(820, 480)

        self._build_ui()
        self._attach_handler(level=logging.DEBUG)
        self._apply_level("DEBUG")

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        header = QLabel(
            "<span style='font-size:16px;font-weight:700;'>Log Console</span>"
            " &nbsp;<span style='color:#6E7681;'>logger = \"PyMemoryEditor\"</span>"
        )
        header.setTextFormat(Qt.RichText)
        layout.addWidget(header)

        hint = QLabel(
            "Records emitted by the library while this dialog is open. "
            "DEBUG-level entries surface transient skips during scans; "
            "WARNING entries flag recovered-but-noisy conditions."
        )
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        bar = QHBoxLayout()
        bar.setSpacing(8)

        bar.addWidget(QLabel("Level:"))
        self._level_combo = QComboBox()
        for label, _ in _LEVELS:
            self._level_combo.addItem(label)
        self._level_combo.setCurrentText("DEBUG")
        self._level_combo.currentTextChanged.connect(self._apply_level)
        bar.addWidget(self._level_combo)

        self._autoscroll_check = QCheckBox("Auto-scroll")
        self._autoscroll_check.setChecked(True)
        bar.addWidget(self._autoscroll_check)

        bar.addStretch(1)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._on_clear)
        bar.addWidget(clear_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        bar.addWidget(close_btn)

        layout.addLayout(bar)

        self._console = QPlainTextEdit()
        self._console.setReadOnly(True)
        self._console.setFont(QFont("Menlo, Consolas, Courier New", 10))
        self._console.setLineWrapMode(QPlainTextEdit.NoWrap)
        # Cap the buffer so a long-running auto-scan doesn't grow the dialog
        # memory unboundedly. ~5000 lines is plenty for live debugging.
        self._console.setMaximumBlockCount(5000)
        layout.addWidget(self._console, 1)

    def _attach_handler(self, level: int) -> None:
        handler = _QtLogHandler()
        handler.setLevel(level)
        handler.setFormatter(
            logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s", "%H:%M:%S")
        )
        # QueuedConnection ensures the widget update happens on the UI thread
        # even when the log record was emitted from a scan worker QThread.
        handler.bridge.line_emitted.connect(
            self._console_append, Qt.ConnectionType.QueuedConnection
        )
        self._logger.addHandler(handler)
        if self._logger.level == logging.NOTSET or self._logger.level > level:
            self._logger.setLevel(level)
        self._handler = handler

    def _apply_level(self, label: str) -> None:
        level = dict(_LEVELS).get(label, logging.DEBUG)
        if self._handler is not None:
            self._handler.setLevel(level)
        if self._logger.level == logging.NOTSET or self._logger.level > level:
            self._logger.setLevel(level)

    def _console_append(self, line: str) -> None:
        self._console.appendPlainText(line)
        if self._autoscroll_check.isChecked():
            sb = self._console.verticalScrollBar()
            sb.setValue(sb.maximum())

    def _on_clear(self) -> None:
        self._console.clear()

    def closeEvent(self, event):  # noqa: N802 — Qt naming
        # Detach the handler so the library doesn't keep emitting into a
        # dialog the user has dismissed. Don't lower the logger level past
        # what the caller had configured before us.
        if self._handler is not None:
            try:
                self._handler.bridge.line_emitted.disconnect()
            except (RuntimeError, TypeError):
                pass
            self._logger.removeHandler(self._handler)
            self._handler = None
        self._logger.setLevel(self._previous_level)
        super().closeEvent(event)
