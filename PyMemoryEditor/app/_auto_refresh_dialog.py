# -*- coding: utf-8 -*-
"""
Shared base for the read-only, auto-refreshing table dialogs (Memory Map,
Modules, Threads).

All three did the same dance — run a one-shot read off the UI thread, repopulate
a sortable table when it returns, poll on a timer, and tear the worker down
safely on close — each with its own near-identical ``_*Worker(QThread)`` and
lifecycle boilerplate. That triplicated the fiddly bits (the in-flight guard
that self-throttles the poll, the detach-on-shutdown safety) where a fix to one
copy wouldn't reach the others. This owns the lifecycle once; subclasses provide
only what differs: how to fetch the data, and how to render it.
"""
from typing import Callable, Optional

from PySide6.QtCore import QThread, QTimer, Signal
from PySide6.QtWidgets import QDialog

from ._widgets import shutdown_worker_thread


class _DataWorker(QThread):
    """Runs a no-arg ``fetch`` callable off the UI thread, once."""

    ready = Signal(object)
    failed = Signal(str)

    def __init__(self, fetch: Callable[[], object], parent=None):
        super().__init__(parent)
        self._fetch = fetch

    def run(self) -> None:
        try:
            data = self._fetch()
        except Exception as exc:  # noqa: BLE001 — surfaced to the UI as a string
            self.failed.emit(str(exc))
            return
        self.ready.emit(data)


class AutoRefreshTableDialog(QDialog):
    """Owns the fetch-worker lifecycle + auto-refresh timer for a table dialog.

    Subclasses must:

    * call ``super().__init__(process, refresh_interval_ms=..., parent=...)``,
      then build their UI, then ``refresh()``, then ``_start_auto_refresh()``;
    * implement :meth:`_fetch_data` (runs in the worker thread) and
      :meth:`_on_data_ready` (runs on the UI thread);
    * implement :meth:`_on_data_failed` and (optionally) :meth:`_set_loading_hint`.
    """

    def __init__(self, process, *, refresh_interval_ms: int, parent=None):
        super().__init__(parent)
        self._process = process
        self._worker: Optional[_DataWorker] = None
        self._has_data = False
        self._refresh_interval_ms = refresh_interval_ms
        self._auto_timer: Optional[QTimer] = None

    def _start_auto_refresh(self) -> None:
        """Begin polling. Call once, after the first ``refresh()``.

        The ``refresh()`` in-flight guard self-throttles the cadence to however
        long a fetch actually takes, so the timer can't stack workers on a slow
        target.
        """
        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(self._refresh_interval_ms)
        self._auto_timer.timeout.connect(self.refresh)
        self._auto_timer.start()

    # ------------------------------------------------------------------ #
    # Hooks for subclasses
    # ------------------------------------------------------------------ #

    def _fetch_data(self):
        """Read the data to display. Runs in the worker thread; may raise."""
        raise NotImplementedError

    def _on_data_ready(self, data) -> None:
        """Render ``data`` into the table. Runs on the UI thread."""
        raise NotImplementedError

    def _on_data_failed(self, message: str) -> None:
        """Report a failed fetch. Runs on the UI thread."""
        raise NotImplementedError

    def _set_loading_hint(self) -> None:
        """Optionally show a one-time loading message before the first fetch."""

    # ------------------------------------------------------------------ #
    # Lifecycle (shared)
    # ------------------------------------------------------------------ #

    def refresh(self) -> None:
        # Skip if a fetch is already in flight — the timer would otherwise stack
        # workers on a slow target. This self-throttles to the real fetch time.
        if self._worker is not None and self._worker.isRunning():
            return

        # Loading hint only before the first successful fetch; the periodic
        # refresh updates silently to avoid flicker.
        if not self._has_data:
            self._set_loading_hint()

        worker = _DataWorker(self._fetch_data, self)
        worker.ready.connect(self._handle_ready)
        worker.failed.connect(self._on_data_failed)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def _handle_ready(self, data) -> None:
        self._has_data = True
        self._on_data_ready(data)

    def _on_worker_finished(self) -> None:
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.deleteLater()

    def closeEvent(self, event):  # noqa: N802 — Qt naming
        if self._auto_timer is not None:
            self._auto_timer.stop()
        # Unhook + join the worker; if it can't stop in time it's detached
        # rather than destroyed under us.
        shutdown_worker_thread(self._worker, wait_ms=1000)
        self._worker = None
        super().closeEvent(event)
