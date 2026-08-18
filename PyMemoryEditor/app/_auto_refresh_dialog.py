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

It also owns *when* a failure is worth interrupting the user — see
:meth:`AutoRefreshTableDialog._handle_failed`.
"""
from typing import Callable, Optional

from PySide6.QtCore import QElapsedTimer, QThread, QTimer, Signal
from PySide6.QtWidgets import QDialog

from ._widgets import TearsDownOnClose, shutdown_worker_thread


# How long a target may keep failing before the auto-refresh gives up. Not
# every failure is terminal (``CreateToolhelp32Snapshot`` is documented to fail
# transiently while a target loads images), so a blip must not freeze a window
# that would recover next tick. In wall-clock, not ticks: the intervals differ
# by more than 10x across the windows that share this budget.
_FAILURE_GRACE_MS = 3000


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


class AutoRefreshTableDialog(TearsDownOnClose, QDialog):
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
        # Failure state, all reset by a success or an explicit refresh(). See
        # _handle_failed for how they decide what reaches the user.
        self._last_error: Optional[str] = None  # doubles as "already reported"
        self._failing_since: Optional[QElapsedTimer] = None  # streak clock
        # Read by subclasses that rebuild their status line on user input, so
        # the "stopped" note isn't replaced by a count that looks live.
        self._polling_gave_up = False

    def _start_auto_refresh(self) -> None:
        """Begin polling. Call once, after the first ``refresh()``.

        The ``refresh()`` in-flight guard self-throttles the cadence to however
        long a fetch actually takes, so the timer can't stack workers on a slow
        target.
        """
        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(self._refresh_interval_ms)
        self._auto_timer.timeout.connect(self._auto_refresh_tick)
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
        """Report a failed fetch. Runs on the UI thread.

        Called only for a failure the user needs to see — the first fetch, or
        the one that makes the poll give up — and never twice for the same
        error (see :meth:`_handle_failed`), so a modal is safe here.
        """
        raise NotImplementedError

    def _set_loading_hint(self) -> None:
        """Optionally show a one-time loading message before the first fetch."""

    def _on_polling_stopped(self) -> None:
        """Note that the auto-refresh gave up. Runs on the UI thread.

        Fires once, when a target has been failing for ``_FAILURE_GRACE_MS``.
        The table is frozen on its last good data from here on, so subclasses
        should say so. Optional.
        """

    # ------------------------------------------------------------------ #
    # Lifecycle (shared)
    # ------------------------------------------------------------------ #

    def refresh(self) -> None:
        """Fetch now, on the user's behalf.

        Clears the error latch and restarts a poll that repeated failures
        stopped. The timer goes through :meth:`_auto_refresh_tick` instead,
        which must *not* re-arm — and neither may a dismissed dialog, whose
        teardown latch is one-way.
        """
        if self._is_dismissed():
            return
        self._last_error = None
        self._failing_since = None
        self._polling_gave_up = False
        if self._auto_timer is not None and not self._auto_timer.isActive():
            self._auto_timer.start()
        self._start_fetch()

    def _auto_refresh_tick(self) -> None:
        """Timer-driven fetch — never re-arms after a failure."""
        self._start_fetch()

    def _start_fetch(self) -> None:
        # A worker started after the teardown could never be joined again.
        if self._is_dismissed():
            return

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
        worker.failed.connect(self._handle_failed)
        worker.finished.connect(lambda w=worker: self._on_worker_finished(w))
        self._worker = worker
        worker.start()

    def _handle_ready(self, data) -> None:
        if self._is_dismissed():
            return
        self._has_data = True
        self._last_error = None
        self._failing_since = None
        self._on_data_ready(data)

    def _handle_failed(self, message: str) -> None:
        """Handle a failed fetch: report it only when the user needs to know.

        Once the target is gone (or its handle was closed by File → Change
        Process) *every* tick fails, and ``_on_data_failed`` pops a **modal**
        dialog. A modal runs a nested event loop, so the timer fires again while
        it is up and the failures stack — hundreds of focus-stealing dialogs the
        user could only escape by killing the app from another TTY (issue #74).

        Reporting is therefore tied to the two moments where a failure changes
        what the user sees: the **first** fetch (empty window) and the one that
        makes the poll **give up** (frozen table). Everything in between heals
        quietly — and that silence is load-bearing: reporting every failure
        re-opens the spam, since a target failing on alternating ticks stacks a
        modal per failure until the stack runs out.

        A dismissed dialog reports nothing. The teardown disconnects the worker,
        but a delivery already queued then must not raise a modal over a window
        that is gone — during ``MainWindow.closeEvent`` that would be a nested
        event loop in the middle of teardown.
        """
        if self._is_dismissed():
            return

        if self._failing_since is None:
            self._failing_since = QElapsedTimer()
            self._failing_since.start()
            gave_up = False
        else:
            gave_up = (
                self._failing_since.elapsed() >= _FAILURE_GRACE_MS
                and self._auto_timer is not None
                and self._auto_timer.isActive()
            )

        if gave_up and self._auto_timer is not None:
            self._auto_timer.stop()
            self._polling_gave_up = True

        never_reported_yet = not self._has_data and self._last_error is None
        if (gave_up or never_reported_yet) and message != self._last_error:
            self._last_error = message
            self._on_data_failed(message)

        # After the report, so the "stopped" note is what stays on screen.
        if gave_up:
            self._on_polling_stopped()

    def _on_worker_finished(self, worker) -> None:
        """Retire the worker that just finished — and only that one.

        ``finished`` is queued, so it can arrive after the next tick already
        started a replacement. Clearing ``self._worker`` blindly would drop the
        reference to that *running* worker and ``deleteLater()`` it — destroying
        a live QThread aborts the process.
        """
        if worker is self._worker:
            self._worker = None
        worker.deleteLater()

    def _teardown(self) -> None:
        if self._auto_timer is not None:
            self._auto_timer.stop()
        # Unhook + join the worker; if it can't stop in time it's detached
        # rather than destroyed under us.
        shutdown_worker_thread(self._worker, wait_ms=1000)
        self._worker = None
