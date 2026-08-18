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

It also owns *when a failure is worth interrupting the user*, which a polling
dialog cannot get wrong quietly: ``_on_data_failed`` is a modal, a modal runs a
nested event loop, and a poll left running underneath one stacks a dialog per
tick (issue #74). See :meth:`AutoRefreshTableDialog._handle_failed`.
"""
from typing import Callable, Optional

from PySide6.QtCore import QElapsedTimer, QThread, QTimer, Signal
from PySide6.QtWidgets import QDialog

from ._widgets import TearsDownOnClose, shutdown_worker_thread


# How long a target may keep failing before the auto-refresh gives up. A
# failure is usually terminal — the target exited, or its handle was closed by
# File → Change Process — but not always: a module/thread enumeration can blip
# while the target loads images (``CreateToolhelp32Snapshot`` is documented to
# fail with ``ERROR_BAD_LENGTH`` mid-load), and giving up on the first blip
# would freeze a window that would have recovered on the next tick.
#
# Measured in wall-clock rather than ticks on purpose: "how long does the target
# get to recover" is the same question for every window, but the intervals are
# not (300 ms for Threads, 1000 ms for Memory Map / Modules, and anything from
# 50 ms up in the Hex Viewer, which shares this budget), so a tick count would
# hand them budgets differing by more than an order of magnitude. What gets *reported* is decided
# separately, in ``_handle_failed`` — this constant only bounds how long a
# failing target keeps a worker running.
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
        # Last error handed to ``_on_data_failed``, so a target that fails on
        # every tick is reported once instead of once per tick. Cleared by a
        # successful fetch or an explicit ``refresh()`` (see ``_handle_failed``).
        self._last_error: Optional[str] = None
        # Started on the first failure of a streak; None whenever the last
        # fetch succeeded. Measures how long the target has been failing.
        self._failing_since: Optional[QElapsedTimer] = None
        # True from the moment the poll gives up until the next refresh(). Read
        # by subclasses that rebuild their status line on user input (a filter
        # keystroke), so the "stopped" note survives instead of being replaced
        # by a count that looks live.
        self._polling_gave_up = False
        # Set by refresh() only, so it can never fire on a timer tick.
        self._report_next_failure = False

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
        error (see :meth:`_handle_failed`), so a modal dialog is safe here.
        """
        raise NotImplementedError

    def _set_loading_hint(self) -> None:
        """Optionally show a one-time loading message before the first fetch."""

    def _on_polling_stopped(self) -> None:
        """Note that the auto-refresh gave up. Runs on the UI thread.

        Fires once, when a target has been failing for ``_FAILURE_GRACE_MS``
        (see :meth:`_handle_failed`). The table is frozen on its last good data
        from here on, so subclasses should say so — a silently stale window is
        worse than an honest one. Optional.
        """

    # ------------------------------------------------------------------ #
    # Lifecycle (shared)
    # ------------------------------------------------------------------ #

    def refresh(self) -> None:
        """Fetch now, on the user's behalf.

        Explicit (re)fetch: it clears the error latch and restarts a poll that
        repeated failures stopped, so reopening the dialog against a live target
        picks the cadence back up. The timer itself goes through
        :meth:`_auto_refresh_tick` instead, which must *not* re-arm.

        A dismissed dialog stays dismissed: the teardown latch is one-way, so
        re-arming here would leave a timer running on a dialog nothing can join
        again.
        """
        if getattr(self, "_teardown_done", False):
            return
        self._last_error = None
        self._failing_since = None
        self._polling_gave_up = False
        # An explicit retry deserves an answer either way: without this, a
        # refresh against a still-dead target would sit silent until the grace
        # window expired, because `_has_data` is still True from before.
        #
        # ``_start_fetch`` binds it to the fetch it starts, so it answers the
        # request and nothing later. A fetch already in flight when this runs
        # was started before the user asked for anything, so the flag waits for
        # the next one rather than being consumed by that stranger's result.
        self._report_next_failure = True
        if self._auto_timer is not None and not self._auto_timer.isActive():
            self._auto_timer.start()
        self._start_fetch()

    def _auto_refresh_tick(self) -> None:
        """Timer-driven fetch — never re-arms after a failure."""
        self._start_fetch()

    def _start_fetch(self) -> None:
        # Nothing may start a fetch after the dialog was dismissed: the teardown
        # latch is one-way, so a worker started here could never be joined
        # again (and its dialog is on its way to being deleted).
        if getattr(self, "_teardown_done", False):
            return

        # Skip if a fetch is already in flight — the timer would otherwise stack
        # workers on a slow target. This self-throttles to the real fetch time.
        if self._worker is not None and self._worker.isRunning():
            return

        # Loading hint only before the first successful fetch; the periodic
        # refresh updates silently to avoid flicker.
        if not self._has_data:
            self._set_loading_hint()

        # Consume the "the user asked for this" flag into *this* fetch: bound to
        # the outcome that answers the request, and cleared here so it can't
        # leak into an unrelated failure minutes later. A refresh that found a
        # fetch already in flight left it set, and it applies to this one.
        asked_for_it = self._report_next_failure
        self._report_next_failure = False

        worker = _DataWorker(self._fetch_data, self)
        worker.ready.connect(self._handle_ready)
        worker.failed.connect(
            lambda message, asked=asked_for_it: self._handle_failed(message, asked)
        )
        worker.finished.connect(lambda w=worker: self._on_worker_finished(w))
        self._worker = worker
        worker.start()

    def _handle_ready(self, data) -> None:
        self._has_data = True
        self._last_error = None
        self._failing_since = None
        self._on_data_ready(data)

    def _handle_failed(self, message: str, asked_for_it: bool = False) -> None:
        """Handle a failed fetch: report it only when the user needs to know.

        Once the target is gone (or its handle was closed by File → Change
        Process) *every* tick fails, and ``_on_data_failed`` pops a **modal**
        dialog. A modal runs a nested event loop, so the timer fires again while
        it is up and the failures stack — hundreds of focus-stealing dialogs the
        user could only escape by killing the app from another TTY (issue #74).

        Reporting is therefore tied to the two moments where a failure actually
        changes what the user sees:

        * the **first** fetch fails — the window is empty, so there is nothing
          to look at but the error;
        * the poll **gives up** after ``_FAILURE_GRACE_MS`` of continuous
          failure — the table is frozen on stale data from here on;
        * the fetch was one the user explicitly asked for (``asked_for_it``,
          set by :meth:`refresh`) — a retry that answers with silence is worse
          than one that answers with the error.

        Everything in between heals quietly: the table keeps its last good rows
        and the next tick usually recovers. That "quietly" is load-bearing, not
        just tidy — reporting *every* failure re-opens the spam, because a
        modal's nested loop lets the poll keep running underneath it, and a
        target that fails on alternating ticks then stacks a fresh modal on each
        failure until the interpreter runs out of stack.
        """
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

        # ``_last_error`` doubles as "already reported": it keeps a repeat of the
        # same error quiet, and its None-ness marks a window that has never
        # reported anything (cleared by a successful fetch and by refresh()).
        never_reported_yet = not self._has_data and self._last_error is None
        if (
            gave_up or never_reported_yet or asked_for_it
        ) and message != self._last_error:
            self._last_error = message
            self._on_data_failed(message)

        # After the report, so the subclass's "stopped" note is what stays on
        # screen once the user dismisses the modal.
        if gave_up:
            self._on_polling_stopped()

    def _on_worker_finished(self, worker) -> None:
        """Retire the worker that just finished — and only that one.

        ``finished`` is queued, so it can arrive *after* the next tick already
        started a replacement: a worker exits ``run()`` (``isRunning()`` goes
        False, the guard in :meth:`_start_fetch` lets the next fetch through)
        and its signal is delivered a moment later. Clearing ``self._worker``
        blindly there would drop the reference to the *running* replacement and
        ``deleteLater()`` it — destroying a live QThread aborts the process.
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
