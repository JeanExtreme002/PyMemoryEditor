# -*- coding: utf-8 -*-
"""
Background thread that drives the cheat table's read/freeze loop.

Lives off the UI thread so a slow target (especially on macOS Mach-VM reads)
doesn't stall input. The owning widget publishes a snapshot of every entry
via :meth:`_CheatPollWorker.update_snapshot`; the worker reads the current
value for every snapshot row, re-writes frozen rows, and emits
``values_ready`` with ``(address, pytype, length, value)`` tuples for the UI
to render. Identifying entries by ``(address, pytype, length)`` rather than
by row index means deletes/reorders between snapshot and signal can't apply
a value to the wrong row.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import QMutex, QMutexLocker, QThread, Signal

from PyMemoryEditor import AbstractProcess


# Child of the "PyMemoryEditor" logger, so the Log Console (which attaches a
# handler to "PyMemoryEditor") picks these up via propagation.
_LOG = logging.getLogger(__name__)


# Identity tuple for an entry: (address, pytype, length). Same key the cheat
# table uses to match worker results back to a row across reorders/deletes.
_EntryKey = Tuple[int, type, int]


# Threshold above which the per-tick refresh collapses N read_process_memory
# calls into one search_by_addresses batch. Below this the per-entry path is
# simpler and roughly equivalent in syscalls (search_by_addresses still has
# to enumerate the target's memory regions internally on every call).
_BATCH_THRESHOLD = 8

# Tick interval for the background read/freeze loop in the cheat table.
TICK_INTERVAL_MS = 100


class _CheatPollWorker(QThread):
    """
    Background thread that polls the target process for every active entry's
    current value and re-writes frozen entries.

    Communication is single-direction: the UI publishes the current entry
    snapshot via :meth:`update_snapshot`; the worker emits ``values_ready``
    with ``(address, pytype, length, value)`` tuples for the UI to render.
    The worker also handles the freeze write itself, so the syscall never
    crosses thread boundaries.

    A frozen value is re-written every tick (~10 Hz). When that write *fails*
    — a protected page, the target exiting — the worker can't pop a dialog per
    tick, so it instead tracks the failing entries and emits ``freeze_failed``
    with the current ``{key: "ErrorType: message"}`` map. The signal fires only
    when that set *changes* (a freeze starts or stops failing), so the UI gets a
    persistent cue without 10 Hz spam, and the first failure of each entry is
    logged once. Previously the exception was swallowed silently, so a freeze
    that never landed looked identical to one that did.
    """

    values_ready = Signal(object)  # list[tuple[int, type, int, Any]]
    freeze_failed = Signal(object)  # dict[_EntryKey, str] — current failing freezes
    write_failed = Signal(object)  # tuple[int, type, int, str] — a manual write that failed

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process
        self._mutex = QMutex()
        self._snapshot: List[Tuple[int, type, int, Any, bool]] = []
        # One-shot manual writes queued from the UI (inline value edits). Drained
        # at the top of each tick so the syscall runs here, not on the UI thread.
        self._pending_writes: List[Tuple[int, type, int, Any]] = []
        self._stop = False
        # Entries whose freeze write is currently failing → last error string.
        # Touched only by the worker thread (run() / _poll_once), so no lock.
        self._freeze_failures: Dict[_EntryKey, str] = {}
        # Last map handed to the UI, so run() can emit only on change.
        self._last_emitted_failures: Dict[_EntryKey, str] = {}

    def update_snapshot(
        self, snapshot: List[Tuple[int, type, int, Any, bool]]
    ) -> None:
        """Replace the entry list the worker iterates each tick.

        The tuple is ``(address, pytype, length, frozen_value, is_frozen)``.
        Defensive copy: the snapshot is small (one tuple per row) and
        decoupling the worker's view from the UI's avoids races on edits.
        """
        with QMutexLocker(self._mutex):
            self._snapshot = list(snapshot)

    def request_write(
        self, address: int, pytype: type, length: int, value: Any
    ) -> None:
        """Queue a one-shot manual write to be performed on the worker thread.

        The cheat table's inline value edits used to call
        ``write_process_memory`` directly on the UI thread, freezing the UI when
        the target was slow or the page faulted. Routing them here keeps the
        syscall off the UI thread; a write that fails comes back via the
        ``write_failed`` signal. Latency is at most one tick (~100 ms), which is
        imperceptible for a manual edit.
        """
        with QMutexLocker(self._mutex):
            self._pending_writes.append((address, pytype, length, value))

    def _stopping(self) -> bool:
        """Whether ``stop`` was asked for. Cheap enough to check per entry."""
        with QMutexLocker(self._mutex):
            return self._stop

    def stop(self) -> None:
        with QMutexLocker(self._mutex):
            self._stop = True

    def _drain_pending_writes(self) -> List[Tuple[int, type, int, str]]:
        """Perform and clear every queued manual write.

        Returns one ``(address, pytype, length, message)`` tuple per write that
        failed, so ``run`` can surface it via ``write_failed``. Reads and clears
        the queue under the lock, then runs the syscalls outside it so a slow
        write never blocks a UI thread enqueuing the next edit.
        """
        with QMutexLocker(self._mutex):
            if not self._pending_writes:
                return []
            pending = self._pending_writes
            self._pending_writes = []

        failures: List[Tuple[int, type, int, str]] = []
        for address, pytype, length, value in pending:
            if self._stopping():
                break  # the handle is about to go — see _poll_once
            try:
                self._process.write_process_memory(address, pytype, length, value)
            except Exception as exc:  # noqa: BLE001
                message = "%s: %s" % (type(exc).__name__, exc)
                failures.append((address, pytype, length, message))
                _LOG.warning(
                    "Cheat-table write failed at 0x%X (%s, %dB): %s",
                    address, pytype.__name__, length, message,
                )
        return failures

    def run(self) -> None:
        while True:
            with QMutexLocker(self._mutex):
                if self._stop:
                    return
                snapshot = list(self._snapshot)

            # Never let an exception escape the loop body: a QThread whose
            # run() raises dies silently, and the table would then stop
            # auto-updating forever while the rest of the app (separate
            # workers) keeps working. Catch, log the cause, and keep ticking.
            try:
                # Apply queued manual writes before reading, so a just-typed
                # value lands and is read back as the new current value this tick.
                for failure in self._drain_pending_writes():
                    self.write_failed.emit(failure)

                if snapshot:
                    results = self._poll_once(snapshot)
                    if results:
                        self.values_ready.emit(results)

                # Emit the freeze-failure state only when it changed since the
                # last tick — a frozen page that keeps failing shouldn't fire the
                # signal 10×/second, but the UI must learn the moment one starts
                # or stops failing (including recovering back to an empty map).
                if self._freeze_failures != self._last_emitted_failures:
                    self._last_emitted_failures = dict(self._freeze_failures)
                    self.freeze_failed.emit(dict(self._freeze_failures))
            except Exception:  # noqa: BLE001
                _LOG.exception("Cheat poll tick failed; continuing")

            QThread.msleep(TICK_INTERVAL_MS)

    def _poll_once(
        self, snapshot: List[Tuple[int, type, int, Any, bool]]
    ) -> List[Tuple[int, type, int, Any]]:
        """Read every entry and (re-)write frozen values. Returns key→value."""
        # Group by (pytype, length) so search_by_addresses can amortize the
        # per-region enumeration when groups are large enough.
        groups: Dict[Tuple[type, int], List[int]] = {}
        freeze_by_addr: Dict[Tuple[type, int, int], Tuple[Any, bool]] = {}
        for address, pytype, length, frozen_value, is_frozen in snapshot:
            key = (pytype, length)
            groups.setdefault(key, []).append(address)
            freeze_by_addr[(*key, address)] = (frozen_value, is_frozen)

        results: List[Tuple[int, type, int, Any]] = []

        # Recompute the failing-freeze set from scratch this tick. Rebuilding
        # (rather than mutating in place) prunes entries that were deleted or
        # unfrozen since the last tick for free; `previous` is kept only to log
        # the *first* failure of each entry instead of once per tick.
        previous = self._freeze_failures
        new_failures: Dict[_EntryKey, str] = {}

        for (pytype, length), addresses in groups.items():
            values_by_address: Optional[Dict[int, Any]] = None
            if len(addresses) >= _BATCH_THRESHOLD:
                try:
                    values_by_address = dict(
                        self._process.search_by_addresses(pytype, length, addresses)
                    )
                except Exception:  # noqa: BLE001
                    # Batched read failed (target died mid-tick?). Fall through
                    # to the per-entry path so we still surface what we can.
                    values_by_address = None

            for address in addresses:
                # Per entry, not per tick: shutdown() closes the handle right
                # after stop(), and a write on a recycled one hits another
                # process.
                if self._stopping():
                    return results
                frozen_value, is_frozen = freeze_by_addr[(pytype, length, address)]
                if values_by_address is not None:
                    current = values_by_address.get(address)
                else:
                    try:
                        current = self._process.read_process_memory(
                            address, pytype, length
                        )
                    except Exception:  # noqa: BLE001
                        current = None

                if is_frozen and frozen_value is not None:
                    key: _EntryKey = (address, pytype, length)
                    try:
                        self._process.write_process_memory(
                            address, pytype, length, frozen_value
                        )
                        current = frozen_value
                    except Exception as exc:  # noqa: BLE001
                        # A freeze write that fails every tick must not be
                        # swallowed: record it (surfaced to the UI via
                        # freeze_failed) and log the first occurrence. `current`
                        # keeps the value we actually read, so the table shows
                        # the value drifting — the visible symptom of the freeze
                        # not taking hold.
                        message = "%s: %s" % (type(exc).__name__, exc)
                        new_failures[key] = message
                        if key not in previous:
                            _LOG.warning(
                                "Freeze write failed at 0x%X (%s, %dB): %s",
                                address, pytype.__name__, length, message,
                            )

                results.append((address, pytype, length, current))

        self._freeze_failures = new_failures
        return results


__all__ = ("_CheatPollWorker", "TICK_INTERVAL_MS")
