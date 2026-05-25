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
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import QMutex, QMutexLocker, QThread, Signal

from PyMemoryEditor import AbstractProcess


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
    """

    values_ready = Signal(object)  # list[tuple[int, type, int, Any]]

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process
        self._mutex = QMutex()
        self._snapshot: List[Tuple[int, type, int, Any, bool]] = []
        self._stop = False

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

    def stop(self) -> None:
        with QMutexLocker(self._mutex):
            self._stop = True

    def run(self) -> None:
        while True:
            with QMutexLocker(self._mutex):
                if self._stop:
                    return
                snapshot = list(self._snapshot)

            if snapshot:
                results = self._poll_once(snapshot)
                if results:
                    self.values_ready.emit(results)

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
                    try:
                        self._process.write_process_memory(
                            address, pytype, length, frozen_value
                        )
                        current = frozen_value
                    except Exception:  # noqa: BLE001
                        pass

                results.append((address, pytype, length, current))

        return results


__all__ = ("_CheatPollWorker", "TICK_INTERVAL_MS")
