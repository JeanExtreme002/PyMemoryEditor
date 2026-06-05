# -*- coding: utf-8 -*-

"""Small Qt widgets shared between dialogs.

Centralises tiny helpers (numeric sort items, hex address parsing) that
previously appeared duplicated across several dialog modules.
"""

from typing import List, Optional

from PySide6.QtCore import Qt, QThread
from PySide6.QtGui import QStandardItem


# Workers that wouldn't stop in time on close are parked here so they are never
# destroyed while still running (that aborts the whole process with
# "QThread: Destroyed while thread is still running"). The list is module-level
# so it outlives the dialog that owned the worker. Each detached worker removes
# itself once it finishes.
_DETACHED_WORKERS: "List[QThread]" = []


def shutdown_worker_thread(worker: Optional[QThread], wait_ms: int = 2000) -> None:
    """Stop a dialog's background ``QThread`` safely.

    Disconnects every signal first (so a late emit can't touch a now-closing
    dialog), asks the worker to cancel, then waits up to ``wait_ms``. If the
    worker is still wedged in a backend call when the wait expires, it is
    *detached* — reparented away from the dialog and held in a module-level
    list — so the dialog can be destroyed without taking a live thread down
    with it. The worker drops itself from the list once it finishes.

    The worker is expected to expose a ``cancel()`` method (all of this app's
    workers do); it's called if present.
    """
    if worker is None:
        return
    cancel = getattr(worker, "cancel", None)
    if callable(cancel):
        cancel()
    try:
        worker.disconnect()  # drop every outgoing connection at once
    except (RuntimeError, TypeError):
        pass

    if worker.isRunning():
        worker.wait(wait_ms)

    if worker.isRunning():
        worker.setParent(None)
        _DETACHED_WORKERS.append(worker)
        worker.finished.connect(lambda: _reap_detached_worker(worker))
    else:
        worker.deleteLater()


def _reap_detached_worker(worker: QThread) -> None:
    if worker in _DETACHED_WORKERS:
        _DETACHED_WORKERS.remove(worker)
    worker.deleteLater()


class NumericItem(QStandardItem):
    """A QStandardItem that compares by its Qt.UserRole int payload.

    Used by columns showing formatted numbers (sizes, addresses, PIDs) so the
    table sorts by the underlying value rather than the lexical label.
    """

    def __lt__(self, other):
        try:
            return int(self.data(Qt.UserRole)) < int(other.data(Qt.UserRole))
        except (TypeError, ValueError):
            return super().__lt__(other)


def parse_hex_address(text: str) -> Optional[int]:
    """Parse a hex address string (with or without 0x prefix) into an int.

    Returns None on any parse error. Whitespace is tolerated.
    """
    if not text:
        return None
    cleaned = text.strip()
    if not cleaned:
        return None
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    try:
        return int(cleaned, 16)
    except (TypeError, ValueError):
        return None
