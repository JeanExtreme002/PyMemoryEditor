# -*- coding: utf-8 -*-

"""Small Qt widgets shared between dialogs.

Centralises tiny helpers (numeric sort items, hex address parsing) shared by
several dialog modules.
"""

import threading
from typing import Any, Callable, Iterable, List, Optional, Tuple

from PySide6.QtCore import QCoreApplication, QObject, Qt, QThread, QTimer
from PySide6.QtGui import QStandardItem


# Monospace stack used across the app for address/value text. An explicit
# family list rather than the platform's default fixed font, so every table
# renders addresses at the same family and size on every OS.
MONOSPACE_FAMILY = "Menlo, Consolas, Courier New"

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
        # The four-argument static form on purpose: bare `worker.disconnect()`
        # raises TypeError in PySide6, and `worker.disconnect(worker)` only
        # drops connections whose *receiver* is the worker — ours belong to the
        # dialog.
        QObject.disconnect(worker, None, None, None)
    except (RuntimeError, TypeError):
        pass

    if worker.isRunning():
        worker.wait(wait_ms)

    if worker.isRunning():
        detach_worker(worker)
    else:
        worker.deleteLater()


def detach_worker(worker: QThread) -> None:
    """Park a worker that wouldn't stop, so its owner can be destroyed.

    Reparents it away from the dying widget and holds it in the module-level
    registry until it finishes on its own. Callers that stop workers their own
    way park them here too, so threads that outlived their owner are all in one
    place.
    """
    worker.setParent(None)
    _DETACHED_WORKERS.append(worker)
    worker.finished.connect(lambda: _reap_detached_worker(worker))
    # A worker that finished before this connect already emitted, so the reaper
    # would never run and it would sit here for good.
    if worker.isFinished():
        _reap_detached_worker(worker)


def _reap_detached_worker(worker: QThread) -> None:
    if worker in _DETACHED_WORKERS:
        _DETACHED_WORKERS.remove(worker)
    worker.deleteLater()


def detached_workers_running() -> bool:
    """Whether any worker that outlived its owner is still running."""
    return any(worker.isRunning() for worker in _DETACHED_WORKERS)


def run_after_detached_workers(callback: Callable[[], None]) -> None:
    """Run ``callback`` once every currently detached worker has finished.

    A detached worker can still be inside a backend syscall on the process it
    was given, so releasing that process (``close()``) must wait for it: on
    Windows the handle value can be recycled for an unrelated object the moment
    it is closed, and a late write from the cheat poller would land there.
    With no worker still running, ``callback`` runs immediately.
    """
    pending = [worker for worker in _DETACHED_WORKERS if worker.isRunning()]
    if not pending:
        callback()
        return

    remaining = set(pending)
    done = False
    # `finished` can be delivered from the worker's own thread while the
    # isFinished() sweep below runs on this one: guard the bookkeeping so the
    # callback (a handle close) runs exactly once.
    guard = threading.Lock()
    # Whichever thread notices the last worker finishing, the callback is
    # posted to the GUI thread (the application object lives there), so it
    # never runs concurrently with the GUI setting up the next process.
    gui = QCoreApplication.instance()

    def _on_finished(worker: QThread) -> None:
        nonlocal done
        with guard:
            remaining.discard(worker)
            if remaining or done:
                return
            done = True
        if gui is None:
            callback()
        else:
            QTimer.singleShot(0, gui, callback)

    for worker in pending:
        worker.finished.connect(lambda w=worker: _on_finished(w))
    # Same race as detach_worker: one may have finished before its connect.
    for worker in pending:
        if worker.isFinished():
            _on_finished(worker)


class TearsDownOnClose:
    """Mixin that runs a dialog's teardown on *every* way out, not just close.

    ``QDialog`` delivers a ``QCloseEvent`` only for a real close. The app's own
    "Close" buttons call ``accept()`` and Esc reaches ``reject()``; both land in
    ``done()``, which hides the dialog and emits ``finished`` *without* any
    close event — so a teardown living in ``closeEvent`` would never run, and
    the dialog would keep polling, hidden and unreachable.

    Subclasses implement :meth:`_teardown`; the mixin runs it exactly once,
    whichever way the dialog is dismissed, and must precede ``QDialog`` in the
    bases so its overrides win. Running once makes instances single-use, which
    is what every caller here assumes.
    """

    def _teardown(self) -> None:
        """Release timers and background threads. Runs exactly once."""
        raise NotImplementedError

    def _is_dismissed(self) -> bool:
        """Whether the teardown has run. Guards live on this, not on a repeated
        attribute lookup a typo could silently disable."""
        return getattr(self, "_teardown_done", False)

    def _run_teardown_once(self) -> None:
        if self._is_dismissed():
            return
        self._teardown_done = True
        self._teardown()

    def done(self, result: int) -> None:  # noqa: N802 — Qt naming
        self._run_teardown_once()
        super().done(result)

    def closeEvent(self, event) -> None:  # noqa: N802 — Qt naming
        self._run_teardown_once()
        super().closeEvent(event)


class NumericItem(QStandardItem):
    """A QStandardItem that compares by its Qt.UserRole int payload.

    Used by columns showing formatted numbers (sizes, addresses, PIDs) so the
    table sorts by the underlying value rather than the lexical label.

    The data storage interface is overridden because Qt keeps item data in a
    QVariant, whose integers cap at qint64. Values past 2**63 can't make that
    conversion — Linux x86-64 maps [vsyscall] at 0xffffffffff600000, so the
    memory map hands one such address to the C++ side and gets "OverflowError:
    int too big to convert", leaving the table half-populated. The workaround
    is to keep user-role payloads on the Python side, where an int is an int.

    The flip side: those payloads never reach the C++ model, so read them off
    the item (``item.data(role)``) and never through ``model.data(index,
    role)`` — that path converts the value back into a QVariant and overflows
    all over again.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_data: dict[int, Any] = {}

    def setData(self, value: Any, role: int = Qt.UserRole):
        if role >= Qt.UserRole:
            self._user_data[int(role)] = value
            self.emitDataChanged()
        else:
            super().setData(value, role)

    def data(self, role: int = Qt.UserRole) -> Any:
        if role >= Qt.UserRole:
            return self._user_data.get(int(role))
        else:
            return super().data(role)

    def __lt__(self, other: QStandardItem) -> bool:
        try:
            return int(self.data()) < int(other.data())
        except (TypeError, ValueError):
            return self.text() < other.text()


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _parse_hex_digits(text: str) -> Optional[int]:
    """``text`` as an unsigned hex number, or None. Accepts a ``0x`` prefix."""
    cleaned = text.strip()
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    # Explicit digit check rather than relying on int(): int(x, 16) also takes
    # "1_0" (underscore separators) and leading sign/whitespace, none of which
    # is a hex address a user meant to type.
    if not cleaned or not _HEX_DIGITS.issuperset(cleaned):
        return None
    return int(cleaned, 16)


def parse_hex_address(text: str) -> Optional[int]:
    """Parse a hex address string (with or without 0x prefix) into an int.

    Addresses are unsigned: a leading sign makes the string invalid. Returns
    None on any parse error. Surrounding whitespace is tolerated.
    """
    if not text:
        return None
    return _parse_hex_digits(text)


def parse_hex_offset(text: str) -> Optional[int]:
    """Parse a hex pointer-chain offset, which unlike an address may be negative.

    ``"-0x10"`` → -16, ``"10"`` → 16. Returns None on any parse error.
    """
    if not text:
        return None
    cleaned = text.strip()
    negative = cleaned.startswith("-")
    if negative or cleaned.startswith("+"):
        cleaned = cleaned[1:]
    parsed = _parse_hex_digits(cleaned)
    if parsed is None:
        return None
    return -parsed if negative else parsed


def format_size(size: int) -> str:
    """Human-readable byte count (``1536`` → ``"1.5 KB"``), binary units."""
    units = ["B", "KB", "MB", "GB", "TB"]
    s = float(size)
    for unit in units:
        if s < 1024 or unit == units[-1]:
            return f"{s:,.1f} {unit}" if unit != "B" else f"{int(s):,} B"
        s /= 1024
    return f"{size:,} B"


def parse_offsets(texts: Iterable[str]) -> Optional[List[int]]:
    """Parse pointer-chain offset tokens (in order) from raw field strings.

    Empty tokens are skipped; every remaining token is read as hex (with or
    without ``0x``, optionally negative). Returns ``None`` if any non-empty
    token can't be parsed — the caller treats that as "invalid chain, do
    nothing". Pure (no Qt) so it can be unit-tested directly.
    """
    offsets: List[int] = []
    for text in texts:
        if not text:
            continue
        parsed = parse_hex_offset(text)
        if parsed is None:
            return None
        offsets.append(parsed)
    return offsets


def resolve_base_address(
    text: str, module_lookup: Callable[[str], Optional[int]]
) -> Tuple[Optional[int], Optional[str]]:
    """Resolve a pointer-chain base field into an absolute address.

    Accepts either a plain hex address (``0x14010F4F4``) or Cheat-Engine's
    ``"module"+0xoffset`` form (``"libpython3.12.dylib"+0x4ED3D0``); for the
    latter the module's current load base is looked up via ``module_lookup``
    (a ``name -> base | None`` callable) and the offset added, so a saved
    pointer-scan path resolves correctly despite ASLR.

    Returns ``(address, None)`` on success or ``(None, error_message)`` on
    failure — the caller renders ``error_message`` in a dialog. Pure (no Qt).
    """
    text = text.strip()

    if "+" in text:
        name_part, _, offset_part = text.partition("+")
        module_name = name_part.strip().strip('"').strip("'").strip()
        offset = parse_hex_address(offset_part)
        if offset is None:
            return None, (
                "The offset after '+' must be hex "
                '(e.g. "game.exe"+0x10F4F4).'
            )
        module_base = module_lookup(module_name)
        if module_base is None:
            return None, (
                f"Module {module_name!r} is not loaded in this process.\n\n"
                "Open Tools → Modules to see the exact names available."
            )
        return module_base + offset, None

    base = parse_hex_address(text)
    if base is None:
        return None, (
            'Base must be hex (0x14010F4F4) or "module"+0xoffset '
            '(e.g. "game.exe"+0x10F4F4).'
        )
    return base, None
