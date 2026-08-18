# -*- coding: utf-8 -*-

"""Small Qt widgets shared between dialogs.

Centralises tiny helpers (numeric sort items, hex address parsing) that
previously appeared duplicated across several dialog modules.
"""

from typing import Any, Callable, Iterable, List, Optional, Tuple

from PySide6.QtCore import QElapsedTimer, Qt, QThread
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
        worker.disconnect()  # drop every outgoing connection at once
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
    way (``MainWindow._shutdown_worker`` pumps the event loop for its blocking
    connections) must park them *here* rather than in a list of their own:
    ``wait_for_detached_workers`` and ``call_when_detached_workers_finish``
    protect a process handle from exactly these threads, and a second registry
    is a set of threads they cannot see.
    """
    worker.setParent(None)
    _DETACHED_WORKERS.append(worker)
    worker.finished.connect(lambda: _reap_detached_worker(worker))


def _reap_detached_worker(worker: QThread) -> None:
    if worker in _DETACHED_WORKERS:
        _DETACHED_WORKERS.remove(worker)
    worker.deleteLater()


def wait_for_detached_workers(timeout_ms: int = 2000) -> bool:
    """Block until no detached worker is running. Returns whether that happened.

    The blocking sibling of :func:`call_when_detached_workers_finish`, for
    teardown that has no event loop left to deliver ``finished`` — application
    exit, once ``app.exec()`` has returned. ``QThread.wait`` needs no loop, so
    this is the only shape that works there.

    ``False`` means a worker is still wedged in a backend read after
    ``timeout_ms``; the caller must then leave whatever that worker reads
    through alone (at exit, the OS reclaims it moments later anyway).
    """
    deadline_left = timeout_ms
    for worker in list(_DETACHED_WORKERS):
        try:
            if not worker.isRunning():
                continue
            elapsed = QElapsedTimer()
            elapsed.start()
            worker.wait(max(deadline_left, 0))
            deadline_left -= int(elapsed.elapsed())
            if worker.isRunning():
                return False
        except RuntimeError:
            # Already reaped and deleted between the snapshot and here.
            continue
    return True


def call_when_detached_workers_finish(callback: Callable[[], None]) -> None:
    """Run ``callback`` once no currently-detached worker can still be running.

    Detaching (see :func:`shutdown_worker_thread`) keeps a wedged thread alive
    *past* the dialog that owned it — which is the whole point, but it means the
    thread may still be inside a backend read after its dialog is gone. Anything
    that pulls the ground out from under such a read (closing the process handle
    the worker reads through) has to wait for it, and this is how it waits
    without blocking the UI thread.

    Runs ``callback`` synchronously when nothing is detached, which is the
    normal case — detaching only happens when a worker blows its join timeout.

    The gate is the whole registry, not "the workers reading through *this*
    handle" — the registry doesn't track what each worker reads, and being
    over-conservative here costs a delayed close, while being wrong costs a
    read-after-close. The price is that one permanently wedged worker strands
    every later callback too: each subsequent process switch then leaks its old
    handle for the life of the app.

    That is the deliberate trade — a leaked handle over a read-after-close — so
    the callback must be something a leak can survive (releasing a handle, not
    freeing memory the app needs back). Callers that cannot wait for an event
    loop want :func:`wait_for_detached_workers`, which is bounded instead.
    """
    pending = [worker for worker in _DETACHED_WORKERS if worker.isRunning()]
    if not pending:
        callback()
        return

    remaining = {"count": len(pending), "called": False}

    def _one_finished() -> None:
        remaining["count"] -= 1
        if remaining["count"] <= 0 and not remaining["called"]:
            remaining["called"] = True
            callback()

    for worker in pending:
        fired = {"yet": False}

        def _slot(*_args, fired=fired) -> None:
            # Idempotent: `finished` and the isFinished() poll below can both
            # reach this, and only the first arrival may count.
            if fired["yet"]:
                return
            fired["yet"] = True
            _one_finished()

        try:
            worker.finished.connect(_slot)
            # The worker may have finished between the isRunning() filter and
            # the connect above, in which case `finished` already fired and
            # nothing would ever call the slot. Poll once to cover that window.
            done = worker.isFinished()
        except RuntimeError:
            # Reaped and deleted from under us: it cannot be reading any more,
            # and leaving it uncounted would strand the callback forever.
            done = True
        if done:
            _slot()


class TearsDownOnClose:
    """Mixin that runs a dialog's teardown on *every* way out, not just close.

    ``QDialog`` delivers a ``QCloseEvent`` only for a real close — the window
    manager's button, or an explicit ``close()``. This app's own "Close" buttons
    call ``accept()`` and Esc reaches ``reject()``; both land in ``done()``,
    which hides the dialog and emits ``finished`` **without** any close event.

    A dialog that stops its timers and joins its worker in ``closeEvent`` is
    therefore still polling after the user closed it — hidden, unreachable
    (the main window drops its reference on ``finished``), leaking a thread per
    open/close cycle, and able to pop a modal from behind nothing. Worse for
    this app: its worker never reaches :func:`shutdown_worker_thread`, so it is
    absent from the detached registry that keeps a process handle alive while
    something is still reading through it.

    Subclasses implement :meth:`_teardown`; the mixin runs it exactly once,
    whichever way the dialog is dismissed. It must precede ``QDialog`` in the
    bases so its overrides win.

    Running *once* makes instances single-use, which is what every caller here
    already assumes: the main window drops its reference on ``finished`` and
    builds a fresh dialog next time. A dialog meant to be reshown after being
    dismissed would have to re-arm what ``_teardown`` released rather than lean
    on the latch.
    """

    def _teardown(self) -> None:
        """Release timers and background threads. Runs exactly once."""
        raise NotImplementedError

    def _run_teardown_once(self) -> None:
        if getattr(self, "_teardown_done", False):
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


def parse_offsets(texts: Iterable[str]) -> Optional[List[int]]:
    """Parse pointer-chain offset tokens (in order) from raw field strings.

    Empty tokens are skipped; every remaining token is read as hex (with or
    without ``0x``). Returns ``None`` if any non-empty token can't be parsed —
    the caller treats that as "invalid chain, do nothing". Pure (no Qt) so it
    can be unit-tested directly.
    """
    offsets: List[int] = []
    for text in texts:
        if not text:
            continue
        parsed = parse_hex_address(text)
        if parsed is None:
            # parse_hex_address handles the 0x form; fall back to a plain hex
            # int for ambiguous tokens like "10" (the dialog treats offsets as
            # hex throughout).
            try:
                parsed = int(text, 16)
            except ValueError:
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
            try:
                offset = int(offset_part.strip(), 16)
            except ValueError:
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
