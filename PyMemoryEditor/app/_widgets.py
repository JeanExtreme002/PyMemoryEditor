# -*- coding: utf-8 -*-

"""Small Qt widgets shared between dialogs.

Centralises tiny helpers (numeric sort items, hex address parsing) that
previously appeared duplicated across several dialog modules.
"""

from typing import Any, Callable, Iterable, List, Optional, Tuple

from PySide6.QtCore import Qt, QThread
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

    The data storage interface for QStandardItem is overridden because the Pyside6
    bindings do not seem to support, detect, or coerce to unsigned integers,
    leading to overflow errors when converting from large Python ints to fixed
    size signed integers in Qt. The workaround is to keep the potentially overflowing
    integers on the Python side.
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
