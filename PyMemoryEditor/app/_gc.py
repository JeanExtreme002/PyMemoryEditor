# -*- coding: utf-8 -*-

"""Run Python's cyclic garbage collector on the GUI thread only.

The automatic collector runs in whichever thread happens to allocate when a
threshold is crossed -- in this app, often a ``QThread`` worker in the middle
of a scan. If that collection frees a reference cycle holding Qt objects that
belong to the GUI thread, they are destroyed from the worker, which crashes
the process (a segfault on macOS, an access violation on Windows; seen on CI
in the pointer-scan worker's ``_hand_over``).

So while the app runs, automatic collection is switched off and a timer on the
GUI thread collects instead, generation by generation, as the automatic
collector would have. Plain reference counting still frees everything that is
not in a cycle immediately, in any thread.
"""

import contextlib
import gc
from typing import Iterator, Optional

from PySide6.QtCore import QObject, QTimer


#: How often the GUI thread checks whether a collection is due.
COLLECT_INTERVAL_MS = 500


class MainThreadGarbageCollector(QObject):
    """Disable automatic collection and collect from a GUI-thread timer.

    Create it on the GUI thread; :meth:`stop` restores the collector's previous
    state, so an embedder's own setting survives the app.
    """

    def __init__(
        self, parent: Optional[QObject] = None, interval_ms: int = COLLECT_INTERVAL_MS
    ) -> None:
        super().__init__(parent)
        self._was_enabled = gc.isenabled()
        self._threshold = gc.get_threshold()
        gc.disable()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.collect_if_due)
        self._timer.start(interval_ms)

    def collect_if_due(self) -> None:
        """Collect each generation whose allocation count passed its threshold."""
        count0, count1, count2 = gc.get_count()
        if count0 > self._threshold[0]:
            gc.collect(0)
            if count1 > self._threshold[1]:
                gc.collect(1)
                if count2 > self._threshold[2]:
                    gc.collect(2)

    def stop(self) -> None:
        """Stop the timer and give automatic collection back."""
        self._timer.stop()
        if self._was_enabled:
            gc.enable()


@contextlib.contextmanager
def garbage_collected_on_gui_thread(parent: Optional[QObject] = None) -> Iterator[None]:
    """Run the body with :class:`MainThreadGarbageCollector` in charge."""
    collector = MainThreadGarbageCollector(parent)
    try:
        yield
    finally:
        collector.stop()
