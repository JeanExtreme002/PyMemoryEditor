# -*- coding: utf-8 -*-

"""``MainThreadGarbageCollector``: the cyclic collector runs on the GUI thread."""

import gc
import threading

import pytest

pytest.importorskip("PySide6")


class _Cycle:
    def __init__(self, sink):
        self.self = self
        self.sink = sink

    def __del__(self):
        self.sink.append(threading.current_thread() is threading.main_thread())


def test_it_turns_automatic_collection_off_and_back_on(qtbot):
    from PyMemoryEditor.app._gc import MainThreadGarbageCollector

    gc.enable()
    collector = MainThreadGarbageCollector()
    try:
        assert not gc.isenabled()
    finally:
        collector.stop()
    assert gc.isenabled()


def test_it_keeps_a_caller_disabled_collector_disabled(qtbot):
    from PyMemoryEditor.app._gc import MainThreadGarbageCollector

    gc.disable()
    try:
        MainThreadGarbageCollector().stop()
        assert not gc.isenabled()
    finally:
        gc.enable()


def test_its_timer_collects_cycles_on_the_gui_thread(qtbot, monkeypatch):
    from PyMemoryEditor.app._gc import MainThreadGarbageCollector

    gc.collect()
    # Any allocation makes a collection due, so the first tick runs one.
    monkeypatch.setattr(gc, "get_threshold", lambda: (0, 0, 0))
    collector = MainThreadGarbageCollector(interval_ms=10)
    try:
        freed = []
        _Cycle(freed)
        qtbot.waitUntil(lambda: bool(freed), timeout=2000)
        assert freed == [True]
    finally:
        collector.stop()
