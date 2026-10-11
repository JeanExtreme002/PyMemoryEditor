# -*- coding: utf-8 -*-

"""
Tests for the shared item widgets in ``PyMemoryEditor/app/_widgets.py``.

Only ``NumericItem`` so far, whose sort payload can't live in a ``QVariant``:
Qt caps those integers at ``qint64``, but Linux x86-64 maps ``[vsyscall]`` at
0xffffffffff600000 (above 2**63), so pushing that address through
``QStandardItem.setData`` raises "OverflowError: int too big to convert" and
leaves the memory map half-populated.

Unlike the dialog tests these need no ``qtbot`` — a ``QApplication`` is enough,
so they keep running when ``pytest-qt`` isn't installed.

Skipped when ``PySide6`` isn't installed (the runtime dependency is opt-in via
the ``app`` extra).
"""

import os

import pytest


pytest.importorskip("PySide6", reason="App tests require PySide6 (install with [app] extra).")

# Offscreen platform plugin: no display server needed, runs on CI.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qapp():
    """A single QApplication for the module (Qt allows only one per process)."""
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_pyside_widget_regressions(qapp):
    """
    Test for Pyside related regressions, like potential overflow and comparison in NumericItem.
    """

    from PySide6.QtCore import Qt
    from PySide6.QtGui import QStandardItemModel

    from PyMemoryEditor.app import _widgets

    unsigned_64bit_max = 0xffff_ffff_ffff_ffff
    big_number = 2 ** 128

    # Overflow regressions.
    item = _widgets.NumericItem()
    item.setData(unsigned_64bit_max)
    assert item.data() == unsigned_64bit_max

    item2 = _widgets.NumericItem()
    item2.setData(big_number)
    assert item2.data() == big_number

    # Non-numeric payloads must fall back to the labels instead of recursing
    # into QStandardItem::operator< (that recursion segfaulted mid-sort).
    assert item < item2

    item3 = _widgets.NumericItem('aaa')
    item3.setData('hello world')
    item4 = _widgets.NumericItem('bbb')
    item4.setData('hello world')
    assert item3 < item4
    assert not (item4 < item3)

    # Distinct user roles must not share a slot.
    item5 = _widgets.NumericItem()
    item5.setData(111, Qt.UserRole)
    item5.setData(222, Qt.UserRole + 1)
    assert item5.data(Qt.UserRole) == 111
    assert item5.data(Qt.UserRole + 1) == 222

    # The path that actually crashed: the C++ sort driving the comparisons over
    # a column mixing payloads and None (the process picker's memory column).
    model = QStandardItemModel()
    for label, payload in (('120 MB', 120), ('-', None), ('8 MB', 8), ('-', None)):
        row_item = _widgets.NumericItem(label)
        row_item.setData(payload, Qt.UserRole)
        model.appendRow([row_item])
    model.sort(0, Qt.AscendingOrder)
    order = [model.item(row, 0).data(Qt.DisplayRole) for row in range(model.rowCount())]
    assert order.index('8 MB') < order.index('120 MB')


# --- hex parsing ---------------------------------------------------------- #


@pytest.mark.parametrize(
    "text, expected",
    (
        ("0x1000", 0x1000),
        ("1000", 0x1000),
        ("  0X7FFE  ", 0x7FFE),
        ("deadBEEF", 0xDEADBEEF),
    ),
)
def test_parse_hex_address_accepts_plain_and_prefixed_hex(text, expected):
    from PyMemoryEditor.app._widgets import parse_hex_address

    assert parse_hex_address(text) == expected


@pytest.mark.parametrize("text", ("", "   ", "0x", "zz", "-10", "+10", "1_0", "0x-1", "1 0"))
def test_parse_hex_address_rejects_what_is_not_an_unsigned_hex_number(text):
    """
    Addresses are unsigned. ``int(text, 16)`` alone also took a leading sign
    and underscore separators, so a manual cheat entry could end up with a
    negative address.
    """
    from PyMemoryEditor.app._widgets import parse_hex_address

    assert parse_hex_address(text) is None


@pytest.mark.parametrize(
    "text, expected",
    (("0x10", 0x10), ("-0x10", -0x10), ("-10", -0x10), ("+8", 8), ("0", 0)),
)
def test_parse_hex_offset_allows_a_sign(text, expected):
    from PyMemoryEditor.app._widgets import parse_hex_offset

    assert parse_hex_offset(text) == expected


@pytest.mark.parametrize("text", ("", "-", "--10", "1_0", "zz"))
def test_parse_hex_offset_rejects_garbage(text):
    from PyMemoryEditor.app._widgets import parse_hex_offset

    assert parse_hex_offset(text) is None


# --- size formatting ------------------------------------------------------ #


@pytest.mark.parametrize(
    "size, expected",
    (
        (0, "0 B"),
        (1023, "1,023 B"),
        (1024, "1.0 KB"),
        (1536, "1.5 KB"),
        (3 * 1024 ** 2, "3.0 MB"),
        (1024 ** 5, "1,024.0 TB"),
    ),
)
def test_format_size_uses_binary_units(size, expected):
    """One formatter for the Memory Map, Modules and Open Process tables."""
    from PyMemoryEditor.app._widgets import format_size

    assert format_size(size) == expected


# --- releasing a process after detached workers ---------------------------- #


def test_run_after_detached_workers_runs_at_once_when_none_is_running(qapp):
    from PyMemoryEditor.app._widgets import run_after_detached_workers

    calls = []
    run_after_detached_workers(lambda: calls.append("closed"))
    assert calls == ["closed"]


def test_run_after_detached_workers_waits_for_a_wedged_worker(qapp):
    """Changing process must not close the old handle under a worker that is
    still inside a syscall on it: the close waits for the worker to finish."""
    import threading

    from PySide6.QtCore import QCoreApplication, QThread

    from PyMemoryEditor.app._widgets import (
        _DETACHED_WORKERS,
        detach_worker,
        run_after_detached_workers,
    )

    release = threading.Event()

    class _Wedged(QThread):
        def run(self):
            release.wait(5)

    worker = _Wedged()
    worker.start()
    detach_worker(worker)
    joined = False
    try:
        calls = []
        threads = []

        def close():
            calls.append("closed")
            threads.append(threading.current_thread())

        run_after_detached_workers(close)
        assert calls == []

        release.set()
        joined = worker.wait(5000)
        assert joined
        # `finished` is delivered to the GUI thread as a queued call.
        for _ in range(50):
            QCoreApplication.processEvents()
            if calls:
                break
            QThread.msleep(10)
        assert calls == ["closed"]
        # On the GUI thread, never the worker's: the close must not race the
        # GUI setting up the next process.
        assert threads == [threading.main_thread()]
        assert worker not in _DETACHED_WORKERS
    finally:
        release.set()
        # Once joined, the reaper may already have deleted the QThread; only
        # an early failure leaves a running thread to wait for.
        if not joined:
            worker.wait(5000)
