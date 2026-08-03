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
