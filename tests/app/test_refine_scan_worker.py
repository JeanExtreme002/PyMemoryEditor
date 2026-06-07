# -*- coding: utf-8 -*-

"""
Functional tests for ``RefineScanWorker`` — Cheat Engine's "Next Scan".

These focus on the comparison block, including the app-only Increased /
Decreased / Changed / Unchanged / *_BY types that compare the freshly-read
value against the value recorded by the previous scan. ``run`` is a ``QThread``
method but we call it directly (no thread, no event loop) and collect the
``chunk_ready`` signal — the same pattern as ``test_cheat_poll_worker``.
"""

import os

import pytest


pytest.importorskip(
    "PySide6", reason="App tests require PySide6 (install with [app] extra)."
)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyMemoryEditor.app.scan_types import NextScanType  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


class _FakeProcess:
    """Returns the configured current value for each requested address."""

    def __init__(self, current):
        self._current = current  # {address: value}

    def search_by_addresses(self, pytype, length, addresses, *, memory_regions=None):
        for addr in addresses:
            yield addr, self._current.get(addr)


def _spec():
    from PyMemoryEditor.app.value_types import VALUE_TYPES

    return VALUE_TYPES[0]  # 4 Bytes (Int32)


def _run(process, scan_type, value, previous, current):
    """Run a refine pass and return {address: keeps} for the readable rows."""
    from PyMemoryEditor.app.scan_worker import RefineScanWorker, ScanRequest

    request = ScanRequest(
        spec=_spec(),
        length=4,
        scan_type=scan_type,
        value=value,
    )
    worker = RefineScanWorker(
        process,
        request,
        list(previous.keys()),
        filter_only=True,
        previous_values=previous,
    )

    collected = {}

    def collect(chunk):
        for address, _current, keeps in chunk:
            collected[address] = keeps

    worker.chunk_ready.connect(collect)
    worker.run()
    return collected


@pytest.mark.parametrize(
    "scan_type, value, expected_kept",
    [
        (NextScanType.INCREASED_VALUE, None, {0x10, 0x30}),  # 10→11, 30→31 up
        (NextScanType.DECREASED_VALUE, None, {0x20}),        # 20→5 down
        (NextScanType.CHANGED_VALUE, None, {0x10, 0x20, 0x30}),
        (NextScanType.UNCHANGED_VALUE, None, {0x40}),        # 40 stayed 8
        (NextScanType.INCREASED_VALUE_BY, 1, {0x10, 0x30}),  # both rose by exactly 1
        (NextScanType.DECREASED_VALUE_BY, 15, {0x20}),       # 20 → 5 is -15
    ],
)
def test_previous_value_comparisons(qapp, scan_type, value, expected_kept):
    previous = {0x10: 10, 0x20: 20, 0x30: 30, 0x40: 8}
    current = {0x10: 11, 0x20: 5, 0x30: 31, 0x40: 8}
    process = _FakeProcess(current)

    collected = _run(process, scan_type, value, previous, current)
    kept = {addr for addr, keeps in collected.items() if keeps}
    assert kept == expected_kept


def test_increased_value_by_rejects_wrong_delta(qapp):
    previous = {0x10: 10}
    current = {0x10: 13}  # rose by 3, not by 1
    process = _FakeProcess(current)

    collected = _run(process, NextScanType.INCREASED_VALUE_BY, 1, previous, current)
    assert collected == {0x10: False}


def test_missing_baseline_is_dropped(qapp):
    # Address has no recorded previous value → nothing to compare, so drop it.
    previous = {0x10: None}
    current = {0x10: 99}
    process = _FakeProcess(current)

    collected = _run(process, NextScanType.INCREASED_VALUE, None, previous, current)
    assert collected == {0x10: False}


def test_unreadable_address_is_dropped(qapp):
    previous = {0x10: 10}
    current = {0x10: None}  # dead/unreadable page
    process = _FakeProcess(current)

    collected = _run(process, NextScanType.CHANGED_VALUE, None, previous, current)
    assert collected == {0x10: False}
