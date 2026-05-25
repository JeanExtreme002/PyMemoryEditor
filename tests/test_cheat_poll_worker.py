# -*- coding: utf-8 -*-

"""
Functional tests for ``_CheatPollWorker._poll_once`` — the hot path that
polls the target process for every cheat-table entry's current value and
re-writes frozen entries.

The worker is a ``QThread`` but ``_poll_once`` is just a method — these
tests instantiate the worker with a fake process and call the method
directly without ever running the Qt event loop or starting a thread.
This pins down the polling behavior (batching threshold, freeze-write,
exception swallowing) that drives every cheat-table refresh.
"""

import os

import pytest


pytest.importorskip(
    "PySide6", reason="App tests require PySide6 (install with [app] extra)."
)

# Headless Qt is enough for the QObject machinery we touch.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qapp():
    """A single QApplication for the module — QObjects need one to exist."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


class _FakeProcess:
    """
    Minimal stand-in for AbstractProcess. Records every call so tests can
    assert the worker dispatched the right read path and surfaced the
    frozen-write.
    """

    def __init__(self, values=None, raise_on_batch=False, raise_on_read=False):
        # Map (address, pytype, length) → value to return on read.
        self.values = values or {}
        self.raise_on_batch = raise_on_batch
        self.raise_on_read = raise_on_read
        self.read_calls = []
        self.write_calls = []
        self.batch_calls = []

    def search_by_addresses(self, pytype, length, addresses):
        self.batch_calls.append((pytype, length, tuple(addresses)))
        if self.raise_on_batch:
            raise OSError("simulated batch failure")
        for addr in addresses:
            yield addr, self.values.get((addr, pytype, length))

    def read_process_memory(self, address, pytype, length):
        self.read_calls.append((address, pytype, length))
        if self.raise_on_read:
            raise OSError("simulated read failure")
        return self.values.get((address, pytype, length))

    def write_process_memory(self, address, pytype, length, value):
        self.write_calls.append((address, pytype, length, value))
        return value


def _make_worker(process):
    """Build a worker without starting its thread."""
    from PyMemoryEditor.app.cheat_table import _CheatPollWorker

    return _CheatPollWorker(process)


def test_per_entry_read_path_when_below_batch_threshold(qapp):
    """Fewer than 8 entries → per-entry read_process_memory, no batched call."""
    process = _FakeProcess(
        values={(0x1000, int, 4): 42, (0x1004, int, 4): 7},
    )
    worker = _make_worker(process)

    snapshot = [
        (0x1000, int, 4, None, False),
        (0x1004, int, 4, None, False),
    ]
    results = worker._poll_once(snapshot)

    by_addr = {addr: value for addr, _pytype, _length, value in results}
    assert by_addr == {0x1000: 42, 0x1004: 7}
    assert process.batch_calls == []  # No batching below threshold.
    assert len(process.read_calls) == 2


def test_batched_read_path_above_threshold(qapp):
    """≥ 8 entries with shared (pytype, length) → single search_by_addresses call."""
    addresses = list(range(0x1000, 0x1000 + 8 * 4, 4))  # 8 addrs, int32
    process = _FakeProcess(
        values={(addr, int, 4): addr & 0xFF for addr in addresses},
    )
    worker = _make_worker(process)

    snapshot = [(addr, int, 4, None, False) for addr in addresses]
    results = worker._poll_once(snapshot)

    assert len(results) == 8
    assert len(process.batch_calls) == 1
    # No per-entry fallback when batched read succeeded.
    assert process.read_calls == []


def test_batched_path_falls_back_to_per_entry_on_failure(qapp):
    """If the batched read raises, the worker must still surface what it can per-entry."""
    addresses = list(range(0x2000, 0x2000 + 8 * 4, 4))
    process = _FakeProcess(
        values={(addr, int, 4): 1 for addr in addresses},
        raise_on_batch=True,
    )
    worker = _make_worker(process)

    snapshot = [(addr, int, 4, None, False) for addr in addresses]
    results = worker._poll_once(snapshot)

    assert len(results) == 8
    assert all(value == 1 for _addr, _pt, _len, value in results)
    assert len(process.batch_calls) == 1  # tried once
    assert len(process.read_calls) == 8   # then fell through per-entry


def test_frozen_entries_get_written_each_tick(qapp):
    """A frozen entry must be re-written every poll, even if the read succeeded."""
    process = _FakeProcess(values={(0x3000, int, 4): 999})
    worker = _make_worker(process)

    snapshot = [
        (0x3000, int, 4, 42, True),  # frozen with frozen_value=42
    ]
    results = worker._poll_once(snapshot)

    # Frozen value overrides whatever was read.
    assert results == [(0x3000, int, 4, 42)]
    assert process.write_calls == [(0x3000, int, 4, 42)]


def test_frozen_entry_with_none_value_does_not_write(qapp):
    """Freeze checkbox active but no frozen_value yet → don't write."""
    process = _FakeProcess(values={(0x4000, int, 4): 5})
    worker = _make_worker(process)

    snapshot = [
        (0x4000, int, 4, None, True),  # frozen=True but value not captured
    ]
    results = worker._poll_once(snapshot)

    assert results == [(0x4000, int, 4, 5)]
    assert process.write_calls == []


def test_read_failure_is_absorbed(qapp):
    """A read that raises must surface as value=None, not crash the poll loop."""
    process = _FakeProcess(raise_on_read=True)
    worker = _make_worker(process)

    snapshot = [
        (0x5000, int, 4, None, False),
        (0x5004, int, 4, None, False),
    ]
    results = worker._poll_once(snapshot)

    assert results == [
        (0x5000, int, 4, None),
        (0x5004, int, 4, None),
    ]


def test_mixed_types_are_grouped_separately(qapp):
    """Entries with different (pytype, length) keys go to independent groups."""
    process = _FakeProcess(
        values={
            (0x6000, int, 4): 1,
            (0x7000, float, 8): 3.14,
            (0x8000, bytes, 16): b"hello",
        },
    )
    worker = _make_worker(process)

    snapshot = [
        (0x6000, int, 4, None, False),
        (0x7000, float, 8, None, False),
        (0x8000, bytes, 16, None, False),
    ]
    results = worker._poll_once(snapshot)

    by_addr = {addr: value for addr, _pt, _len, value in results}
    assert by_addr == {0x6000: 1, 0x7000: 3.14, 0x8000: b"hello"}


def test_empty_snapshot_yields_nothing(qapp):
    """No entries → no syscalls, empty result."""
    process = _FakeProcess()
    worker = _make_worker(process)

    assert worker._poll_once([]) == []
    assert process.read_calls == []
    assert process.batch_calls == []
    assert process.write_calls == []
