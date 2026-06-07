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

    def __init__(
        self,
        values=None,
        raise_on_batch=False,
        raise_on_read=False,
        raise_on_write=False,
    ):
        # Map (address, pytype, length) → value to return on read.
        self.values = values or {}
        self.raise_on_batch = raise_on_batch
        self.raise_on_read = raise_on_read
        self.raise_on_write = raise_on_write
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
        if self.raise_on_write:
            raise OSError("simulated write failure")
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


def test_frozen_write_failure_is_recorded_not_swallowed(qapp):
    """A failing freeze write must be recorded (so the UI can flag it), not
    silently swallowed, and the read value must still be surfaced so the table
    shows the value drifting away from the frozen target."""
    process = _FakeProcess(values={(0x3000, int, 4): 123}, raise_on_write=True)
    worker = _make_worker(process)

    snapshot = [(0x3000, int, 4, 42, True)]  # frozen with frozen_value=42
    results = worker._poll_once(snapshot)

    # The write was attempted...
    assert process.write_calls == [(0x3000, int, 4, 42)]
    # ...failed, so the surfaced value is the real (drifting) read, not 42.
    assert results == [(0x3000, int, 4, 123)]
    # ...and the failure is tracked for the UI cue.
    assert (0x3000, int, 4) in worker._freeze_failures
    assert "OSError" in worker._freeze_failures[(0x3000, int, 4)]


def test_frozen_write_failure_clears_when_write_recovers(qapp):
    """Once the freeze write succeeds again, the entry drops out of the failing
    set so the UI can clear its red cue."""
    process = _FakeProcess(values={(0x3000, int, 4): 123}, raise_on_write=True)
    worker = _make_worker(process)
    snapshot = [(0x3000, int, 4, 42, True)]

    worker._poll_once(snapshot)
    assert (0x3000, int, 4) in worker._freeze_failures

    # Backend recovers; next tick's write lands.
    process.raise_on_write = False
    results = worker._poll_once(snapshot)

    assert worker._freeze_failures == {}
    assert results == [(0x3000, int, 4, 42)]  # frozen value applied again


def test_unfreezing_a_failing_entry_drops_it_from_failures(qapp):
    """An entry removed/unfrozen between ticks must not linger in the failing
    set (it's rebuilt from the live snapshot each tick)."""
    process = _FakeProcess(values={(0x3000, int, 4): 123}, raise_on_write=True)
    worker = _make_worker(process)

    worker._poll_once([(0x3000, int, 4, 42, True)])
    assert (0x3000, int, 4) in worker._freeze_failures

    # Same entry, but no longer frozen → no write attempt, no failure.
    worker._poll_once([(0x3000, int, 4, 42, False)])
    assert worker._freeze_failures == {}


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


def test_request_write_is_queued_and_drained(qapp):
    """A manual write is queued and performed by the worker, not inline.

    Routing the cheat-table's inline value edit through the worker keeps the
    write_process_memory syscall off the UI thread.
    """
    process = _FakeProcess()
    worker = _make_worker(process)

    # Queuing alone performs no syscall.
    worker.request_write(0x1000, int, 4, 77)
    assert process.write_calls == []

    failures = worker._drain_pending_writes()

    assert failures == []
    assert process.write_calls == [(0x1000, int, 4, 77)]
    # The queue is cleared after draining.
    assert worker._drain_pending_writes() == []
    assert process.write_calls == [(0x1000, int, 4, 77)]


def test_request_write_failure_is_reported(qapp):
    """A manual write that fails comes back as a (key, message) failure tuple
    so the UI can surface it via the write_failed signal."""
    process = _FakeProcess(raise_on_write=True)
    worker = _make_worker(process)

    worker.request_write(0x2000, int, 4, 5)
    failures = worker._drain_pending_writes()

    assert len(failures) == 1
    address, pytype, length, message = failures[0]
    assert (address, pytype, length) == (0x2000, int, 4)
    assert "OSError" in message
