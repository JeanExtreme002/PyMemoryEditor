# -*- coding: utf-8 -*-

"""
Handle bookkeeping: sessions, scan result sets, and the region batching.
"""

import pytest

from PyMemoryEditor.mcp import session as session_module
from PyMemoryEditor.mcp.session import (
    MAX_OPEN_SESSIONS,
    MAX_SCANS_PER_SESSION,
    SessionError,
    SessionStore,
    batch_regions,
    region_to_dict,
)
from PyMemoryEditor.process.region import MemoryRegion

from .conftest import FakeProcess


@pytest.fixture
def store() -> SessionStore:
    return SessionStore()


class TestSessions:
    def test_ids_are_short_and_sequential(self, store):
        # Not UUIDs: a model retypes these into the next call, and every extra
        # character is both context and a chance to get it wrong.
        first = store.open(FakeProcess(), 1, "a")
        second = store.open(FakeProcess(), 2, "b")
        assert first.session_id == "proc-1"
        assert second.session_id == "proc-2"

    def test_get_returns_the_session(self, store):
        session = store.open(FakeProcess(), 1, "a")
        assert store.get(session.session_id) is session

    def test_unknown_session_lists_the_live_ones(self, store):
        store.open(FakeProcess(), 1, "a")
        with pytest.raises(SessionError, match="proc-1"):
            store.get("proc-99")

    def test_unknown_session_says_how_to_get_one(self, store):
        with pytest.raises(SessionError, match="open_process"):
            store.get("proc-1")

    def test_close_closes_the_target_handle(self, store):
        process = FakeProcess()
        session = store.open(process, 1, "a")
        store.close(session.session_id)
        assert process.closed

    def test_close_forgets_the_session(self, store):
        session = store.open(FakeProcess(), 1, "a")
        store.close(session.session_id)
        with pytest.raises(SessionError):
            store.get(session.session_id)

    def test_double_close_raises_rather_than_silently_passing(self, store):
        session = store.open(FakeProcess(), 1, "a")
        store.close(session.session_id)
        with pytest.raises(SessionError):
            store.close(session.session_id)

    def test_close_survives_a_target_that_already_died(self, store):
        class Dying(FakeProcess):
            def close(self):
                raise OSError("process is gone")

        session = store.open(Dying(), 1, "a")
        # The handle is unusable either way; failing here would leave the
        # session stuck in the store forever.
        assert store.close(session.session_id) is session

    def test_close_all_closes_every_handle(self, store):
        processes = [FakeProcess(pid=index) for index in range(3)]
        for index, process in enumerate(processes):
            store.open(process, index, "p%d" % index)

        assert store.close_all() == 3
        assert all(process.closed for process in processes)
        assert store.sessions == ()


class TestConcurrentLookups:
    def test_an_unknown_id_error_survives_concurrent_open_and_close(self):
        # The error path built its message from `sorted(self._sessions)` outside
        # the lock. Tool calls run on a thread pool, so a concurrent open/close
        # could resize the dict mid-iteration and replace a helpful SessionError
        # with a bare "dictionary changed size during iteration".
        import threading

        store = SessionStore()
        stop = threading.Event()
        failures = []

        def churn():
            while not stop.is_set():
                try:
                    session = store.open(FakeProcess(), 1, "a")
                    store.close(session.session_id)
                except Exception as error:  # pragma: no cover
                    failures.append(error)

        def lookup():
            while not stop.is_set():
                try:
                    store.get("proc-does-not-exist")
                except SessionError:
                    pass
                except Exception as error:
                    failures.append(error)

        threads = [threading.Thread(target=churn) for _ in range(3)]
        threads += [threading.Thread(target=lookup) for _ in range(3)]
        for thread in threads:
            thread.start()
        stop.wait(1.0)
        stop.set()
        for thread in threads:
            thread.join()

        assert not failures, failures[:3]


class TestScanResults:
    def _scan(self, store, session, addresses=(1, 2, 3), **kwargs):
        return store.new_scan(
            session,
            value_type="int",
            bufflength=4,
            addresses=list(addresses),
            description="int == 1",
            **kwargs,
        )

    def test_scan_ids_are_unique_across_sessions(self, store):
        first = store.open(FakeProcess(), 1, "a")
        second = store.open(FakeProcess(), 2, "b")
        assert self._scan(store, first).scan_id != self._scan(store, second).scan_id

    def test_find_scan_resolves_without_naming_the_session(self, store):
        session = store.open(FakeProcess(), 1, "a")
        scan = self._scan(store, session)
        found_session, found_scan = store.find_scan(scan.scan_id)
        assert found_session is session and found_scan is scan

    def test_find_unknown_scan_explains_how_to_get_one(self, store):
        with pytest.raises(SessionError, match="scan_value"):
            store.find_scan("scan-42")

    def test_count_reflects_the_addresses(self, store):
        session = store.open(FakeProcess(), 1, "a")
        assert self._scan(store, session, addresses=range(10)).count == 10

    @pytest.mark.parametrize("flags", [{"truncated": True}, {"timed_out": True}])
    def test_either_early_stop_marks_the_set_partial(self, store, flags):
        session = store.open(FakeProcess(), 1, "a")
        assert self._scan(store, session, **flags).is_partial

    def test_a_complete_set_is_not_partial(self, store):
        session = store.open(FakeProcess(), 1, "a")
        assert not self._scan(store, session).is_partial

    def test_oldest_scans_are_evicted_past_the_cap(self, store):
        session = store.open(FakeProcess(), 1, "a")
        scans = [self._scan(store, session) for _ in range(MAX_SCANS_PER_SESSION + 5)]

        assert len(session.scan_ids) == MAX_SCANS_PER_SESSION
        # The oldest are gone; the newest are all still reachable.
        with pytest.raises(SessionError, match="most recent"):
            session.get_scan(scans[0].scan_id)
        assert session.get_scan(scans[-1].scan_id) is scans[-1]

    def test_closing_a_session_drops_its_scans(self, store):
        session = store.open(FakeProcess(), 1, "a")
        scan = self._scan(store, session)
        store.close(session.session_id)
        with pytest.raises(SessionError):
            store.find_scan(scan.scan_id)


class TestRegionSnapshotCaching:
    def test_first_call_takes_a_snapshot(self, store):
        session = store.open(FakeProcess(), 1, "a")
        assert session.regions is None
        assert len(session.snapshot_regions()) == 2

    def test_snapshot_is_reused_until_refreshed(self, store):
        session = store.open(FakeProcess(), 1, "a")
        first = session.snapshot_regions()
        assert session.snapshot_regions() is first
        assert session.snapshot_regions(refresh=True) is not first

    def test_snapshot_is_address_sorted(self, store):
        session = store.open(FakeProcess(), 1, "a")
        regions = session.snapshot_regions()
        assert [region.address for region in regions] == sorted(
            region.address for region in regions
        )


@pytest.fixture
def all_alive(monkeypatch):
    """Pin every session's target as live.

    The store reaps sessions whose pid is gone, and a fake's pid is an
    arbitrary number — so without this these tests depend on the host's
    process table, and the cap either fires or does not by luck. (Several
    passed only because `pid_exists(1)` is true on a Unix host.)
    """
    monkeypatch.setattr(session_module, "pid_exists", lambda pid: True)


class TestOpenSessionsAreCapped:
    """The store used to accept any number of open processes, each holding an
    OS handle that only `close_process` releases."""

    def test_the_cap_is_enforced(self, store, all_alive):
        for _ in range(MAX_OPEN_SESSIONS):
            store.open(FakeProcess(), 1, "a")

        with pytest.raises(SessionError) as error:
            store.open(FakeProcess(), 1, "a")

        assert str(MAX_OPEN_SESSIONS) in str(error.value)

    def test_the_refusal_says_how_to_recover(self, store, all_alive):
        """The model cannot see the store, so the message has to name an id to
        close and list what is open."""
        for index in range(MAX_OPEN_SESSIONS):
            store.open(FakeProcess(pid=100 + index), 100 + index, "target%d" % index)

        with pytest.raises(SessionError) as error:
            store.open(FakeProcess(), 999, "another")

        message = str(error.value)
        assert "close_process" in message
        assert "proc-1" in message          # every open session is listed
        assert "target0" in message
        assert "pid 100" in message
        # No "close the oldest": the oldest is usually the target the whole
        # session has been refining, and closing it discards its scans too.
        assert "oldest" not in message
        # The scan count is what makes the list actionable.
        assert "scan" in message

    def test_closing_one_frees_a_slot(self, store, all_alive):
        ids = [store.open(FakeProcess(), 1, "a").session_id
               for _ in range(MAX_OPEN_SESSIONS)]

        store.close(ids[0])
        reopened = store.open(FakeProcess(), 2, "b")

        assert reopened.session_id not in ids
        assert len(store.sessions) == MAX_OPEN_SESSIONS

    def test_ids_keep_climbing_after_a_close(self, store, all_alive):
        """Reusing an id would let a model holding a stale one address a
        different process."""
        first = store.open(FakeProcess(), 1, "a").session_id
        store.close(first)
        second = store.open(FakeProcess(), 2, "b").session_id

        assert first != second


class TestDeadSessionsDoNotHoldSlots:
    """The lockout the cap created, and the reason it evicts here but nowhere
    else.

    Nothing in this server notices a target exiting: `_rows_for` swallows the
    read error, `process_info` keeps answering from cached state, and the
    session stays in the store. With a cap that refuses rather than evicts,
    eight exited processes held every slot for the life of the server and the
    model had no way to tell which sessions were the dead ones.

    Evicting a *dead* session is the exception that proves the rule about not
    evicting: its handle is already useless, so nothing is taken away.
    """

    def test_a_dead_session_is_reaped_to_make_room(self, store, monkeypatch):
        for index in range(MAX_OPEN_SESSIONS):
            store.open(FakeProcess(pid=500 + index), 500 + index, "gone%d" % index)

        monkeypatch.setattr(session_module, "pid_exists", lambda pid: pid == 4242)

        # Would have raised before the reaper existed.
        session = store.open(FakeProcess(pid=4242), 4242, "live")

        assert session.pid == 4242
        assert [held.pid for held in store.sessions] == [4242], (
            "the eight dead sessions should be gone, not merely joined"
        )

    def test_a_live_session_is_never_reaped(self, store, monkeypatch):
        store.open(FakeProcess(pid=4242), 4242, "live")
        for index in range(MAX_OPEN_SESSIONS - 1):
            store.open(FakeProcess(pid=600 + index), 600 + index, "gone%d" % index)

        monkeypatch.setattr(session_module, "pid_exists", lambda pid: pid == 4242)
        store.open(FakeProcess(pid=4243), 4243, "second")

        pids = sorted(s.pid for s in store.sessions)
        assert 4242 in pids, "a live session was evicted"

    def test_reaping_closes_the_handle(self, store, monkeypatch):
        process = FakeProcess(pid=700)
        store.open(process, 700, "gone")
        monkeypatch.setattr(session_module, "pid_exists", lambda pid: False)

        store._reap_dead()

        assert process.closed is True, "the handle was dropped without closing"
        assert store.sessions == ()

    @pytest.mark.parametrize("pid", [2 ** 31, 2 ** 64, -3, 0])
    def test_a_pid_the_os_refuses_reads_as_dead_not_as_a_crash(self, store, pid):
        """The reaper runs inside `open`, so anything it raises escapes as
        something other than SessionError and the model sees only "Error
        executing tool".

        `pid_exists(2**31)` raises OverflowError — the value does not fit the
        platform's pid type — which the argument fuzzer found by generating
        exactly that. Intermittently, because it also needed the store to be
        at capacity at that moment.
        """
        from PyMemoryEditor.mcp.session import _looks_alive

        assert _looks_alive(pid) is False

        for index in range(MAX_OPEN_SESSIONS):
            store.open(FakeProcess(pid=pid), pid, "weird%d" % index)

        # Must not raise anything but SessionError, and here it makes room.
        session = store.open(FakeProcess(pid=pid), pid, "another")
        assert session.pid == pid

    def test_a_full_server_of_live_targets_still_refuses(self, store, all_alive):
        """The reaper must not become a back door around the cap."""
        for index in range(MAX_OPEN_SESSIONS):
            store.open(FakeProcess(pid=800 + index), 800 + index, "live%d" % index)

        with pytest.raises(SessionError) as error:
            store.open(FakeProcess(pid=900), 900, "another")

        assert "all of them are live" in str(error.value)

    def test_the_refusal_points_at_an_already_open_pid(self, store, all_alive):
        """A model that lost count re-attaches instead of reusing the id."""
        store.open(FakeProcess(pid=4242), 4242, "faketarget")
        for index in range(MAX_OPEN_SESSIONS - 1):
            store.open(FakeProcess(pid=810 + index), 810 + index, "other%d" % index)

        with pytest.raises(SessionError) as error:
            store.open(FakeProcess(pid=4242), 4242, "faketarget")

        message = str(error.value)
        assert "already open as proc-1" in message


class TestBatchRegions:
    def _regions(self, sizes):
        address = 0x1000
        regions = []
        for size in sizes:
            regions.append(MemoryRegion(address=address, size=size))
            address += size
        return regions

    def test_every_region_lands_in_exactly_one_batch(self):
        regions = self._regions([100] * 10)
        batches = batch_regions(regions, 250)
        flattened = [region for batch in batches for region in batch]
        assert flattened == regions

    def test_batches_respect_the_byte_budget(self):
        batches = batch_regions(self._regions([100] * 10), 250)
        assert len(batches) == 4  # 3 x 300 bytes, then the 100-byte remainder

    def test_a_region_larger_than_the_budget_gets_its_own_batch(self):
        # A region can't be split without splitting a value across the seam,
        # so the budget is a target -- but the batch that busts it should not
        # carry anything else. This asserted `[2, 1]` under the same name,
        # i.e. it pinned the opposite of what the name claims.
        batches = batch_regions(self._regions([10, 5000, 10]), 100)
        assert [[region.size for region in batch] for batch in batches] == [
            [10], [5000], [10]
        ]

    def test_a_run_of_small_regions_does_not_ride_along_with_a_large_one(self):
        """Without the flush, `[10, 10, 10, 5000]` on a 100-byte budget was one
        batch of four, so the deadline was checked once for the whole scan."""
        batches = batch_regions(self._regions([10, 10, 10, 5000]), 100)

        assert len(batches) == 2
        assert [region.size for region in batches[0]] == [10, 10, 10]
        assert [region.size for region in batches[1]] == [5000]

    def test_consecutive_oversized_regions_each_get_a_batch(self):
        batches = batch_regions(self._regions([5000, 5000]), 100)
        assert [len(batch) for batch in batches] == [1, 1]

    def test_no_regions_means_no_batches(self):
        assert batch_regions([], 1000) == []

    def test_trailing_partial_batch_is_kept(self):
        batches = batch_regions(self._regions([10]), 1000)
        assert len(batches) == 1 and len(batches[0]) == 1


class TestRegionRendering:
    def test_addresses_render_as_hex_strings(self):
        rendered = region_to_dict(
            MemoryRegion(address=0x1_4000_0000, size=4096, is_writable=True)
        )
        assert rendered["address"] == "0x140000000"
        assert rendered["size"] == 4096
        assert rendered["writable"] is True

    def test_empty_path_becomes_null(self):
        rendered = region_to_dict(MemoryRegion(address=0x1000, size=1, path=""))
        assert rendered["path"] is None
