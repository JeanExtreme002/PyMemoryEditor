# -*- coding: utf-8 -*-

"""
Handle bookkeeping: sessions, scan result sets, and the region batching.
"""

import pytest

from PyMemoryEditor.mcp.session import (
    MAX_SCANS_PER_SESSION,
    SessionError,
    SessionStore,
    batch_regions,
    region_to_dict,
)
from PyMemoryEditor.process.region import MemoryRegion, MemoryRegionSnapshot

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
        # It cannot be split without splitting a value across the seam, so the
        # budget is a target rather than a guarantee.
        batches = batch_regions(self._regions([10, 5000, 10]), 100)
        assert [len(batch) for batch in batches] == [2, 1]

    def test_no_regions_means_no_batches(self):
        assert batch_regions([], 1000) == []

    def test_trailing_partial_batch_is_kept(self):
        batches = batch_regions(self._regions([10]), 1000)
        assert len(batches) == 1 and len(batches[0]) == 1

    # --- the snapshot tag has to survive the batching -------------------- #
    #
    # `snapshot_regions()` hands `_run_batched_scan` a MemoryRegionSnapshot,
    # whose whole purpose is to let the scanning helpers skip a defensive
    # `sorted(...)`. Rebuilding each batch as a plain list threw that away, so
    # every `search_by_value(memory_regions=batch)` re-sorted an input already
    # known to be ordered -- once per batch, per scan.

    def test_snapshot_input_yields_snapshot_batches(self):
        regions = MemoryRegionSnapshot(self._regions([100] * 10))
        batches = batch_regions(regions, 250)

        assert len(batches) > 1  # otherwise the claim is untested
        assert all(isinstance(batch, MemoryRegionSnapshot) for batch in batches)

    def test_snapshot_batches_skip_the_defensive_resort(self):
        """The consequence, not just the type: the helper reuses the batch."""
        from PyMemoryEditor.process.scanning import _ensure_sorted_by_address

        regions = MemoryRegionSnapshot(self._regions([100] * 10))
        for batch in batch_regions(regions, 250):
            assert _ensure_sorted_by_address(batch) is batch

    def test_a_plain_list_stays_plain(self):
        """The tag is a claim about order, so it is never invented here.

        A caller that filtered or reordered the regions itself gets plain
        lists, and the helpers keep sorting them defensively.
        """
        batches = batch_regions(self._regions([100] * 10), 250)
        assert not any(isinstance(batch, MemoryRegionSnapshot) for batch in batches)

    def test_snapshot_batches_are_still_in_address_order(self):
        """What makes rebuilding the tag legitimate.

        The tag asserts sortedness, so batching must preserve order for the
        claim to be true. Asserted directly, because a future change here
        would otherwise make every batch lie to the scanning helpers.
        """
        regions = MemoryRegionSnapshot(self._regions([100] * 10))
        flattened = [region for batch in batch_regions(regions, 250) for region in batch]

        assert flattened == list(regions)
        assert flattened == sorted(flattened, key=lambda region: region.address)


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
