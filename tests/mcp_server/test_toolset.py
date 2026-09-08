# -*- coding: utf-8 -*-

"""
The tools themselves, driven against the fake target from ``conftest.py``.

The interesting assertions here are about the *contract with the model*: that a
scan hands back a handle rather than a result set, that a refine narrows by the
same rules a fresh scan would apply, that a partial set stays flagged as
partial through a whole refine chain, and that the safety gates hold.
"""

from itertools import count

import pytest

from PyMemoryEditor.mcp import ServerConfig
from PyMemoryEditor.mcp import toolset as toolset_module
from PyMemoryEditor.mcp.session import SessionError
from PyMemoryEditor.mcp.toolset import SAMPLE_SIZE, VALUE_TYPES, ToolError

from .conftest import READONLY_BASE, WRITABLE_BASE, FakeProcess, config


class TestServerInfo:
    def test_reports_writes_available_by_default(self, make_toolset):
        # Writing is what a memory editor is for; consent is enforced at the
        # attach prompt and at each write, not by hiding the tool.
        info = make_toolset(config()).server_info()
        assert info["write_enabled"] is True

    def test_default_note_tells_the_model_writes_are_confirmed(self, make_toolset):
        # So it explains what it is about to change instead of firing a write
        # the user then has to judge blind.
        info = make_toolset(config()).server_info()
        assert "confirmed" in info["write_note"]

    def test_read_only_note_names_the_flag(self, make_toolset):
        info = make_toolset(config(allow_write=False)).server_info()
        assert info["write_enabled"] is False
        assert "--read-only" in info["write_note"]

    def test_reports_the_live_limits(self, make_toolset):
        limits = make_toolset(
            config(max_scan_results=7, max_scan_seconds=1.5)
        ).server_info()["limits"]
        assert limits["max_scan_results"] == 7
        assert limits["max_scan_seconds"] == 1.5

    def test_lists_open_sessions_with_their_scans(self, toolset, session):
        toolset.scan_value(session["session_id"], "int", "0")
        listed = toolset.server_info()["open_sessions"]
        assert len(listed) == 1
        assert listed[0]["session_id"] == session["session_id"]
        assert listed[0]["scan_ids"] == ["scan-1"]


class TestListProcessesUnderTheDefaultPolicy:
    """A target awaiting approval must still be listable.

    Regression: ``list_processes`` used to keep only entries whose decision was
    ``allowed``. In the default *ask* mode nothing is allowed outright, so the
    tool returned an empty list and reported every process as hidden — leaving
    the model with nothing to name when it asked permission. Every other test
    in this file opts into ``allow_any_process``, which is exactly why this
    went unnoticed.
    """

    def test_askable_processes_are_listed(self, make_toolset):
        toolset = make_toolset(ServerConfig())  # mode "ask", deliberately
        listed = toolset.list_processes(limit=200)
        assert listed["returned"] > 0
        assert listed["total_matching"] > 0

    def test_they_are_flagged_as_needing_approval(self, make_toolset):
        toolset = make_toolset(ServerConfig())
        listed = toolset.list_processes(limit=200)
        assert any(entry["needs_approval"] for entry in listed["processes"])

    def test_preapproved_targets_are_not_flagged(self, make_toolset):
        # list_processes enumerates the *real* host processes (the fake target
        # only stands in for the one being attached to), so pre-approve a name
        # taken from that listing rather than the fake's.
        listing = make_toolset(ServerConfig()).list_processes(limit=200)
        # Skip nameless entries: a process whose name this user cannot read
        # sorts first and can never be pre-approved (there is no name to
        # consent to), so it would always come back needing approval.
        name = next(e["name"] for e in listing["processes"] if e["name"])

        toolset = make_toolset(ServerConfig(allowed_processes=(name,)))
        listed = toolset.list_processes(name_filter=name, limit=200)
        assert listed["returned"] > 0
        assert all(not entry["needs_approval"] for entry in listed["processes"])

    def test_denylisted_processes_are_still_hidden(self, make_toolset):
        # The listing opened up for *askable* targets only; forbidden ones stay
        # out of it.
        toolset = make_toolset(ServerConfig())
        listed = toolset.list_processes(limit=200)
        denied = set(_system_names())
        assert not [e for e in listed["processes"] if e["name"].casefold() in denied]


def _system_names():
    from PyMemoryEditor.mcp.policy import system_process_names

    return system_process_names()


class TestOpenProcess:
    def test_returns_a_session_and_target_facts(self, toolset):
        opened = toolset.open_process(pid=4242)
        assert opened["opened"] is True
        assert opened["session_id"] == "proc-1"
        assert opened["pid"] == 4242
        assert opened["is_64bit"] is True
        assert opened["pointer_size"] == 8

    def test_requires_one_of_pid_or_name(self, toolset):
        with pytest.raises(ToolError, match="list_processes"):
            toolset.open_process()

    def test_rejects_both_pid_and_name(self, toolset):
        # They can disagree, and silently preferring one is how you attach to
        # the wrong process.
        with pytest.raises(ToolError, match="not both"):
            toolset.open_process(pid=4242, name="faketarget")

    def test_unlisted_target_is_not_opened_without_approval(self, make_toolset):
        # A bare toolset has no channel to ask the user, so it must refuse
        # rather than attach. The protocol layer is what turns this into a
        # prompt — see test_server.py::TestAttachApproval.
        toolset = make_toolset(ServerConfig(allowed_processes=("game",)))
        with pytest.raises(ToolError, match="approval") as caught:
            toolset.open_process(pid=4242)
        # And the message names both ways out, so the model can relay them.
        assert "--allow-process" in str(caught.value)
        assert "--allow-any-process" in str(caught.value)

    def test_allowlisted_target_opens(self, make_toolset):
        toolset = make_toolset(ServerConfig(allowed_processes=("faketarget",)))
        assert toolset.open_process(pid=4242)["opened"] is True

    def test_each_open_is_a_separate_session(self, toolset):
        first = toolset.open_process(pid=4242)["session_id"]
        second = toolset.open_process(pid=4242)["session_id"]
        assert first != second


class TestCloseProcess:
    def test_closes_the_target(self, toolset, session, fake_process):
        toolset.close_process(session["session_id"])
        assert fake_process.closed

    def test_session_is_unusable_afterwards(self, toolset, session):
        toolset.close_process(session["session_id"])
        with pytest.raises(SessionError):
            toolset.process_info(session["session_id"])


class TestProcessInfo:
    def test_summarizes_the_address_space(self, toolset, session):
        info = toolset.process_info(session["session_id"])
        assert info["address_space"]["region_count"] == 2
        assert info["address_space"]["writable_regions"] == 1
        assert info["address_space"]["writable_bytes"] == 0x1000

    def test_module_bases_are_hex_strings(self, toolset, session):
        module = toolset.process_info(session["session_id"])["modules"][0]
        assert module["base_address"] == "0x150000000"

    def test_lowest_thread_id_is_the_minimum_not_the_first(self, toolset, session):
        # The fake yields 101 before 99, so this pins that the answer is the
        # minimum rather than the first one enumerated. Named `lowest_thread_id`
        # rather than `main_thread_id` because "smallest tid is the main thread"
        # only holds on Linux — see the note the tool returns alongside it.
        info = toolset.process_info(session["session_id"])
        assert info["lowest_thread_id"] == 99
        assert "macOS" in info["lowest_thread_id_note"]


class TestListMemoryRegions:
    def test_lists_every_region_by_default(self, toolset, session):
        listed = toolset.list_memory_regions(session["session_id"])
        assert listed["total_matching"] == 2

    def test_writable_filter(self, toolset, session):
        listed = toolset.list_memory_regions(session["session_id"], writable_only=True)
        assert listed["total_matching"] == 1
        assert listed["regions"][0]["address"] == "0x140000000"

    def test_executable_filter(self, toolset, session):
        listed = toolset.list_memory_regions(session["session_id"], executable_only=True)
        assert listed["total_matching"] == 1
        assert listed["regions"][0]["executable"] is True

    def test_path_filter(self, toolset, session):
        listed = toolset.list_memory_regions(session["session_id"], path_filter="libfake")
        assert listed["total_matching"] == 1

    def test_paging_reports_whether_more_remain(self, toolset, session):
        first = toolset.list_memory_regions(session["session_id"], limit=1)
        assert first["has_more"] is True
        second = toolset.list_memory_regions(session["session_id"], limit=1, offset=1)
        assert second["has_more"] is False

    def test_limit_is_capped_by_the_server(self, toolset, session):
        # A model asking for 10 000 rows has lost the thread; the cap keeps the
        # client's context intact regardless.
        listed = toolset.list_memory_regions(session["session_id"], limit=10_000)
        assert listed["returned"] <= 100


class TestScanValue:
    def test_finds_a_planted_value(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0x100, int, 1234567)
        scan = toolset.scan_value(session["session_id"], "int", "1234567", bufflength=4)
        assert scan["count"] == 1
        assert scan["sample"][0]["address"] == "0x%X" % address
        assert scan["sample"][0]["value"] == 1234567

    def test_returns_a_handle_not_the_addresses(self, toolset, session, fake_process):
        for offset in range(0, 0x400, 4):
            fake_process.poke(WRITABLE_BASE + offset, int, 77)
        scan = toolset.scan_value(session["session_id"], "int", "77", bufflength=4)

        assert scan["count"] > SAMPLE_SIZE
        assert len(scan["sample"]) == SAMPLE_SIZE
        assert "addresses" not in scan
        assert scan["scan_id"] == "scan-1"

    def test_sample_is_spread_rather_than_the_first_n(self, toolset, session, fake_process):
        for offset in range(0, 0x800, 4):
            fake_process.poke(WRITABLE_BASE + offset, int, 88)
        scan = toolset.scan_value(session["session_id"], "int", "88", bufflength=4)

        sampled = [int(row["address"], 16) for row in scan["sample"]]
        # The first ten hits would be 40 bytes apart and tell the model nothing
        # about the shape of the set.
        assert max(sampled) - min(sampled) > 0x400

    def test_writable_only_is_the_default(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x10, int, 555)
        fake_process.poke(READONLY_BASE + 0x10, int, 555)

        default = toolset.scan_value(session["session_id"], "int", "555", bufflength=4)
        everywhere = toolset.scan_value(
            session["session_id"], "int", "555", bufflength=4, writable_only=False
        )
        assert default["count"] == 1
        assert everywhere["count"] == 2

    def test_hex_value_is_accepted(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x20, int, 0x64)
        scan = toolset.scan_value(session["session_id"], "int", "0x64", bufflength=4)
        assert scan["count"] == 1

    def test_float_scan(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x30, float, 2.5)
        scan = toolset.scan_value(session["session_id"], "float", "2.5")
        assert scan["count"] == 1
        assert scan["sample"][0]["value"] == 2.5

    def test_bytes_scan_takes_hex(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x40, bytes, b"\xde\xad\xbe\xef", 4)
        scan = toolset.scan_value(session["session_id"], "bytes", "DEADBEEF")
        assert scan["count"] == 1
        assert scan["sample"][0]["value"] == "DEADBEEF"

    def test_ordered_scan(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x50, int, 900)
        scan = toolset.scan_value(
            session["session_id"], "int", "800", scan_type="bigger", bufflength=4
        )
        assert any(row["value"] == 900 for row in scan["sample"])

    def test_range_scan(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x60, int, 150)
        scan = toolset.scan_value(
            session["session_id"], "int", "100", end_value="200",
            scan_type="between", bufflength=4,
        )
        assert any(row["value"] == 150 for row in scan["sample"])

    def test_range_scan_needs_both_bounds(self, toolset, session):
        with pytest.raises(ToolError, match="end_value"):
            toolset.scan_value(
                session["session_id"], "int", "100", scan_type="between", bufflength=4
            )

    def test_end_value_is_rejected_for_a_non_range_scan(self, toolset, session):
        # Silently ignoring it would let a model believe it ran a range scan.
        with pytest.raises(ToolError, match="only applies"):
            toolset.scan_value(
                session["session_id"], "int", "100", end_value="200", bufflength=4
            )

    def test_no_matches_explains_the_usual_causes(self, toolset, session):
        scan = toolset.scan_value(session["session_id"], "int", "123456789", bufflength=4)
        assert scan["count"] == 0
        assert "width" in scan["hint"]

    def test_many_matches_points_at_the_refine_step(self, toolset, session, fake_process):
        for offset in range(0, 0x100, 4):
            fake_process.poke(WRITABLE_BASE + offset, int, 66)
        scan = toolset.scan_value(session["session_id"], "int", "66", bufflength=4)
        assert "refine_scan" in scan["hint"]

    def test_result_cap_marks_the_set_partial(self, make_toolset, fake_process):
        toolset = make_toolset(config(max_scan_results=5))
        opened = toolset.open_process(pid=4242)
        for offset in range(0, 0x100, 4):
            fake_process.poke(WRITABLE_BASE + offset, int, 44)

        scan = toolset.scan_value(opened["session_id"], "int", "44", bufflength=4)
        assert scan["count"] == 5
        assert scan["partial"] is True
        assert "prefix" in scan["partial_reason"]

    def test_scan_refreshes_the_region_snapshot(self, toolset, session, fake_process):
        stale = toolset.store.get(session["session_id"]).snapshot_regions()
        toolset.scan_value(session["session_id"], "int", "1", bufflength=4)
        # A stale map silently skips wherever the value moved to.
        assert toolset.store.get(session["session_id"]).regions is not stale


class TestScanBatching:
    """Splitting the region list must not change what a scan finds.

    Scans are driven one batch of regions at a time so the wall-clock budget
    can be checked between batches (a value scan yields only on a hit, so a
    rare value gives the consumer no other chance). That rewrite is only safe
    because the library scans per region: this pins it, against a target whose
    memory cannot churn — the same comparison on a live process is meaningless,
    since two identical scans of a running program already disagree.
    """

    def _many_regions(self, fake_process, count=24):
        base = 0x2_0000_0000
        for index in range(count):
            fake_process._blocks.append(
                (base + index * 0x2000, bytearray(0x1000), True)
            )
        planted = set()
        for region_base, block, writable in fake_process._blocks:
            if not writable:
                continue
            for offset in (0, len(block) // 2, len(block) - 4):
                planted.add(fake_process.poke(region_base + offset, int, 4242))
        return planted

    @pytest.mark.parametrize("budget", [0x1000, 0x4000, 64 * 1024 * 1024])
    def test_every_batch_size_finds_the_same_addresses(
        self, make_toolset, fake_process, budget
    ):
        planted = self._many_regions(fake_process)

        toolset = make_toolset(
            config(
                max_scan_results=10**6, max_scan_seconds=600, scan_batch_bytes=budget
            )
        )
        session_id = toolset.open_process(pid=4242)["session_id"]
        scan = toolset.scan_value(session_id, "int", "4242", bufflength=4)

        found = set(toolset.store.find_scan(scan["scan_id"])[1].addresses)
        assert found == planted

    def test_results_stay_sorted_and_unique_across_batches(
        self, make_toolset, fake_process
    ):
        self._many_regions(fake_process)

        toolset = make_toolset(
            config(
                max_scan_results=10**6, max_scan_seconds=600, scan_batch_bytes=0x1000
            )
        )
        session_id = toolset.open_process(pid=4242)["session_id"]
        scan = toolset.scan_value(session_id, "int", "4242", bufflength=4)

        addresses = toolset.store.find_scan(scan["scan_id"])[1].addresses
        assert addresses == sorted(addresses)
        assert len(addresses) == len(set(addresses))


class TestScanPattern:
    def test_finds_a_byte_pattern(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0x200, bytes, b"\x48\x8b\x05\x00", 4)
        scan = toolset.scan_pattern(session["session_id"], "48 8B 05 00")
        assert any(row["address"] == "0x%X" % address for row in scan["sample"])

    def test_wildcards_are_honoured(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x210, bytes, b"\x48\x8b\x77\x00", 4)
        scan = toolset.scan_pattern(session["session_id"], "48 8B ? 00")
        assert scan["count"] >= 1

    def test_empty_pattern_is_rejected_with_an_example(self, toolset, session):
        with pytest.raises(ToolError, match="48 8B"):
            toolset.scan_pattern(session["session_id"], "   ")

    def test_pattern_results_carry_addresses_but_no_value(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x220, bytes, b"\x11\x22", 2)
        scan = toolset.scan_pattern(session["session_id"], "11 22")
        assert "value" not in scan["sample"][0]


class TestRefineScan:
    def _scan_two(self, toolset, session, fake_process):
        """Plant two matching values, so a refine has something to drop."""
        first = fake_process.poke(WRITABLE_BASE + 0x300, int, 500)
        second = fake_process.poke(WRITABLE_BASE + 0x310, int, 500)
        scan = toolset.scan_value(session["session_id"], "int", "500", bufflength=4)
        return scan, first, second

    def test_narrows_to_the_address_that_changed(self, toolset, session, fake_process):
        scan, first, second = self._scan_two(toolset, session, fake_process)
        assert scan["count"] == 2

        fake_process.poke(first, int, 250)
        refined = toolset.refine_scan(scan["scan_id"], value="250")

        assert refined["count"] == 1
        assert refined["sample"][0]["address"] == "0x%X" % first

    def test_reports_what_it_dropped(self, toolset, session, fake_process):
        scan, first, _second = self._scan_two(toolset, session, fake_process)
        fake_process.poke(first, int, 250)
        refined = toolset.refine_scan(scan["scan_id"], value="250")

        assert refined["refined_from"]["scan_id"] == scan["scan_id"]
        assert refined["refined_from"]["count"] == 2
        assert refined["refined_from"]["dropped"] == 1

    def test_produces_a_new_handle_and_keeps_the_old_one(self, toolset, session, fake_process):
        scan, first, _second = self._scan_two(toolset, session, fake_process)
        fake_process.poke(first, int, 250)
        refined = toolset.refine_scan(scan["scan_id"], value="250")

        assert refined["scan_id"] != scan["scan_id"]
        # A refine that narrows too far must be retryable from the set before.
        assert toolset.store.find_scan(scan["scan_id"])[1].count == 2

    def test_chains_the_description(self, toolset, session, fake_process):
        scan, first, _second = self._scan_two(toolset, session, fake_process)
        fake_process.poke(first, int, 250)
        refined = toolset.refine_scan(scan["scan_id"], value="250")
        assert refined["description"] == "int == 500 -> int == 250"

    def test_reuses_the_original_type_and_width(self, toolset, session, fake_process):
        # The model states the value only; restating the type on every refine
        # is an invitation to drift from the scan that produced the set.
        fake_process.poke(WRITABLE_BASE + 0x320, float, 3.5)
        scan = toolset.scan_value(session["session_id"], "float", "3.5")
        fake_process.poke(WRITABLE_BASE + 0x320, float, 4.5)

        refined = toolset.refine_scan(scan["scan_id"], value="4.5")
        assert refined["count"] == 1

    def test_ordered_refine(self, toolset, session, fake_process):
        scan, first, second = self._scan_two(toolset, session, fake_process)
        fake_process.poke(first, int, 900)
        refined = toolset.refine_scan(scan["scan_id"], scan_type="bigger", value="600")
        assert refined["count"] == 1

    def test_range_refine(self, toolset, session, fake_process):
        scan, first, _second = self._scan_two(toolset, session, fake_process)
        fake_process.poke(first, int, 150)
        refined = toolset.refine_scan(
            scan["scan_id"], scan_type="between", value="100", end_value="200"
        )
        assert refined["count"] == 1

    def test_empty_result_points_back_at_the_previous_set(self, toolset, session, fake_process):
        scan, _first, _second = self._scan_two(toolset, session, fake_process)
        refined = toolset.refine_scan(scan["scan_id"], value="999999")
        assert refined["count"] == 0
        assert scan["scan_id"] in refined["hint"]

    def test_addresses_that_became_unreadable_are_counted(self, toolset, session, fake_process):
        scan, _first, _second = self._scan_two(toolset, session, fake_process)
        # Drop the region out from under the result set, as a target that frees
        # memory mid-loop would.
        fake_process._blocks = fake_process._blocks[1:]
        refined = toolset.refine_scan(scan["scan_id"], value="500")
        assert refined["refined_from"]["unreadable"] == 2
        assert refined["count"] == 0

    def test_a_partial_set_stays_partial_through_the_chain(self, make_toolset, fake_process):
        # The whole point: addresses the first scan never reached are still
        # missing, so a refine chain built on a prefix must not start claiming
        # to be complete.
        toolset = make_toolset(config(max_scan_results=3))
        opened = toolset.open_process(pid=4242)
        for offset in range(0, 0x100, 4):
            fake_process.poke(WRITABLE_BASE + offset, int, 33)

        scan = toolset.scan_value(opened["session_id"], "int", "33", bufflength=4)
        assert scan["partial"] is True

        refined = toolset.refine_scan(scan["scan_id"], value="33")
        assert refined["partial"] is True

    def test_text_sets_reject_ordered_comparisons(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x330, str, "abc", 3)
        scan = toolset.scan_value(session["session_id"], "str", "abc")
        with pytest.raises(ToolError, match="exact"):
            toolset.refine_scan(scan["scan_id"], scan_type="bigger", value="abd")

    def test_pattern_sets_cannot_be_refined(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x340, bytes, b"\x01\x02", 2)
        scan = toolset.scan_pattern(session["session_id"], "01 02")
        with pytest.raises(ToolError, match="scan_pattern"):
            toolset.refine_scan(scan["scan_id"], value="1")

    def test_unknown_scan_id_is_explained(self, toolset, session):
        with pytest.raises(SessionError, match="scan_value"):
            toolset.refine_scan("scan-999", value="1")


class TestListScanResults:
    def test_reads_current_values(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0x400, int, 11)
        scan = toolset.scan_value(session["session_id"], "int", "11", bufflength=4)

        # Values are read live, so the page reflects the target now — which is
        # what makes "which address tracks the game?" answerable.
        fake_process.poke(address, int, 22)
        listed = toolset.list_scan_results(scan["scan_id"])
        assert listed["results"][0]["value"] == 22

    def test_pages_in_the_requested_order(self, toolset, session, fake_process):
        for offset in range(0, 0x40, 4):
            fake_process.poke(WRITABLE_BASE + offset, int, 55)
        scan = toolset.scan_value(session["session_id"], "int", "55", bufflength=4)

        page = toolset.list_scan_results(scan["scan_id"], limit=4)
        addresses = [int(row["address"], 16) for row in page["results"]]
        assert addresses == sorted(addresses)

    def test_paging_reports_more(self, toolset, session, fake_process):
        for offset in range(0, 0x40, 4):
            fake_process.poke(WRITABLE_BASE + offset, int, 55)
        scan = toolset.scan_value(session["session_id"], "int", "55", bufflength=4)

        first = toolset.list_scan_results(scan["scan_id"], limit=2)
        assert first["has_more"] is True
        assert first["returned"] == 2

    def test_unreadable_addresses_are_flagged_not_dropped(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x410, int, 12)
        scan = toolset.scan_value(session["session_id"], "int", "12", bufflength=4)
        fake_process._blocks = fake_process._blocks[1:]

        listed = toolset.list_scan_results(scan["scan_id"])
        assert listed["results"][0]["readable"] is False


class TestReadValue:
    def test_reads_an_int(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0x500, int, 4321)
        read = toolset.read_value(session["session_id"], hex(address), "int", 4)
        assert read["value"] == 4321

    def test_reads_bytes_as_hex(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0x510, bytes, b"\xaa\xbb", 2)
        read = toolset.read_value(session["session_id"], hex(address), "bytes", 2)
        assert read["value"] == "AABB"

    def test_text_reads_require_a_width(self, toolset, session):
        with pytest.raises(ToolError, match="bufflength is required"):
            toolset.read_value(session["session_id"], hex(WRITABLE_BASE), "str")

    def test_unmapped_address_explains_itself(self, toolset, session):
        with pytest.raises(ToolError, match="freed"):
            toolset.read_value(session["session_id"], "0xDEAD0000", "int", 4)

    def test_accepts_the_address_form_the_tools_return(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0x520, int, 9)
        scan = toolset.scan_value(session["session_id"], "int", "9", bufflength=4)

        echoed = scan["sample"][0]["address"]
        assert echoed == "0x%X" % address
        assert toolset.read_value(session["session_id"], echoed, "int", 4)["value"] == 9


class TestWriteValue:
    def test_writes_and_reports_the_previous_value(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0x600, int, 10)
        written = toolset.write_value(session["session_id"], hex(address), "int", "99", 4)

        assert written["previous_value"] == 10
        assert fake_process.read_process_memory(address, int, 4) == 99

    def test_undo_hint_restores_the_original(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0x610, int, 10)
        written = toolset.write_value(session["session_id"], hex(address), "int", "99", 4)
        assert "99" not in written["undo_hint"]

        toolset.write_value(
            session["session_id"], hex(address), "int",
            str(written["previous_value"]), 4,
        )
        assert fake_process.read_process_memory(address, int, 4) == 10

    def test_is_refused_under_read_only(self, make_toolset, fake_process):
        # Defence in depth: the tool is not registered at all in read-only
        # mode, so reaching this check means registration was bypassed.
        toolset = make_toolset(config(allow_write=False))
        opened = toolset.open_process(pid=4242)
        with pytest.raises(ToolError, match="--read-only"):
            toolset.write_value(opened["session_id"], hex(WRITABLE_BASE), "int", "1", 4)

    def test_read_only_region_failure_points_at_the_region_list(self, toolset, session):
        with pytest.raises(ToolError, match="list_memory_regions"):
            toolset.write_value(
                session["session_id"], hex(READONLY_BASE + 0x10), "int", "1", 4
            )

    def test_write_survives_an_unreadable_previous_value(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0x620, bytes, b"\x00\x00", 2)
        written = toolset.write_value(session["session_id"], hex(address), "bytes", "AABB")
        assert written["written"] == "AABB"


class TestPointers:
    def test_resolves_a_chain(self, toolset, session, fake_process):
        # "base -> [+0x0] -> +0x8" dereferences twice: the base slot holds a
        # pointer to an object, whose field at +0x0 holds a pointer to the
        # struct, and the final +0x8 is added without dereferencing.
        base_slot = WRITABLE_BASE + 0x800
        middle = WRITABLE_BASE + 0x900
        target = WRITABLE_BASE + 0x700

        fake_process.poke(base_slot, int, middle, 8)
        fake_process.poke(middle + 0x0, int, target, 8)

        resolved = toolset.resolve_pointer_chain(
            session["session_id"], hex(base_slot), ["0x0", "0x8"]
        )
        assert resolved["address"] == "0x%X" % (target + 8)

    def test_offsets_accept_hex_strings(self, toolset, session, fake_process):
        # A Cheat Engine table records offsets in hex; making the model convert
        # them to decimal first is an error waiting to happen.
        target = WRITABLE_BASE + 0x700
        fake_process.poke(WRITABLE_BASE + 0x810, int, target, 8)
        resolved = toolset.resolve_pointer_chain(
            session["session_id"], hex(WRITABLE_BASE + 0x810), ["0x158"]
        )
        assert resolved["address"] == "0x%X" % (target + 0x158)

    def test_empty_offsets_dereference_once(self, toolset, session, fake_process):
        target = WRITABLE_BASE + 0x700
        fake_process.poke(WRITABLE_BASE + 0x820, int, target, 8)
        resolved = toolset.resolve_pointer_chain(
            session["session_id"], hex(WRITABLE_BASE + 0x820), []
        )
        assert resolved["address"] == "0x%X" % target

    def test_broken_chain_says_it_is_stale(self, toolset, session, fake_process):
        fake_process.poke(WRITABLE_BASE + 0x830, int, 0xDEAD0000, 8)
        with pytest.raises(ToolError, match="stale"):
            toolset.resolve_pointer_chain(
                session["session_id"], hex(WRITABLE_BASE + 0x830), ["0x0", "0x8"]
            )

    def test_no_paths_found_suggests_a_deeper_scan(self, toolset, session):
        found = toolset.find_pointer_paths(session["session_id"], hex(WRITABLE_BASE))
        assert found["count"] == 0
        assert "max_depth" in found["hint"]

    def test_depth_and_offset_are_clamped(self, toolset, session):
        found = toolset.find_pointer_paths(
            session["session_id"], hex(WRITABLE_BASE), max_depth=99, max_offset=10**9
        )
        assert found["max_depth"] <= 7
        assert found["max_offset"] <= 0x10000


class TestSessionIsolation:
    def test_a_scan_belongs_to_its_own_session(self, toolset, fake_process):
        first = toolset.open_process(pid=4242)["session_id"]
        second = toolset.open_process(pid=4242)["session_id"]

        fake_process.poke(WRITABLE_BASE + 0x900, int, 1717)
        scan = toolset.scan_value(first, "int", "1717", bufflength=4)

        found_session, _scan = toolset.store.find_scan(scan["scan_id"])
        assert found_session.session_id == first
        assert found_session.session_id != second


class TestFakeMatchesTheRealProcessApi:
    """Guards the fake in ``conftest.py`` against drifting from the real class.

    The fast tests in this file are only worth anything while the fake accepts
    the same calls the real backends do. A renamed keyword — ``writeable_only``
    is already spelled two ways in the library — would otherwise leave 200
    green tests exercising a shape that no longer exists.

    ``test_live.py`` catches this too, but it costs a minute and is skipped by
    ``-m "not slow"``; this catches it in milliseconds.
    """

    #: Methods where the fake must accept exactly the real parameter list.
    EXACT = (
        "close",
        "get_memory_regions",
        "get_modules",
        "get_threads",
        "read_process_memory",
        "resolve_pointer_chain",
        "search_by_addresses",
        "search_by_pattern",
        "search_by_value",
        "search_by_value_between",
        "snapshot_memory_regions",
        "write_process_memory",
    )

    @pytest.mark.parametrize("name", EXACT)
    def test_parameter_names_match(self, name):
        import inspect

        from PyMemoryEditor.process.abstract import AbstractProcess

        real = inspect.signature(getattr(AbstractProcess, name)).parameters
        fake = inspect.signature(getattr(FakeProcess, name)).parameters
        assert list(fake) == list(real), name

    @pytest.mark.parametrize("name", ["is_64bit", "pointer_size", "is_bitness_certain"])
    def test_properties_exist_on_both(self, name):
        from PyMemoryEditor.process.abstract import AbstractProcess

        assert isinstance(getattr(AbstractProcess, name), property)
        assert isinstance(getattr(FakeProcess, name), property)

    def test_pointer_scan_keywords_are_accepted_by_the_real_method(self):
        # The fake takes **kwargs here (it returns no paths), so instead assert
        # the real method accepts every keyword the toolset passes it.
        import inspect

        from PyMemoryEditor.process.abstract import AbstractProcess

        real = inspect.signature(AbstractProcess.scan_pointer_paths).parameters
        for keyword in (
            "max_depth",
            "max_offset",
            "max_results",
            "memory_regions",
            "progress_callback",
        ):
            assert keyword in real, keyword


class TestReviewRegressions:
    """Bugs found reviewing this package, each pinned so it cannot return.

    Grouped rather than scattered because what they have in common is *how*
    they hid: every one sat on a path the happy-path tests never took — an
    empty string, a target that exits, a config nobody passes.
    """

    # --- an empty text value is a zero-width scan --------------------- #

    def test_an_empty_str_scan_is_rejected(self, toolset, session):
        # A zero-width target matches at every offset: the scan came back
        # capped and full of meaningless addresses, and every refine against
        # "" kept all of them, so a model could chase it for turns.
        with pytest.raises(ToolError, match="empty string"):
            toolset.scan_value(session["session_id"], "str", "")

    def test_an_empty_bytes_scan_is_still_rejected(self, toolset, session):
        with pytest.raises(ToolError, match="hex"):
            toolset.scan_value(session["session_id"], "bytes", "")

    def test_a_non_empty_str_scan_still_works(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0x900, str, "hp", 2)
        scan = toolset.scan_value(session["session_id"], "str", "hp")
        assert any(int(row["address"], 16) == address for row in scan["sample"])

    # --- the undo hint used to corrupt memory ------------------------- #

    def test_undo_restores_bytes_that_are_not_valid_utf8(
        self, toolset, session, fake_process
    ):
        # Reading the replaced range as `str` decodes with errors="replace",
        # so following the undo hint wrote U+FFFD's encoding over the original
        # bytes — corrupting exactly what it promised to restore.
        address = WRITABLE_BASE + 0xA00
        fake_process.poke(address, bytes, b"\xff\xfe\xfd\xfc", 4)

        written = toolset.write_value(session["session_id"], hex(address), "str", "ab")
        toolset.write_value(
            session["session_id"], hex(address),
            written["previous_value_type"], written["previous_value"],
        )
        assert fake_process.read_process_memory(address, bytes, 4) == b"\xff\xfe\xfd\xfc"

    def test_undo_restores_multibyte_text_exactly(
        self, toolset, session, fake_process
    ):
        # The widths disagreed too: the read counted bytes while a str write
        # caps characters.
        address = WRITABLE_BASE + 0xA20
        fake_process.poke(address, str, "ólá", 5)
        before = fake_process.read_process_memory(address, bytes, 5)

        written = toolset.write_value(session["session_id"], hex(address), "str", "ok")
        toolset.write_value(
            session["session_id"], hex(address),
            written["previous_value_type"], written["previous_value"],
        )
        assert fake_process.read_process_memory(address, bytes, 5) == before

    def test_numeric_undo_stays_readable(self, toolset, session, fake_process):
        # Only text is rendered as hex; an int undo should still read as a
        # number, which is what makes the hint useful to a human.
        address = fake_process.poke(WRITABLE_BASE + 0xA40, int, 4321)
        written = toolset.write_value(session["session_id"], hex(address), "int", "99", 4)
        assert written["previous_value"] == 4321
        assert written["previous_value_type"] == "int"

    # --- backend failures reached the model stripped of their message -- #

    @pytest.mark.parametrize(
        "call",
        [
            "process_info",
            "list_memory_regions",
            "scan_value",
            "scan_pattern",
            "refine_scan",
        ],
    )
    def test_a_dead_target_is_reported_not_swallowed(
        self, make_toolset, fake_process, call
    ):
        # The SDK withholds the message of anything that is not our ToolError,
        # so an untranslated OSError reached the model as a bare "Error
        # executing tool <name>" — with no hint that the target had exited.
        toolset = make_toolset(config(max_scan_seconds=30))
        session_id = toolset.open_process(pid=4242)["session_id"]

        fake_process.poke(WRITABLE_BASE + 0x10, int, 5)
        scan = toolset.scan_value(session_id, "int", "5", bufflength=4)

        def die(*_args, **_kwargs):
            raise OSError(2, "No such file or directory: /proc/4242/maps")

        fake_process.get_memory_regions = die
        fake_process.snapshot_memory_regions = die
        fake_process.search_by_addresses = die

        calls = {
            "process_info": lambda: toolset.process_info(session_id),
            "list_memory_regions": lambda: toolset.list_memory_regions(session_id),
            "scan_value": lambda: toolset.scan_value(
                session_id, "int", "1", bufflength=4
            ),
            "scan_pattern": lambda: toolset.scan_pattern(session_id, "01 02"),
            "refine_scan": lambda: toolset.refine_scan(scan["scan_id"], value="5"),
        }
        with pytest.raises(ToolError, match="exited or freed"):
            calls[call]()

    def test_a_bad_pattern_is_still_its_own_error(self, toolset, session):
        # The target-failure wrapper must not swallow the pattern-syntax error.
        with pytest.raises(ToolError, match="48 8B"):
            toolset.scan_pattern(session["session_id"], "   ")

    # --- the configured batch size was ignored ------------------------ #

    def test_the_configured_batch_size_is_used(self, make_toolset, fake_process):
        # _run_batched_scan hardcoded the module default, so a caller asking
        # for finer-grained deadline checks silently got 64 MB.
        seen = []
        toolset = make_toolset(config(scan_batch_bytes=0x1000))
        original = fake_process.search_by_value

        def counting(*args, **kwargs):
            seen.append(kwargs.get("memory_regions"))
            return original(*args, **kwargs)

        fake_process.search_by_value = counting
        session_id = toolset.open_process(pid=4242)["session_id"]
        toolset.scan_value(session_id, "int", "1", bufflength=4)

        # Two 4 KiB regions against a 4 KiB budget: two batches, not one.
        assert len(seen) == 2, seen


class TestRefineMatchesAFreshScan:
    """A refine must keep exactly the addresses a fresh scan would.

    It compares re-read values instead of walking memory, which is the whole
    point — but a scan does not compare against the caller's Python value. The
    target goes through ``value_to_bytes`` at the scan width and back
    (``decode_scan_target``), so ``0.1`` in 4 bytes becomes
    ``0.10000000149011612`` and a ``str`` is compared as the integer view of its
    NUL-padded buffer. Refining against the raw value rejected the very
    addresses the scan had just matched — silently, and only for the types
    where the round trip is not the identity.
    """

    def test_float32_survives_a_refine(self, toolset, session, fake_process):
        # 4-byte float is Cheat Engine's default "Float", so this is the
        # common case, not an exotic one.
        address = fake_process.poke(WRITABLE_BASE + 0xB00, float, 0.1, 4)
        scan = toolset.scan_value(session["session_id"], "float", "0.1", bufflength=4)
        assert address in toolset.store.find_scan(scan["scan_id"])[1].addresses

        refined = toolset.refine_scan(scan["scan_id"], value="0.1")
        assert address in toolset.store.find_scan(refined["scan_id"])[1].addresses

    def test_float64_survives_a_refine(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0xB20, float, 0.1, 8)
        scan = toolset.scan_value(session["session_id"], "float", "0.1", bufflength=8)
        refined = toolset.refine_scan(scan["scan_id"], value="0.1")
        assert address in toolset.store.find_scan(refined["scan_id"])[1].addresses

    def test_nul_padded_text_survives_a_refine(self, toolset, session, fake_process):
        # bufflength wider than the value: the scan matches b"hi" + NULs.
        address = fake_process.poke(WRITABLE_BASE + 0xB40, str, "hi", 8)
        scan = toolset.scan_value(session["session_id"], "str", "hi", bufflength=8)
        assert address in toolset.store.find_scan(scan["scan_id"])[1].addresses

        refined = toolset.refine_scan(scan["scan_id"], value="hi")
        assert address in toolset.store.find_scan(refined["scan_id"])[1].addresses

    def test_padded_bytes_survive_a_refine(self, toolset, session, fake_process):
        address = fake_process.poke(WRITABLE_BASE + 0xB60, bytes, b"\xde\xad", 8)
        scan = toolset.scan_value(
            session["session_id"], "bytes", "DEAD", bufflength=8
        )
        refined = toolset.refine_scan(scan["scan_id"], value="DEAD")
        assert address in toolset.store.find_scan(refined["scan_id"])[1].addresses

    def test_an_ordered_float32_refine_uses_the_scan_target(
        self, toolset, session, fake_process
    ):
        # 0.1 narrowed to 4 bytes is *greater* than the double 0.1, so a
        # "smaller than 0.1" refine must not keep it.
        address = fake_process.poke(WRITABLE_BASE + 0xB80, float, 0.1, 4)
        scan = toolset.scan_value(
            session["session_id"], "float", "0.0", scan_type="bigger", bufflength=4
        )
        assert address in toolset.store.find_scan(scan["scan_id"])[1].addresses

        refined = toolset.refine_scan(
            scan["scan_id"], scan_type="smaller", value="0.1"
        )
        assert address not in toolset.store.find_scan(refined["scan_id"])[1].addresses

    # (label, value_type, width, planted, scan_type, value, end_value)
    EQUIVALENCE_CASES = [
        ("int32", "int", 4, 246813, "exact", "246813", None),
        ("int32-negative", "int", 4, -246813, "exact", "-246813", None),
        ("int16-negative", "int", 2, -4242, "exact", "-4242", None),
        ("int64", "int", 8, 2**40 + 7, "exact", str(2**40 + 7), None),
        ("int-bigger", "int", 4, 500000, "bigger", "499999", None),
        ("int-smaller-negative", "int", 4, -500000, "smaller", "-499999", None),
        ("int-between", "int", 4, 777, "between", "700", "800"),
        ("int-not-exact", "int", 4, 12345, "not_exact", "999999", None),
        ("float32", "float", 4, 0.1, "exact", "0.1", None),
        ("float32-bigger", "float", 4, 12.5, "bigger", "12.4", None),
        ("float64", "float", 8, 0.1, "exact", "0.1", None),
        ("float64-smaller", "float", 8, -3.75, "smaller", "-3.7", None),
        ("str", "str", 2, "hi", "exact", "hi", None),
        ("str-padded", "str", 8, "hi", "exact", "hi", None),
        ("bytes-padded", "bytes", 8, b"\xde\xad", "exact", "DEAD", None),
        ("bool", "bool", 1, True, "exact", "true", None),
    ]

    @pytest.mark.parametrize(
        "label, value_type, width, planted, scan_type, value, end_value",
        EQUIVALENCE_CASES,
        ids=[case[0] for case in EQUIVALENCE_CASES],
    )
    def test_a_refine_equals_a_fresh_scan(
        self, make_toolset, fake_process,
        label, value_type, width, planted, scan_type, value, end_value,
    ):
        """The property the whole design rests on, stated directly.

        On a target that cannot change, refining a set by the value it was
        scanned for must return that same set — for every type, width,
        signedness and comparison. The same check on a live process is
        worthless: two identical scans of a running program already disagree,
        so any difference drowns in churn.
        """
        pytype = VALUE_TYPES[value_type]
        address = fake_process.poke(WRITABLE_BASE + 0x100, pytype, planted, width)

        toolset = make_toolset(
            config(max_scan_results=10**6, max_scan_seconds=600)
        )
        session_id = toolset.open_process(pid=4242)["session_id"]

        scan_kwargs = {"scan_type": scan_type, "bufflength": width}
        refine_kwargs = {"scan_type": scan_type, "value": value}
        if end_value is not None:
            scan_kwargs["end_value"] = end_value
            refine_kwargs["end_value"] = end_value

        first = toolset.scan_value(session_id, value_type, value, **scan_kwargs)
        fresh = toolset.scan_value(session_id, value_type, value, **scan_kwargs)
        refined = toolset.refine_scan(first["scan_id"], **refine_kwargs)

        def addresses(result):
            return set(toolset.store.find_scan(result["scan_id"])[1].addresses)

        assert addresses(refined) == addresses(fresh) == addresses(first)
        assert address in addresses(refined)

    # `_TEXT_SCAN_TYPES` has to be a policy choice, not a correctness crutch.
    #
    # `scan_memory` compares `str` big-endian (`is_string = pytype is str`),
    # and refine_scan decoded with `sys.byteorder`. For exact/not_exact both
    # sides cancel, so nothing showed -- and exact/not_exact is all the guard
    # lets through. The equivalence this class asserts therefore held only
    # because of the guard, and widening it would have inverted
    # bigger/smaller. `ha` against `ai` is a pair the two orders disagree
    # about: big-endian 0x6861 > 0x6169, little-endian 0x6168 < 0x6961.
    @pytest.mark.parametrize("planted, value, scan_type", [
        ("ha", "ai", "bigger"),
        ("ai", "ha", "smaller"),
    ])
    def test_an_ordered_text_refine_equals_a_fresh_scan(
        self, make_toolset, fake_process, monkeypatch, planted, value, scan_type
    ):
        monkeypatch.setattr(
            toolset_module,
            "_TEXT_SCAN_TYPES",
            frozenset({"exact", "not_exact", "bigger", "smaller"}),
        )
        address = fake_process.poke(WRITABLE_BASE + 0x140, str, planted, 2)

        toolset = make_toolset(
            config(max_scan_results=10**6, max_scan_seconds=600)
        )
        session_id = toolset.open_process(pid=4242)["session_id"]

        first = toolset.scan_value(
            session_id, "str", value, scan_type=scan_type, bufflength=2
        )
        fresh = toolset.scan_value(
            session_id, "str", value, scan_type=scan_type, bufflength=2
        )
        refined = toolset.refine_scan(
            first["scan_id"], scan_type=scan_type, value=value
        )

        def addresses(result):
            return set(toolset.store.find_scan(result["scan_id"])[1].addresses)

        assert address in addresses(fresh), "the fresh scan must match it first"
        assert addresses(refined) == addresses(fresh)

    def test_a_stray_end_value_is_refused_like_scan_value_refuses_it(
        self, toolset, session, fake_process
    ):
        """Silently dropping it pointed the model away from its own mistake.

        `refine_scan(scan_type="exact", value="90", end_value="100")` became a
        plain exact-90. When that came back empty, the hint suggested trying
        another value -- so the one argument that was ignored was the one thing
        never questioned. `scan_value` has always refused this.
        """
        fake_process.poke(WRITABLE_BASE + 0x160, int, 90, 4)
        scan = toolset.scan_value(session["session_id"], "int", "90", bufflength=4)

        with pytest.raises(ToolError) as error:
            toolset.refine_scan(
                scan["scan_id"], scan_type="exact", value="90", end_value="100"
            )

        assert "end_value" in str(error.value)

    def test_a_refine_value_too_wide_for_the_scan_is_explained(
        self, make_toolset, fake_process
    ):
        # The target is encoded at the *original* scan's width, so a refine
        # value that no longer fits raises from value_to_bytes. That encoding
        # sat outside the error guard, so the message was withheld — the same
        # gap that scan_value had, reintroduced by moving the encoding.
        fake_process.poke(WRITABLE_BASE + 0x10, int, 100)
        toolset = make_toolset(config())
        session_id = toolset.open_process(pid=4242)["session_id"]
        scan = toolset.scan_value(session_id, "int", "100", bufflength=2)

        with pytest.raises(ToolError, match="does not fit"):
            toolset.refine_scan(scan["scan_id"], value="70000")

    def test_refine_still_drops_what_stopped_matching(
        self, toolset, session, fake_process
    ):
        # The fix must not turn the predicate into "keep everything".
        address = fake_process.poke(WRITABLE_BASE + 0xBA0, float, 0.1, 4)
        scan = toolset.scan_value(session["session_id"], "float", "0.1", bufflength=4)

        fake_process.poke(address, float, 9.5, 4)
        refined = toolset.refine_scan(scan["scan_id"], value="0.1")
        assert address not in toolset.store.find_scan(refined["scan_id"])[1].addresses


class TestSecondReviewRegressions:
    """The remaining findings from the second review pass."""

    def test_a_value_too_wide_for_its_bufflength_is_explained(
        self, toolset, session
    ):
        # The encoders' own message is exactly the right advice; it just never
        # reached the model, because the SDK withholds the text of anything
        # that is not our ToolError.
        with pytest.raises(ToolError, match="does not fit"):
            toolset.scan_value(session["session_id"], "int", "70000", bufflength=2)

    def test_text_too_long_for_its_bufflength_is_explained(self, toolset, session):
        with pytest.raises(ToolError, match="too long"):
            toolset.scan_value(session["session_id"], "str", "hello", bufflength=2)

    def test_a_negative_pid_is_explained(self, toolset):
        # `pid` is a plain integer in the tool schema, so nothing stops a model
        # sending -1.
        with pytest.raises(ToolError, match="non-negative"):
            toolset.open_process(pid=-1)

    def test_an_exhaustive_set_at_the_cap_is_not_called_partial(
        self, make_toolset, fake_process
    ):
        # Stopping at the cap marked a complete set partial, and refine_scan
        # propagates that down the chain — so the server kept telling the model
        # to rescan a set that was already exhaustive.
        for offset in range(0, 5 * 4, 4):
            fake_process.poke(WRITABLE_BASE + offset, int, 999)

        toolset = make_toolset(config(max_scan_results=5))
        session_id = toolset.open_process(pid=4242)["session_id"]
        scan = toolset.scan_value(session_id, "int", "999", bufflength=4)

        assert scan["count"] == 5
        assert scan["partial"] is False

    def test_a_genuinely_truncated_set_is_still_partial(
        self, make_toolset, fake_process
    ):
        for offset in range(0, 9 * 4, 4):
            fake_process.poke(WRITABLE_BASE + offset, int, 999)

        toolset = make_toolset(config(max_scan_results=5))
        session_id = toolset.open_process(pid=4242)["session_id"]
        scan = toolset.scan_value(session_id, "int", "999", bufflength=4)

        assert scan["count"] == 5
        assert scan["partial"] is True

    def test_the_capped_set_holds_exactly_the_cap(self, make_toolset, fake_process):
        # The extra address fetched to detect truncation must not be kept.
        for offset in range(0, 9 * 4, 4):
            fake_process.poke(WRITABLE_BASE + offset, int, 999)

        toolset = make_toolset(config(max_scan_results=5))
        session_id = toolset.open_process(pid=4242)["session_id"]
        scan = toolset.scan_value(session_id, "int", "999", bufflength=4)

        addresses = toolset.store.find_scan(scan["scan_id"])[1].addresses
        assert len(addresses) == 5
        assert addresses == sorted(addresses)


class TestThirdReviewRegressions:
    """Findings from the third review pass."""

    # --- the region snapshot sat outside every error guard ------------- #

    def test_a_dead_target_is_reported_by_find_pointer_paths(
        self, make_toolset, fake_process
    ):
        # Every other region-walking tool translated this; find_pointer_paths
        # took its snapshot before the try, so the model got a bare
        # "Error executing tool find_pointer_paths".
        toolset = make_toolset(config())
        session_id = toolset.open_process(pid=4242)["session_id"]

        def die(*_args, **_kwargs):
            raise OSError(2, "No such file or directory: /proc/4242/maps")

        fake_process.snapshot_memory_regions = die
        fake_process.get_memory_regions = die

        with pytest.raises(ToolError, match="exited or freed"):
            toolset.find_pointer_paths(session_id, hex(WRITABLE_BASE))

    # --- max_offset=0 is a real request, not an unset sentinel --------- #

    def test_max_offset_zero_is_honoured(self, toolset, session):
        # 0 keeps only hops pointing exactly at the address — the tightest
        # scan there is. The `or 1024` sentinel silently widened it.
        result = toolset.find_pointer_paths(
            session["session_id"], hex(WRITABLE_BASE), max_offset=0
        )
        assert result["max_offset"] == 0

    def test_max_offset_is_still_clamped_at_the_top(self, toolset, session):
        result = toolset.find_pointer_paths(
            session["session_id"], hex(WRITABLE_BASE), max_offset=10**9
        )
        assert result["max_offset"] == 0x10000

    # --- the one address no parser ever sees --------------------------- #

    def test_a_refused_attach_does_not_leak_the_handle(
        self, make_toolset, fake_process, monkeypatch
    ):
        """`attach` opens the handle and *then* registers the session, so a
        refusal must close it or the cap leaks what it exists to bound."""
        from PyMemoryEditor.mcp.session import MAX_OPEN_SESSIONS

        abertos = []

        def fake_open(**_kwargs):
            process = FakeProcess()
            abertos.append(process)
            return process

        toolset = make_toolset(config())
        monkeypatch.setattr(toolset, "_open_process", fake_open)

        for _ in range(MAX_OPEN_SESSIONS):
            toolset.open_process(pid=4242)

        with pytest.raises(SessionError):
            toolset.open_process(pid=4242)

        # The last one is the refused attach's, and only it should be closed.
        assert len(abertos) == MAX_OPEN_SESSIONS + 1
        assert abertos[-1].closed is True
        assert all(process.closed is False for process in abertos[:-1])

    def test_a_chain_resolving_past_64_bits_is_refused_not_returned(
        self, make_toolset, fake_process
    ):
        """`parse_address` guards what the model types, not what memory says.

        The resolved address comes out of the target's own bytes plus the
        offsets, so it never passes through an argument parser. Returning one
        that would truncate the moment the model handed it to write_value is
        the same bug as accepting it, one call later.
        """
        toolset = make_toolset(config())
        session_id = toolset.open_process(pid=4242)["session_id"]

        # A hop that "reads" a value no address can hold. Patched on the fake
        # rather than planted in it, because a real pointer read is bounded by
        # ptr_size by construction -- the failure this guards is a chain whose
        # arithmetic leaves the space, not a byte pattern.
        fake_process.resolve_pointer_chain = lambda base, offsets: 1 << 70

        with pytest.raises(ToolError) as error:
            toolset.resolve_pointer_chain(
                session_id, hex(WRITABLE_BASE), offsets=["0x10"]
            )

        assert "64-bit" in str(error.value)

    def test_a_chain_resolving_below_zero_says_the_pointer_was_dead(
        self, make_toolset, fake_process
    ):
        """The negative half, which had the guard but no test.

        A mutation that dropped the `0 <=` half of the bound passed the whole
        suite, so the branch was unverified -- and it is the *reachable* half:
        `resolve_pointer_chain` adds the last offset without dereferencing it,
        so a hop that read NULL plus a negative offset lands under zero. That
        is the ordinary stale-chain case, not an exotic one.

        Two things are asserted because the guard got both wrong: the message
        used "0x%X", which renders -8 as the malformed "0x-8" that
        `parse_offset` rejects, and it blamed the address space when the cause
        is a dead pointer.
        """
        toolset = make_toolset(config())
        session_id = toolset.open_process(pid=4242)["session_id"]

        # A NULL pointer, then a negative offset applied to it.
        fake_process.poke(WRITABLE_BASE + 0x200, int, 0, 8)

        with pytest.raises(ToolError) as error:
            toolset.resolve_pointer_chain(
                session_id, hex(WRITABLE_BASE + 0x200), offsets=["-0x8"]
            )

        message = str(error.value)
        assert "0x-8" not in message, "the malformed hex form format_offset exists to prevent"
        assert "-0x8" in message
        assert "NULL" in message

    def test_format_address_refuses_a_negative_rather_than_rendering_it(self):
        """The rendering hole itself, not just the one caller that hit it."""
        from PyMemoryEditor.mcp.toolset import format_address, format_offset

        with pytest.raises(ValueError):
            format_address(-8)

        # And the signed renderer still produces the parseable form.
        assert format_offset(-8) == "-0x8"

    # The paired half -- that an ordinary chain still resolves -- is
    # `test_resolves_a_chain` above and `test_resolves_a_chain_built_by_hand`
    # in test_live.py, so a bound that rejected everything would fail there.

    # --- the timeout hint named the wrong phase ------------------------ #

    def test_a_pointer_map_timeout_does_not_blame_the_depth(
        self, make_toolset, fake_process, monkeypatch
    ):
        # scan_pointer_paths maps every pointer before searching for any path,
        # and only that phase reports progress. So a timeout there means zero
        # paths, and max_depth / max_offset — used only by the later search —
        # cannot be the remedy the hint suggests.
        #
        # The clock is faked rather than the budget squeezed. `0.0` used to
        # force the timeout, but `ServerConfig` now rejects a non-positive
        # budget the way the CLI always did -- and the obvious replacement, a
        # tiny positive one, is not reliably spent everywhere: Windows advances
        # `monotonic()` in ~15.6 ms ticks, so the deadline and the progress
        # callback read the *same* instant and `1e-9` never expired. Green on
        # Linux and macOS, red on Windows.
        #
        # A clock that jumps 1000s per reading expires any sane budget on every
        # platform, so the config keeps its real default and the test asserts
        # the deadline logic instead of the host's timer granularity.
        clock = count(0.0, 1000.0)
        monkeypatch.setattr(toolset_module, "monotonic", lambda: next(clock))

        toolset = make_toolset(config())

        def scan(_target, **kwargs):
            callback = kwargs.get("progress_callback")
            if callback is not None:
                callback(0.5)  # trips the deadline
            return iter(())

        fake_process.scan_pointer_paths = scan
        session_id = toolset.open_process(pid=4242)["session_id"]
        result = toolset.find_pointer_paths(session_id, hex(WRITABLE_BASE))

        assert result["timed_out"] is True
        assert result["timed_out_phase"] == "pointer_map"
        assert result["count"] == 0
        assert "max-scan-seconds" in result["hint"]
        assert "smaller max_depth" not in result["hint"]

    def test_a_completed_scan_reports_no_timeout_phase(self, toolset, session):
        result = toolset.find_pointer_paths(
            session["session_id"], hex(WRITABLE_BASE)
        )
        assert result["timed_out"] is False
        assert result["timed_out_phase"] is None

    # --- the fake diverged from every real backend on capped text ------ #

    @pytest.mark.parametrize(
        "value_type, value, bufflength, expected",
        [
            # A str/bytes bufflength is a cap that truncates and never pads.
            ("str", "hello", 3, b"hel"),
            ("str", "ola", 10, b"ola"),
            ("bytes", "DEADBEEF", 2, b"\xde\xad"),
            ("bytes", "DEAD", 8, b"\xde\xad"),
        ],
    )
    def test_a_capped_text_write_truncates_and_never_pads(
        self, toolset, session, fake_process, value_type, value, bufflength, expected
    ):
        # No test passed a bufflength to a str/bytes write, so this branch of
        # _write_span was untested — and untestable, because the fake rejected
        # an over-long value and NUL-padded a short one where a real target
        # truncates and leaves the rest alone.
        address = WRITABLE_BASE + 0xC00
        fake_process.poke(address, bytes, b"\xaa" * 16, 16)

        toolset.write_value(
            session["session_id"], hex(address), value_type, value, bufflength
        )
        written = fake_process.read_process_memory(address, bytes, 16)
        assert written[: len(expected)] == expected
        # Everything past the value is untouched: no padding, no clobber.
        assert written[len(expected) :] == b"\xaa" * (16 - len(expected))

    def test_a_capped_text_write_undo_covers_exactly_what_it_replaced(
        self, toolset, session, fake_process
    ):
        address = WRITABLE_BASE + 0xC40
        fake_process.poke(address, bytes, b"\xaa" * 16, 16)

        written = toolset.write_value(
            session["session_id"], hex(address), "str", "hello", 3
        )
        toolset.write_value(
            session["session_id"], hex(address),
            written["previous_value_type"], written["previous_value"],
        )
        assert fake_process.read_process_memory(address, bytes, 16) == b"\xaa" * 16


class TestParallelReviewRegressions:
    """Findings from a review run in parallel with the scoped one."""

    def test_negative_pointer_offsets_are_accepted(
        self, toolset, session, fake_process
    ):
        # The library resolves a negative offset fine, and walking backwards
        # through a struct is ordinary in a published Cheat Engine recipe.
        # parse_address rejected them with "must not be negative", which reads
        # like a formatting complaint — so a model would mangle the offset
        # rather than report that the server cannot express the recipe.
        # base -> [-0x8] -> +0x0. The negative offset applies to the pointer
        # that was *read*, not to the base: current = read(base) = middle, then
        # current = read(middle - 0x8), which is where the target pointer sits.
        base_slot = WRITABLE_BASE + 0x9A0
        middle = WRITABLE_BASE + 0x980
        target_address = WRITABLE_BASE + 0x700

        fake_process.poke(base_slot, int, middle, 8)
        fake_process.poke(middle - 0x8, int, target_address, 8)

        resolved = toolset.resolve_pointer_chain(
            session["session_id"], hex(base_slot), ["-0x8", "0x0"]
        )
        assert resolved["address"] == "0x%X" % target_address

        # And the echoed recipe has to parse back. "0x%X" % -8 renders "0x-8",
        # which our own parser rejects — so the server was returning a chain it
        # could not read again, and a model feeding its own output back in got
        # told the offset was malformed.
        assert resolved["offsets"] == ["-0x8", "0x0"]
        again = toolset.resolve_pointer_chain(
            session["session_id"], resolved["base_address"], resolved["offsets"]
        )
        assert again["address"] == resolved["address"]

    def test_addresses_themselves_stay_non_negative(self, toolset, session):
        # Only offsets are signed; an address never is.
        with pytest.raises(ToolError, match="negative"):
            toolset.read_value(session["session_id"], "-0x10", "int", 4)

    def test_list_processes_honours_the_advertised_cap(self, toolset):
        # The clamp was 200 while server_info advertised 100, and there was no
        # offset — so everything after the first page was unreachable.
        advertised = toolset.server_info()["limits"]["max_page_size"]
        listed = toolset.list_processes(limit=10**6)
        assert listed["returned"] <= advertised

    @pytest.mark.parametrize("limit, offset", [
        (2, 0), (2, 2), (1, 0), (1, 9), (5, 0),
    ])
    def test_list_processes_pages(self, make_toolset, monkeypatch, limit, offset):
        # Over a stubbed process list, so the boundaries are actually covered:
        # list_processes reads the real host's processes, and the previous
        # version hid its only real assertions behind `if total > 4`, which
        # no-ops on a slim CI container.
        import PyMemoryEditor.mcp.toolset as toolset_module

        fleet = [(1000 + index, "proc%02d" % index) for index in range(10)]
        monkeypatch.setattr(toolset_module, "iter_processes", lambda: iter(fleet))

        toolset = make_toolset(config())
        page = toolset.list_processes(limit=limit, offset=offset)

        expected = fleet[offset : offset + limit]
        assert [entry["pid"] for entry in page["processes"]] == [
            pid for pid, _name in expected
        ]
        assert page["returned"] == len(expected)
        assert page["total_matching"] == len(fleet)
        assert page["offset"] == offset
        assert page["has_more"] is (offset + len(expected) < len(fleet))

    def test_list_processes_past_the_end_is_empty_not_an_error(
        self, make_toolset, monkeypatch
    ):
        import PyMemoryEditor.mcp.toolset as toolset_module

        fleet = [(1000 + index, "proc%02d" % index) for index in range(3)]
        monkeypatch.setattr(toolset_module, "iter_processes", lambda: iter(fleet))

        toolset = make_toolset(config())
        for offset in (3, 4, 10_000):
            page = toolset.list_processes(offset=offset)
            assert page["processes"] == []
            assert page["returned"] == 0
            assert page["total_matching"] == 3
            assert page["has_more"] is False

    def test_max_offset_null_does_not_crash(self, toolset, session):
        # Dropping the `or` sentinel made this the only one of the four
        # arguments that raised on an explicit JSON null.
        for kwargs in ({"max_offset": None}, {"max_depth": None},
                       {"max_results": None}):
            result = toolset.find_pointer_paths(
                session["session_id"], hex(WRITABLE_BASE), **kwargs
            )
            assert result["count"] == 0  # no paths in the fake, but no crash

    def test_an_allowlist_built_in_code_is_stripped(self):
        # The strip lived only in parse_args, so an embedder constructing a
        # ServerConfig — or reading an mcpServers args array — kept the silent
        # no-op a trailing space causes.
        from PyMemoryEditor.mcp.policy import ProcessPolicy

        policy = ProcessPolicy(allowed_names=[" game.exe ", "   "])
        assert policy.allowed_names == ("game.exe",)
        assert policy.check(5000, "game.exe").allowed

    def test_an_empty_text_write_is_still_a_no_op(self):
        # get_c_type_of's new length guard turned a documented, successful
        # zero-byte write into a ValueError. Not reachable through MCP, but a
        # behaviour change on the public library API.
        import ctypes
        import os

        from PyMemoryEditor import OpenProcess

        buffer = (ctypes.c_char * 8)(*b"\xaa" * 8)
        with OpenProcess(pid=os.getpid()) as process:
            process.write_process_memory(
                ctypes.addressof(buffer), bytes, None, b""
            )
        assert bytes(buffer) == b"\xaa" * 8


class TestScopedReviewRegressions:
    """Findings from the review scoped to the previous round's fixes."""

    def test_a_scalar_allowlist_is_not_split_into_letters(self):
        # `str` is a valid Sequence[str], so a scalar was consumed character by
        # character: "notepad.exe" became eleven single-letter rules, mode
        # reported "allowlist", and every process containing any of those
        # letters was pre-approved — turning the consent prompt off silently.
        from PyMemoryEditor.mcp.policy import ProcessPolicy

        policy = ProcessPolicy(allowed_names="notepad.exe", platform="win32")
        assert policy.allowed_names == ("notepad.exe",)
        assert policy.check(9999, "MyBank.exe").needs_approval
        assert policy.check(9999, "notepad.exe").allowed

    def test_scan_batch_bytes_must_be_positive(self):
        # 0 or negative made every region its own batch: thousands of generator
        # setups per scan on a desktop target, with no error at launch.
        from PyMemoryEditor.mcp import parse_args

        for value in ("0", "-1"):
            with pytest.raises(SystemExit):
                parse_args(["--scan-batch-bytes", value])
        config_, _transport = parse_args(["--scan-batch-bytes", "4096"])
        assert config_.scan_batch_bytes == 4096

    def test_an_inferred_text_width_is_capped_too(self, toolset, session):
        # parse_bufflength capped an *explicit* width, but leaving it at 0 —
        # which the tool docstrings recommend — inferred it from the value with
        # no ceiling, handing create_string_buffer whatever arrived.
        from PyMemoryEditor.mcp.toolset import MAX_TEXT_BYTES

        with pytest.raises(ToolError, match="over the"):
            toolset.scan_value(
                session["session_id"], "str", "x" * (MAX_TEXT_BYTES + 1)
            )

    def test_a_normal_inferred_text_width_still_works(
        self, toolset, session, fake_process
    ):
        fake_process.poke(WRITABLE_BASE + 0xD00, str, "hp", 2)
        scan = toolset.scan_value(session["session_id"], "str", "hp")
        assert scan["count"] >= 1

    def test_the_width_rules_are_advertised(self, toolset):
        # So a width never has to be discovered by tripping the error — this is
        # the argument the server's own hints tell the model to guess.
        limits = toolset.server_info()["limits"]
        assert limits["valid_numeric_widths"]["int"] == [1, 2, 4, 8]
        assert limits["valid_numeric_widths"]["float"] == [4, 8]
        assert limits["valid_numeric_widths"]["bool"] == [1]
        # Against what the code enforces, not against 1: comparing to 1 meant
        # server_info could drift to a stale literal and this test — the one
        # added to catch exactly that — would stay green.
        from PyMemoryEditor.mcp.toolset import MAX_TEXT_BYTES

        assert limits["max_text_bytes"] == MAX_TEXT_BYTES
        assert limits["scan_batch_bytes"] == toolset.config.scan_batch_bytes

    def test_bitness_failure_does_not_break_attach(
        self, make_toolset, fake_process, monkeypatch
    ):
        # Bitness detection falls back to walking the region map, which raises
        # FileNotFoundError off /proc/<pid>/maps on Linux when the target exits
        # between OpenProcess and the read. `attach` sits outside
        # _target_errors, so an OSError there escaped raw on the first tool a
        # user hits.
        # monkeypatch, not a manual set/del on the class: `del` removed the
        # property FakeProcess actually defines, so every later test sharing
        # the xdist worker died with "no attribute 'is_64bit'". It stayed
        # invisible on a machine whose worker count distributed the files
        # differently — Linux with 2 workers failed 20 tests.
        monkeypatch.setattr(
            type(fake_process),
            "is_64bit",
            property(
                lambda self: (_ for _ in ()).throw(
                    OSError(2, "No such file or directory: /proc/4242/maps")
                )
            ),
        )
        toolset = make_toolset(config())
        opened = toolset.open_process(pid=4242)
        assert opened["opened"] is True
        assert opened["is_64bit"] is None


class TestPointerScanArgumentDefaults:
    """`null` means the documented default, for all three arguments alike.

    They used to disagree: `max_depth or 3` and `max_results or 20` sent a
    null to their documented default, while `max_offset or 0` sent it to 0 --
    the *narrowest* search possible. So a client that renders an unset integer
    as JSON null, which is exactly the case the code claimed to tolerate, got
    "No static path reached that address" for a target the default call finds.
    The three defaults now come from one table shared with the signature.
    """

    @pytest.mark.parametrize("argument", ["max_depth", "max_offset", "max_results"])
    def test_null_resolves_to_the_documented_default(self, argument):
        # Against the resolver, not the tool result: `max_results` is not
        # echoed in the payload, and asserting "only if the key is present"
        # is how a test ends up vacuous for exactly the row that matters.
        from PyMemoryEditor.mcp.toolset import (
            POINTER_SCAN_DEFAULTS,
            _clamp_pointer_arg,
        )

        assert _clamp_pointer_arg(argument, None) == POINTER_SCAN_DEFAULTS[argument]

    def test_null_max_offset_is_the_default_not_zero(self, toolset, session):
        from PyMemoryEditor.mcp.toolset import POINTER_SCAN_DEFAULTS

        result = toolset.find_pointer_paths(
            session["session_id"], hex(WRITABLE_BASE), max_offset=None
        )
        assert result["max_offset"] == POINTER_SCAN_DEFAULTS["max_offset"]

    def test_an_explicit_zero_max_offset_is_still_honoured(self, toolset, session):
        # The tightest search there is: only hops pointing exactly at the
        # address. Distinguishable from "unset" precisely because null is not 0.
        result = toolset.find_pointer_paths(
            session["session_id"], hex(WRITABLE_BASE), max_offset=0
        )
        assert result["max_offset"] == 0

    @pytest.mark.parametrize("argument, value, expected", [
        ("max_depth", 0, 1),          # clamps to the minimum, not the default
        ("max_depth", 99, 7),
        ("max_offset", -5, 0),
        ("max_offset", 10**9, 0x10000),
    ])
    def test_out_of_range_values_clamp(
        self, toolset, session, argument, value, expected
    ):
        result = toolset.find_pointer_paths(
            session["session_id"], hex(WRITABLE_BASE), **{argument: value}
        )
        assert result[argument] == expected

    def test_the_signature_defaults_come_from_the_shared_table(self):
        # The bug was one default written in two places. This pins that they
        # cannot drift apart again.
        import inspect

        from PyMemoryEditor.mcp.toolset import (
            POINTER_SCAN_DEFAULTS,
            MemoryToolset,
        )

        signature = inspect.signature(MemoryToolset.find_pointer_paths)
        for name, default in POINTER_SCAN_DEFAULTS.items():
            assert signature.parameters[name].default == default, name
