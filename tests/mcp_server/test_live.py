# -*- coding: utf-8 -*-

"""
The MCP tools against a real process — this one.

``test_toolset.py`` proves the orchestration with a fake target; this file
proves the tools are wired to the *actual* backends, on whichever of the three
platforms is running. It is the test that would catch a signature drifting
between ``AbstractProcess`` and what the fake pretends it looks like.

Marked ``slow`` because each scan walks this process's whole writable address
space, following the convention in ``tests/memory/test_editor.py``.
"""

import ctypes
import os

import pytest

from PyMemoryEditor.mcp import MemoryToolset, ServerConfig
from PyMemoryEditor.mcp.toolset import ToolError

pytestmark = pytest.mark.slow


@pytest.fixture
def live() -> MemoryToolset:
    """A toolset attached to the running test process, writes enabled.

    Self-attachment is the one target guaranteed to exist and to be permitted
    on every platform and CI runner.

    ``allow_any_process`` is on because these tests are about the memory tools,
    not the approval gate: the server's default *ask* mode has no channel to
    prompt from a bare toolset. The gate itself is covered by
    ``test_server.py::TestAttachApproval`` and by
    ``TestLiveSafety`` below.
    """
    toolset = MemoryToolset(
        ServerConfig(allow_write=True, allow_any_process=True, max_scan_seconds=120)
    )
    yield toolset
    toolset.store.close_all()


@pytest.fixture
def live_session(live: MemoryToolset) -> str:
    return live.open_process(pid=os.getpid())["session_id"]


class TestLiveDiscovery:
    def test_lists_this_process(self, live):
        listed = live.list_processes(name_filter="python", limit=200)
        assert any(entry["pid"] == os.getpid() for entry in listed["processes"])

    def test_opens_this_process(self, live):
        opened = live.open_process(pid=os.getpid())
        assert opened["opened"] is True
        assert opened["pid"] == os.getpid()
        assert opened["pointer_size"] in (4, 8)

    def test_reports_a_real_address_space(self, live, live_session):
        info = live.process_info(live_session)
        assert info["address_space"]["writable_regions"] > 0
        assert info["module_count"] > 0

    def test_lists_writable_regions(self, live, live_session):
        listed = live.list_memory_regions(live_session, writable_only=True, limit=5)
        assert listed["total_matching"] > 0
        assert all(region["writable"] for region in listed["regions"])

    def test_nonexistent_pid_is_reported_cleanly(self, live):
        with pytest.raises(ToolError, match="Could not open"):
            live.open_process(pid=2**31 - 1)


class TestLiveLoop:
    def test_the_full_scan_refine_read_write_loop(self, live, live_session):
        # A distinctive value, to keep the first scan's result set small.
        target = ctypes.c_int(1928374)
        address = ctypes.addressof(target)

        scan = live.scan_value(live_session, "int", "1928374", bufflength=4)
        assert scan["count"] >= 1
        assert scan["partial"] is False, scan.get("partial_reason")

        session = live.store.get(live_session)
        assert address in session.get_scan(scan["scan_id"]).addresses

        # Change it, exactly as a player would, and refine.
        target.value = 5647382
        refined = live.refine_scan(scan["scan_id"], value="5647382")
        assert address in session.get_scan(refined["scan_id"]).addresses
        assert refined["count"] <= scan["count"]

        read = live.read_value(live_session, hex(address), "int", 4)
        assert read["value"] == 5647382

        written = live.write_value(live_session, hex(address), "int", "1234", 4)
        assert written["previous_value"] == 5647382
        # The write landed in this process's own memory, so ctypes can see it.
        assert target.value == 1234

    def test_scan_finds_a_float(self, live, live_session):
        target = ctypes.c_double(1234.5678)
        address = ctypes.addressof(target)

        scan = live.scan_value(live_session, "float", "1234.5678", bufflength=8)
        session = live.store.get(live_session)
        assert address in session.get_scan(scan["scan_id"]).addresses

    def test_scan_finds_a_byte_pattern(self, live, live_session):
        marker = b"\x8f\x2c\x71\xd4\x5a\xe3\x06\xbb"
        target = (ctypes.c_char * len(marker)).from_buffer_copy(marker)
        address = ctypes.addressof(target)

        scan = live.scan_pattern(live_session, "8F 2C 71 ? 5A E3 06 BB")
        session = live.store.get(live_session)
        assert address in session.get_scan(scan["scan_id"]).addresses

    def test_range_scan_finds_a_value_in_the_window(self, live, live_session):
        target = ctypes.c_int(918273)
        address = ctypes.addressof(target)

        scan = live.scan_value(
            live_session, "int", "918270", end_value="918275",
            scan_type="between", bufflength=4,
        )
        session = live.store.get(live_session)
        assert address in session.get_scan(scan["scan_id"]).addresses

    def test_list_scan_results_reads_live_values(self, live, live_session):
        target = ctypes.c_int(776655)
        address = ctypes.addressof(target)
        scan = live.scan_value(live_session, "int", "776655", bufflength=4)

        target.value = 443322
        listed = live.list_scan_results(scan["scan_id"], limit=100)
        rows = {row["address"]: row.get("value") for row in listed["results"]}
        assert rows.get("0x%X" % address) == 443322


class TestLivePointers:
    def test_resolves_a_chain_built_by_hand(self, live, live_session):
        # Two real pointer levels in this process: slot -> middle -> value.
        value = ctypes.c_int(42)
        middle = ctypes.c_void_p(ctypes.addressof(value))
        slot = ctypes.c_void_p(ctypes.addressof(middle))

        resolved = live.resolve_pointer_chain(
            live_session, hex(ctypes.addressof(slot)), ["0x0", "0x0"]
        )
        assert resolved["address"] == "0x%X" % ctypes.addressof(value)
        assert live.read_value(live_session, resolved["address"], "int", 4)["value"] == 42

    def test_a_broken_chain_is_reported_not_crashed(self, live, live_session):
        dangling = ctypes.c_void_p(0xDEAD0000)
        with pytest.raises(ToolError):
            live.resolve_pointer_chain(
                live_session, hex(ctypes.addressof(dangling)), ["0x0", "0x0"]
            )


class TestLiveSafety:
    def test_read_only_mode_refuses_to_write(self):
        toolset = MemoryToolset(
            ServerConfig(allow_write=False, allow_any_process=True)
        )
        try:
            session_id = toolset.open_process(pid=os.getpid())["session_id"]
            target = ctypes.c_int(5)
            with pytest.raises(ToolError, match="--read-only"):
                toolset.write_value(
                    session_id, hex(ctypes.addressof(target)), "int", "9", 4
                )
            assert target.value == 5
        finally:
            toolset.store.close_all()

    def test_an_unapproved_target_is_not_opened(self):
        # Even this process, even with a matching pid: without a channel to ask
        # the user, the default mode refuses rather than attaching.
        toolset = MemoryToolset(ServerConfig(allowed_processes=("no-such-target",)))
        try:
            with pytest.raises(ToolError, match="approval"):
                toolset.open_process(pid=os.getpid())
            assert toolset.store.sessions == ()
        finally:
            toolset.store.close_all()

    def test_a_remembered_approval_opens_the_real_process(self):
        # The runtime grant path, end to end against a live target.
        toolset = MemoryToolset(ServerConfig())
        try:
            with pytest.raises(ToolError, match="approval"):
                toolset.open_process(pid=os.getpid())

            toolset.policy.grant(toolset._name_for_pid(os.getpid()))
            assert toolset.open_process(pid=os.getpid())["opened"] is True
        finally:
            toolset.store.close_all()

    def test_scan_time_budget_is_honoured(self):
        # A budget too small for a full scan must return a flagged partial set
        # rather than run to completion or hang.
        toolset = MemoryToolset(
            ServerConfig(max_scan_seconds=0.001, allow_any_process=True)
        )
        try:
            session_id = toolset.open_process(pid=os.getpid())["session_id"]
            scan = toolset.scan_value(session_id, "int", "13571357", bufflength=4)
            assert scan["partial"] is True
            assert "budget" in scan["partial_reason"]
        finally:
            toolset.store.close_all()

    def test_handles_are_closed_on_shutdown(self):
        toolset = MemoryToolset(ServerConfig(allow_any_process=True))
        toolset.open_process(pid=os.getpid())
        assert toolset.store.close_all() == 1
        assert toolset.store.sessions == ()
