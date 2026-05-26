# -*- coding: utf-8 -*-

"""
Cross-platform tests for ``AbstractProcess.get_threads`` and the
``main_thread`` property. Spawns a few extra Python threads in the test
process so we can verify that the enumeration sees more than just one.
"""

import os
import sys
import threading
import time

import pytest

if sys.platform not in ("win32", "darwin") and not sys.platform.startswith("linux"):
    pytest.skip("Platform not supported by PyMemoryEditor", allow_module_level=True)


from PyMemoryEditor import OpenProcess, ThreadInfo  # noqa: E402


@pytest.fixture
def extra_threads():
    """
    Start a handful of long-running Python threads, yield to the test, then
    signal them to exit. Each spinning thread bumps the kernel-visible
    thread count for the duration of the test — without that we'd be
    racing with the GIL/GC threads to assert ``len(threads) > 1`` and the
    test could pass coincidentally.
    """
    stop = threading.Event()

    def _spin():
        while not stop.is_set():
            time.sleep(0.05)

    threads = [threading.Thread(target=_spin, daemon=True) for _ in range(3)]
    for t in threads:
        t.start()

    # Give the OS a moment to actually schedule the new threads — without
    # this delay, Toolhelp32 (Windows) and task_threads (macOS) sometimes
    # snapshot before the threads have been registered.
    time.sleep(0.1)

    try:
        yield threads
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=2.0)


def test_get_threads_returns_thread_infos(extra_threads):
    """Each yielded item must be a ``ThreadInfo`` with a non-negative tid."""
    with OpenProcess(pid=os.getpid()) as process:
        threads = list(process.get_threads())

    assert threads, "expected at least one thread"
    for info in threads:
        assert isinstance(info, ThreadInfo)
        assert isinstance(info.tid, int)
        assert info.tid >= 0


def test_get_threads_sees_extra_threads(extra_threads):
    """The spinning threads from the fixture must show up in the enumeration."""
    with OpenProcess(pid=os.getpid()) as process:
        threads = list(process.get_threads())

    # The exact mapping from Python ``Thread.ident`` to the OS-visible tid is
    # platform-specific (and on macOS, Mach port names don't match POSIX
    # tids), so we can't compare ident-to-tid directly. Instead we assert
    # the *count*: with 3 extra spinning threads, the main thread, plus
    # Python's GC / runtime helpers, the count must comfortably exceed 1.
    assert len(threads) > 1, (
        "expected get_threads() to see at least the main + 1 spinning thread; "
        "got %d" % len(threads)
    )


def test_get_threads_yields_unique_tids(extra_threads):
    """``tid`` should be unique within the snapshot."""
    with OpenProcess(pid=os.getpid()) as process:
        tids = [t.tid for t in process.get_threads()]

    assert len(tids) == len(set(tids)), "duplicate tids in enumeration"


def test_main_thread_is_smallest_tid(extra_threads):
    """``main_thread`` returns the ThreadInfo with the smallest tid."""
    with OpenProcess(pid=os.getpid()) as process:
        all_threads = list(process.get_threads())
        main = process.main_thread

    assert main is not None
    assert main.tid == min(t.tid for t in all_threads)


def test_thread_info_is_hashable_and_comparable():
    """``ThreadInfo`` is a frozen dataclass — usable as dict keys / set members."""
    info_a = ThreadInfo(tid=42)
    info_b = ThreadInfo(tid=42)
    info_c = ThreadInfo(tid=43)

    # Frozen dataclasses get __eq__ + __hash__ from the dataclass decorator.
    assert info_a == info_b
    assert info_a != info_c
    # ``raw`` is excluded from equality (compare=False) so two entries from
    # different snapshots with the same tid still compare equal.
    info_d = ThreadInfo(tid=42, raw="snapshot-1")
    info_e = ThreadInfo(tid=42, raw="snapshot-2")
    assert info_d == info_e

    # And hashable:
    {info_a, info_b, info_c}


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux-specific: /proc/<pid>/task/<tid>/stat exposes state/priority",
)
def test_linux_threads_populate_state_and_priority(extra_threads):
    """Linux backend should fill ``state`` and ``priority`` from /proc/.../stat."""
    with OpenProcess(pid=os.getpid()) as process:
        threads = list(process.get_threads())

    # Not every entry — the file can vanish between listdir and open — but
    # at least one should have parsed values.
    has_state = any(t.state is not None for t in threads)
    has_priority = any(t.priority is not None for t in threads)
    assert has_state, "expected at least one thread to have a state field"
    assert has_priority, "expected at least one thread to have a priority field"
