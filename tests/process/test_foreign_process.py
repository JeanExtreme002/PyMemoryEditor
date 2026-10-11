# -*- coding: utf-8 -*-

"""
The one thing the self-process tests cannot show: attaching to a process that
is *not* the test runner.

A child Python holds a ctypes buffer with a sentinel, prints the address and
blocks on stdin. The test opens the child by pid, reads the sentinel, writes a
new value, and has the child echo what it now sees -- so the write is checked
through the target's own eyes, not by reading it back from here. It then kills
the child and checks the dead pid is refused.

On macOS, ``task_for_pid`` on a sibling process needs the debugger
entitlement (or root), which the self-process tests do not. When the platform
refuses, the test skips with the backend's own message rather than pretending
the path was exercised.
"""

import struct
import subprocess
import sys

import pytest

from PyMemoryEditor import OpenProcess, PyMemoryEditorError, ProcessIDNotExistsError

SENTINEL = 0x5EC0DE11
REPLACEMENT = 0x7E57ED42

CHILD = """
import ctypes, sys
buf = ctypes.c_uint32(%d)
sys.stdout.write("%%d\\n" %% ctypes.addressof(buf))
sys.stdout.flush()
sys.stdin.readline()                      # wait for the parent's write
sys.stdout.write("%%d\\n" %% buf.value)   # echo what the memory holds now
sys.stdout.flush()
sys.stdin.readline()                      # stay alive until killed
""" % SENTINEL


@pytest.fixture
def child():
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", CHILD],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        address = int(proc.stdout.readline())
        yield proc, address
    finally:
        proc.kill()
        proc.wait(timeout=30)


def _open(pid):
    try:
        return OpenProcess(pid=pid)
    except PermissionError as error:
        pytest.skip("attaching to a child process is refused here: %s" % error)


def test_read_write_and_death_of_a_foreign_process(child):
    proc, address = child

    with _open(proc.pid) as process:
        assert process.read_process_memory(address, int, 4) == SENTINEL
        assert process.read_process_memory(address, bytes, 4) == struct.pack("<I", SENTINEL)

        process.write_process_memory(address, int, 4, REPLACEMENT)
        assert process.read_process_memory(address, int, 4) == REPLACEMENT

        # The target itself reports the new value: the write landed in *its*
        # address space, not in some buffer of ours.
        proc.stdin.write("\n")
        proc.stdin.flush()
        assert int(proc.stdout.readline()) == REPLACEMENT

        proc.kill()
        proc.wait(timeout=30)

        # The open handle outlives the target; reads through it must fail
        # loudly rather than return stale or zeroed bytes.
        with pytest.raises((OSError, PyMemoryEditorError)):
            process.read_process_memory(address, int, 4)

    # A reaped pid no longer exists, so opening it is refused up front.
    with pytest.raises(ProcessIDNotExistsError):
        OpenProcess(pid=proc.pid)
