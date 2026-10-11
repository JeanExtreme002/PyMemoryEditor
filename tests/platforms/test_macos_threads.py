# -*- coding: utf-8 -*-

"""
macOS-only test: ``get_threads`` must release the thread send rights that
``task_threads`` hands back, and still report stable thread ids.

Each ``task_threads`` call adds one user reference per thread to the caller's
IPC space. The backend used to free only the array, so every call leaked a
reference per thread — unbounded growth for anything that polls the thread
list. Measured on the test's own task: the reference count of the current
thread's port must not move across repeated enumerations.
"""

import ctypes
import os
import sys
import threading

import pytest


if sys.platform != "darwin":
    pytest.skip("macOS-only module", allow_module_level=True)


from ctypes.util import find_library  # noqa: E402

from PyMemoryEditor import OpenProcess  # noqa: E402


# A private handle so the argtypes set here don't leak into the library's own.
_libsystem = ctypes.CDLL(find_library("System"))
_libsystem.mach_thread_self.restype = ctypes.c_uint
_libsystem.mach_thread_self.argtypes = ()
_libsystem.mach_port_get_refs.restype = ctypes.c_int
_libsystem.mach_port_get_refs.argtypes = (
    ctypes.c_uint,
    ctypes.c_uint,
    ctypes.c_uint,
    ctypes.POINTER(ctypes.c_uint),
)
_libsystem.mach_port_deallocate.restype = ctypes.c_int
_libsystem.mach_port_deallocate.argtypes = (ctypes.c_uint, ctypes.c_uint)
_libsystem.pthread_threadid_np.restype = ctypes.c_int
_libsystem.pthread_threadid_np.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64))

_MACH_PORT_RIGHT_SEND = 0
_TASK_SELF = ctypes.c_uint.in_dll(_libsystem, "mach_task_self_").value


def _current_thread_send_refs() -> int:
    """User references this task holds on the calling thread's port."""
    port = _libsystem.mach_thread_self()  # +1 reference, dropped below
    try:
        refs = ctypes.c_uint(0)
        kr = _libsystem.mach_port_get_refs(
            _TASK_SELF, port, _MACH_PORT_RIGHT_SEND, ctypes.byref(refs)
        )
        assert kr == 0
        return refs.value
    finally:
        _libsystem.mach_port_deallocate(_TASK_SELF, port)


def test_repeated_get_threads_does_not_leak_send_rights():
    process = OpenProcess(pid=os.getpid())
    try:
        before = _current_thread_send_refs()
        for _ in range(25):
            threads = list(process.get_threads())
            assert threads
        after = _current_thread_send_refs()
    finally:
        process.close()

    assert after == before, (
        "get_threads leaked %d send right(s) on the current thread's port"
        % (after - before)
    )


def test_an_abandoned_get_threads_generator_does_not_leak_either():
    """Rights are released before the first item, not when iteration ends."""
    process = OpenProcess(pid=os.getpid())
    try:
        before = _current_thread_send_refs()
        for _ in range(10):
            generator = process.get_threads()
            next(iter(generator))
            # Deliberately not exhausted or closed.
        after = _current_thread_send_refs()
    finally:
        process.close()

    assert after == before


def test_thread_ids_are_unique_and_include_the_current_thread():
    process = OpenProcess(pid=os.getpid())
    try:
        tids = [thread.tid for thread in process.get_threads()]
    finally:
        process.close()

    assert len(tids) == len(set(tids))
    current = ctypes.c_uint64(0)
    assert _libsystem.pthread_threadid_np(None, ctypes.byref(current)) == 0
    assert current.value in tids


def test_thread_ids_are_stable_across_calls_and_the_main_thread_is_the_oldest():
    """``tid`` is the system-wide thread id, not the port name: releasing the
    send rights must not make the same thread come back under another id, and
    the main thread (the oldest) has the smallest one."""
    # On macOS, CPython's native_id is pthread_threadid_np — the same id.
    main_native_id = threading.main_thread().native_id
    assert main_native_id is not None

    process = OpenProcess(pid=os.getpid())
    try:
        first = sorted(thread.tid for thread in process.get_threads())
        second = sorted(thread.tid for thread in process.get_threads())
        main = process.main_thread
    finally:
        process.close()

    assert first == second
    assert main is not None and main.tid == main_native_id


def test_a_thread_whose_id_cannot_be_read_is_left_out(monkeypatch):
    """A thread that exits between task_threads and thread_info has no id to
    report; it is skipped rather than listed under its port name, which lives
    in another id space and would pose as the smallest (main) thread."""
    from PyMemoryEditor.macos import functions as mac

    real_thread_id = mac._thread_id
    calls = {"count": 0}

    def first_one_only(port):
        calls["count"] += 1
        return real_thread_id(port) if calls["count"] == 1 else None

    process = OpenProcess(pid=os.getpid())
    try:
        expected = len(list(process.get_threads()))
        if expected < 2:
            pytest.skip("needs at least two threads in the test process")
        monkeypatch.setattr(mac, "_thread_id", first_one_only)
        threads = list(process.get_threads())
    finally:
        process.close()

    assert len(threads) == 1
    assert threads[0].tid != threads[0].raw  # a real thread id, not the port


def test_a_task_refusing_every_lookup_falls_back_to_port_names(monkeypatch):
    """No lookup succeeding is not threads exiting but a task that won't
    answer thread_info: the threads are still listed, under their port names."""
    from PyMemoryEditor.macos import functions as mac

    monkeypatch.setattr(mac, "_thread_id", lambda _port: None)
    process = OpenProcess(pid=os.getpid())
    try:
        threads = list(process.get_threads())
    finally:
        process.close()

    assert threads
    assert all(thread.tid == thread.raw for thread in threads)
