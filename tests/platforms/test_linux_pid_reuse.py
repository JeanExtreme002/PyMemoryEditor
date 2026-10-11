# -*- coding: utf-8 -*-

"""
Linux-only tests: an opened process is bound to the original process, not to
its pid number.

Nothing on the Linux I/O path pins the target (no handle as on Windows, no
task port as on macOS): process_vm_readv / process_vm_writev take a bare pid.
Once the target exits and is reaped, the pid can be recycled, and without a
guard every later write would land in an unrelated process. ``LinuxProcess``
holds a pidfd (or, without pidfds, the /proc start time) and verifies it
before each operation.

Real pid reuse is impractical to force in a test, so reuse is simulated by
making the identity check fail while the pid still exists; the kill tests use
a child process the test owns and always reaps.
"""

import errno
import os
import subprocess
import sys

import pytest


if not sys.platform.startswith("linux"):
    pytest.skip("Linux-only module", allow_module_level=True)


from PyMemoryEditor import OpenProcess, ProcessIDNotExistsError  # noqa: E402
from PyMemoryEditor.linux import functions as lin  # noqa: E402
from PyMemoryEditor.linux import process as lin_process  # noqa: E402


_HAS_PIDFD = lin.open_pidfd(os.getpid()) is not None


@pytest.fixture
def child():
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"]
    )
    try:
        yield proc
    finally:
        proc.kill()
        proc.wait()


@pytest.fixture
def no_pidfd(monkeypatch):
    """Force the start-time fallback used when pidfd_open is unavailable."""
    monkeypatch.setattr(lin_process, "open_pidfd", lambda pid: None)


def _first_readable_address(process):
    for region in process.get_memory_regions():
        if region.is_readable:
            return region.address
    raise AssertionError("target maps no readable region")


def _fail_if_called(*args, **kwargs):
    raise AssertionError("the syscall reached a pid the guard should reject")


def _kill_and_reap(proc):
    proc.kill()
    proc.wait()


@pytest.mark.skipif(not _HAS_PIDFD, reason="pidfd_open unavailable here")
def test_open_holds_a_pidfd_and_close_releases_it(child):
    process = OpenProcess(pid=child.pid)
    pidfd = process._LinuxProcess__pidfd
    assert pidfd is not None
    os.fstat(pidfd)  # open

    assert process.close() is True
    with pytest.raises(OSError) as excinfo:
        os.fstat(pidfd)
    assert excinfo.value.errno == errno.EBADF

    # Idempotent: a second close (or __exit__ / __del__) is a no-op.
    assert process.close() is True


@pytest.mark.parametrize("fallback", [False, True], ids=["pidfd", "start_time"])
def test_operations_on_a_reaped_target_raise(child, request, fallback):
    if fallback:
        request.getfixturevalue("no_pidfd")
    elif not _HAS_PIDFD:
        pytest.skip("pidfd_open unavailable here")

    with OpenProcess(pid=child.pid) as process:
        address = _first_readable_address(process)
        process.read_process_memory(address, bytes, 1)  # works while alive

        _kill_and_reap(child)

        with pytest.raises(ProcessIDNotExistsError):
            process.write_process_memory(address, bytes, 1, b"\x00")
        with pytest.raises(ProcessIDNotExistsError):
            list(process.get_memory_regions())

        # Single-value reads are verified only with the cheap pidfd probe;
        # under the fallback they reach the kernel, which rejects the reaped
        # pid itself (ESRCH) — pid reuse within that window is the residual.
        expected = OSError if fallback else ProcessIDNotExistsError
        with pytest.raises(expected):
            process.read_process_memory(address, bytes, 1)
        assert process._target_alive() is False


@pytest.mark.skipif(not _HAS_PIDFD, reason="pidfd_open unavailable here")
def test_write_after_pid_reuse_never_reaches_the_new_process(child, monkeypatch):
    with OpenProcess(pid=child.pid) as process:
        address = _first_readable_address(process)

        # The pid still exists (as it would after reuse), but the pidfd says
        # the process this object was opened on is gone.
        monkeypatch.setattr(lin_process, "pidfd_alive", lambda pidfd: False)
        monkeypatch.setattr(lin.libc, "process_vm_writev", _fail_if_called)
        monkeypatch.setattr(lin.libc, "process_vm_readv", _fail_if_called)

        assert os.path.isdir("/proc/%d" % child.pid)
        with pytest.raises(ProcessIDNotExistsError):
            process.write_process_memory(address, int, 4, 1)
        with pytest.raises(ProcessIDNotExistsError):
            process.read_process_memory(address, int, 4)


def test_start_time_fallback_detects_pid_reuse(child, no_pidfd, monkeypatch):
    with OpenProcess(pid=child.pid) as process:
        assert process._LinuxProcess__pidfd is None
        address = _first_readable_address(process)
        original = process._LinuxProcess__start_time
        assert original is not None

        # A recycled pid carries a later start time.
        monkeypatch.setattr(lin_process, "read_start_time", lambda pid: original + 1)
        monkeypatch.setattr(lin.libc, "process_vm_writev", _fail_if_called)

        with pytest.raises(ProcessIDNotExistsError):
            process.write_process_memory(address, int, 4, 1)
        with pytest.raises(ProcessIDNotExistsError):
            list(process.search_by_addresses(int, 4, [address]))


def test_inconclusive_pidfd_probe_falls_back_to_start_time(child, monkeypatch):
    with OpenProcess(pid=child.pid) as process:
        original = process._LinuxProcess__start_time
        monkeypatch.setattr(lin_process, "pidfd_alive", lambda pidfd: None)

        assert process._target_alive() is True
        monkeypatch.setattr(lin_process, "read_start_time", lambda pid: original + 1)
        assert process._target_alive() is False


def test_pidfd_open_on_vanished_pid_raises(monkeypatch):
    def gone(pid, flags):
        raise ProcessLookupError(errno.ESRCH, "No such process")

    monkeypatch.setattr(lin.os, "pidfd_open", gone, raising=False)
    monkeypatch.setattr(lin.signal, "pidfd_send_signal", lambda *a: None, raising=False)

    with pytest.raises(ProcessIDNotExistsError):
        lin.open_pidfd(os.getpid())


@pytest.mark.parametrize("code", [errno.ENOSYS, errno.EPERM, errno.EINVAL])
def test_pidfd_open_unavailable_falls_back(monkeypatch, code):
    def unavailable(pid, flags):
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(lin.os, "pidfd_open", unavailable, raising=False)
    monkeypatch.setattr(lin.signal, "pidfd_send_signal", lambda *a: None, raising=False)

    assert lin.open_pidfd(os.getpid()) is None


def test_pidfd_alive_classifies_errors(monkeypatch):
    def raising(exc):
        def fake(pidfd, sig):
            raise exc
        return fake

    cases = [
        (ProcessLookupError(errno.ESRCH, "gone"), False),
        (PermissionError(errno.EPERM, "other user"), True),
        (OSError(errno.EINVAL, "other namespace"), None),
    ]
    for exc, expected in cases:
        monkeypatch.setattr(lin.signal, "pidfd_send_signal", raising(exc), raising=False)
        assert lin.pidfd_alive(3) is expected


def test_read_start_time_handles_parens_in_comm(monkeypatch, tmp_path):
    fields = ["S"] + [str(n) for n in range(4, 30)]  # field 3 .. 29
    stat = tmp_path / "stat"
    stat.write_bytes(b"42 (we ird) name)) " + " ".join(fields).encode())

    real_open = open
    monkeypatch.setattr(
        lin, "open", lambda path, mode="r": real_open(stat, mode), raising=False
    )
    assert lin.read_start_time(42) == 22


def test_read_start_time_of_self_is_stable():
    first = lin.read_start_time(os.getpid())
    assert first is not None
    assert lin.read_start_time(os.getpid()) == first
