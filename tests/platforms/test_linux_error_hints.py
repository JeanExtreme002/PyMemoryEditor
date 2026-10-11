# -*- coding: utf-8 -*-

"""
Linux-only tests: each permission failure names the gate that refused it,
and a denied thread listing is an error rather than "no threads".

Two different kernel checks are involved and they used to be conflated:

- ``/proc/<pid>/maps`` needs ``PTRACE_MODE_READ``, which Yama's
  ``ptrace_scope`` does not restrict — a denial there is uid/dumpable.
- ``process_vm_readv`` / ``process_vm_writev`` need ``PTRACE_MODE_ATTACH``,
  which ``ptrace_scope=1`` denies for non-children — that is the knob the
  hint must point at.

The syscalls are patched at the ctypes seam like tests/memory/test_partial_io.py.
"""

import ctypes
import errno
import os
import sys

import pytest


if not sys.platform.startswith("linux"):
    pytest.skip("Linux-only module", allow_module_level=True)


from PyMemoryEditor.linux import functions as lin  # noqa: E402


def _failing_syscall(code):
    def fake(pid, local, local_count, remote, remote_count, flags):
        ctypes.set_errno(code)
        return -1
    return fake


def test_eperm_on_read_points_at_ptrace_scope(monkeypatch):
    monkeypatch.setattr(lin.libc, "process_vm_readv", _failing_syscall(errno.EPERM))
    buffer = (ctypes.c_byte * 4)()

    with pytest.raises(PermissionError, match="ptrace_scope") as excinfo:
        lin._process_vm_readv(os.getpid(), ctypes.addressof(buffer), 0x1000, 4)

    assert excinfo.value.errno == errno.EPERM


def test_efault_on_write_mentions_read_only_pages(monkeypatch):
    monkeypatch.setattr(lin.libc, "process_vm_writev", _failing_syscall(errno.EFAULT))
    buffer = (ctypes.c_byte * 4)()

    with pytest.raises(OSError, match="not writable") as excinfo:
        lin._process_vm_writev(os.getpid(), ctypes.addressof(buffer), 0x1000, 4)

    # errno is what `_is_transient` keys on — the hint must not replace it.
    assert excinfo.value.errno == errno.EFAULT
    assert lin._is_transient(excinfo.value)


def test_efault_on_read_stays_a_plain_transient_oserror(monkeypatch):
    monkeypatch.setattr(lin.libc, "process_vm_readv", _failing_syscall(errno.EFAULT))
    buffer = (ctypes.c_byte * 4)()

    with pytest.raises(OSError) as excinfo:
        lin._process_vm_readv(os.getpid(), ctypes.addressof(buffer), 0x1000, 4)

    assert excinfo.value.errno == errno.EFAULT
    assert "ptrace_scope" not in str(excinfo.value)
    assert lin._is_transient(excinfo.value)


def test_denied_maps_file_blames_ownership_not_ptrace_scope(monkeypatch):
    def denied_open(*args, **kwargs):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(lin, "open", denied_open, raising=False)

    with pytest.raises(PermissionError) as excinfo:
        list(lin.get_memory_regions(os.getpid()))

    message = str(excinfo.value)
    assert "another user or is not dumpable" in message
    assert "ptrace_scope" not in message


def test_denied_task_listing_raises_instead_of_yielding_nothing(monkeypatch):
    def denied_listdir(path):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(lin.os, "listdir", denied_listdir)

    with pytest.raises(PermissionError, match="Cannot list"):
        list(lin.get_threads(os.getpid()))


def test_vanished_task_directory_still_yields_nothing(monkeypatch):
    def gone_listdir(path):
        raise FileNotFoundError(errno.ENOENT, "No such file or directory")

    monkeypatch.setattr(lin.os, "listdir", gone_listdir)

    assert list(lin.get_threads(os.getpid())) == []
