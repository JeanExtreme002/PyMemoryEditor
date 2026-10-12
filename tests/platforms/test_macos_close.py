# -*- coding: utf-8 -*-

"""
macOS-only tests: ``close()`` reports a failed task-port release through its
return value, like the Windows (``CloseHandle``) and Linux (pidfd) backends,
instead of always returning ``True``.

``mach_port_deallocate`` is patched at the ctypes seam and the object is
pointed at a fake port name, so the test process's real task port is never
released.
"""

import os
import sys

import pytest


if sys.platform != "darwin":
    pytest.skip("macOS-only module", allow_module_level=True)


from PyMemoryEditor import ClosedProcess, OpenProcess  # noqa: E402
from PyMemoryEditor.macos import functions as mac  # noqa: E402
from PyMemoryEditor.macos.libsystem import mach_task_self_  # noqa: E402
from PyMemoryEditor.macos.types import KERN_SUCCESS  # noqa: E402


# kern_return_t KERN_INVALID_RIGHT: the name does not denote a right we hold.
_KERN_INVALID_RIGHT = 17


_FAKE_PORT = 0x7777


def _process_on_fake_port():
    process = OpenProcess(pid=os.getpid())
    # Only the port name is swapped; the self task port is never deallocated.
    process._MacProcess__task = _FAKE_PORT
    return process


def test_close_returns_false_when_the_port_cannot_be_released(monkeypatch):
    released = []

    def failing(task, name):
        released.append(name)
        return _KERN_INVALID_RIGHT

    monkeypatch.setattr(mac.libsystem, "mach_port_deallocate", failing)
    process = _process_on_fake_port()

    assert process.close() is False
    assert released == [_FAKE_PORT]
    # Closed all the same: the port name must not be reused.
    with pytest.raises(ClosedProcess):
        process.read_process_memory(0x1000, int)
    assert process.close() is True  # idempotent


def test_close_returns_true_when_the_port_is_released(monkeypatch):
    monkeypatch.setattr(
        mac.libsystem, "mach_port_deallocate", lambda task, name: KERN_SUCCESS
    )
    assert _process_on_fake_port().close() is True


def test_release_task_never_touches_the_self_port(monkeypatch):
    calls = []
    monkeypatch.setattr(
        mac.libsystem, "mach_port_deallocate", lambda *args: calls.append(args)
    )
    assert mac.release_task(mach_task_self_.value) is True
    assert mac.release_task(0) is True
    assert calls == []
