# -*- coding: utf-8 -*-

"""
Windows-only: a 64-bit Python reading a real 32-bit (WOW64) process.

Regression: the region walk used to hand ``VirtualQueryEx`` the 28-byte
``MEMORY_BASIC_INFORMATION_32`` for a WOW64 target. ``VirtualQueryEx`` always
fills the *caller's* native layout and fails with ``ERROR_BAD_LENGTH`` for a
smaller buffer, so every region query failed and every scan of a 32-bit
process raised. Only a real WOW64 target exercises that path, so this module
spawns one it owns: ``SysWOW64\\cmd.exe`` blocked reading an idle stdin pipe.
It is opened read-only, inspected, and terminated in a ``finally``. No other
process is touched.

Skipped unless the host is 64-bit Windows with a 64-bit Python and the WOW64
subsystem installed (``%SystemRoot%\\SysWOW64\\cmd.exe`` exists).
"""

import ctypes
import os
import subprocess
import sys
import time

import pytest


if sys.platform != "win32":
    pytest.skip("Windows-only module", allow_module_level=True)

if ctypes.sizeof(ctypes.c_void_p) != 8:
    pytest.skip("needs a 64-bit Python to attach to a 32-bit target", allow_module_level=True)

_WOW64_CMD = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64", "cmd.exe")

if not os.path.isfile(_WOW64_CMD):
    pytest.skip("WOW64 is not installed (no SysWOW64\\cmd.exe)", allow_module_level=True)


from PyMemoryEditor import OpenProcess, ProcessOperationsEnum  # noqa: E402


_READ_ONLY = (
    ProcessOperationsEnum.PROCESS_VM_READ.value
    | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION.value
)
_CREATE_NO_WINDOW = 0x08000000
_FOUR_GB = 1 << 32


@pytest.fixture(scope="module")
def wow64_child():
    """A 32-bit cmd.exe we own, kept alive by an open stdin pipe."""
    child = subprocess.Popen(
        [_WOW64_CMD, "/Q", "/K"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=_CREATE_NO_WINDOW,
    )
    try:
        yield child
    finally:
        child.kill()
        try:
            child.wait(timeout=10)
        finally:
            if child.stdin is not None:
                child.stdin.close()


@pytest.fixture
def target(wow64_child):
    """The child opened read-only, once its loader has mapped cmd.exe."""
    assert wow64_child.poll() is None, "the WOW64 child exited early"
    with OpenProcess(pid=wow64_child.pid, permission=_READ_ONLY) as process:
        # A just-started process can fail the module snapshot
        # (ERROR_PARTIAL_COPY) until its loader is initialized; wait for it.
        deadline = time.monotonic() + 15
        while True:
            try:
                if any(m.name.lower() == "cmd.exe" for m in process.get_modules()):
                    break
            except OSError:
                pass
            if time.monotonic() > deadline:
                pytest.fail("cmd.exe never showed up in the WOW64 child's modules")
            time.sleep(0.1)
        yield process


def _cmd_module(process):
    return next(m for m in process.get_modules() if m.name.lower() == "cmd.exe")


def test_target_is_detected_as_32bit(target):
    assert target.is_64bit is False


def test_region_walk_of_a_wow64_target_succeeds(target):
    regions = list(target.get_memory_regions())

    readable_low = [r for r in regions if r.is_readable and r.address < _FOUR_GB]
    assert readable_low, "no readable region below 4 GB in a 32-bit process"
    # The image of the 32-bit cmd.exe is a file-backed view, so the walk must
    # name it — proving the region fields (State/Type) decode correctly.
    assert any(
        r.path.lower().endswith("\\syswow64\\cmd.exe") for r in regions
    ), "SysWOW64\\cmd.exe image region not found in the region walk"


def test_modules_of_a_wow64_target_are_32bit_and_readable(target):
    module = _cmd_module(target)

    assert 0 < module.base_address < _FOUR_GB
    assert module.path.lower().endswith("\\syswow64\\cmd.exe")
    assert target.read_process_memory(module.base_address, bytes, 2) == b"MZ"


def test_scans_of_a_wow64_target_work(target):
    module = _cmd_module(target)
    image = [
        r for r in target.snapshot_memory_regions()
        if r.address == module.base_address
    ]
    assert image, "no region starts at the cmd.exe image base"

    # Pattern scan restricted to the image header region (fast, deterministic).
    found = list(target.search_by_pattern("4D 5A", memory_regions=image))
    assert module.base_address in found

    # Address-list read through the chunked path, with an unrestricted walk.
    ((address, value),) = list(
        target.search_by_addresses(bytes, 2, [module.base_address])
    )
    assert address == module.base_address
    assert value == b"MZ"
