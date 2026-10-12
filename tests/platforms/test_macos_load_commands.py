# -*- coding: utf-8 -*-

"""
macOS-only tests: the Mach-O / dyld walk behind ``get_modules`` must stay
bounded however the target's memory lies about itself.

``ncmds``, ``sizeofcmds`` and dyld's ``infoArrayCount`` are all read from the
*target*; a corrupted or hostile process could make the walk loop ~4 billion
times. Every fake image / dyld table here is built in a ctypes buffer inside
the test's own process and walked through ``mach_task_self`` — no foreign
process is involved.
"""

import ctypes
import struct
import sys

import pytest


if sys.platform != "darwin":
    pytest.skip("macOS-only module", allow_module_level=True)


from PyMemoryEditor.macos import functions as mac  # noqa: E402
from PyMemoryEditor.macos.libsystem import mach_task_self_  # noqa: E402


_TASK = mach_task_self_.value
_MH_MAGIC_64 = 0xFEEDFACF
_LC_SEGMENT_64 = 0x19
_LC_UUID = 0x1B

_TEXT_VMADDR = 0x100000000
_TEXT_VMSIZE = 0x4000
_DATA_VMSIZE = 0x8000


def _segment(name: bytes, vmaddr: int, vmsize: int) -> bytes:
    """A 72-byte segment_command_64 (no sections)."""
    return struct.pack(
        "<II16sQQQQiiII",
        _LC_SEGMENT_64, 72, name, vmaddr, vmsize, 0, vmsize, 5, 5, 0, 0,
    )


def _uuid_command() -> bytes:
    return struct.pack("<II16s", _LC_UUID, 24, b"\x00" * 16)


def _image(commands: bytes, *, ncmds: int, sizeofcmds=None) -> ctypes.Array:
    """A fake mach_header_64 followed by ``commands``, kept alive by the caller."""
    if sizeofcmds is None:
        sizeofcmds = len(commands)
    header = struct.pack(
        "<IiiIIIII", _MH_MAGIC_64, 0x0100000C, 0, 2, ncmds, sizeofcmds, 0, 0
    )
    return ctypes.create_string_buffer(header + commands, len(header) + len(commands))


_COMMANDS = (
    _segment(b"__PAGEZERO", 0, 0x100000000)
    + _segment(b"__TEXT", _TEXT_VMADDR, _TEXT_VMSIZE)
    + _uuid_command()
    + _segment(b"__DATA", _TEXT_VMADDR + _TEXT_VMSIZE, _DATA_VMSIZE)
)


def _expected_segments(base: int):
    return [(base, _TEXT_VMSIZE), (base + _TEXT_VMSIZE, _DATA_VMSIZE)]


def test_a_well_formed_image_parses():
    image = _image(_COMMANDS, ncmds=4)
    base = ctypes.addressof(image)
    assert mac._macho_image_size(_TASK, base) == _TEXT_VMSIZE
    assert mac.get_image_segments(_TASK, base) == _expected_segments(base)


def test_a_huge_ncmds_is_capped_by_sizeofcmds(monkeypatch):
    """ncmds=0xFFFFFFFF must not drive ~4 billion iterations."""
    image = _image(_COMMANDS, ncmds=0xFFFFFFFF)
    base = ctypes.addressof(image)

    reads = []
    real_read = mac.read_process_memory

    def counting_read(*args):
        reads.append(args)
        return real_read(*args)

    monkeypatch.setattr(mac, "read_process_memory", counting_read)
    assert mac.get_image_segments(_TASK, base) == _expected_segments(base)
    # Header + one bulk read of the command block.
    assert len(reads) == 2


def test_a_huge_sizeofcmds_is_capped(monkeypatch):
    monkeypatch.setattr(mac, "_MAX_SIZEOFCMDS", len(_COMMANDS))
    image = _image(_COMMANDS, ncmds=4, sizeofcmds=0xFFFFFFFF)
    base = ctypes.addressof(image)

    sizes = []
    real_read = mac.read_process_memory

    def recording_read(task, address, pytype, length):
        sizes.append(length)
        return real_read(task, address, pytype, length)

    monkeypatch.setattr(mac, "read_process_memory", recording_read)
    assert mac.get_image_segments(_TASK, base) == _expected_segments(base)
    assert max(sizes) == len(_COMMANDS)


@pytest.mark.parametrize("bad_size", (0, 4))
def test_an_undersized_cmdsize_stops_the_walk(bad_size):
    bogus = struct.pack("<II", _LC_UUID, bad_size) + b"\x00" * 16
    image = _image(
        _segment(b"__TEXT", _TEXT_VMADDR, _TEXT_VMSIZE) + bogus,
        ncmds=0xFFFFFFFF,
    )
    base = ctypes.addressof(image)
    assert mac.get_image_segments(_TASK, base) == [(base, _TEXT_VMSIZE)]


def test_a_command_running_past_sizeofcmds_stops_the_walk():
    overlong = struct.pack("<II", _LC_UUID, 0x7FFFFFF0) + b"\x00" * 16
    image = _image(
        _segment(b"__TEXT", _TEXT_VMADDR, _TEXT_VMSIZE) + overlong,
        ncmds=3,
    )
    base = ctypes.addressof(image)
    assert mac.get_image_segments(_TASK, base) == [(base, _TEXT_VMSIZE)]


def test_the_walk_falls_back_to_per_command_reads(monkeypatch):
    """If the bulk read of the command block fails, commands are read one by one."""
    image = _image(_COMMANDS, ncmds=4)
    base = ctypes.addressof(image)
    real_read = mac.read_process_memory

    def failing_bulk_read(task, address, pytype, length):
        if length == len(_COMMANDS):
            raise mac.MachReadError(1, "simulated bulk-read failure")
        return real_read(task, address, pytype, length)

    monkeypatch.setattr(mac, "read_process_memory", failing_bulk_read)
    assert mac._macho_image_size(_TASK, base) == _TEXT_VMSIZE
    assert mac.get_image_segments(_TASK, base) == _expected_segments(base)


def test_a_huge_dyld_image_count_is_capped(monkeypatch, caplog):
    """infoArrayCount=0xFFFFFFFF lists at most _MAX_DYLD_IMAGES images."""
    cap = 3
    monkeypatch.setattr(mac, "_MAX_DYLD_IMAGES", cap)

    image = _image(_COMMANDS, ncmds=4)
    path = ctypes.create_string_buffer(b"/usr/lib/libfake.dylib")
    # dyld_image_info { load address, path pointer, mod date } x (cap + 2):
    # more real entries than the cap, so the cap is what stops the walk.
    entries = b"".join(
        struct.pack("<QQQ", ctypes.addressof(image), ctypes.addressof(path), 0)
        for _ in range(cap + 2)
    )
    info_array = ctypes.create_string_buffer(entries, len(entries))
    # dyld_all_image_infos { u32 version; u32 infoArrayCount; infoArray* }
    all_infos = ctypes.create_string_buffer(
        struct.pack("<IIQ", 17, 0xFFFFFFFF, ctypes.addressof(info_array)), 16
    )

    with caplog.at_level("WARNING", logger="PyMemoryEditor"):
        modules = list(mac._iter_dyld_images(_TASK, ctypes.addressof(all_infos)))

    assert len(modules) == cap
    assert all(module.name == "libfake.dylib" for module in modules)
    assert all(module.size == _TEXT_VMSIZE for module in modules)
    assert "only the first %d" % cap in caplog.text


def test_the_real_module_list_is_unaffected():
    """The bounds never truncate a live process's own image list."""
    modules = list(mac.get_modules(_TASK))
    assert len(modules) > 1
    assert any(module.size > 0 for module in modules)
    assert len(modules) < mac._MAX_DYLD_IMAGES


# --- dead target -------------------------------------------------------------

# A pid that is not in use (pid_max's ceiling), as in test_macos_region_walk.
_DEAD_PID = 2**31 - 1


def test_get_modules_of_a_gone_process_raises_process_id_not_exists(monkeypatch):
    from PyMemoryEditor import ProcessIDNotExistsError
    from PyMemoryEditor.macos.types import MACH_SEND_INVALID_DEST

    monkeypatch.setattr(
        mac.libsystem, "task_info", lambda *args: MACH_SEND_INVALID_DEST
    )

    with pytest.raises(ProcessIDNotExistsError) as excinfo:
        list(mac.get_modules(0x1234, _DEAD_PID))
    assert excinfo.value.pid == _DEAD_PID


def test_get_modules_of_a_live_process_keeps_the_os_error(monkeypatch):
    import os

    from PyMemoryEditor.macos.types import MACH_SEND_INVALID_DEST

    monkeypatch.setattr(
        mac.libsystem, "task_info", lambda *args: MACH_SEND_INVALID_DEST
    )

    with pytest.raises(OSError, match="task_info"):
        list(mac.get_modules(0x1234, os.getpid()))


# --- one load-command parse per image for the pointer scanner ----------------


def test_static_image_ranges_parse_each_image_once(monkeypatch):
    import os

    from PyMemoryEditor import OpenProcess

    calls = []
    real = mac._iter_load_commands

    def counting(task, load_address):
        calls.append(load_address)
        return real(task, load_address)

    with OpenProcess(pid=os.getpid()) as process:
        modules = list(process.get_modules())
        without_segments = sum(
            1 for module in modules
            if not mac.get_image_segments(_TASK, module.base_address)
        )
        monkeypatch.setattr(mac, "_iter_load_commands", counting)
        ranges = process._static_image_ranges()

    assert ranges
    # get_image_segments parses each image once; the __TEXT size parse that
    # get_modules used to add for every image now runs only as the fallback
    # for an image without segments.
    assert len(calls) == len(modules) + without_segments
