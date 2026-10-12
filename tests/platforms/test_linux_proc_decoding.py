# -*- coding: utf-8 -*-

"""
Linux-only tests: bytes read from ``/proc`` that are not valid UTF-8 never
abort a listing.

``/proc/<pid>/comm`` and the ``comm`` field of ``/proc/<pid>/task/<tid>/stat``
are whatever a process named itself (``prctl(PR_SET_NAME)`` takes raw bytes),
and a path in ``/proc/<pid>/maps`` is whatever bytes the file system holds.
They used to be read in strict text mode, so a single process named
``b"\\xff"`` made ``get_processes`` — and therefore ``OpenProcess(name=...)``
for *every* process — raise ``UnicodeDecodeError``, and one non-UTF-8 mapped
path broke every region listing and scan of its process.

``open`` is replaced in the backend module with a fake that serves canned
file contents and honours ``mode`` / ``encoding`` / ``errors`` the way the
real ``open`` does (strict decoding unless told otherwise), so the test runs
with no special process present.
"""

import io
import os
import sys

import pytest


if not sys.platform.startswith("linux"):
    pytest.skip("Linux-only module", allow_module_level=True)


from PyMemoryEditor.linux import functions as lin  # noqa: E402


def _fake_open(files):
    def fake(path, mode="r", encoding=None, errors=None, **kwargs):
        try:
            data = files[path]
        except KeyError:
            raise FileNotFoundError(2, "No such file or directory", path)
        if "b" in mode:
            return io.BytesIO(data)
        return io.TextIOWrapper(
            io.BytesIO(data), encoding=encoding or "utf-8", errors=errors
        )

    return fake


def test_a_non_utf8_process_name_does_not_break_the_process_list(monkeypatch):
    files = {
        "/proc/100/comm": b"\xff\xfeodd\n",
        "/proc/200/comm": b"sentinel-app\n",
    }
    monkeypatch.setattr(lin, "open", _fake_open(files), raising=False)
    monkeypatch.setattr(lin.os, "listdir", lambda path: ["100", "200", "self"])

    processes = dict(lin.get_processes())

    assert processes[200] == "sentinel-app"
    assert processes[100] == "��odd"


def test_a_non_utf8_mapped_path_does_not_break_the_region_walk(monkeypatch):
    maps = (
        b"00400000-00401000 r-xp 00000000 08:01 1234 /opt/app/caf\xe9.so\n"
        b"00600000-00602000 rw-p 00000000 00:00 0 \n"
        b"7f0000000000-7f0000001000 r--s 00001000 08:01 99 /usr/lib/ok.so\n"
    )
    monkeypatch.setattr(lin, "open", _fake_open({"/proc/42/maps": maps}), raising=False)

    regions = list(lin.get_memory_regions(42))

    assert [(r.address, r.size) for r in regions] == [
        (0x400000, 0x1000),
        (0x600000, 0x2000),
        (0x7F0000000000, 0x1000),
    ]
    # The struct keeps the raw bytes; the portable path is decoded leniently.
    assert bytes(regions[0].struct.Path).rstrip(b"\x00") == b"/opt/app/caf\xe9.so"
    assert regions[0].path == "/opt/app/caf�.so"
    assert regions[0].is_executable and not regions[0].is_writable
    assert regions[1].path == "" and regions[1].is_writable
    assert regions[2].path == "/usr/lib/ok.so" and regions[2].is_shared
    assert regions[2].struct.Offset == 0x1000
    assert regions[2].struct.InodeID == 99


def test_a_non_utf8_thread_name_does_not_break_the_thread_list(monkeypatch):
    fields = ["S"] + ["0"] * 14 + ["20"] + ["0"] * 30
    stat = b"7 (\xffworker) " + " ".join(fields).encode() + b"\n"
    monkeypatch.setattr(
        lin, "open", _fake_open({"/proc/42/task/7/stat": stat}), raising=False
    )
    monkeypatch.setattr(lin.os, "listdir", lambda path: ["7"])

    threads = list(lin.get_threads(42))

    assert len(threads) == 1
    assert threads[0].tid == 7
    assert threads[0].state == "S"
    assert threads[0].priority == 20


def test_the_real_process_list_includes_this_process():
    assert os.getpid() in dict(lin.get_processes())
