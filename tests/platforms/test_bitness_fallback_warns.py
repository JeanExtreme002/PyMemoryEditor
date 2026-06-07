# -*- coding: utf-8 -*-

"""
Regression guard: the bitness detectors must *warn* when they can't read the
target's header and fall back to a guess, instead of mis-detecting silently.

A wrong bitness silently poisons the pointer-width default used by the pointer
APIs (resolve_pointer_chain / RemotePointer / scan_pointer_paths). The Windows
path (``IsProcess64Bit`` / ``mbi_class_for_handle``) already warned on the
``IsWow64Process`` failure; these tests lock the same contract on the macOS and
Linux fallbacks so a refactor can't drop the warning unnoticed.

Each test forces the no-header fallback via monkeypatch (no special process or
permission needed) and asserts a WARNING reaches the ``PyMemoryEditor`` logger.
"""

import logging
import sys

import pytest


@pytest.fixture
def warning_records():
    """Capture WARNING+ records emitted on the PyMemoryEditor logger."""
    records = []

    class _ListHandler(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger("PyMemoryEditor")
    handler = _ListHandler(level=logging.WARNING)
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS backend only")
def test_is_task_64bit_warns_when_no_header_readable(monkeypatch, warning_records):
    from PyMemoryEditor.macos import functions as mac

    # No module yields a readable Mach-O header → the fallback fires.
    monkeypatch.setattr(mac, "get_modules", lambda task: iter(()))

    result = mac.is_task_64bit(0)

    assert result is True  # macOS is 64-bit only since Catalina
    assert any(
        r.levelno == logging.WARNING and "is_task_64bit" in r.getMessage()
        for r in warning_records
    )


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux backend only"
)
def test_is_process_64bit_warns_when_elf_class_unknown(monkeypatch, warning_records):
    from PyMemoryEditor.linux import functions as lin

    # Neither /proc/<pid>/exe nor any file-backed mapping yields an EI_CLASS.
    monkeypatch.setattr(lin, "_read_elf_class", lambda path: None)
    monkeypatch.setattr(lin, "get_memory_regions", lambda pid: iter(()))

    result = lin.is_process_64bit(12345)

    assert isinstance(result, bool)
    assert any(
        r.levelno == logging.WARNING and "is_process_64bit" in r.getMessage()
        for r in warning_records
    )
