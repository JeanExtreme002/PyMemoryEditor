# -*- coding: utf-8 -*-

"""
Multi-platform library developed with ctypes for reading, writing and
searching at process memory, in a simple and friendly way with Python 3.

Supported platforms: Windows, Linux and macOS (32-bit and 64-bit).
"""

__author__ = "Jean Loui Bernard Silva de Jesus"
__version__ = "2.0.0"

import logging
import sys
from typing import TYPE_CHECKING

from .enums import ScanTypesEnum
from .process.abstract import AbstractProcess
from .process.errors import (
    AmbiguousProcessNameError,
    ClosedProcess,
    ProcessIDNotExistsError,
    ProcessNotFoundError,
    PyMemoryEditorError,
)
from .process.module_info import ModuleInfo
from .process.thread_info import ThreadInfo


# Package-wide logger. Silent by default (NullHandler) — embedding apps opt in
# with `logging.basicConfig(level=logging.DEBUG)` or by attaching a handler to
# the "PyMemoryEditor" logger. Backends emit DEBUG for transient skips (pages
# vanished mid-scan) and WARNING for surprising-but-recovered conditions
# (partial reads, mach_vm_protect restore failure).
logger = logging.getLogger("PyMemoryEditor")
logger.addHandler(logging.NullHandler())


if sys.platform == "win32":
    from .win32.process import WindowsProcess
    from .win32.enums.process_operations import ProcessOperationsEnum

    OpenProcess = WindowsProcess
    _PLATFORM_EXPORTS = ("ProcessOperationsEnum",)

elif sys.platform.startswith("linux"):
    from .linux.process import LinuxProcess

    OpenProcess = LinuxProcess
    _PLATFORM_EXPORTS = ()

elif sys.platform == "darwin":
    from .macos.process import MacProcess

    OpenProcess = MacProcess
    _PLATFORM_EXPORTS = ()

else:
    raise ImportError(
        "PyMemoryEditor supports Windows, Linux and macOS. "
        "Current platform: %r is not supported." % sys.platform
    )


# At runtime `OpenProcess` is the single concrete backend chosen for the host
# platform above — that's all Python needs. For type-checkers (pyright/mypy)
# running on a Linux dev box but analyzing code that targets Windows (or vice
# versa), expose the union of every backend so the Windows-only `permission=`
# kwarg is visible regardless of where the checker runs. This block is never
# evaluated at runtime.
if TYPE_CHECKING:
    from typing import Union

    from .linux.process import LinuxProcess as _LinuxProcess
    from .macos.process import MacProcess as _MacProcess
    from .win32.process import WindowsProcess as _WindowsProcess

    AnyProcess = Union[_WindowsProcess, _LinuxProcess, _MacProcess]


__all__ = (
    "AbstractProcess",
    "AmbiguousProcessNameError",
    "ClosedProcess",
    "ModuleInfo",
    "OpenProcess",
    "ProcessIDNotExistsError",
    "ProcessNotFoundError",
    "PyMemoryEditorError",
    "ScanTypesEnum",
    "ThreadInfo",
    "__author__",
    "__version__",
    "logger",
) + _PLATFORM_EXPORTS
