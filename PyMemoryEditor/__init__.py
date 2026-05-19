# -*- coding: utf-8 -*-

"""
Multi-platform library developed with ctypes for reading, writing and
searching at process memory, in a simple and friendly way with Python 3.

Supported platforms: Windows, Linux and macOS (32-bit and 64-bit).
"""

__author__ = "Jean Loui Bernard Silva de Jesus"
__version__ = "2.0.0"

import sys

from .enums import ScanTypesEnum
from .process.errors import (
    AmbiguousProcessNameError,
    ClosedProcess,
    ProcessIDNotExistsError,
    ProcessNotFoundError,
    PyMemoryEditorError,
    WindowNotFoundError,
)


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


__all__ = (
    "AmbiguousProcessNameError",
    "ClosedProcess",
    "OpenProcess",
    "ProcessIDNotExistsError",
    "ProcessNotFoundError",
    "PyMemoryEditorError",
    "ScanTypesEnum",
    "WindowNotFoundError",
    "__author__",
    "__version__",
) + _PLATFORM_EXPORTS
