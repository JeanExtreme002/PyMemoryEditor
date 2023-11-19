# -*- coding: utf-8 -*-

"""
Multi-platform library developed with ctypes for reading, writing and
searching process memory, in a simple and friendly way with Python 3.

The package supports Windows and Linux (32-bit and 64-bit).
"""

__author__ = "Jean Loui Bernard Silva de Jesus"
__version__ = "1.5.10"


from .enums import ScanTypesEnum
import sys

# For Windows.
if "win" in sys.platform:
    from .win32.process import WindowsProcess
    from .win32.enums.process_operations import ProcessOperationsEnum
    OpenProcess = WindowsProcess

# For Linux.
else:
    from .linux.process import LinuxProcess
    from .linux.ptrace import ptrace
    from .linux.ptrace.enums import PtraceCommandsEnum
    OpenProcess = LinuxProcess
