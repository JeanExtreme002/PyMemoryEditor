# -*- coding: utf-8 -*-

"""
A Python library developed with ctypes to manipulate Windows and Linux processes (32 bits and 64 bits),
reading and writing values in the process memory.
"""

__author__ = "Jean Loui Bernard Silva de Jesus"
__version__ = "1.5.2"


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
    OpenProcess = LinuxProcess
