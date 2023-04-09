# -*- coding: utf-8 -*-

"""
A Python library developed with ctypes to manipulate Windows processes (32 bits and 64 bits),
reading and writing values in the process memory.
"""

__author__ = "Jean Loui Bernard Silva de Jesus"
__version__ = "1.4.0"

import sys

if "win" not in sys.platform:
    raise OSError("Only Windows OS is currently supported.")

from .open_process import OpenProcess, ProcessOperations
