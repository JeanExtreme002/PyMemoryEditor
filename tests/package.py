# -*- coding: utf-8 -*-

import os
import sys

current_dir = os.getcwd()
sys.path.append(current_dir)

from PyMemoryEditor import OpenProcess, ScanTypesEnum
from PyMemoryEditor import __version__ as version
