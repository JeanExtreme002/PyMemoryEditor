# PyMemoryEditor

A Python library developed with [ctypes](https://docs.python.org/3/library/ctypes.html) to manipulate Windows and Linux processes (32 bits and 64 bits), <br>
reading and writing values in the process memory.

[![Python Package](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml/badge.svg)](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml)
[![Pypi](https://img.shields.io/pypi/v/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![License](https://img.shields.io/pypi/l/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux-8A2BE2)](https://pypi.org/project/PyMemoryEditor/)
[![Python Version](https://img.shields.io/badge/python-3.6%20%7C%20...%20%7C%203.10%20%7C%203.11-blue)](https://pypi.org/project/PyMemoryEditor/)
[![Downloads](https://static.pepy.tech/personalized-badge/pymemoryeditor?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads)](https://pypi.org/project/PyMemoryEditor/)

# Installing PyMemoryEditor:
```
pip3 install PyMemoryEditor
```

# Basic Usage:
Import `PyMemoryEditor` and open a process using the `OpenProcess` class, passing a window title, process name <br>
or PID as an argument. You can use the context manager to do this.
```py
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name = "example.exe") as process:
    # Do something...
```

After that, use the methods `read_process_memory` and `write_process_memory` to manipulate the process <br>
memory, passing in the function call the memory address, data type and its size. See the example below:
```py
from PyMemoryEditor import OpenProcess

title = "Window title of an example program"
address = 0x0005000C

with OpenProcess(window_title = title) as process:

    # Getting value from the process memory.
    value = process.read_process_memory(address, int, 4)

    # Writing to the process memory.
    process.write_process_memory(address, int, 4, value + 7)
```

# Getting memory addresses by a target value:
You can look up a value in memory and get the address of all matches, like this:
```py
for address process.search_by_value(int, 4, target_value):
    print("Found address:", address)
```

## Choosing the comparison method used for scanning:
There are many options to scan the memory. Check all available options in [`ScanTypesEnum`](https://github.com/JeanExtreme002/PyMemoryEditor/blob/master/PyMemoryEditor/win32/enums/scan_types.py).

The default option is `EXACT_VALUE`, but you can change it at `scan_type` parameter:
```py
for address process.search_by_value(int, 4, target_value, scan_type = ScanTypesEnum.BIGGER_THAN):
    print("Found address:", address)
```

**Note:** The scan types `EXACT_VALUE` and `NOT_EXACT_VALUE` uses [KMP (Knuth–Morris–Pratt) Algorithm](https://en.wikipedia.org/wiki/Knuth%E2%80%93Morris%E2%80%93Pratt_algorithm) to speed up the search process.

You can also search for a value within a range:
```py
for address process.search_by_value_between(int, 4, min_value, max_value, ...):
    print("Found address:", address)
```

All the methods above even work for strings.

## Extra information from search_by_value method:
This method also has the `progress_information` parameter that returns a dictionary containing search progress information.
```py
for address, info process.search_by_value(int, 4, target_value, progress_information = True):
    template = "Address: 0x{:<10X} | Progress: {:.1f}%"
    progress = info["progress"] * 100
    
    print(template.format(address, progress))
```
