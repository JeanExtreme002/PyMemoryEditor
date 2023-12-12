# PyMemoryEditor
A Python library developed with [ctypes](https://docs.python.org/3/library/ctypes.html) to manipulate Windows and Linux processes (32 bits and 64 bits), <br>
reading, writing and searching values in the process memory.

[![Python Package](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml/badge.svg)](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml)
[![Pypi](https://img.shields.io/pypi/v/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![License](https://img.shields.io/pypi/l/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux-8A2BE2)](https://pypi.org/project/PyMemoryEditor/)
[![Python Version](https://img.shields.io/badge/python-3.6%20%7C...%7C%203.11%20%7C%203.12-blue)](https://pypi.org/project/PyMemoryEditor/)
[![Downloads](https://static.pepy.tech/personalized-badge/pymemoryeditor?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads)](https://pypi.org/project/PyMemoryEditor/)

# Installing PyMemoryEditor:
```
pip install PyMemoryEditor
```

### Tkinter application sample:
Type `pymemoryeditor` at the CLI to run a tkinter app — similar to the [Cheat Engine](https://en.wikipedia.org/wiki/Cheat_Engine) — to scan a process.

# Basic Usage:
Import `PyMemoryEditor` and open a process using the `OpenProcess` class, passing a window title, process name <br>
or PID as an argument. You can use the context manager for doing it.
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
for address in process.search_by_value(int, 4, target_value):
    print("Found address:", address)
```

## Choosing the comparison method used for scanning:
There are many options to scan the memory. Check all available options in [`ScanTypesEnum`](https://github.com/JeanExtreme002/PyMemoryEditor/blob/master/PyMemoryEditor/win32/enums/scan_types.py).

The default option is `EXACT_VALUE`, but you can change it at `scan_type` parameter:
```py
for address in process.search_by_value(int, 4, target_value, scan_type = ScanTypesEnum.BIGGER_THAN):
    print("Found address:", address)
```

**Note:** The scan types `EXACT_VALUE` and `NOT_EXACT_VALUE` uses [KMP (Knuth–Morris–Pratt) Algorithm](https://en.wikipedia.org/wiki/Knuth%E2%80%93Morris%E2%80%93Pratt_algorithm), that has completixy O(n + m) — `n` is the size of the memory page and `m` is the value length — to speed up the search process. The other scan types use the [brute force algorithm](https://en.wikipedia.org/wiki/Brute-force_search), which is O(n * m), so the search may be slower depending on the length of the target value.

You can also search for a value within a range:
```py
for address in process.search_by_value_between(int, 4, min_value, max_value, ...):
    print("Found address:", address)
```

All methods described above work even for strings, including the method `search_by_value_between` — however, `bytes` comparison may work differently than `str` comparison, depending on the `byteorder` of your system.

## Progress information on searching:
These methods has the `progress_information` parameter that returns a dictionary containing the search progress information.
```py
for address, info in process.search_by_value(..., progress_information = True):
    template = "Address: 0x{:<10X} | Progress: {:.1f}%"
    progress = info["progress"] * 100
    
    print(template.format(address, progress))
```

# Reading multiple addresses efficiently:
If you have a large number of addresses where their values need to be read from memory, using the `search_by_addresses` method is much more efficient than reading the value of each address one by one.
```py
for address, value in process.search_by_addresses(int, 4, addresses_list):
    print(f"Address", address, "holds the value", value)
```
The key advantage of this method is that it reads a memory page just once, obtaining the values of the addresses within the page. This approach reduces the frequency of system calls.

## Getting memory regions:
Use the method `get_memory_regions()` to get the base address, size and more information of all memory regions used by the process.

```py
for memory_region in process.get_memory_regions():
    base_address = memory_region["address"]
    size = memory_region["size"]
    information = memory_region["struct"]
```
