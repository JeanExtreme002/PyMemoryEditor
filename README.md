# PyMemoryEditor

A Python library developed with [ctypes](https://docs.python.org/3/library/ctypes.html) to manipulate Windows processes (32 bits and 64 bits), <br>
reading and writing values in the process memory.

[![Python Package](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml/badge.svg)](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml)
[![Pypi](https://img.shields.io/pypi/v/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![License](https://img.shields.io/pypi/l/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![Python Version](https://img.shields.io/badge/python-3.6%20%7C%203.7%20%7C%203.8-blue)](https://pypi.org/project/PyMemoryEditor/)

# Installing PyMemoryEditor:
```
pip3 install PyMemoryEditor
```

# Basic Usage:

Import `PyMemoryEditor` and open a process using the `OpenProcess` class, passing a window title, process name <br>
or PID as an argument. You can use the context manager to do this.

```
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name = "example.exe") as process:
    # Do something...
```

After that, use the methods `read_process_memory` and `write_process_memory` to manipulate the process <br>
memory, passing in the function call the memory address, data type and its size. See the example below:

```
from PyMemoryEditor import OpenProcess

title = "Window title of an example program"
address = 0x0005000C

with OpenProcess(window_title = title) as process:

    # Getting value from the process memory.
    value = process.read_process_memory(address, int, 4)

    # Writing to the process memory.
    process.write_process_memory(address, int, 4, value + 7)
```
