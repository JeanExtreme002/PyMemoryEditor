# PyMemoryEditor
A Python library developed with [ctypes](https://docs.python.org/3/library/ctypes.html) to manipulate Windows, Linux and macOS processes (32-bit and 64-bit), <br>
reading, writing and searching values in the process memory.

[![Python Package](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml/badge.svg)](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml)
[![Pypi](https://img.shields.io/pypi/v/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![License](https://img.shields.io/pypi/l/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-red)](https://pypi.org/project/PyMemoryEditor/)
[![Python Version](https://img.shields.io/badge/python-3.10+-8A2BE2)](https://pypi.org/project/PyMemoryEditor/)
[![Downloads](https://static.pepy.tech/personalized-badge/pymemoryeditor?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads)](https://pypi.org/project/PyMemoryEditor/)

# Installing PyMemoryEditor:
```
pip install PyMemoryEditor
```

> **Upgrading from 1.x?** See `CHANGELOG.md` — version 2.0 changes the default
> permission from `PROCESS_ALL_ACCESS` to
> `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` (the minimal read-only set,
> covering both `ReadProcessMemory` and `VirtualQueryEx`). Callers that need
> to write must request
> `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION`.

### Qt app:
Type `pymemoryeditor` at the CLI to launch a [Cheat Engine](https://en.wikipedia.org/wiki/Cheat_Engine)-style memory scanner built on Qt (PySide6). The app exercises every public surface of the library: all eight `ScanTypesEnum` modes, the five value types (`bool`, `int`, `float`, `str`, `bytes`), `search_by_value`, `search_by_value_between`, `search_by_addresses`, `read_process_memory`, `write_process_memory`, `get_memory_regions` / `snapshot_memory_regions`, plus value freezing and a hex viewer.

> The app requires **PySide6**. Install it with the `app` extra:
>
> ```
> pip install "PyMemoryEditor[app]"
> ```
>
> or separately: `pip install PySide6`. The app aborts with a clear
> message if PySide6 is missing.

# Basic Usage:
Import `PyMemoryEditor` and open a process using the `OpenProcess` class, passing a window title, process name <br>
or PID as an argument. You can use the context manager for doing it.
```py
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name = "example.exe") as process:
    # Do something...
```

## Refine-scan workflow (recommended)
For the common "scan → restrict → restrict" pattern (Cheat Engine's classic
loop), enumerate the regions **once** and reuse the snapshot across every
subsequent call. On heavy targets (browsers, JVMs with 100k regions) this is
a massive win — the per-call region enumeration is the dominant cost
otherwise:
```py
with OpenProcess(pid=1234) as process:
    regions = process.snapshot_memory_regions()

    # First pass: every address holding the value 100.
    candidates = list(process.search_by_value(int, None, 100, memory_regions=regions))

    # Refine: keep only those that now hold 95.
    refined = [
        addr for addr, value in process.search_by_addresses(int, None, candidates, memory_regions=regions)
        if value == 95
    ]
```
`snapshot_memory_regions()`, `search_by_value`, `search_by_value_between` and
`search_by_addresses` all accept the same `memory_regions=` keyword. Pass an
empty list (`[]`) to explicitly scan nothing.

## Reading and writing
Use the methods `read_process_memory` and `write_process_memory` to manipulate the process <br>
memory. Numeric types (`int`, `float`, `bool`) infer the buffer length automatically; pass an
explicit length only for `str`/`bytes` or when overriding the default width:
```py
from PyMemoryEditor import OpenProcess, ProcessOperationsEnum

title = "Window title of an example program"
address = 0x0005000C

# By default OpenProcess only requests read permission. To write, opt in explicitly:
permission = (
    ProcessOperationsEnum.PROCESS_VM_READ.value
    | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION.value
    | ProcessOperationsEnum.PROCESS_VM_WRITE.value
    | ProcessOperationsEnum.PROCESS_VM_OPERATION.value
)

with OpenProcess(window_title=title, permission=permission) as process:

    # Reading: bufflength is inferred (int → 4 bytes).
    value = process.read_process_memory(address, int)

    # Writing: same — pass None to use the default size.
    process.write_process_memory(address, int, None, value + 7)

    # Strings require an explicit size:
    name = process.read_process_memory(address, str, 32)
```

## Selecting processes by name (case-insensitive)
On Windows process names are case-insensitive — pass `case_sensitive=False` to match the
OS convention:
```py
with OpenProcess(process_name="NOTEPAD.EXE", case_sensitive=False) as process:
    ...
```

> On Linux, `permission` is ignored. The library uses `process_vm_readv` /
> `process_vm_writev`, which depend on `ptrace_scope` and process ownership. If
> the target process is not a child of the caller and `ptrace_scope=1` (the
> common default), you'll get a `PermissionError`. Run as root or adjust
> `/proc/sys/kernel/yama/ptrace_scope`.

> On macOS, `permission` is ignored. The library uses the Mach VM APIs
> (`task_for_pid`, `mach_vm_read_overwrite`, `mach_vm_write`, `mach_vm_region`).
> Opening **another** process requires the Python binary to be signed with the
> `com.apple.security.cs.debugger` entitlement (or SIP disabled and running as
> root). Opening the **current** process always works because the library calls
> `mach_task_self_` directly — handy for self-inspection and tests.

> ⚠️ **macOS write side effect.** `write_process_memory` on a read-only page
> transparently elevates the page protection via `mach_vm_protect`, performs
> the write, and tries to restore the original protection. **If the restore
> step fails** (e.g. the target task disappears mid-call), the library emits
> a `ResourceWarning` and the target page is left more permissive than it
> started — a persistent side effect outside the library's process. Treat
> the warning as a signal to investigate, not log noise. The Win32 and Linux
> backends do not have this property: protection elevation is opt-in on
> Windows (`PROCESS_VM_OPERATION`) and Linux does not need protection
> changes for `process_vm_writev`.

# Getting memory addresses by a target value:
You can look up a value in memory and get the address of all matches, like this:
```py
for address in process.search_by_value(int, 4, target_value):
    print("Found address:", address)
```

## Choosing the comparison method used for scanning:
There are many options to scan the memory. Check all available options in [`ScanTypesEnum`](https://github.com/JeanExtreme002/PyMemoryEditor/blob/main/PyMemoryEditor/enums.py).

The default option is `EXACT_VALUE`, but you can change it at `scan_type` parameter:
```py
for address in process.search_by_value(int, 4, target_value, scan_type = ScanTypesEnum.BIGGER_THAN):
    print("Found address:", address)
```

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


