# PyMemoryEditor
A Python library developed with [ctypes](https://docs.python.org/3/library/ctypes.html) to manipulate Windows, Linux and macOS processes (32-bit and 64-bit), <br>
reading, writing and searching values in the process memory.

[![Python Package](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml/badge.svg)](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml)
[![Pypi](https://img.shields.io/pypi/v/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![License](https://img.shields.io/pypi/l/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-red)](https://pypi.org/project/PyMemoryEditor/)
[![Python Version](https://img.shields.io/badge/python-3.10+-8A2BE2)](https://pypi.org/project/PyMemoryEditor/)
[![Downloads](https://static.pepy.tech/personalized-badge/pymemoryeditor?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads)](https://pypi.org/project/PyMemoryEditor/)

---

<p align="center">
  <img src="https://raw.githubusercontent.com/JeanExtreme002/PyMemoryEditor/main/PyMemoryEditor/app/assets/icon.svg" alt="PyMemoryEditor logo" width="120" />
</p>

<p align="center">
  <b>Read, write and scan the memory of any process — straight from Python.</b><br>
  <i>One unified API. Three operating systems. No C compiler. No native build step.</i>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-usage-guide">Usage Guide</a> ·
  <a href="#-pattern-scan-aob--find-code-or-data-by-signature">Pattern Scan</a> ·
  <a href="#-pointer-chains--survive-a-process-restart">Pointer Chains</a> ·
  <a href="#platform-notes">Platform Notes</a> ·
  <a href="#-bonus-the-pymemoryeditor-app">The App</a> ·
  <a href="#-contributing">Contributing</a>
</p>

<p align="center">
  Runs on <b>🪟 Windows</b> · <b>🐧 Linux</b> · <b>🍎 macOS</b> — 32-bit and 64-bit, with the same code on all three.
</p>

---

## ✨ Highlights

|     |     |
| --- | --- |
| **Read & write memory** | Change live values on the fly — just like Cheat Engine, but in a few lines of Python. |
| **Pure-Python via `ctypes`** | No compilation, no native wheels — `pip install` and you're done. |
| **Scan modes** | Exact, not-exact, bigger / smaller (±equal), in-range, out-of-range. |
| **Pattern scan (AOB)** | Find code or data by byte signature with `?` wildcards — IDA / Cheat-Engine style. |
| **Pointer chains** | Walk multi-level pointers (`[[base+0x10]+0x20]+0x30`) in one call. |
| **Snapshot caching** | The Cheat-Engine "scan → refine → refine" loop, accelerated. |
| **Bundled GUI app** | A full memory scanner ships in the box — just type `pymemoryeditor`. |

---

## Installation

Available on PyPI for Windows, Linux and macOS — no native build step, no extra wheels.

```bash
$ pip install PyMemoryEditor
```

To also install the bundled GUI app, use the `app` extra and launch it from any terminal:

```bash
$ pip install "PyMemoryEditor[app]"
$ pymemoryeditor
```

---

## 🚀 Quick Start

Open a target process inside a `with` block, then read, write or scan its memory using
plain Python types. Everything fits in a handful of lines:

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name="example.exe") as process:
    # Read a 4-byte int at a known address.
    value = process.read_process_memory(0x0005000C, int)
    print("Current value:", value)

    # Scan the whole process for every address holding that value.
    for address in process.search_by_value(int, 4, value):
        print(f"Found at 0x{address:X}")
```

Open a process by **process name** or **PID** — whichever you have:

```python
OpenProcess(process_name="notepad.exe")   # by process name
OpenProcess(pid=1234)                     # by PID
```

---

## 📚 Usage Guide

### Reading and writing memory

The building blocks are `read_process_memory` and `write_process_memory`. Numeric types
(`int`, `float`, `bool`) infer the buffer length automatically; `str` and `bytes`
need an explicit size.

```python
from PyMemoryEditor import OpenProcess

# By default OpenProcess opens a read+write handle, 
# so no permission needed for the common case.
with OpenProcess(process_name="notepad.exe") as process:
    address = 0x0005000C

    # Read: 4 bytes inferred for int.
    value = process.read_process_memory(address, int)

    # Write: same — pass None to use the default width.
    process.write_process_memory(address, int, None, value + 7)

    # Strings require an explicit size:
    name = process.read_process_memory(address, str, 32)
```

### Searching for a value

Look up a value anywhere in memory and stream every match:

```python
for address in process.search_by_value(int, 4, target_value):
    print(f"Found address: 0x{address:X}")
```

#### Comparison modes — pick one of eight

The default is `EXACT_VALUE`, but you can swap in any `ScanTypesEnum` mode:

<details>
<summary>Click to see all eight modes</summary>

| Mode | Description |
| --- | --- |
| `EXACT_VALUE` | Value equals the target. *(default)* |
| `NOT_EXACT_VALUE` | Value is anything **but** the target. |
| `BIGGER_THAN` | Value is strictly greater than the target. |
| `SMALLER_THAN` | Value is strictly less than the target. |
| `BIGGER_THAN_OR_EXACT_VALUE` | `value ≥ target` |
| `SMALLER_THAN_OR_EXACT_VALUE` | `value ≤ target` |
| `VALUE_BETWEEN` | `min ≤ value ≤ max` (use `search_by_value_between`) |
| `NOT_VALUE_BETWEEN` | Value falls **outside** the given range. |

</details>

```python
from PyMemoryEditor import ScanTypesEnum

for address in process.search_by_value(int, 4, target, scan_type=ScanTypesEnum.BIGGER_THAN):
    ...

for address in process.search_by_value_between(int, 4, min_value, max_value):
    ...
```

All of these work with strings too — just remember that for `bytes` the comparison
depends on your system's `byteorder`.

#### Progress information

For long scans, the same methods can yield progress alongside each address:

```python
for address, info in process.search_by_value(int, 4, target, progress_information=True):
    print(f"Address: 0x{address:<10X} | Progress: {info['progress'] * 100:.1f}%")
```

### The refine-scan workflow *(recommended)*

For the classic Cheat-Engine loop — *"first scan → restrict → restrict"* — enumerate
the memory regions **once** and reuse the snapshot across every subsequent call. On
heavy targets (browsers, JVMs with 100 000+ regions) this is a huge win, because the
per-call region enumeration is the dominant cost otherwise.

```python
with OpenProcess(pid=1234) as process:
    regions = process.snapshot_memory_regions()

    # First pass — every address holding 100.
    candidates = list(process.search_by_value(int, None, 100, memory_regions=regions))

    # Refine — keep only those that now hold 95.
    refined = [
        addr
        for addr, value in process.search_by_addresses(int, None, candidates, memory_regions=regions)
        if value == 95
    ]
```

All of `snapshot_memory_regions()`, `search_by_value`, `search_by_value_between` and
`search_by_addresses` accept the same `memory_regions=` keyword. Pass an empty list
(`[]`) to explicitly scan nothing.

### Reading many addresses efficiently

If you have a long list of addresses to read, `search_by_addresses` is *far* faster
than calling `read_process_memory` in a loop — it reads each memory page only once
and pulls every requested address out of it, slashing the number of syscalls.

```python
for address, value in process.search_by_addresses(int, 4, addresses_list):
    print("Address", hex(address), "holds the value", value)
```

### Walking the memory map

`get_memory_regions()` streams the address, size and metadata of every region the
target owns:

```python
for region in process.get_memory_regions():
    print(hex(region["address"]), region["size"], region["struct"])
```

### 🎯 Pattern scan (AOB) — find code or data by signature

When addresses move between builds, **byte patterns don't**. Drop in an IDA-style
hex string with `?` wildcards and PyMemoryEditor will find every match — the same
trick Cheat Engine, IDA and Ghidra use to anchor onto a moving target.

```python
for address in process.search_by_pattern("48 8B ? ? 00 00 89 ?"):
    print(f"Match at 0x{address:X}")
```

Prefer a raw bytes regex? Pass it through — just tell us how many bytes one
match consumes:

```python
process.search_by_pattern(rb"\x48\x8B..\x00\x00", byte_length=6)
```

### 🔗 Pointer chains — survive a process restart

Cheat Engine cheat tables describe pointers as `module + offset → [+x] → [+y] → …`.
Walk the whole chain in one line, then read or write the final address as usual:

```python
# "game.exe"+0x10F4F4 -> [+0x0] -> [+0x158]   (HP, from a cheat-table dump)
hp_address = process.resolve_pointer_chain(base + 0x10F4F4, [0x0, 0x158])
hp = process.read_process_memory(hp_address, int, 4)
```

`ptr_size=4` for 32-bit targets, `ptr_size=8` (default) for 64-bit.

---

## Platform Notes

PyMemoryEditor abstracts away the OS, but the OS still gets a say in **what you're allowed to touch**. Here's the short version per platform.

<details>
<summary><b>🪟 Windows</b> — works out of the box for most cases</summary>

- Process names are matched case-insensitively in practice. Pass `case_sensitive=False`
  to follow the OS convention.
- The `permission=` kwarg maps directly to the `PROCESS_*` flags of `OpenProcess`.
  The default is read+write (`PROCESS_VM_READ | PROCESS_VM_WRITE |
  PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION`) — pass a narrower mask if you
  want a read-only handle.

</details>

<details>
<summary><b>🐧 Linux</b> — governed by <code>ptrace_scope</code></summary>

- The `permission` argument is ignored — the library uses `process_vm_readv` /
  `process_vm_writev`.
- Access depends on `ptrace_scope` and process ownership. If the target is **not**
  a child of the caller and `ptrace_scope=1` (the common default), you'll see a
  `PermissionError`. Run as root or relax
  `/proc/sys/kernel/yama/ptrace_scope`.

</details>

<details>
<summary><b>🍎 macOS</b> — governed by Mach entitlements</summary>

- The `permission` argument is ignored — the library uses the Mach VM APIs
  (`task_for_pid`, `mach_vm_read_overwrite`, `mach_vm_write`, `mach_vm_region`).
- Opening **another** process requires the Python binary to be signed with the
  `com.apple.security.cs.debugger` entitlement (or SIP disabled and running as root).
- Opening the **current** process always works — handy for self-inspection and tests.

> [!WARNING]
> **macOS write side effect.** `write_process_memory` on a read-only page transparently
> elevates the page protection via `mach_vm_protect`, performs the write, and tries to
> restore the original protection. **If the restore step fails** (e.g. the target task
> disappears mid-call), the library emits a `ResourceWarning` and the target page is
> left more permissive than it started. Treat the warning as a signal to investigate.
> The Win32 and Linux backends do not have this property: protection elevation is
> opt-in on Windows (`PROCESS_VM_OPERATION`), and Linux does not need protection
> changes for `process_vm_writev`.

</details>

---

## 🎁 Bonus: The PyMemoryEditor App

> A **Cheat Engine-style** memory scanner, included for free with every install.

PyMemoryEditor isn't just a library — it also ships with a polished cross-platform GUI built on **PySide6 (Qt for Python)**, so you can play with everything the library does without writing a single line of code. Launch it from any terminal:

```bash
$ pymemoryeditor
```

The app is a living demo of the library — it exercises every public surface (every `ScanTypesEnum` mode, every value type, scanning, refining, freezing values, the hex viewer, the memory map). If you're learning the API, it's the fastest way to see what's possible.

<p align="center">
  <img src="https://raw.githubusercontent.com/JeanExtreme002/PyMemoryEditor/main/assets/screenshots/app.png" alt="PyMemoryEditor app attached to a running process" width="820" />
</p>

<table>
<tr>
<td width="50%" valign="top">

**✨ What you get out of the box**

- **Process picker** — list all running processes and pick by row, PID or name
- **Live scanner** — eight scan modes, value-between ranges, typed inputs
- **Refine workflow** — *First Scan → Next Scan → Next Scan…* like Cheat Engine
- **Value freezing** — pin a value so the target can't change it back
- **Memory map** — every region of the target, with R/W/X flags
- **Hex viewer** — auto-refreshing dump, write bytes back
- **Import/export** cheat tables as JSON

</td>
<td width="50%" valign="top">

**📦 Install the app extra** (adds PySide6):

```bash
$ pip install "PyMemoryEditor[app]"
```

Then launch the app by running `pymemoryeditor` from any terminal. The library itself stays dependency-free.

> Cross-platform dark theme. Single-keystroke shortcuts. Works on Windows, Linux and macOS.

</td>
</tr>
</table>

---

## What can I build with this?

- **Debugging & introspection** — inspect live state without attaching a debugger.
- **Observability tooling** — sample variables in a running process for telemetry.
- **Security & reverse-engineering research** — on systems you own or are authorized to test.
- **Personal game modding & speedrunning tools** — the classic Cheat-Engine use case.
- **Learning** — the bundled app is a great teaching tool for how memory scanning works.

> [!NOTE]
> **Responsible use.** PyMemoryEditor talks to other processes through OS-level APIs.
> Only point it at processes you own or have explicit permission to inspect.

---

## 🤝 Contributing

Pull requests, bug reports and feature ideas are very welcome. Read
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the development setup, test layout and the
small set of platform-specific quirks to be aware of.

If PyMemoryEditor helped your project, please ⭐ the repo — it's the easiest way to
support the work and to help others discover the library.

---

## License

Released under the [MIT License](LICENSE) — free for personal and commercial use.
