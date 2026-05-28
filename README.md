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
  Tweak a value in a running game · inspect a live program's state ·
  harvest data straight from RAM — <b>on Windows, Linux and macOS</b>.
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-usage-guide">Usage Guide</a> ·
  <a href="#-troubleshooting">Troubleshooting</a> ·
  <a href="#platform-notes">Platform Notes</a> ·
  <a href="#-bonus-the-pymemoryeditor-app">The App</a> ·
  <a href="#-contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/JeanExtreme002/PyMemoryEditor/main/assets/screenshots/app.png" alt="PyMemoryEditor app attached to a running process" width="820" />
</p>

<p align="center">
  Runs on <b>🪟 Windows</b> · <b>🐧 Linux</b> · <b>🍎 macOS</b> — 32-bit and 64-bit, with the same code on all three.
</p>

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
    value = 120

    # Scan the whole process for every address holding that value.
    for address in process.search_by_value(int, 4, value):
        print(f"Found at 0x{address:X}")
```

Open a process by **process name** or **PID** — whichever you have:

```python
OpenProcess(process_name="notepad.exe")   # by process name
OpenProcess(pid=1234)                     # by PID
```

### How it works in practice

You rarely know the address of a value up front — you **find it by scanning**.
The typical loop is the same one Cheat Engine made famous:

1. **Scan** for a value you can see (e.g. your health is `100`) — you get back
   many candidate addresses.
2. **Let the value change** in the target (you take damage → `95`).
3. **Refine**: keep only the addresses that now hold the new value. Repeat until
   one address remains — that's your value.
4. **Read, write or freeze** it.

```python
with OpenProcess(process_name="game.exe") as process:
    # 1. First scan — every address currently holding 100.
    candidates = list(process.search_by_value(int, 4, 100))

    # 3. After the value drops to 95 in-game, keep only the matches that agree.
    survivors = [
        address
        for address, value in process.search_by_addresses(int, 4, candidates)
        if value == 95
    ]

    # 4. Overwrite the survivors back to a high value.
    for address in survivors:
        process.write_process_memory(address, int, 4, 9999)
```

> For big targets, cache the region map once and reuse it across scans — see
> [the refine-scan workflow](#the-refine-scan-workflow-recommended).

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

### 🔍 Searching for a value

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

### 🗺️ Exploring the memory regions

A process's address space is split into regions — contiguous blocks of memory,
each with its own size and permissions. `get_memory_regions()` streams the
address, size and metadata of every region the target owns:

```python
for region in process.get_memory_regions():
    print(hex(region["address"]), region["size"], region["struct"])
```

### 📦 Listing the loaded modules

A *module* is a file mapped into the process — the main executable plus every
shared library it loaded (`.exe`/`.dll` on Windows, the binary and `.so` files
on Linux, the Mach-O image and `.dylib` files on macOS). `get_modules()` yields
a `ModuleInfo` for each one:

```python
for module in process.get_modules():
    print(
        module.name,
        hex(module.base_address), 
        module.size,
        module.path
    )
    ...
```


### 🧵 Listing the process threads

`get_threads()` yields a `ThreadInfo` for every thread running inside the
target — useful for introspection (how many workers does it spawn? is the
main thread still alive?). `main_thread` is a shortcut to the lowest-id one.

```python
for thread in process.get_threads():
    print(thread.tid, thread.state, thread.priority)

print("Main thread:", process.main_thread.tid)
```

> `tid` is the OS-native thread id (POSIX TID on Linux, thread id on Windows,
> Mach port on macOS); `state` and `priority` are filled in where the platform
> exposes them and are `None` otherwise.

### 🎯 Pattern scan — grep for process memory

Pass a raw `bytes` regular expression and the scanner applies it directly to
memory, letting you locate *data* by its shape. The example below extracts
every email address held in the target's memory.

```python
email = rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"

# byte_length is the maximum length of a single match (used to span chunk reads).
for address in process.search_by_pattern(email, byte_length=128):
    raw = process.read_process_memory(address, bytes, 128)
    print(address, raw.split(b"\x00", 1)[0].decode("ascii", "replace"))
```

Patterns also work the other way — for *code*. Absolute addresses shift between
builds, but **byte signatures remain stable**: provide an IDA-style hex string
with `?` wildcards and `search_by_pattern` returns every match, the same
technique Cheat Engine, IDA and Ghidra use to locate code that has moved.

```python
for address in process.search_by_pattern("48 8B ? ? 00 00 89 ?"):
    print(f"Match at 0x{address:X}")
```

### 🔗 Pointer chains — resolve addresses that change every run

A multi-level pointer is a static base plus a series of offsets —
`module + offset → [+x] → [+y] → …`. Walk the whole chain in one line, then
read or write the final address as usual:

```python
# module + 0x10F4F4 -> [+0x0] -> [+0x158]   (a value behind a two-level pointer)
hp_address = process.resolve_pointer_chain(base + 0x10F4F4, [0x0, 0x158])
hp = process.read_process_memory(hp_address, int, 4)
```

`ptr_size=4` for 32-bit targets, `ptr_size=8` (default) for 64-bit.

### 📍 Live pointers — a handle you keep around

`resolve_pointer_chain` finds an address once. A **`RemotePointer`** wraps that
recipe in a reusable handle: read or write the value through `.value`, and it
re-walks the chain every time — so the same handle keeps working even when the
target moves things around in memory.

```python
# A handle to the player's HP, behind a two-level pointer.
hp_ptr = process.get_pointer(address, pytype=int, bufflength=4)

print(hp_ptr.value)   # read it
hp_ptr.value = 9999   # write it
```

You can do pointer math too: `hp_ptr + 4` gives a **new** handle 4 bytes further
along (handy when values sit side by side), without touching memory. Omit the
offsets to wrap an address you already have — e.g. one found by a scan.

```python
# Mana is stored right after HP, so just step 4 bytes forward.
mp_ptr = hp_ptr + 4
print(mp_ptr.value)
```

### 🧭 Pointer scan — find a pointer that survives restarts

A scanned address is gone the next launch — the OS loads everything somewhere new every
time (ASLR). A **pointer chain** is the cure, but where do you *get* the chain?
You **pointer-scan** for it: give the value's address **right now** and the library finds
the static paths (`module + offsets`) that lead to it — the inverse of `resolve_pointer_chain`.

```python
# The value is at this address right now (e.g. from search_by_value).
for path in process.scan_pointer_paths(0x1FA3C140):
    print(path)                          # "game.exe"+0x10F4F4 -> [+0x0] -> +0x158
    print(hex(path.resolve(process)))    # walk it -> the current address
```

Each result is a `PointerPath` you can keep: `path.to_pointer(process)` turns it into a
live `RemotePointer`, and `path.rebase(process)` re-anchors it after a restart.

> A first scan usually finds **many** candidates. Start narrow and widen only if needed —
> `scan_pointer_paths(addr, max_depth=2, max_offset=0x100)`. Depth is the big cost.

#### Narrowing down to the real one

The reliable pointers are the ones that keep working after the value moves. So you
**save a scan, restart the target, and rescan** — keeping only the paths that still land
on the value. Repeat a couple of times and a handful of solid pointers remain:

```python
# Run 1 — scan and save.
pointer_paths = process.scan_pointer_paths(address)
process.save_pointer_paths(pointer_paths, "scan1.json")

# …close the target, restart it, find the value's new address again…

# Run 2 — keep only the saved paths that still reach it.
survivors = process.rescan_pointer_paths("scan1.json", new_address)
process.save_pointer_paths(survivors, "scan2.json")
```

Prefer working from independent scans? Save one per run, then **intersect** them — the
paths present in *every* file are your stable pointers (no live address needed):

```python
stable = process.compare_pointer_scans("scan1.json", "scan2.json", "scan3.json")
```

Once you're down to one, use it forever — `path.rebase(process).to_pointer(process)`
re-resolves itself on every read/write, so it just works in any future run.

### 🧱 Allocating memory in the target

Reserve a fresh block inside the target process, write to it like any other
address, then release it. The library remembers each allocation's size, so
`free_memory(address)` works without you tracking it:

```python
address = process.allocate_memory(64)             # base of a new 64-byte region
process.write_process_memory(address, int, 4, 1337)
process.free_memory(address)                       # release it
```

`allocate_memory` takes an optional, platform-specific `permission` (a `PAGE_*`
value on Windows — default `PAGE_EXECUTE_READWRITE`; a `VM_PROT_*` bitmask on
macOS — default read+write), mirroring `OpenProcess(permission=...)`.

> [!NOTE]
> **Linux is not supported here.** It has no syscall to allocate memory in
> another process's address space (`mmap` only affects the calling process);
> doing so would require a ptrace-based engine to make the target call `mmap`
> itself. Both methods raise `NotImplementedError` on Linux. Windows
> (`VirtualAllocEx`/`VirtualFreeEx`) and macOS
> (`mach_vm_allocate`/`mach_vm_deallocate`) are fully supported.

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

<table>
<tr>
<td width="50%" valign="top">

**✨ What you get out of the box**

- **Scanner** — eight scan modes, ranges, byte-signature or regex search
- **Refine workflow** — *First Scan → Next Scan → Next Scan…* like Cheat Engine
- **Cheat table** — freeze / write values, import/export as JSON
- **Pointer scan** — find static pointers; export, rescan & compare to narrow them down;
- **Memory map** — regions with R/W/X flags
- **Hex viewer** — live dump with write-back

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

## 🛟 Troubleshooting

<b>`PermissionError` when opening another process</b> — the OS is denying access.
This is the most common first hurdle:
- **Windows:** run your terminal **as Administrator** for protected targets.
- **Linux:** run as root, or relax `ptrace_scope`
  (`sudo sysctl kernel.yama.ptrace_scope=0`). Opening your own process always works.
- **macOS:** the Python binary must be signed with the
  `com.apple.security.cs.debugger` entitlement (or SIP off + root). Opening the
  *current* process always works — great for trying things out.

<b>`ProcessNotFoundError`</b> — the name didn't match. Names are case-sensitive by
default; try `OpenProcess(process_name="chrome", exact_match=False, case_sensitive=False)`
for a fuzzy match, or pass the `pid=` directly.

<b>`AmbiguousProcessNameError`</b> — more than one process matches. Pick one from the
listed PIDs and pass `pid=` instead.

<b>A scan returns nothing on Windows</b> — region enumeration needs
`PROCESS_QUERY_INFORMATION`, which the default permission already includes. If you
passed a custom `permission=` mask, make sure that flag is in it.

<b>Reading an address gives garbage or raises `OSError`</b> — the page may have been
freed between scan and read (normal during a live scan), or the value type / size
is wrong. Wrap one-off reads in `try/except OSError` and double-check the byte width.

Need more detail? The library logs to a standard `logging` logger named
`"PyMemoryEditor"` (silent by default). Turn it on to see exactly which pages
the library skips during a scan and why:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("PyMemoryEditor").setLevel(logging.DEBUG)
```

> The bundled app exposes the same stream in its **Log Console** (Tools → Log Console).

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
