# Why PyMemoryEditor?

Reading and writing another process's memory has always meant one of two things:
wrestling with the Win32 API through `ctypes` by hand, or reaching for a
platform-specific C extension that you have to compile. PyMemoryEditor gives you
a **single, friendly Python API** that does the hard parts for you — and the
*same* code runs on Windows, Linux and macOS.

If you've ever used **Cheat Engine**, you already know the workflow: scan for a
value, refine until one address remains, then read, write or freeze it.
PyMemoryEditor brings that exact workflow to Python — scriptable, repeatable and
cross-platform.

```{admonition} Enjoying PyMemoryEditor?
:class: tip

If this page convinces you, the single easiest way to support the project is to
**[⭐ star it on GitHub](https://github.com/JeanExtreme002/PyMemoryEditor)** —
it helps others discover the library too.
```

## What you get

<table class="feature-grid">
<tr>
<td width="50%" valign="top">

**🌍 Truly cross-platform**

One identical API on **Windows, Linux and macOS**, 32-bit and 64-bit. Write your
script once; it runs everywhere.

**🪶 Zero dependencies**

Pure Python on top of [ctypes](https://docs.python.org/3/library/ctypes.html) —
no C compiler, no native build step, no wheels to chase.

**🔎 The full Cheat Engine toolkit**

Value scans with eight comparison modes, AOB / regex pattern scans, and the
classic *first scan → refine* loop.

</td>
<td width="50%" valign="top">

**🔗 Pointers that survive restarts**

A reverse pointer scan finds the static `module + offsets` chains that beat
ASLR — save them once and reuse them every launch.

**⚡ Optional NumPy acceleration**

Add the [`speed`](installation.md#install-with-scan-acceleration-speed) extra
and selective scans get **~10–30× faster** — a drop-in fast path, identical
results.

**🖥️ A GUI app, included**

No code required: the bundled [Cheat Engine-style app](app.md) lets anyone
explore, scan and freeze values by clicking.

</td>
</tr>
</table>

## Who it's for

- **Game hackers and trainer authors** — find health, ammo or score addresses,
  build static pointer paths that survive restarts, and freeze values.
- **Reverse engineers** — script memory inspection of a debugger target, dump
  regions, or scan for byte patterns across a process.
- **QA and tooling engineers** — read or poke another process's state from an
  automated test, without bolting on a debugger.
- **The curious** — learn how processes lay out memory, what ASLR does, and why
  pointer chains matter, with a hands-on, Pythonic API.

## Why not just use ctypes directly?

You *can* call `ReadProcessMemory` / `process_vm_readv` yourself — but then you
own all of this:

- Per-platform handle management, permission flags and error codes.
- Buffer allocation, type packing and unpacking for every value type.
- Walking memory regions, modules and pointer chains by hand.
- A completely separate code path for Windows vs. Linux vs. macOS.

PyMemoryEditor wraps all of that behind a handful of methods — `OpenProcess`,
`read_process_memory`, `write_process_memory`, `search_by_value`,
`scan_pointer_paths` — that behave the same everywhere. See the
[platform notes](platform-notes.md) for the details it handles for you.

## See it in action

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(name="game.exe") as process:

    # Scan the whole process for every address holding the value 100.
    for address in process.search_by_value(int, value=100):
        print(f"Found at 0x{address:X}")

    # Read the current value, then write a new one back.
    current = process.read_int(address)
    process.write_int(address, current + 500)
```

Convinced? Head to the [Installation](installation.md) page, then the
[Quick Start](quickstart.md) — you'll be overwriting a value in another process
in about five minutes.

```{admonition} ⚖️ Responsible use
:class: warning

PyMemoryEditor talks to other processes through OS-level APIs. **Only point it
at processes you own or have explicit permission to inspect.**
```
