# PyMemoryEditor

<p align="center">
  <img src="https://raw.githubusercontent.com/JeanExtreme002/PyMemoryEditor/main/PyMemoryEditor/app/assets/icon.svg" alt="PyMemoryEditor logo" width="110" />
</p>

<p align="center">
  <b>Read, write and scan the memory of any process — straight from Python.</b><br>
  <i>One unified API. Three operating systems. No C compiler, no native build step.</i>
</p>

<p align="center">
  Runs on <b>🪟 Windows</b> · <b>🐧 Linux</b> · <b>🍎 macOS</b> — 32-bit and 64-bit.
</p>

<p align="center">
  <a href="https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml"><img src="https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml/badge.svg" alt="Python Package" /></a>
  <a href="https://pypi.org/project/PyMemoryEditor/"><img src="https://img.shields.io/pypi/v/PyMemoryEditor" alt="Pypi" /></a>
  <a href="https://github.com/JeanExtreme002/PyMemoryEditor"><img src="https://img.shields.io/pypi/l/PyMemoryEditor" alt="License" /></a>
  <a href="https://github.com/JeanExtreme002/PyMemoryEditor"><img src="https://img.shields.io/badge/python-3.10+-8A2BE2" alt="Python Version" /></a>
  <a href="https://pypi.org/project/PyMemoryEditor/"><img src="https://static.pepy.tech/personalized-badge/pymemoryeditor?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads" alt="Downloads" /></a>
</p>

Welcome to PyMemoryEditor's documentation. PyMemoryEditor is a pure-Python
library — built on [ctypes](https://docs.python.org/3/library/ctypes.html) — that
lets you **inspect, modify and search the memory of any running process**: your
own scripts, a game, a debugger target, anything. It brings the operations
Cheat Engine made famous (value scans, pattern scans, pointer chains, pointer
scans, freezing values) to a small, friendly API that works **identically on
Windows, Linux and macOS**.

Get going with the [Installation](installation.md) and [Quick Start](quickstart.md)
pages, then dig into the [User Guide](guide/index.md) for the in-depth walkthroughs.
Prefer to click rather than type? The bundled [GUI app](app.md) gives you a
Cheat Engine-style interface for free.

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name="game.exe") as process:

    # Scan the whole process for every address holding the value 100.
    for address in process.search_by_value(int, value=100):
        print(f"Found at 0x{address:X}")

    # Read the current value, then write a new one back.
    current = process.read_int(address)
    process.write_int(address, current + 500)
```

```{admonition} Enjoying PyMemoryEditor?
:class: tip

If the library saved you time, please **[⭐ star it on GitHub](https://github.com/JeanExtreme002/PyMemoryEditor)** —
it's the single easiest way to support the project and help others discover it.
```

## Why PyMemoryEditor?

<table class="feature-grid">
<tr>
<td width="50%" valign="top">

**🌍 Truly cross-platform**

One identical API on **Windows, Linux and macOS**, 32- and 64-bit. Write your
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
and selective scans get **10–60× faster** — a drop-in fast path, identical
results.

**🖥️ A GUI app, included**

No code required: the bundled [Cheat Engine-style app](app.md) lets anyone
explore, scan and freeze values by clicking.

</td>
</tr>
</table>

## User's Guide

This part of the documentation walks you through every workflow, from opening a
process to following multi-level pointer chains, plus the bundled GUI app.

```{toctree}
:maxdepth: 2

why
installation
quickstart
guide/index
app
```

## API Reference

If you are looking for information on a specific class, method or parameter,
this part of the documentation is for you.

```{toctree}
:maxdepth: 2

api/index
```

## Additional Notes

Platform-specific behaviour, troubleshooting, logging, a glossary of the terms
used throughout these docs, plus how to contribute and the project's license.

```{toctree}
:maxdepth: 1

platform-notes
troubleshooting
guide/logging
glossary
contributing
license
```

## Project links

- 📦 **PyPI:** <https://pypi.org/project/PyMemoryEditor/>
- 🐙 **GitHub:** <https://github.com/JeanExtreme002/PyMemoryEditor>
- 🐛 **Issues:** <https://github.com/JeanExtreme002/PyMemoryEditor/issues>
- 🤝 **Contributing:** [How to Contribute](contributing.md)
- 📜 **License:** [MIT License](license.md)
