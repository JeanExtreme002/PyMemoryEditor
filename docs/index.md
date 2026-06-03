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
  <a href="https://pypi.org/project/PyMemoryEditor/"><img src="https://img.shields.io/pypi/l/PyMemoryEditor" alt="License" /></a>
  <a href="https://pypi.org/project/PyMemoryEditor/"><img src="https://img.shields.io/badge/python-3.10+-8A2BE2" alt="Python Version" /></a>
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
    for address in process.search_by_value(int, 4, 100):
        print(f"Found at 0x{address:X}")

    # Write a new value at a known address.
    process.write_process_memory(address, int, 4, 9999)
```

```{admonition} Enjoying PyMemoryEditor?
:class: tip

If the library saved you time, please **[⭐ star it on GitHub](https://github.com/JeanExtreme002/PyMemoryEditor)** —
it's the single easiest way to support the project and help others discover it.
```

## User's Guide

This part of the documentation walks you through every workflow, from opening a
process to following multi-level pointer chains, plus the bundled GUI app.

```{toctree}
:maxdepth: 2

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
