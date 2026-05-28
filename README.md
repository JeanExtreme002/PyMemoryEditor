# PyMemoryEditor

A pure-Python library (built on [ctypes](https://docs.python.org/3/library/ctypes.html)) that lets you **inspect, modify and search the memory of any running process in a few lines of Python** — Cheat Engine-style scans, pointer chains and AOB search on Windows, Linux and macOS.

[![Python Package](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml/badge.svg)](https://github.com/JeanExtreme002/PyMemoryEditor/actions/workflows/python-package.yml)
[![Pypi](https://img.shields.io/pypi/v/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![License](https://img.shields.io/pypi/l/PyMemoryEditor)](https://pypi.org/project/PyMemoryEditor/)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-red)](https://pypi.org/project/PyMemoryEditor/)
[![Python Version](https://img.shields.io/badge/python-3.10+-8A2BE2)](https://pypi.org/project/PyMemoryEditor/)
[![Downloads](https://static.pepy.tech/personalized-badge/pymemoryeditor?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads)](https://pypi.org/project/PyMemoryEditor/)

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
  <img src="https://raw.githubusercontent.com/JeanExtreme002/PyMemoryEditor/main/assets/screenshots/app.png" alt="PyMemoryEditor app attached to a running process" width="820" />
</p>

<p align="center">
  Runs on <b>🪟 Windows</b> · <b>🐧 Linux</b> · <b>🍎 macOS</b> — 32-bit and 64-bit, with the same code on all three.
</p>

---

## Install

```bash
pip install PyMemoryEditor
```

To also install the bundled GUI app (a Cheat Engine-style scanner), use the `app` extra:

```bash
pip install "PyMemoryEditor[app]"
pymemoryeditor
```

---

## A 60-second taste

```python
from PyMemoryEditor import OpenProcess

with OpenProcess(process_name="game.exe") as process:

    # Scan the whole process for every address holding the value 100.
    for address in process.search_by_value(int, 4, 100):
        print(f"Found at 0x{address:X}")

    # Write a new value at a known address.
    process.write_process_memory(0x006A9EC0, int, 4, 9999)
```

That's it — read, write or scan another process in three lines, the same way on every platform.

---

## What's inside

<table>
<tr>
<td width="50%" valign="top">

**🐍 The Python library**

- ✅ **Read & write** values (`int`, `float`, `bool`, `str`, `bytes`)
- 🔍 **Value scan** with eight comparison modes
- 🎯 **Pattern scan** (IDA-style AOB & regex)
- 🔗 **Pointer chains** + a live `RemotePointer` handle
- 🧭 **Pointer scan** — find static pointers that survive ASLR
- 🗺️ **Memory map**, **modules**, **threads**
- 🧱 **Allocate & free** remote memory (Windows / macOS)

</td>
<td width="50%" valign="top">

**🖥️ The bundled GUI app**

- 🎯 **Scanner** — every scan mode, ranges, regex/AOB search
- 🔁 **Refine workflow** — First Scan → Next Scan…
- 📋 **Cheat table** — freeze / write values, JSON import/export
- 🔗 **Pointer scan** — export, rescan & compare
- 🗺️ **Memory map** with R/W/X flags
- 🔬 **Hex viewer** with write-back

</td>
</tr>
</table>

---

## 📖 Documentation

Full documentation lives at **[pymemoryeditor.readthedocs.io](https://pymemoryeditor.readthedocs.io)** — installation, the Cheat Engine workflow, every method and parameter, the GUI app guide, platform notes and troubleshooting.

A quick map of where to go:

<table>
<tr><td><a href="docs/quickstart.md"><b>Quick Start</b></a></td><td>Open a process, read, write and run your first scan.</td></tr>
<tr><td><a href="docs/guide/searching.md"><b>Searching memory</b></a></td><td>Value scans, ranges, refining results, the Cheat Engine loop.</td></tr>
<tr><td><a href="docs/guide/pattern-scan.md"><b>Pattern scan</b></a></td><td>Find code/data with byte signatures (AOB) and regex.</td></tr>
<tr><td><a href="docs/guide/pointers.md"><b>Pointers</b></a></td><td>Multi-level pointer chains and the live <code>RemotePointer</code>.</td></tr>
<tr><td><a href="docs/guide/pointer-scan.md"><b>Pointer scan</b></a></td><td>Find static pointers that survive ASLR.</td></tr>
<tr><td><a href="docs/app.md"><b>The GUI app</b></a></td><td>The bundled Cheat Engine-style scanner.</td></tr>
<tr><td><a href="docs/api/openprocess.md"><b>API reference</b></a></td><td>Every public class, method and parameter.</td></tr>
<tr><td><a href="docs/platform-notes.md"><b>Platform notes</b></a></td><td>Permissions and quirks on Windows, Linux and macOS.</td></tr>
<tr><td><a href="docs/troubleshooting.md"><b>Troubleshooting</b></a></td><td>Common errors and how to fix them.</td></tr>
</table>

---

## What can I build with this?

- 🎮 **Game modding & speedrunning tools** — the classic Cheat Engine use case.
- 🔬 **Debugging & introspection** — inspect live state without attaching a debugger.
- 📊 **Observability tooling** — sample variables in a running process for telemetry.
- 🔐 **Security & reverse-engineering research** — on systems you own or are authorized to test.
- 🎓 **Learning** — the bundled app is a great teaching tool for how memory scanning works.

> [!NOTE]
> **Responsible use.** PyMemoryEditor talks to other processes through OS-level APIs.
> Only point it at processes you own or have explicit permission to inspect.

---

## 🤝 Contributing

Pull requests, bug reports and feature ideas are very welcome. Read
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the development setup, test layout and
the small set of platform-specific quirks to be aware of.

If PyMemoryEditor helped your project, please ⭐ the repo — it's the easiest way to
support the work and to help others discover the library.

---

## License

Released under the [MIT License](LICENSE) — free for personal and commercial use.
