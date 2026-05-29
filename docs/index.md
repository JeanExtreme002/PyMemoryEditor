# <span class="main-title">PyMemoryEditor Documentation</span>

<p align="center">
  <img src="https://raw.githubusercontent.com/JeanExtreme002/PyMemoryEditor/main/PyMemoryEditor/app/assets/icon.svg" alt="PyMemoryEditor logo" width="120" />
</p>

<p align="center">
  <b>Read, write and scan the memory of any process — straight from Python.</b><br>
  <i>One unified API. Three operating systems. No C compiler. No native build step.</i>
</p>

<p align="center">
  Runs on <b>🪟 Windows</b> · <b>🐧 Linux</b> · <b>🍎 macOS</b> — 32-bit and 64-bit.
</p>

---

## What is PyMemoryEditor?

PyMemoryEditor is a pure-Python library (built on [ctypes](https://docs.python.org/3/library/ctypes.html))
that lets you **inspect, modify and search the memory of any process running on
your computer** — your own scripts, a game, a debugger target, anything.

It exposes the same operations Cheat Engine made famous (value scans, pattern
scans, pointer chains, pointer scans, freezing values) behind a small, friendly
Python API that works identically on **Windows, Linux and macOS**.

If you've never done memory editing before, start with the
[Quick Start](quickstart.md). If you'd rather click than type, the bundled
[GUI app](app.md) gives you a Cheat Engine-style interface for free.

---

## Why use it?

<table class="feature-grid">
<tr>
<td width="33%" valign="top">

### 🌍 Cross-platform

One API across **Windows, Linux and macOS** — the same code, no platform-specific
branches in user-land.

</td>
<td width="33%" valign="top">

### 🐍 Pure Python

Pure-Python on top of `ctypes` — no C compiler, no native build step, no
platform-specific wheels.

</td>
<td width="33%" valign="top">

### 🧰 Complete toolkit

Value scans, AOB scans, pointer chains, pointer scans, a GUI app — all the
Cheat Engine workflows in one package.

</td>
</tr>
</table>

---

## Where to next?

```{toctree}
:caption: Getting Started
:maxdepth: 2

installation
quickstart
```

```{toctree}
:caption: User Guide
:maxdepth: 2

guide/index
```

```{toctree}
:caption: The GUI App
:maxdepth: 2

app
```

```{toctree}
:caption: API Reference
:maxdepth: 2

api/index
```

```{toctree}
:caption: Reference
:maxdepth: 2

platform-notes
troubleshooting
guide/logging
glossary
```

---

## Quick links

- 📦 **PyPI:** <https://pypi.org/project/PyMemoryEditor/>
- 🐙 **GitHub:** <https://github.com/JeanExtreme002/PyMemoryEditor>
- 🐛 **Issues:** <https://github.com/JeanExtreme002/PyMemoryEditor/issues>
- 📜 **License:** [MIT](https://github.com/JeanExtreme002/PyMemoryEditor/blob/main/LICENSE)
