# Installation

PyMemoryEditor is published on [PyPI](https://pypi.org/project/PyMemoryEditor/)
as a pure-Python wheel — there is no native build step or compiler required on
any platform.

## Requirements

<table>
<tr><td><b>Python</b></td><td>3.10 or newer</td></tr>
<tr><td><b>Operating systems</b></td><td>🪟 Windows · 🐧 Linux · 🍎 macOS</td></tr>
</table>
<br>

## Install the library

```bash
pip install PyMemoryEditor
```

## Install with the bundled GUI app

The library ships an optional Cheat Engine-style GUI built on **PySide6
(Qt for Python)**. To install it, use the `app` extra:

```bash
pip install "PyMemoryEditor[app]"
```

Once installed, launch the app from any terminal:

```bash
pymemoryeditor
```

The library itself stays dependency-free — only the `app` extra pulls in its
dependencies (PySide6 and psutil, used by the GUI's process picker).

See the [GUI App guide](app.md) for a tour of every feature.

## Install with scan acceleration (`speed`)

Scans run in pure Python by default — no dependencies, works everywhere. If you
scan large processes often, the optional `speed` extra pulls in
[NumPy](https://pypi.org/project/numpy/) and **automatically** vectorizes the
inner comparison loop of the typed numeric scans (`BIGGER_THAN`,
`SMALLER_THAN`, `VALUE_BETWEEN`, …):

```bash
pip install "PyMemoryEditor[speed]"
```

That's the only change required — there is no new API and no flag to toggle.
PyMemoryEditor detects NumPy at import time and switches the fast path on; if
NumPy is absent it falls back to the pure-Python loop transparently. The results
are **identical** either way — only the speed changes (typically ~10–30× faster
on selective scans of large regions). See
[Scan acceleration](guide/searching.md#scan-acceleration-the-speed-extra) for
details and benchmarks.

NumPy ships prebuilt wheels for Windows, Linux and macOS, so the `speed` extra
stays compiler-free and cross-platform — no native build step on any OS.

## Install from source

```bash
git clone https://github.com/JeanExtreme002/PyMemoryEditor.git
cd PyMemoryEditor
pip install -e ".[dev]"
```

The `dev` extra installs the test toolchain (`pytest`, `pytest-xdist`,
`pytest-qt`, `hypothesis`, `mypy`, etc.) — see
[CONTRIBUTING.md](https://github.com/JeanExtreme002/PyMemoryEditor/blob/main/CONTRIBUTING.md)
for the development workflow.

## Verifying the installation

```python
import PyMemoryEditor
print(PyMemoryEditor.__version__)
```

If that prints a version number, you're ready to go — head to the
[Quick Start](quickstart.md).

## Platform-specific notes

```{admonition} 🪟 Windows
:class: note

Works out of the box. To attach to **protected processes** (system services,
elevated apps), run your terminal **as Administrator**.
```

```{admonition} 🐧 Linux
:class: note

Access depends on `ptrace_scope` and process ownership. If the target is **not**
a child of the caller and `ptrace_scope=1` (the common default), you'll see a
`PermissionError`. Run as root, or relax it:

    sudo sysctl kernel.yama.ptrace_scope=0
```

```{admonition} 🍎 macOS
:class: note

Opening **another** process requires the Python binary to be signed with the
`com.apple.security.cs.debugger` entitlement (or SIP disabled and root).
**Opening the current process** always works — handy for self-inspection and
experimentation.
```

For the long version, see [Platform Notes](platform-notes.md).
