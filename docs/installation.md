# Installation

PyMemoryEditor is published on [PyPI](https://pypi.org/project/PyMemoryEditor/)
as a pure-Python wheel — there is no native build step or compiler required on
any platform.

## Requirements

<table>
<tr><td><b>Python</b></td><td>3.10 or newer</td></tr>
<tr><td><b>Operating systems</b></td><td>🪟 Windows · 🐧 Linux · 🍎 macOS (32-bit and 64-bit)</td></tr>
<tr><td><b>Runtime dependency</b></td><td><a href="https://pypi.org/project/psutil/"><code>psutil</code></a> (installed automatically)</td></tr>
</table>

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

The library itself stays dependency-free — only the `app` extra pulls
PySide6 in.

See the [GUI App guide](app.md) for a tour of every feature.

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
